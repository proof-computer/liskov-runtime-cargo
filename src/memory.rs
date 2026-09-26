//! The closed memory summary carried on Cargo `runtime.health` beats and on
//! `runtime.cargo.process.exited` / `.signaled` (BKLG-20260924-fbpm;
//! ADR-0157 §2, amending ADR-0079).
//!
//! Local procfs only: the device's `/proc/meminfo` and the customer process
//! tree's `/proc/<pid>/status`, reduced to seven scalar attrs. No process
//! name, PID or per-process value ever leaves this module. The key set is kept
//! synchronized by hand with the memory keys liskov-rs admits on exactly those
//! three stages in `crates/slipway-executor-contracts/src/runtime_cargo_diagnostics.rs`
//! (BKLG-20260924-ejs0), which refuses an unknown `mem*` key.
//!
//! Unlike the thermal summary the seven keys are always present: a value that
//! could not be read is null, never zero, and `memDeniedCount` says how many
//! reads failed.
//!
//! The customer process never waits on this. Reads happen on one worker
//! thread and the supervisor waits at most [`MEMORY_READ_BUDGET`] for them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

/// The kernel's process filesystem.
pub const PROC_ROOT: &str = "/proc";

/// The longest the supervisor waits for one summary: the whole read.
pub const MEMORY_READ_BUDGET: Duration = Duration::from_millis(50);
/// The process-tree walk's own deadline, which leaves the rest of
/// [`MEMORY_READ_BUDGET`] for `/proc/meminfo` and the reply.
const WALK_BUDGET: Duration = Duration::from_millis(40);
/// At most this many `/proc/<pid>/status` reads per summary.
const MAX_PROCESSES: usize = 256;
/// `/proc/meminfo` is about 1.5 KiB.
const MAX_MEMINFO_BYTES: u64 = 16 * 1024;
/// `/proc/<pid>/status` is about 1.5 KiB; the lines read here come early.
const MAX_STATUS_BYTES: u64 = 4 * 1024;

/// The seven scalar attrs, in wire spelling.
pub const MEMORY_SUMMARY_ATTRS: [&str; 7] = [
    "memTotalKib",
    "memAvailableKib",
    "swapTotalKib",
    "swapFreeKib",
    "workloadRssKib",
    "workloadRssPeakKib",
    "memDeniedCount",
];

/// One instant's memory summary, in KiB. A value that could not be read is
/// `None`, which goes on the wire as null, never as zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemorySummary {
    pub mem_total_kib: Option<i32>,
    pub mem_available_kib: Option<i32>,
    pub swap_total_kib: Option<i32>,
    pub swap_free_kib: Option<i32>,
    /// The sum of `VmRSS` over the customer process tree.
    pub workload_rss_kib: Option<i32>,
    /// The largest `VmHWM` in the customer process tree.
    pub workload_rss_peak_kib: Option<i32>,
    /// Reads that failed: an unreadable file, a missing or malformed line, a
    /// value outside the `i32` range, a denied process, or an exceeded
    /// process or time budget. A process that exits mid-walk is not one.
    pub denied_count: u32,
}

impl MemorySummary {
    /// Nothing could be read within the budget: every value null, one
    /// failure counted.
    pub fn unread() -> Self {
        Self {
            denied_count: 1,
            ..Self::default()
        }
    }

    /// Insert the seven attrs into a diagnostic's attr object.
    pub fn write_attrs(&self, attrs: &mut Map<String, Value>) {
        let values = [
            json!(self.mem_total_kib),
            json!(self.mem_available_kib),
            json!(self.swap_total_kib),
            json!(self.swap_free_kib),
            json!(self.workload_rss_kib),
            json!(self.workload_rss_peak_kib),
            json!(self.denied_count),
        ];
        for (key, value) in MEMORY_SUMMARY_ATTRS.into_iter().zip(values) {
            attrs.insert(key.to_owned(), value);
        }
    }

    fn deny(&mut self) {
        self.denied_count = self.denied_count.saturating_add(1);
    }
}

/// The customer process tree to measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Workload {
    /// The customer child the supervisor spawned. It leads its own process
    /// group.
    pub root: u32,
    /// The supervisor itself. Orphaned customer descendants are reparented to
    /// it (it is the child subreaper), but it is never part of the tree.
    pub supervisor: u32,
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<String> {
    let mut contents = String::new();
    File::open(path)?
        .take(limit)
        .read_to_string(&mut contents)?;
    Ok(contents)
}

/// The value of a `Name:  1234 kB` line as KiB.
fn kib_line(contents: &str, name: &str) -> Option<u64> {
    let line = contents.lines().find_map(|line| {
        line.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(':'))
    })?;
    let mut fields = line.split_whitespace();
    let value = fields.next()?.parse::<u64>().ok()?;
    (fields.next() == Some("kB") && fields.next().is_none()).then_some(value)
}

/// The first field of a `Name:  1234 ...` line.
fn int_line(contents: &str, name: &str) -> Option<u32> {
    contents
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(':'))
        })?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// A KiB count on the wire. Nothing is clamped: above `i32::MAX` it is null
/// and counted.
fn wire_kib(value: Option<u64>, summary: &mut MemorySummary) -> Option<i32> {
    let value = value.and_then(|value| i32::try_from(value).ok());
    if value.is_none() {
        summary.deny();
    }
    value
}

fn read_device(proc_root: &Path, summary: &mut MemorySummary) {
    let Ok(meminfo) = read_bounded(&proc_root.join("meminfo"), MAX_MEMINFO_BYTES) else {
        summary.deny();
        return;
    };
    summary.mem_total_kib = wire_kib(kib_line(&meminfo, "MemTotal"), summary);
    summary.mem_available_kib = wire_kib(kib_line(&meminfo, "MemAvailable"), summary);
    summary.swap_total_kib = wire_kib(kib_line(&meminfo, "SwapTotal"), summary);
    summary.swap_free_kib = wire_kib(kib_line(&meminfo, "SwapFree"), summary);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Process {
    parent: Option<u32>,
    group: Option<u32>,
    /// `None` for a zombie: its memory is already released.
    rss_kib: Option<u64>,
    peak_kib: Option<u64>,
}

enum StatusRead {
    Read(Process),
    /// The process exited between listing and reading.
    Gone,
    Denied,
}

fn read_status(dir: &Path) -> StatusRead {
    match read_bounded(&dir.join("status"), MAX_STATUS_BYTES) {
        Ok(status) => StatusRead::Read(Process {
            parent: int_line(&status, "PPid"),
            // The leftmost NSpgid is in the namespace of this procfs, the one
            // the supervisor's PIDs are in. Kernels without it fall back to
            // the parent links alone.
            group: int_line(&status, "NSpgid"),
            rss_kib: kib_line(&status, "VmRSS"),
            peak_kib: kib_line(&status, "VmHWM"),
        }),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            StatusRead::Gone
        }
        Err(_) => StatusRead::Denied,
    }
}

enum Walk {
    Processes(BTreeMap<u32, Process>),
    OverBudget,
    Unlisted,
}

fn walk(proc_root: &Path, supervisor: u32, deadline: Instant, summary: &mut MemorySummary) -> Walk {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Walk::Unlisted;
    };
    let mut pids = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            summary.deny();
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == supervisor {
            continue;
        }
        if pids.len() == MAX_PROCESSES {
            return Walk::OverBudget;
        }
        pids.push(pid);
    }
    let mut processes = BTreeMap::new();
    for pid in pids {
        if Instant::now() >= deadline {
            return Walk::OverBudget;
        }
        match read_status(&proc_root.join(pid.to_string())) {
            StatusRead::Read(process) => {
                processes.insert(pid, process);
            }
            StatusRead::Gone => {}
            // Customer descendants share the child's credentials, so a
            // process the supervisor may not read is counted, not assumed
            // to be the customer's.
            StatusRead::Denied => summary.deny(),
        }
    }
    Walk::Processes(processes)
}

/// The root, every process whose parent chain reaches it, and every member of
/// its process group (orphans reparented to the supervisor keep the group).
fn tree(processes: &BTreeMap<u32, Process>, root: u32) -> BTreeSet<u32> {
    let mut members: BTreeSet<u32> = processes
        .iter()
        .filter(|(pid, process)| **pid == root || process.group == Some(root))
        .map(|(pid, _)| *pid)
        .collect();
    loop {
        let before = members.len();
        let descendants: Vec<u32> = processes
            .iter()
            .filter(|(pid, process)| {
                !members.contains(pid) && process.parent.is_some_and(|ppid| members.contains(&ppid))
            })
            .map(|(pid, _)| *pid)
            .collect();
        members.extend(descendants);
        if members.len() == before {
            return members;
        }
    }
}

fn read_workload(
    proc_root: &Path,
    workload: Workload,
    deadline: Instant,
    summary: &mut MemorySummary,
) {
    let processes = match walk(proc_root, workload.supervisor, deadline, summary) {
        Walk::Processes(processes) => processes,
        Walk::OverBudget | Walk::Unlisted => {
            summary.deny();
            return;
        }
    };
    // A root that is gone, or already a zombie, has no memory left to read.
    // That is not a failed read; the tree is simply not there.
    let Some(root) = processes.get(&workload.root) else {
        return;
    };
    if root.rss_kib.is_none() {
        return;
    }
    let members = tree(&processes, workload.root);
    let mut rss = 0_u64;
    let mut peak = None::<u64>;
    for pid in members {
        let process = &processes[&pid];
        rss = rss.saturating_add(process.rss_kib.unwrap_or(0));
        if let Some(hwm) = process.peak_kib {
            peak = Some(peak.map_or(hwm, |current| current.max(hwm)));
        }
    }
    summary.workload_rss_kib = wire_kib(Some(rss), summary);
    summary.workload_rss_peak_kib = wire_kib(peak, summary);
}

/// Read `/proc/meminfo` and, when a workload is given, its process tree under
/// `proc_root`. Without a workload (its child is already reaped) the two
/// workload keys are null and nothing more is counted.
pub fn read_summary(proc_root: &Path, workload: Option<Workload>) -> MemorySummary {
    read_summary_by(proc_root, workload, Instant::now() + WALK_BUDGET)
}

fn read_summary_by(
    proc_root: &Path,
    workload: Option<Workload>,
    deadline: Instant,
) -> MemorySummary {
    let mut summary = MemorySummary::default();
    read_device(proc_root, &mut summary);
    if let Some(workload) = workload {
        read_workload(proc_root, workload, deadline, &mut summary);
    }
    summary
}

/// A single long-lived reader. At most one read is ever in flight, so a read
/// that hangs forever costs one parked thread, not one per beat.
pub struct MemorySampler {
    worker: Option<Worker>,
}

struct Worker {
    requests: SyncSender<Option<Workload>>,
    replies: Receiver<MemorySummary>,
    outstanding: bool,
}

impl MemorySampler {
    pub fn start(proc_root: impl Into<PathBuf>) -> Self {
        let proc_root = proc_root.into();
        let (requests, requested) = mpsc::sync_channel::<Option<Workload>>(1);
        let (reply, replies) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("liskov-memory".into())
            .spawn(move || {
                for workload in requested {
                    if reply.send(read_summary(&proc_root, workload)).is_err() {
                        break;
                    }
                }
            });
        Self {
            worker: spawned.ok().map(|_| Worker {
                requests,
                replies,
                outstanding: false,
            }),
        }
    }

    /// The summary at this instant, or [`MemorySummary::unread`] when it is
    /// not ready within [`MEMORY_READ_BUDGET`].
    pub fn sample(&mut self, workload: Option<Workload>) -> MemorySummary {
        self.sample_within(workload, MEMORY_READ_BUDGET)
    }

    fn sample_within(&mut self, workload: Option<Workload>, budget: Duration) -> MemorySummary {
        let Some(worker) = self.worker.as_mut() else {
            return MemorySummary::unread();
        };
        let (summary, alive) = worker.sample_within(workload, budget);
        if !alive {
            self.worker = None;
        }
        summary.unwrap_or_else(MemorySummary::unread)
    }
}

impl Worker {
    /// Returns the summary and whether the worker is still usable.
    fn sample_within(
        &mut self,
        workload: Option<Workload>,
        budget: Duration,
    ) -> (Option<MemorySummary>, bool) {
        if self.outstanding {
            match self.replies.try_recv() {
                // A late reply belongs to an earlier instant; drop it.
                Ok(_) => self.outstanding = false,
                Err(TryRecvError::Empty) => return (None, true),
                Err(TryRecvError::Disconnected) => return (None, false),
            }
        }
        match self.requests.try_send(workload) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return (None, true),
            Err(TrySendError::Disconnected(_)) => return (None, false),
        }
        match self.replies.recv_timeout(budget) {
            Ok(summary) => (Some(summary), true),
            Err(RecvTimeoutError::Timeout) => {
                self.outstanding = true;
                (None, true)
            }
            Err(RecvTimeoutError::Disconnected) => (None, false),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The 8 GB Snapdragon class (`docs/knowledge/edge-inference-8gb-processor-measurements.md`).
    const SNAPDRAGON_MEMINFO: &str = "\
MemTotal:        7177734 kB
MemFree:          412312 kB
MemAvailable:    4003906 kB
Buffers:            2048 kB
Cached:          3301232 kB
SwapCached:        10240 kB
SwapTotal:       8388604 kB
SwapFree:        8120316 kB
";

    pub(crate) const SUPERVISOR: u32 = 100;
    pub(crate) const CHILD: u32 = 101;

    /// A scratch procfs, removed on drop.
    pub(crate) struct ProcFixture {
        pub(crate) root: PathBuf,
    }

    impl ProcFixture {
        pub(crate) fn empty(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("liskov-memory-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        pub(crate) fn snapdragon(name: &str) -> Self {
            let fixture = Self::empty(name);
            std::fs::write(fixture.root.join("meminfo"), SNAPDRAGON_MEMINFO).unwrap();
            fixture
        }

        /// The supervisor, its access sidecar, the customer child, a worker
        /// the child started, and an orphan reparented to the supervisor.
        pub(crate) fn snapdragon_with_tree(name: &str) -> Self {
            let fixture = Self::snapdragon(name);
            fixture.process(SUPERVISOR, 1, SUPERVISOR, Some((9_000, 9_500)));
            fixture.process(102, SUPERVISOR, 102, Some((4_000, 4_000)));
            fixture.process(CHILD, SUPERVISOR, CHILD, Some((2_000, 3_000)));
            fixture.process(103, CHILD, CHILD, Some((600_000, 812_340)));
            fixture.process(104, SUPERVISOR, CHILD, Some((50_000, 70_000)));
            fixture.process(105, 1, 105, Some((1_000_000, 1_000_000)));
            fixture
        }

        pub(crate) fn process(&self, pid: u32, ppid: u32, pgid: u32, vm: Option<(u64, u64)>) {
            let dir = self.root.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let mut status = format!(
                "Name:\tfixture\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nNSpid:\t{pid}\nNSpgid:\t{pgid}\n"
            );
            if let Some((rss, hwm)) = vm {
                status.push_str(&format!("VmHWM:\t{hwm:>8} kB\nVmRSS:\t{rss:>8} kB\n"));
            }
            status.push_str("Threads:\t1\n");
            std::fs::write(dir.join("status"), status).unwrap();
        }
    }

    impl Drop for ProcFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    pub(crate) fn workload() -> Workload {
        Workload {
            root: CHILD,
            supervisor: SUPERVISOR,
        }
    }

    pub(crate) fn snapdragon_summary() -> MemorySummary {
        MemorySummary {
            mem_total_kib: Some(7_177_734),
            mem_available_kib: Some(4_003_906),
            swap_total_kib: Some(8_388_604),
            swap_free_kib: Some(8_120_316),
            workload_rss_kib: Some(2_000 + 600_000 + 50_000),
            workload_rss_peak_kib: Some(812_340),
            denied_count: 0,
        }
    }

    fn euid_is_root() -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn snapdragon_meminfo_produces_the_device_keys() {
        let fixture = ProcFixture::snapdragon("device");
        assert_eq!(
            read_summary_by(&fixture.root, None, far()),
            MemorySummary {
                workload_rss_kib: None,
                workload_rss_peak_kib: None,
                ..snapdragon_summary()
            }
        );
    }

    #[test]
    fn the_tree_sums_rss_and_takes_the_largest_peak_without_the_supervisor() {
        let fixture = ProcFixture::snapdragon_with_tree("tree");
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        assert_eq!(summary, snapdragon_summary());
        assert_ne!(
            summary.workload_rss_peak_kib,
            Some(1_000_000),
            "an unrelated process is not in the tree"
        );
    }

    #[test]
    fn the_supervisor_is_excluded_even_inside_the_customer_group() {
        let fixture = ProcFixture::snapdragon("supervisor");
        fixture.process(SUPERVISOR, CHILD, CHILD, Some((9_000, 9_500)));
        fixture.process(CHILD, SUPERVISOR, CHILD, Some((2_000, 3_000)));
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        assert_eq!(summary.workload_rss_kib, Some(2_000));
        assert_eq!(summary.workload_rss_peak_kib, Some(3_000));
        assert_eq!(summary.denied_count, 0);
    }

    #[test]
    fn a_missing_meminfo_nulls_the_device_keys_and_counts() {
        let fixture = ProcFixture::snapdragon_with_tree("no-meminfo");
        std::fs::remove_file(fixture.root.join("meminfo")).unwrap();
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        assert_eq!(
            summary,
            MemorySummary {
                mem_total_kib: None,
                mem_available_kib: None,
                swap_total_kib: None,
                swap_free_kib: None,
                denied_count: 1,
                ..snapdragon_summary()
            }
        );
    }

    #[test]
    fn a_wrong_unit_a_missing_line_or_an_out_of_range_value_is_null_and_counted() {
        let fixture = ProcFixture::empty("malformed");
        std::fs::write(
            fixture.root.join("meminfo"),
            "MemTotal: 7177734 MB\nSwapTotal: 2147483648 kB\nSwapFree: 2147483647 kB\n",
        )
        .unwrap();
        let summary = read_summary_by(&fixture.root, None, far());
        assert_eq!(
            summary,
            MemorySummary {
                swap_free_kib: Some(i32::MAX),
                denied_count: 3,
                ..MemorySummary::default()
            }
        );
    }

    #[test]
    fn a_process_that_disappears_mid_walk_is_skipped_without_an_error() {
        let fixture = ProcFixture::snapdragon_with_tree("vanished");
        // Listed, but its status is gone by the time it is read.
        std::fs::create_dir_all(fixture.root.join("106")).unwrap();
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        assert_eq!(summary, snapdragon_summary());
    }

    #[test]
    fn a_denied_process_is_counted_and_does_not_fail_the_read() {
        if euid_is_root() {
            eprintln!("skipped: root reads a mode-000 file");
            return;
        }
        let fixture = ProcFixture::snapdragon_with_tree("denied");
        fixture.process(107, 1, 107, Some((1, 1)));
        let status = fixture.root.join("107").join("status");
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o000)).unwrap();
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            summary,
            MemorySummary {
                denied_count: 1,
                ..snapdragon_summary()
            }
        );
    }

    #[test]
    fn more_than_256_processes_nulls_the_workload_keys_and_counts() {
        let fixture = ProcFixture::snapdragon_with_tree("crowded");
        // Five non-supervisor processes already; 252 more make 257.
        for pid in 1_000..1_252 {
            fixture.process(pid, 1, pid, Some((1, 1)));
        }
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        assert_eq!(
            summary,
            MemorySummary {
                workload_rss_kib: None,
                workload_rss_peak_kib: None,
                denied_count: 1,
                ..snapdragon_summary()
            }
        );
        std::fs::remove_dir_all(fixture.root.join("1251")).unwrap();
        assert_eq!(
            read_summary_by(&fixture.root, Some(workload()), far()),
            snapdragon_summary(),
            "exactly 256 is within budget"
        );
    }

    #[test]
    fn an_over_budget_walk_nulls_the_workload_keys_and_counts() {
        let fixture = ProcFixture::snapdragon_with_tree("slow");
        let summary = read_summary_by(&fixture.root, Some(workload()), Instant::now());
        assert_eq!(
            summary,
            MemorySummary {
                workload_rss_kib: None,
                workload_rss_peak_kib: None,
                denied_count: 1,
                ..snapdragon_summary()
            }
        );
    }

    #[test]
    fn a_reaped_or_zombie_root_leaves_the_workload_null_and_uncounted() {
        let fixture = ProcFixture::snapdragon_with_tree("zombie");
        let gone = Workload {
            root: 999,
            ..workload()
        };
        let summary = read_summary_by(&fixture.root, Some(gone), far());
        assert_eq!((summary.workload_rss_kib, summary.denied_count), (None, 0));
        fixture.process(CHILD, SUPERVISOR, CHILD, None);
        let summary = read_summary_by(&fixture.root, Some(workload()), far());
        assert_eq!(
            (summary.workload_rss_kib, summary.workload_rss_peak_kib),
            (None, None)
        );
        assert_eq!(summary.denied_count, 0);
    }

    #[test]
    fn the_live_kernel_status_format_parses() {
        let pid = std::process::id();
        let StatusRead::Read(process) = read_status(&Path::new(PROC_ROOT).join(pid.to_string()))
        else {
            panic!("the test process can read its own status");
        };
        assert!(process.rss_kib.is_some_and(|rss| rss > 0));
        assert!(process.peak_kib.is_some());
        assert!(process.parent.is_some());
        let meminfo = read_bounded(&Path::new(PROC_ROOT).join("meminfo"), MAX_MEMINFO_BYTES)
            .expect("the test host has /proc/meminfo");
        assert!(kib_line(&meminfo, "MemTotal").is_some_and(|total| total > 0));
    }

    #[test]
    fn written_attrs_are_exactly_the_seven_scalars() {
        let mut attrs = Map::new();
        MemorySummary {
            workload_rss_kib: None,
            ..snapdragon_summary()
        }
        .write_attrs(&mut attrs);
        let mut keys: Vec<&str> = attrs.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = MEMORY_SUMMARY_ATTRS;
        expected.sort_unstable();
        assert_eq!(keys, expected);
        assert!(attrs["workloadRssKib"].is_null(), "null, not zero");
        assert_eq!(attrs["memTotalKib"], 7_177_734);
        assert!(
            attrs
                .values()
                .all(|value| value.is_null() || value.is_u64()),
            "every memory attr is a non-negative integer or null: {attrs:?}"
        );
    }

    #[test]
    fn sampler_reads_the_fixture_and_reports_unread_without_a_worker_reply() {
        let fixture = ProcFixture::snapdragon_with_tree("sampler");
        let mut sampler = MemorySampler::start(&fixture.root);
        assert_eq!(
            sampler.sample_within(Some(workload()), Duration::from_secs(5)),
            snapdragon_summary()
        );
        assert_eq!(
            MemorySampler { worker: None }.sample(Some(workload())),
            MemorySummary::unread()
        );
    }

    #[test]
    fn a_hung_read_costs_the_budget_once_and_never_blocks_again() {
        use std::os::unix::ffi::OsStrExt;
        let fixture = ProcFixture::empty("hung");
        let meminfo = fixture.root.join("meminfo");
        let path = std::ffi::CString::new(meminfo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; a FIFO with no writer blocks
        // the reader in open(2), which is what a hung read looks like.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);

        let mut sampler = MemorySampler::start(&fixture.root);
        let started = Instant::now();
        assert_eq!(sampler.sample(None), MemorySummary::unread());
        assert!(started.elapsed() < Duration::from_secs(1));
        let started = Instant::now();
        assert_eq!(
            sampler.sample_within(None, Duration::from_secs(5)),
            MemorySummary::unread()
        );
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a read still in flight is not waited on twice"
        );

        // Release the parked read, then serve an ordinary file.
        {
            use std::io::Write;
            let mut writer = std::fs::OpenOptions::new()
                .write(true)
                .open(&meminfo)
                .unwrap();
            writer.write_all(b"MemTotal: 1 kB\n").unwrap();
        }
        std::fs::remove_file(&meminfo).unwrap();
        std::fs::write(&meminfo, SNAPDRAGON_MEMINFO).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let recovered = loop {
            let summary = sampler.sample_within(None, Duration::from_secs(1));
            if summary != MemorySummary::unread() {
                break summary;
            }
            assert!(Instant::now() < deadline, "sampler never recovered");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            recovered.mem_total_kib,
            Some(7_177_734),
            "the late reply from the hung instant is dropped"
        );
    }
}
