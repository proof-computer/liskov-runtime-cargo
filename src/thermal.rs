//! The closed device-temperature summary carried on Cargo `runtime.health`
//! beats and on `runtime.cargo.process.exited` / `.signaled`
//! (BKLG-20260923-opv9; ADR-0079, ADR-0157).
//!
//! Temperature only, read from local sysfs at the instant of the report, and
//! reduced to nine scalar attrs. The raw zone list is the coverage probe's
//! document, not a 30-second beat: no zone name, zone array or nested object
//! ever leaves this module. The key set is kept synchronized by hand with
//! `THERMAL_SUMMARY_ATTRS` in liskov-rs
//! `crates/slipway-executor-contracts/src/runtime_cargo_diagnostics.rs`
//! (BKLG-20260923-933t), which admits it on exactly those three stages and
//! refuses an unknown key.
//!
//! The customer process never waits on this. Reads happen on one worker
//! thread and the supervisor waits at most [`THERMAL_READ_BUDGET`] for them;
//! a missing thermal class, a hung sensor or a dead worker leaves the thermal
//! keys absent and nothing else changed.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::Duration;

use serde_json::{Map, Value, json};

/// The kernel's thermal class; each `thermal_zoneN` holds `type` and `temp`.
pub const THERMAL_CLASS_ROOT: &str = "/sys/class/thermal";

/// The longest the supervisor waits for one summary.
pub const THERMAL_READ_BUDGET: Duration = Duration::from_millis(200);

/// The probe phone exposed 93 zones; this bounds the walk on a stranger one.
const MAX_ZONES: usize = 256;
/// Both files are a short name or a decimal integer and a newline.
const MAX_ZONE_FILE_BYTES: u64 = 64;
/// Disconnected sensors on the probe phone sat at −40000 and −40960. At or
/// below this a reading is counted as a zone but never promoted into a
/// temperature group.
const SENSOR_SENTINEL_CEILING: i32 = -30_000;

/// The nine scalar attrs, in wire spelling.
pub const THERMAL_SUMMARY_ATTRS: [&str; 9] = [
    "thermalCpuMaxMillic",
    "thermalGpuMaxMillic",
    "thermalBatteryMillic",
    "thermalSkinMaxMillic",
    "thermalPackageMillic",
    "thermalDdrMillic",
    "thermalChargerMillic",
    "thermalZoneCount",
    "thermalDeniedCount",
];

/// One instant's thermal summary. A group with no readable zone is `None`,
/// which goes on the wire as null, never as zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThermalSummary {
    pub cpu_max_millic: Option<i32>,
    pub gpu_max_millic: Option<i32>,
    pub battery_millic: Option<i32>,
    pub skin_max_millic: Option<i32>,
    pub package_millic: Option<i32>,
    pub ddr_millic: Option<i32>,
    pub charger_millic: Option<i32>,
    /// Zones whose `type` and `temp` were both read and the temp parsed,
    /// sentinels included.
    pub zone_count: u32,
    /// Zones where reading `type` or `temp` failed (permission denied, no
    /// such file, a driver error). An empty or non-integer temp that was read
    /// counts in neither.
    pub denied_count: u32,
}

impl ThermalSummary {
    /// Insert the nine attrs into a diagnostic's attr object.
    pub fn write_attrs(&self, attrs: &mut Map<String, Value>) {
        let values = [
            json!(self.cpu_max_millic),
            json!(self.gpu_max_millic),
            json!(self.battery_millic),
            json!(self.skin_max_millic),
            json!(self.package_millic),
            json!(self.ddr_millic),
            json!(self.charger_millic),
            json!(self.zone_count),
            json!(self.denied_count),
        ];
        for (key, value) in THERMAL_SUMMARY_ATTRS.into_iter().zip(values) {
            attrs.insert(key.to_owned(), value);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Zone {
    Readable { kind: String, millic: i32 },
    Unreadable,
    Unparsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Cpu,
    Gpu,
    Battery,
    QcomBattery,
    Skin,
    Package,
    Ddr,
    Charger,
}

fn group(kind: &str) -> Option<Group> {
    // Voltage-style (`vbat`) and current-limit (`*ibat*`, `*bcl*`) zones are
    // not Celsius and never feed a temperature.
    if kind == "vbat" || kind.contains("ibat") || kind.contains("bcl") {
        return None;
    }
    // `cpu-*-usr` excludes `cpuss-*-usr` and every `*-step` zone.
    if kind.starts_with("cpu-") && kind.ends_with("-usr") {
        return Some(Group::Cpu);
    }
    if kind.starts_with("gpuss-") && kind.ends_with("-usr") {
        return Some(Group::Gpu);
    }
    match kind {
        "battery" => Some(Group::Battery),
        "qcom_battery" => Some(Group::QcomBattery),
        "front_temp" | "back_temp" | "quiet_therm" => Some(Group::Skin),
        "msm_therm" => Some(Group::Package),
        "ddr-usr" => Some(Group::Ddr),
        "chg_therm" => Some(Group::Charger),
        _ => None,
    }
}

fn raise(slot: &mut Option<i32>, millic: i32) {
    *slot = Some(slot.map_or(millic, |current| current.max(millic)));
}

fn summarize(zones: impl IntoIterator<Item = Zone>) -> ThermalSummary {
    let mut summary = ThermalSummary::default();
    let mut qcom_battery = None;
    for zone in zones {
        let (kind, millic) = match zone {
            Zone::Readable { kind, millic } => (kind, millic),
            Zone::Unreadable => {
                summary.denied_count = summary.denied_count.saturating_add(1);
                continue;
            }
            Zone::Unparsed => continue,
        };
        summary.zone_count = summary.zone_count.saturating_add(1);
        if millic <= SENSOR_SENTINEL_CEILING {
            continue;
        }
        let slot = match group(&kind) {
            Some(Group::Cpu) => &mut summary.cpu_max_millic,
            Some(Group::Gpu) => &mut summary.gpu_max_millic,
            Some(Group::Battery) => &mut summary.battery_millic,
            Some(Group::QcomBattery) => &mut qcom_battery,
            Some(Group::Skin) => &mut summary.skin_max_millic,
            Some(Group::Package) => &mut summary.package_millic,
            Some(Group::Ddr) => &mut summary.ddr_millic,
            Some(Group::Charger) => &mut summary.charger_millic,
            None => continue,
        };
        raise(slot, millic);
    }
    summary.battery_millic = summary.battery_millic.or(qcom_battery);
    summary
}

fn read_bounded(path: &Path) -> std::io::Result<String> {
    let mut contents = String::new();
    File::open(path)?
        .take(MAX_ZONE_FILE_BYTES)
        .read_to_string(&mut contents)?;
    Ok(contents)
}

fn read_zone(dir: &Path) -> Zone {
    let (Ok(kind), Ok(temp)) = (
        read_bounded(&dir.join("type")),
        read_bounded(&dir.join("temp")),
    ) else {
        return Zone::Unreadable;
    };
    match temp.trim().parse::<i32>() {
        Ok(millic) => Zone::Readable {
            kind: kind.trim().to_owned(),
            millic,
        },
        Err(_) => Zone::Unparsed,
    }
}

/// Read and summarize every `thermal_zoneN` under `root`. `None` when the
/// class itself cannot be listed: the keys are then absent, not null.
pub fn read_summary(root: &Path) -> Option<ThermalSummary> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut unlisted = 0_u32;
    let mut zones = Vec::new();
    for entry in entries {
        if zones.len() >= MAX_ZONES {
            break;
        }
        let Ok(entry) = entry else {
            unlisted = unlisted.saturating_add(1);
            continue;
        };
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("thermal_zone"))
        {
            zones.push(entry.path());
        }
    }
    let mut summary = summarize(zones.iter().map(|dir| read_zone(dir)));
    summary.denied_count = summary.denied_count.saturating_add(unlisted);
    Some(summary)
}

/// A single long-lived reader. At most one read is ever in flight, so a
/// sensor that hangs forever costs one parked thread, not one per beat.
pub struct ThermalSampler {
    worker: Option<Worker>,
}

struct Worker {
    requests: SyncSender<()>,
    replies: Receiver<Option<ThermalSummary>>,
    outstanding: bool,
}

impl ThermalSampler {
    pub fn start(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let (requests, requested) = mpsc::sync_channel::<()>(1);
        let (reply, replies) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("liskov-thermal".into())
            .spawn(move || {
                for () in requested {
                    if reply.send(read_summary(&root)).is_err() {
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

    /// The summary at this instant, or `None` within [`THERMAL_READ_BUDGET`].
    pub fn sample(&mut self) -> Option<ThermalSummary> {
        self.sample_within(THERMAL_READ_BUDGET)
    }

    fn sample_within(&mut self, budget: Duration) -> Option<ThermalSummary> {
        let worker = self.worker.as_mut()?;
        let (summary, alive) = worker.sample_within(budget);
        if !alive {
            self.worker = None;
        }
        summary
    }
}

impl Worker {
    /// Returns the summary and whether the worker is still usable.
    fn sample_within(&mut self, budget: Duration) -> (Option<ThermalSummary>, bool) {
        if self.outstanding {
            match self.replies.try_recv() {
                // A late reply belongs to an earlier instant; drop it.
                Ok(_) => self.outstanding = false,
                Err(TryRecvError::Empty) => return (None, true),
                Err(TryRecvError::Disconnected) => return (None, false),
            }
        }
        match self.requests.try_send(()) {
            Ok(()) => {}
            Err(TrySendError::Full(())) => return (None, true),
            Err(TrySendError::Disconnected(())) => return (None, false),
        }
        match self.replies.recv_timeout(budget) {
            Ok(summary) => (summary, true),
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
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    /// `thermal_zoneN type temp` from the 2026-09-23 Motorola probe readback
    /// (`docs/raw/2026-09-23-moto-processor-hardware-probe.md`). A missing
    /// temp is a zone whose read returned nothing.
    const MOTOROLA_ZONES: &str = "\
0 modem-mmw-pa1-step
1 modem-mmw-pa2-step
2 modem-mmw-pa3-step
3 modem-lte-sub6-pa1 27000
4 modem-lte-sub6-pa2 27000
5 modem-mmw0-usr 27000
6 modem-mmw1-usr 27000
7 modem-mmw2-usr 27000
8 modem-mmw3-usr 27000
9 modem-skin-usr 27000
10 modem-0-usr 27000
11 modem-1-usr 27000
12 modem-streamer-usr 27000
13 modem-mmw0-mod-usr 27000
14 modem-mmw1-mod-usr 27000
15 modem-mmw2-mod-usr 27000
16 modem-mmw3-mod-usr 27000
17 beamer-n-therm-usr 27000
18 beamer-e-therm-usr 27000
19 beamer-w-therm-usr 27000
20 modem-mmw-pa1-usr
21 modem-mmw-pa2-usr
22 modem-mmw-pa3-usr
23 mdm-core0-step 34800
24 mdm-core1-step 35600
25 mdm-vec-step 36300
26 mdm-scl-step 36300
27 mapss-0-usr 36800
28 cpu-0-0-usr 39100
29 cpu-0-1-usr 38700
30 cpu-0-2-usr 38000
31 cpu-0-3-usr 38400
32 cpu-0-4-usr 38000
33 cpu-0-5-usr 38700
34 cpuss-0-usr 41100
35 cpuss-1-usr 39500
36 cpu-1-0-usr 42600
37 cpu-1-1-usr 41100
38 cpu-1-2-usr 42200
39 cpu-1-3-usr 40700
40 gpuss-0-usr 36800
41 gpuss-1-usr 36400
42 mapss-1-usr 36700
43 cwlan-usr 38600
44 audio-usr 37900
45 ddr-usr 36700
46 q6-hvx-usr 37100
47 camera-usr 36300
48 mdm-core0-usr 34800
49 mdm-core1-usr 35200
50 mdm-vec-usr 36700
51 msm-scl-usr 36300
52 video-usr 36300
53 cpu-0-0-step 39100
54 cpu-0-1-step 39100
55 cpu-0-2-step 38400
56 cpu-0-3-step 39100
57 cpu-0-4-step 39100
58 cpu-0-5-step 39500
59 cpu-1-0-step 41800
60 cpu-1-1-step 40300
61 cpu-1-2-step 42200
62 cpu-1-3-step 40300
63 gpuss-max-step 36400
64 q6-hvx-step 36700
65 zeroc-0-step 0
66 zeroc-1-step 0
67 pm7250b_tz 30677
68 pm7250b-ibat-lvl0 -78
69 pm7250b-ibat-lvl1 -78
70 pm7250b-bcl-lvl0 0
71 pm7250b-bcl-lvl1 0
72 pm7250b-bcl-lvl2 0
73 socd 0
74 conn-therm-usr -40000
75 pm6125_tz 33532
76 pmr735a_tz 37000
77 msm_therm 33137
78 chg_therm 31813
79 cam_flash_therm 32696
80 tspk_therm 31568
81 pa_therm2 31911
82 pa_therm1 31323
83 quiet_therm 32794
84 xo_therm 33341
85 qtm_n_therm -40960
86 qtm_e_therm -40960
87 soc_usr 0
88 vbat 4434
89 qcom_battery 29700
90 front_temp 32430
91 back_temp 32545
92 battery 29700
";

    /// A scratch sysfs thermal class, removed on drop.
    pub(crate) struct ThermalFixture {
        pub(crate) root: PathBuf,
    }

    impl ThermalFixture {
        pub(crate) fn empty(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("liskov-thermal-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        pub(crate) fn motorola(name: &str) -> Self {
            let fixture = Self::empty(name);
            for line in MOTOROLA_ZONES.lines() {
                let mut fields = line.split(' ');
                let index = fields.next().unwrap();
                let kind = fields.next().unwrap();
                fixture.zone(index, kind, fields.next().unwrap_or(""));
            }
            fixture
        }

        pub(crate) fn zone(&self, index: &str, kind: &str, temp: &str) -> PathBuf {
            let dir = self.root.join(format!("thermal_zone{index}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
            std::fs::write(dir.join("temp"), format!("{temp}\n")).unwrap();
            dir
        }
    }

    impl Drop for ThermalFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    pub(crate) fn motorola_summary() -> ThermalSummary {
        ThermalSummary {
            cpu_max_millic: Some(42600),
            gpu_max_millic: Some(36800),
            battery_millic: Some(29700),
            skin_max_millic: Some(32794),
            package_millic: Some(33137),
            ddr_millic: Some(36700),
            charger_millic: Some(31813),
            // 93 zones, six of which returned no temperature.
            zone_count: 87,
            denied_count: 0,
        }
    }

    fn euid_is_root() -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn motorola_fixture_produces_the_probe_summary() {
        let fixture = ThermalFixture::motorola("motorola");
        let summary = read_summary(&fixture.root).unwrap();
        assert_eq!(summary, motorola_summary());
        let groups = [
            summary.cpu_max_millic,
            summary.gpu_max_millic,
            summary.battery_millic,
            summary.skin_max_millic,
            summary.package_millic,
            summary.ddr_millic,
            summary.charger_millic,
        ];
        assert!(!groups.contains(&Some(4434)), "vbat is not a temperature");
    }

    #[test]
    fn excluded_and_sentinel_zones_are_counted_but_never_promoted() {
        let summary = summarize([
            Zone::Readable {
                kind: "vbat".into(),
                millic: 90_000,
            },
            Zone::Readable {
                kind: "cpu-bcl-usr".into(),
                millic: 90_000,
            },
            Zone::Readable {
                kind: "cpu-ibat-usr".into(),
                millic: 90_000,
            },
            Zone::Readable {
                kind: "cpu-1-0-step".into(),
                millic: 90_000,
            },
            Zone::Readable {
                kind: "cpuss-0-usr".into(),
                millic: 90_000,
            },
            Zone::Readable {
                kind: "gpuss-max-step".into(),
                millic: 90_000,
            },
            Zone::Readable {
                kind: "front_temp".into(),
                millic: -40_000,
            },
            Zone::Readable {
                kind: "battery".into(),
                millic: -40_960,
            },
        ]);
        assert_eq!(
            summary,
            ThermalSummary {
                zone_count: 8,
                ..ThermalSummary::default()
            },
            "every group stays null, every zone is counted"
        );
    }

    #[test]
    fn battery_falls_back_to_qcom_battery_only_when_absent() {
        let qcom_only = summarize([Zone::Readable {
            kind: "qcom_battery".into(),
            millic: 31_000,
        }]);
        assert_eq!(qcom_only.battery_millic, Some(31_000));
        let both = summarize([
            Zone::Readable {
                kind: "qcom_battery".into(),
                millic: 31_000,
            },
            Zone::Readable {
                kind: "battery".into(),
                millic: 29_000,
            },
        ]);
        assert_eq!(both.battery_millic, Some(29_000));
    }

    #[test]
    fn a_missing_thermal_class_is_no_summary_and_an_empty_one_is_nulls() {
        let fixture = ThermalFixture::empty("missing");
        assert_eq!(read_summary(&fixture.root.join("absent")), None);
        assert_eq!(read_summary(&fixture.root), Some(ThermalSummary::default()));
    }

    #[test]
    fn permission_denied_on_a_zone_counts_and_does_not_fail_the_read() {
        if euid_is_root() {
            eprintln!("skipped: root reads a mode-000 file");
            return;
        }
        let fixture = ThermalFixture::empty("denied");
        fixture.zone("0", "cpu-1-0-usr", "42600");
        let denied = fixture.zone("1", "cpu-1-1-usr", "50000");
        let temp = denied.join("temp");
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o000)).unwrap();
        let summary = read_summary(&fixture.root).unwrap();
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(summary.cpu_max_millic, Some(42600));
        assert_eq!(summary.zone_count, 1);
        assert_eq!(summary.denied_count, 1);
    }

    #[test]
    fn written_attrs_are_exactly_the_nine_scalars() {
        let mut attrs = Map::new();
        ThermalSummary {
            cpu_max_millic: None,
            ..motorola_summary()
        }
        .write_attrs(&mut attrs);
        let mut keys: Vec<&str> = attrs.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = THERMAL_SUMMARY_ATTRS;
        expected.sort_unstable();
        assert_eq!(keys, expected);
        assert!(attrs["thermalCpuMaxMillic"].is_null(), "null, not zero");
        assert_eq!(attrs["thermalZoneCount"], 87);
        assert!(
            attrs
                .values()
                .all(|value| value.is_null() || value.is_i64()),
            "every thermal attr is an integer or null: {attrs:?}"
        );
    }

    #[test]
    fn sampler_reads_the_fixture_and_stays_quiet_without_one() {
        let fixture = ThermalFixture::motorola("sampler");
        let mut sampler = ThermalSampler::start(&fixture.root);
        assert_eq!(
            sampler.sample_within(Duration::from_secs(5)),
            Some(motorola_summary())
        );
        let mut missing = ThermalSampler::start(fixture.root.join("absent"));
        assert_eq!(missing.sample_within(Duration::from_secs(5)), None);
    }

    #[test]
    fn a_hung_sensor_costs_the_budget_once_and_never_blocks_again() {
        let fixture = ThermalFixture::empty("hung");
        let dir = fixture.zone("0", "cpu-1-0-usr", "42600");
        let temp = dir.join("temp");
        std::fs::remove_file(&temp).unwrap();
        let path = std::ffi::CString::new(temp.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; a FIFO with no writer blocks
        // the reader in open(2), which is what a hung sensor looks like.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);

        let mut sampler = ThermalSampler::start(&fixture.root);
        let started = Instant::now();
        assert_eq!(sampler.sample_within(Duration::from_millis(50)), None);
        assert!(started.elapsed() < Duration::from_secs(1));
        let started = Instant::now();
        assert_eq!(sampler.sample_within(Duration::from_secs(5)), None);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a read still in flight is not waited on twice"
        );

        // Release the parked read, then serve an ordinary file.
        {
            use std::io::Write;
            let mut writer = std::fs::OpenOptions::new().write(true).open(&temp).unwrap();
            writer.write_all(b"41000\n").unwrap();
        }
        std::fs::remove_file(&temp).unwrap();
        std::fs::write(&temp, "42600\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let recovered = loop {
            if let Some(summary) = sampler.sample_within(Duration::from_secs(1)) {
                break summary;
            }
            assert!(Instant::now() < deadline, "sampler never recovered");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            recovered.cpu_max_millic,
            Some(42600),
            "the late reply from the hung instant is dropped"
        );
    }
}
