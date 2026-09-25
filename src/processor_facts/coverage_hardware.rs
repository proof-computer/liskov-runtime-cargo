//! `coverage_hardware_raw.v1` — the closed raw hardware reading a platform
//! coverage probe takes under a `coverage-hardware-v1` grant
//! (BKLG-20260923-9bhd; ADR-0079 probe amendment; Q-20260923-z2uc).
//!
//! The file list is the one the Motorola job 174098 readback found useful, and
//! nothing else is opened. The serialized groups are exactly the ones
//! `liskov-rs` decodes in `slipway-processor-registry` `hardware/coverage_raw.rs`,
//! pinned by the shared vectors. The mount table is parsed only to find the
//! guest root's and `/data`'s entries, and only their filesystem type and two
//! flags leave the parser: no mount source, mount point, serial, MAC,
//! environment or retail model has a field.
//!
//! Every file stops at a byte cap and every list at its catalog cap. Denied
//! and missing stay distinct statuses, a zero is a value, and a failed read
//! changes only its own reading.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{Availability, CapabilityClass, FileReadFailure, parse_proc_status};

mod source;

pub use source::{HardwareSource, StatvfsReading, SystemHardwareSource};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_CGROUP_CONTROLLERS: usize = 16;
const MAX_CPU_POLICIES: usize = 16;
const MAX_POLICY_NUMBER: u64 = 1_024;
const MAX_AVAILABLE_FREQUENCIES: usize = 32;
const MAX_CACHES: usize = 64;
const MAX_THERMAL_ZONES: usize = 128;
const MAX_CPU_LIST_BYTES: usize = 64;
const MAX_TEMP_MAGNITUDE: i64 = i32::MAX as i64;
/// The walk behind the 64-entry cache list; far beyond any handset.
const MAX_WALKED_CPUS: usize = 256;
const MAX_WALKED_CACHE_INDEXES: usize = 16;
/// The highest cpu number a cpu list may name before it is a parse error.
const MAX_LISTED_CPU: u32 = 4_095;
/// A sysfs attribute is at most one page.
const MAX_ATTRIBUTE_BYTES: usize = 4 * 1024;
const MAX_PROC_TEXT_BYTES: usize = 64 * 1024;
/// A phone's mount table lists every app's data mounts; it is parsed in
/// memory and dropped.
const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;

const CPU_ROOT: &str = "/sys/devices/system/cpu";
const CPUFREQ_ROOT: &str = "/sys/devices/system/cpu/cpufreq";
const THERMAL_ROOT: &str = "/sys/class/thermal";
const SOC_ROOT: &str = "/sys/devices/soc0";
const KGSL_ROOT: &str = "/sys/class/kgsl/kgsl-3d0";
const PROC_STATUS: &str = "/proc/self/status";
const PROC_CGROUP: &str = "/proc/self/cgroup";
const PROC_MEMINFO: &str = "/proc/meminfo";
const PROC_MOUNTINFO: &str = "/proc/self/mountinfo";
const DATA_MOUNT_POINT: &str = "/data";

/// The closed `/proc/meminfo` key set: kernel line name and catalog field, in
/// catalog order. No other line is representable.
const MEMINFO_LINES: [(&str, &str); 20] = [
    ("MemTotal", "memTotalKb"),
    ("MemFree", "memFreeKb"),
    ("MemAvailable", "memAvailableKb"),
    ("Buffers", "buffersKb"),
    ("Cached", "cachedKb"),
    ("SwapCached", "swapCachedKb"),
    ("SwapTotal", "swapTotalKb"),
    ("SwapFree", "swapFreeKb"),
    ("Dirty", "dirtyKb"),
    ("AnonPages", "anonPagesKb"),
    ("Mapped", "mappedKb"),
    ("Shmem", "shmemKb"),
    ("Slab", "slabKb"),
    ("KernelStack", "kernelStackKb"),
    ("ShadowCallStack", "shadowCallStackKb"),
    ("PageTables", "pageTablesKb"),
    ("CmaTotal", "cmaTotalKb"),
    ("CmaFree", "cmaFreeKb"),
    ("CommitLimit", "commitLimitKb"),
    ("Committed_AS", "committedAsKb"),
];

/// The device's half of the reading: exactly the catalog groups. The domain,
/// profile, helper version and capture instant are the server's to state.
#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageHardwareRawFact {
    kernel: KernelReadings,
    identity: IdentityReadings,
    cgroup_controllers: Availability<Vec<String>>,
    cpu_policies: Availability<Vec<CpuPolicyReading>>,
    caches: Availability<Vec<CacheReading>>,
    meminfo: BTreeMap<&'static str, Availability<u64>>,
    soc: SocReadings,
    gpu: GpuReadings,
    guest_root: GuestRootBytes,
    filesystems: FilesystemReadings,
    thermal_zones: Availability<Vec<ThermalZoneReading>>,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
struct KernelReadings {
    release: Availability<String>,
    /// `uname` machine.
    architecture: Availability<String>,
}

/// The guest's view of itself against the kernel's. Under PRoot the guest is
/// root and the kernel says otherwise; that difference is what this records.
#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IdentityReadings {
    guest_uid: Availability<u64>,
    kernel_uid: Availability<u64>,
    capability_class: Availability<CapabilityClass>,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CpuPolicyReading {
    policy: u64,
    related_cpus: Availability<String>,
    midr: Availability<String>,
    min_khz: Availability<u64>,
    max_khz: Availability<u64>,
    available_khz: Availability<Vec<u64>>,
    capacity: Availability<u64>,
    governor: Availability<String>,
    driver: Availability<String>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum CacheType {
    Data,
    Instruction,
    Unified,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CacheReading {
    level: u64,
    #[serde(rename = "type")]
    cache_type: CacheType,
    shared_cpu_list: String,
    size_bytes: Availability<u64>,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SocReadings {
    family: Availability<String>,
    soc_id: Availability<String>,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct GpuReadings {
    model: Availability<String>,
    max_clock_hz: Availability<u64>,
}

/// `statvfs` of the guest root: the phone volume the guest sits on, not a job
/// quota.
#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct GuestRootBytes {
    total_bytes: Availability<u64>,
    used_bytes: Availability<u64>,
    available_bytes: Availability<u64>,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct FilesystemReadings {
    guest_root: Availability<FilesystemFlags>,
    data: Availability<FilesystemFlags>,
}

/// A filesystem type and two flags. The mount source, the mount point and
/// every other option are unrepresentable.
#[derive(Serialize, Clone, PartialEq, Eq)]
struct FilesystemFlags {
    #[serde(rename = "type")]
    fs_type: String,
    inlinecrypt: bool,
    discard: bool,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
struct ThermalZoneReading {
    #[serde(rename = "type")]
    zone_type: String,
    temp: ThermalTemp,
}

/// A zone's temperature in the kernel's own unit, never converted: `vbat` is
/// a zone reading, not a Celsius value. `Unread` means the read returned
/// nothing or failed, which is not a zero.
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ThermalTemp {
    Observed { value: i64 },
    Unread,
}

pub trait CoverageHardwareCollector: Send + Sync {
    fn collect(&self) -> CoverageHardwareRawFact;
}

pub struct SystemCoverageHardwareCollector;

impl CoverageHardwareCollector for SystemCoverageHardwareCollector {
    fn collect(&self) -> CoverageHardwareRawFact {
        collect_coverage_hardware(&SystemHardwareSource)
    }
}

/// Take the whole reading through `source`. Collection cannot fail
/// structurally: every unavailable surface keeps its own reason.
pub(super) fn collect_coverage_hardware(source: &dyn HardwareSource) -> CoverageHardwareRawFact {
    CoverageHardwareRawFact {
        kernel: collect_kernel(source),
        identity: collect_identity(source),
        cgroup_controllers: reading(
            read_text(source, PROC_CGROUP, MAX_PROC_TEXT_BYTES)
                .and_then(|text| parse_cgroup_controllers(&text)),
        ),
        cpu_policies: collect_cpu_policies(source),
        caches: collect_caches(source),
        meminfo: collect_meminfo(source),
        soc: SocReadings {
            family: text_file(source, &format!("{SOC_ROOT}/family"), 64, printable),
            soc_id: text_file(source, &format!("{SOC_ROOT}/soc_id"), 32, identifier_byte),
        },
        gpu: GpuReadings {
            model: text_file(source, &format!("{KGSL_ROOT}/gpu_model"), 64, model_byte),
            max_clock_hz: u64_file(source, &format!("{KGSL_ROOT}/max_gpuclk")),
        },
        guest_root: collect_guest_root(source),
        filesystems: collect_filesystems(source),
        thermal_zones: collect_thermal_zones(source),
    }
}

/// Why a reading has no value; each maps to one catalog status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unread {
    NotPresent,
    PermissionDenied,
    SurfaceHidden,
    Unsupported,
    ParseError,
}

impl Unread {
    fn status<T>(self) -> Availability<T> {
        match self {
            Self::NotPresent => Availability::NotPresent,
            Self::PermissionDenied => Availability::PermissionDenied,
            Self::SurfaceHidden => Availability::SurfaceHidden,
            Self::Unsupported => Availability::Unsupported,
            Self::ParseError => Availability::ParseError,
        }
    }
}

impl From<FileReadFailure> for Unread {
    fn from(error: FileReadFailure) -> Self {
        match error {
            // Missing and denied never collapse into each other.
            FileReadFailure::NotFound => Self::NotPresent,
            FileReadFailure::PermissionDenied => Self::PermissionDenied,
            FileReadFailure::Unavailable => Self::SurfaceHidden,
            FileReadFailure::UnsafeFile | FileReadFailure::TooLarge => Self::Unsupported,
        }
    }
}

fn reading<T>(result: Result<T, Unread>) -> Availability<T> {
    match result {
        Ok(value) => Availability::Observed { value },
        Err(unread) => unread.status(),
    }
}

fn read_text(source: &dyn HardwareSource, path: &str, cap: usize) -> Result<String, Unread> {
    let bytes = source.read(path, cap)?;
    String::from_utf8(bytes).map_err(|_| Unread::ParseError)
}

fn text_file(
    source: &dyn HardwareSource,
    path: &str,
    max: usize,
    allowed: fn(u8) -> bool,
) -> Availability<String> {
    reading(
        read_text(source, path, MAX_ATTRIBUTE_BYTES)
            .and_then(|text| bounded_text(&text, max, allowed)),
    )
}

fn u64_file(source: &dyn HardwareSource, path: &str) -> Availability<u64> {
    reading(read_text(source, path, MAX_ATTRIBUTE_BYTES).and_then(|text| safe_u64(&text)))
}

/// A Java package name: three or more dot-separated segments, each starting
/// with a lowercase letter. The same rule as the server's codec, applied
/// before sending so a value it would refuse is a `parse_error` here.
fn names_a_package(text: &str) -> bool {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_'))
    })
    .any(|token| {
        let segments = token.split('.').collect::<Vec<_>>();
        segments.len() >= 3
            && segments.iter().all(|segment| {
                segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
            })
    })
}

/// A trimmed value within its grammar. No path and no package name is
/// representable anywhere in this reading.
fn bounded_text(text: &str, max: usize, allowed: fn(u8) -> bool) -> Result<String, Unread> {
    let text = text.trim();
    if text.is_empty()
        || text.len() > max
        || !text.bytes().all(allowed)
        || text.contains('/')
        || names_a_package(text)
    {
        return Err(Unread::ParseError);
    }
    Ok(text.to_owned())
}

const fn printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}

const fn lower_token(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
}

const fn architecture_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

const fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

const fn model_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'+' | b'-')
}

fn safe_u64(text: &str) -> Result<u64, Unread> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Unread::ParseError);
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or(Unread::ParseError)
}

/// The `N` of a `<prefix>N` directory entry, spelled canonically.
fn entry_number(name: &str, prefix: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?;
    let number = digits.parse::<u64>().ok()?;
    (number.to_string() == digits).then_some(number)
}

/// The numbered entries of one directory up to `highest`, ascending, at most
/// `max`.
fn numbered_entries(names: &[String], prefix: &str, highest: u64, max: usize) -> Vec<u64> {
    let mut numbers = names
        .iter()
        .filter_map(|name| entry_number(name, prefix))
        .filter(|number| *number <= highest)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    numbers.truncate(max);
    numbers
}

fn collect_kernel(source: &dyn HardwareSource) -> KernelReadings {
    let Some((release, machine)) = source.uname() else {
        return KernelReadings {
            release: Availability::SurfaceHidden,
            architecture: Availability::SurfaceHidden,
        };
    };
    let text = |bytes: Vec<u8>, max: usize, allowed: fn(u8) -> bool| {
        reading(
            String::from_utf8(bytes)
                .map_err(|_| Unread::ParseError)
                .and_then(|text| bounded_text(&text, max, allowed)),
        )
    };
    KernelReadings {
        release: text(release, 128, printable),
        architecture: text(machine, 32, architecture_byte),
    }
}

fn collect_identity(source: &dyn HardwareSource) -> IdentityReadings {
    let (kernel_uid, capability_class) = match read_text(source, PROC_STATUS, MAX_PROC_TEXT_BYTES) {
        Ok(status) => (kernel_uid(&status), parse_proc_status(&status).2),
        Err(unread) => (unread.status(), unread.status()),
    };
    IdentityReadings {
        guest_uid: Availability::Observed {
            value: source.guest_uid(),
        },
        kernel_uid,
        capability_class,
    }
}

/// The real uid, the first of the four `Uid:` fields.
fn kernel_uid(status: &str) -> Availability<u64> {
    let Some(fields) = status.lines().find_map(|line| line.strip_prefix("Uid:")) else {
        return Availability::NotPresent;
    };
    reading(
        fields
            .split_ascii_whitespace()
            .next()
            .ok_or(Unread::ParseError)
            .and_then(safe_u64),
    )
}

/// Controller names in line order. A v2 line has none and is `unified`; a
/// named v1 hierarchy (`name=systemd`) is not a controller. Paths are never
/// kept.
fn parse_cgroup_controllers(text: &str) -> Result<Vec<String>, Unread> {
    let mut names: Vec<String> = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(_)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(Unread::ParseError);
        };
        let tokens = if controllers.is_empty() {
            vec!["unified"]
        } else {
            controllers.split(',').collect()
        };
        for token in tokens {
            if token.starts_with("name=") {
                continue;
            }
            let valid = token.len() <= 32
                && token.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                && token.bytes().all(architecture_byte);
            if !valid {
                return Err(Unread::ParseError);
            }
            if names.len() < MAX_CGROUP_CONTROLLERS && !names.iter().any(|name| name == token) {
                names.push(token.to_owned());
            }
        }
    }
    Ok(names)
}

struct CpuList {
    /// Range-list form: `0-5,7`.
    text: String,
    first: u32,
    count: usize,
}

/// Normalize a kernel cpu list, space-separated (`related_cpus`) or already in
/// range form (`shared_cpu_list`), into range form.
fn parse_cpu_list(text: &str) -> Result<CpuList, Unread> {
    let number = |text: &str| {
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u32>().ok())
            .flatten()
            .filter(|cpu| *cpu <= MAX_LISTED_CPU)
            .ok_or(Unread::ParseError)
    };
    let mut cpus = BTreeSet::new();
    for token in text
        .split(|character: char| character == ',' || character.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
    {
        let (low, high) = match token.split_once('-') {
            Some((low, high)) => (number(low)?, number(high)?),
            None => {
                let cpu = number(token)?;
                (cpu, cpu)
            }
        };
        if high < low {
            return Err(Unread::ParseError);
        }
        cpus.extend(low..=high);
    }
    let first = *cpus.first().ok_or(Unread::ParseError)?;
    let mut ranges = Vec::new();
    let mut cpus_iter = cpus.iter().copied().peekable();
    while let Some(low) = cpus_iter.next() {
        let mut high = low;
        while cpus_iter.peek() == Some(&(high + 1)) {
            high += 1;
            cpus_iter.next();
        }
        ranges.push(if high == low {
            low.to_string()
        } else {
            format!("{low}-{high}")
        });
    }
    let text = ranges.join(",");
    if text.len() > MAX_CPU_LIST_BYTES {
        return Err(Unread::ParseError);
    }
    Ok(CpuList {
        text,
        first,
        count: cpus.len(),
    })
}

/// `midr_el1` as the kernel prints it (`0x00000000412fd050`), shortened to
/// eight digits when its reserved upper half is zero.
fn parse_midr(text: &str) -> Result<String, Unread> {
    let digits = text
        .trim()
        .strip_prefix("0x")
        .filter(|digits| (1..=16).contains(&digits.len()))
        .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(Unread::ParseError)?;
    let value = u64::from_str_radix(digits, 16).map_err(|_| Unread::ParseError)?;
    Ok(if value <= u64::from(u32::MAX) {
        format!("0x{value:08x}")
    } else {
        format!("0x{value:016x}")
    })
}

fn parse_frequencies(text: &str) -> Result<Vec<u64>, Unread> {
    text.split_ascii_whitespace()
        .take(MAX_AVAILABLE_FREQUENCIES)
        .map(safe_u64)
        .collect()
}

fn collect_cpu_policies(source: &dyn HardwareSource) -> Availability<Vec<CpuPolicyReading>> {
    let names = match source.list(CPUFREQ_ROOT) {
        Ok(names) => names,
        Err(error) => return Unread::from(error).status(),
    };
    Availability::Observed {
        value: numbered_entries(&names, "policy", MAX_POLICY_NUMBER, MAX_CPU_POLICIES)
            .into_iter()
            .map(|policy| collect_policy(source, policy))
            .collect(),
    }
}

fn collect_policy(source: &dyn HardwareSource, policy: u64) -> CpuPolicyReading {
    let base = format!("{CPUFREQ_ROOT}/policy{policy}");
    let related = read_text(source, &format!("{base}/related_cpus"), MAX_ATTRIBUTE_BYTES)
        .and_then(|text| parse_cpu_list(&text));
    // The policy's first cpu owns its MIDR and capacity; a policy is named
    // after that cpu when its list is unreadable.
    let first_cpu = related
        .as_ref()
        .map_or(policy, |list| u64::from(list.first));
    let cpu = format!("{CPU_ROOT}/cpu{first_cpu}");
    CpuPolicyReading {
        policy,
        related_cpus: reading(related.map(|list| list.text)),
        midr: reading(
            read_text(
                source,
                &format!("{cpu}/regs/identification/midr_el1"),
                MAX_ATTRIBUTE_BYTES,
            )
            .and_then(|text| parse_midr(&text)),
        ),
        min_khz: u64_file(source, &format!("{base}/cpuinfo_min_freq")),
        max_khz: u64_file(source, &format!("{base}/cpuinfo_max_freq")),
        available_khz: reading(
            read_text(
                source,
                &format!("{base}/scaling_available_frequencies"),
                MAX_ATTRIBUTE_BYTES,
            )
            .and_then(|text| parse_frequencies(&text)),
        ),
        capacity: u64_file(source, &format!("{cpu}/cpu_capacity")),
        governor: text_file(source, &format!("{base}/scaling_governor"), 32, lower_token),
        driver: text_file(source, &format!("{base}/scaling_driver"), 32, lower_token),
    }
}

/// Dedup and order key: private caches by cpu, then wider sharing, so the
/// list reads from each core outward.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    span: usize,
    first_cpu: u32,
    level: u64,
    cache_type: CacheType,
    shared_cpu_list: String,
}

fn collect_caches(source: &dyn HardwareSource) -> Availability<Vec<CacheReading>> {
    let names = match source.list(CPU_ROOT) {
        Ok(names) => names,
        Err(error) => return Unread::from(error).status(),
    };
    let mut caches = BTreeMap::new();
    let mut first_failure = None;
    for cpu in numbered_entries(&names, "cpu", u64::MAX, MAX_WALKED_CPUS) {
        let directory = format!("{CPU_ROOT}/cpu{cpu}/cache");
        let indexes = match source.list(&directory) {
            Ok(indexes) => indexes,
            Err(error) => {
                first_failure.get_or_insert(Unread::from(error));
                continue;
            }
        };
        for index in numbered_entries(&indexes, "index", u64::MAX, MAX_WALKED_CACHE_INDEXES) {
            match collect_cache(source, &format!("{directory}/index{index}")) {
                Ok((key, size)) => {
                    caches.entry(key).or_insert(size);
                }
                Err(unread) => {
                    first_failure.get_or_insert(unread);
                }
            }
        }
    }
    // Nothing readable is a status, not an observed empty list.
    if let (true, Some(unread)) = (caches.is_empty(), first_failure) {
        return unread.status();
    }
    Availability::Observed {
        value: caches
            .into_iter()
            .take(MAX_CACHES)
            .map(|(key, size_bytes)| CacheReading {
                level: key.level,
                cache_type: key.cache_type,
                shared_cpu_list: key.shared_cpu_list,
                size_bytes,
            })
            .collect(),
    }
}

/// Level, type and sharing identify a cache and must be readable; its size
/// is a reading of its own, denied on the Motorola.
fn collect_cache(
    source: &dyn HardwareSource,
    directory: &str,
) -> Result<(CacheKey, Availability<u64>), Unread> {
    let level = read_text(source, &format!("{directory}/level"), MAX_ATTRIBUTE_BYTES)
        .and_then(|text| safe_u64(&text))
        .and_then(|level| {
            (1..=4)
                .contains(&level)
                .then_some(level)
                .ok_or(Unread::ParseError)
        })?;
    let cache_type = read_text(source, &format!("{directory}/type"), MAX_ATTRIBUTE_BYTES)
        .and_then(|text| match text.trim() {
            "Data" => Ok(CacheType::Data),
            "Instruction" => Ok(CacheType::Instruction),
            "Unified" => Ok(CacheType::Unified),
            _ => Err(Unread::ParseError),
        })?;
    let shared = read_text(
        source,
        &format!("{directory}/shared_cpu_list"),
        MAX_ATTRIBUTE_BYTES,
    )
    .and_then(|text| parse_cpu_list(&text))?;
    let size = reading(
        read_text(source, &format!("{directory}/size"), MAX_ATTRIBUTE_BYTES)
            .and_then(|text| parse_cache_size(&text)),
    );
    Ok((
        CacheKey {
            span: shared.count,
            first_cpu: shared.first,
            level,
            cache_type,
            shared_cpu_list: shared.text,
        },
        size,
    ))
}

/// Sysfs cache sizes are `32K`-style; converted to bytes.
fn parse_cache_size(text: &str) -> Result<u64, Unread> {
    let text = text.trim();
    let (digits, multiplier) = match text.as_bytes().last() {
        Some(b'K') => (&text[..text.len() - 1], 1_u64 << 10),
        Some(b'M') => (&text[..text.len() - 1], 1 << 20),
        Some(b'G') => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    safe_u64(digits)?
        .checked_mul(multiplier)
        .filter(|bytes| *bytes <= MAX_SAFE_INTEGER)
        .ok_or(Unread::ParseError)
}

fn collect_meminfo(source: &dyn HardwareSource) -> BTreeMap<&'static str, Availability<u64>> {
    let text = match read_text(source, PROC_MEMINFO, MAX_PROC_TEXT_BYTES) {
        Ok(text) => text,
        Err(unread) => {
            return MEMINFO_LINES
                .iter()
                .map(|(_, field)| (*field, unread.status()))
                .collect();
        }
    };
    let mut lines = BTreeMap::new();
    for (key, value) in text.lines().filter_map(|line| line.split_once(':')) {
        lines.entry(key).or_insert(value);
    }
    MEMINFO_LINES
        .iter()
        .map(|(key, field)| {
            let value = match lines.get(key) {
                None => Availability::NotPresent,
                Some(value) => {
                    let mut parts = value.split_ascii_whitespace();
                    reading(match (parts.next(), parts.next(), parts.next()) {
                        (Some(kilobytes), Some("kB"), None) => safe_u64(kilobytes),
                        _ => Err(Unread::ParseError),
                    })
                }
            };
            (*field, value)
        })
        .collect()
}

fn collect_guest_root(source: &dyn HardwareSource) -> GuestRootBytes {
    let statvfs = match source.guest_root_statvfs() {
        Ok(statvfs) => statvfs,
        Err(error) => {
            let unread = Unread::from(error);
            return GuestRootBytes {
                total_bytes: unread.status(),
                used_bytes: unread.status(),
                available_bytes: unread.status(),
            };
        }
    };
    let bytes = |blocks: Option<u64>| {
        reading(
            blocks
                .and_then(|blocks| blocks.checked_mul(statvfs.fragment_size))
                .filter(|bytes| *bytes <= MAX_SAFE_INTEGER)
                .ok_or(Unread::ParseError),
        )
    };
    GuestRootBytes {
        total_bytes: bytes(Some(statvfs.blocks)),
        used_bytes: bytes(statvfs.blocks.checked_sub(statvfs.free_blocks)),
        available_bytes: bytes(Some(statvfs.available_blocks)),
    }
}

/// The parts of one `/proc/self/mountinfo` line the collector compares. They
/// are borrowed from the table and dropped with it; only [`FilesystemFlags`]
/// leaves.
struct MountEntry<'a> {
    device: (u64, u64),
    mount_point: &'a str,
    fs_type: &'a str,
    options: Vec<&'a str>,
}

fn parse_mountinfo_line(line: &str) -> Option<MountEntry<'_>> {
    let fields = line.split(' ').collect::<Vec<_>>();
    let (major, minor) = fields.get(2)?.split_once(':')?;
    let separator = fields.iter().skip(6).position(|field| *field == "-")? + 6;
    let mut options = fields.get(5)?.split(',').collect::<Vec<_>>();
    options.extend(fields.get(separator + 3)?.split(','));
    Some(MountEntry {
        device: (major.parse().ok()?, minor.parse().ok()?),
        mount_point: fields.get(4)?,
        fs_type: fields.get(separator + 1)?,
        options,
    })
}

fn filesystem_flags(entry: Option<&MountEntry<'_>>) -> Availability<FilesystemFlags> {
    let Some(entry) = entry else {
        return Availability::NotPresent;
    };
    let fs_type = if entry.fs_type.starts_with("fuse.") {
        "fuse"
    } else {
        entry.fs_type
    };
    reading(
        bounded_text(fs_type, 16, architecture_byte).map(|fs_type| FilesystemFlags {
            fs_type,
            inlinecrypt: entry.options.contains(&"inlinecrypt"),
            discard: entry.options.contains(&"discard"),
        }),
    )
}

/// The guest root is found by its device, because under PRoot the kernel's
/// `/` is Android's system image, not the volume the guest sits on. `/data`
/// is found by its mount point. The last matching line is the one on top.
fn collect_filesystems(source: &dyn HardwareSource) -> FilesystemReadings {
    let table = match read_text(source, PROC_MOUNTINFO, MAX_MOUNTINFO_BYTES) {
        Ok(table) => table,
        Err(unread) => {
            return FilesystemReadings {
                guest_root: unread.status(),
                data: unread.status(),
            };
        }
    };
    let entries = table
        .lines()
        .filter_map(parse_mountinfo_line)
        .collect::<Vec<_>>();
    let guest_root = match source.guest_root_device() {
        Ok(device) => filesystem_flags(entries.iter().rfind(|entry| entry.device == device)),
        Err(error) => Unread::from(error).status(),
    };
    let data = filesystem_flags(
        entries
            .iter()
            .rfind(|entry| entry.mount_point == DATA_MOUNT_POINT),
    );
    FilesystemReadings { guest_root, data }
}

fn parse_temp(text: &str) -> Option<i64> {
    let text = text.trim();
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>()
        .ok()
        .filter(|temp| temp.abs() <= MAX_TEMP_MAGNITUDE)
}

/// Zones in index order. A zone whose type cannot be read has no entry; a
/// temperature that cannot be read is `unread`.
fn collect_thermal_zones(source: &dyn HardwareSource) -> Availability<Vec<ThermalZoneReading>> {
    let names = match source.list(THERMAL_ROOT) {
        Ok(names) => names,
        Err(error) => return Unread::from(error).status(),
    };
    Availability::Observed {
        value: numbered_entries(&names, "thermal_zone", u64::MAX, MAX_THERMAL_ZONES)
            .into_iter()
            .filter_map(|zone| {
                let directory = format!("{THERMAL_ROOT}/thermal_zone{zone}");
                let zone_type =
                    read_text(source, &format!("{directory}/type"), MAX_ATTRIBUTE_BYTES)
                        .and_then(|text| bounded_text(&text, 48, identifier_byte))
                        .ok()?;
                let temp = read_text(source, &format!("{directory}/temp"), MAX_ATTRIBUTE_BYTES)
                    .ok()
                    .and_then(|text| parse_temp(&text))
                    .map_or(ThermalTemp::Unread, |value| ThermalTemp::Observed { value });
                Some(ThermalZoneReading { zone_type, temp })
            })
            .collect(),
    }
}

#[cfg(test)]
pub(crate) mod tests;
