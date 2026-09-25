//! The raw collector against fixture trees shaped like the Motorola job
//! 174098 readback, and the `liskov-rs` contract bytes it must reproduce.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::source::split_device;
use super::*;
use crate::diagnostics::canonical_json_bytes;
use crate::processor_facts::{
    COVERAGE_HARDWARE_PROFILE, HELPER_CONTRACT_EPOCH, MAX_RESULT_BYTES,
    PROCESSOR_FACT_RESULT_DOMAIN, ProcessorFact, ProcessorFactKind, UnsignedProcessorFactResult,
    compiled_coverage_hardware_catalog_digest,
};

// The three files are byte copies from liskov-rs at merge commit
// 9297d1e928fe62fe5df6b83a9103992436eb21bf (PR #1097, BKLG-20260923-mjay):
// `crates/slipway-executor-contracts/contracts/coverage-hardware-v1.json`,
// `crates/slipway-executor-contracts/vectors/processor-fact-coverage-hardware-v1.json`
// and `crates/slipway-processor-registry/vectors/processor-hardware-raw-v1.json`.
const CATALOG: &[u8] = include_bytes!("../../../contracts/coverage-hardware-v1.json");
const RESULT_VECTOR: &[u8] =
    include_bytes!("../../../vectors/processor-fact-coverage-hardware-v1.json");
const PAYLOAD_VECTOR: &[u8] = include_bytes!("../../../vectors/processor-hardware-raw-v1.json");
const CATALOG_SHA256: &str = "f39caf2456a8d4cbca429f06c5b69d014c47dc76cdcbb0c94bd508a04b89ccb5";
const RESULT_VECTOR_SHA256: &str =
    "f35eb94ee1cdee20cb7245cb3e14a708b254c06927d2ca2ab8a742707e375959";
const PAYLOAD_VECTOR_SHA256: &str =
    "345099f5cad2e7d8ae95ad66412aa6cbfe6a9bae9f20c2ede4b8b9ab0486961b";

/// A fixture tree. Anything not inserted does not exist.
pub(crate) struct FixtureSource {
    files: BTreeMap<String, Result<Vec<u8>, FileReadFailure>>,
    directories: BTreeMap<String, Result<Vec<String>, FileReadFailure>>,
    uname: Option<(Vec<u8>, Vec<u8>)>,
    guest_uid: u64,
    statvfs: Result<StatvfsReading, FileReadFailure>,
    root_device: Result<(u64, u64), FileReadFailure>,
    /// Every path read, and every directory listed with a trailing `/`.
    touched: Mutex<Vec<String>>,
}

impl FixtureSource {
    fn empty() -> Self {
        Self {
            files: BTreeMap::new(),
            directories: BTreeMap::new(),
            uname: None,
            guest_uid: 0,
            statvfs: Err(FileReadFailure::NotFound),
            root_device: Err(FileReadFailure::NotFound),
            touched: Mutex::new(Vec::new()),
        }
    }

    fn file(&mut self, path: impl Into<String>, contents: impl Into<String>) {
        self.files
            .insert(path.into(), Ok(contents.into().into_bytes()));
    }

    fn fail(&mut self, path: impl Into<String>, error: FileReadFailure) {
        self.files.insert(path.into(), Err(error));
    }

    fn directory<I, S>(&mut self, path: impl Into<String>, names: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.directories
            .insert(path.into(), Ok(names.into_iter().map(Into::into).collect()));
    }

    fn touched(&self) -> Vec<String> {
        self.touched.lock().unwrap().clone()
    }
}

impl HardwareSource for FixtureSource {
    fn read(&self, path: &str, cap: usize) -> Result<Vec<u8>, FileReadFailure> {
        self.touched.lock().unwrap().push(path.to_owned());
        match self.files.get(path) {
            None => Err(FileReadFailure::NotFound),
            Some(Ok(bytes)) if bytes.len() > cap => Err(FileReadFailure::TooLarge),
            Some(result) => result.clone(),
        }
    }

    fn list(&self, path: &str) -> Result<Vec<String>, FileReadFailure> {
        self.touched.lock().unwrap().push(format!("{path}/"));
        self.directories
            .get(path)
            .cloned()
            .unwrap_or(Err(FileReadFailure::NotFound))
    }

    fn uname(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.uname.clone()
    }

    fn guest_uid(&self) -> u64 {
        self.guest_uid
    }

    fn guest_root_statvfs(&self) -> Result<StatvfsReading, FileReadFailure> {
        self.statvfs
    }

    fn guest_root_device(&self) -> Result<(u64, u64), FileReadFailure> {
        self.root_device
    }
}

const MOTOROLA_STATUS: &str = "\
Name:\tliskov-runtime-
Umask:\t0077
State:\tR (running)
Tgid:\t28163
Pid:\t28163
PPid:\t28150
TracerPid:\t28150
Uid:\t10437\t10437\t10437\t10437
Gid:\t10437\t10437\t10437\t10437
Groups:\t3003 9997 20437 50437
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
NoNewPrivs:\t0
Seccomp:\t2
";

/// The readback's cgroup lines. Their paths name the app uid and pid; none of
/// that may leave.
const MOTOROLA_CGROUP: &str = "\
4:memory:/apps/uid_10437
3:cpuset:/top-app
2:cpu:/top-app
1:blkio:/
0::/uid_10437/pid_28163
";

/// The readback's twenty lines, between the lines a real kernel also prints.
const MOTOROLA_MEMINFO: &str = "\
MemTotal:        3555756 kB
MemFree:           70384 kB
MemAvailable:     726224 kB
Buffers:            1828 kB
Cached:           765828 kB
SwapCached:        42572 kB
Active:           912340 kB
Inactive:        1290112 kB
Unevictable:      145368 kB
Mlocked:          145368 kB
SwapTotal:       2666812 kB
SwapFree:        1045924 kB
Dirty:              2772 kB
Writeback:             0 kB
AnonPages:       1596928 kB
Mapped:           494360 kB
Shmem:             47408 kB
KReclaimable:     160432 kB
Slab:             337616 kB
SReclaimable:      98116 kB
SUnreclaim:       239500 kB
KernelStack:       60332 kB
ShadowCallStack:   15100 kB
PageTables:        84756 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     4444688 kB
Committed_AS:   73129456 kB
VmallocTotal:   263061440 kB
VmallocUsed:      245012 kB
VmallocChunk:          0 kB
Percpu:             9536 kB
CmaTotal:         241664 kB
CmaFree:               0 kB
HugePages_Total:       0
";

/// An Android mount namespace: the guest sits on `/data`'s volume (253:58),
/// the kernel's `/` is the erofs system image, and other applications' data
/// directories are mounted beside the sandbox's own.
const MOTOROLA_MOUNTINFO: &str = "\
1 0 253:13 / / ro,relatime shared:1 - erofs /dev/block/dm-13 ro,seclabel,user_xattr,acl
22 1 0:5 / /dev rw,nosuid,relatime shared:2 - tmpfs tmpfs rw,seclabel,size=1734420k,mode=755
23 1 0:22 / /proc rw,relatime shared:12 - proc proc rw,gid=3009,hidepid=invisible
150 1 253:58 / /data rw,nosuid,nodev,noatime shared:90 - f2fs /dev/block/dm-58 rw,lazytime,seclabel,background_gc=on,discard,no_heap,user_xattr,inline_xattr,acl,inline_data,inline_dentry,flush_merge,extent_cache,mode=adaptive,active_logs=6,reserve_root=32768,resuid=0,resgid=1065,inlinecrypt,alloc_mode=default,checkpoint_merge,fsync_mode=nobarrier
310 150 253:58 /data/com.google.android.gms /data/data/com.google.android.gms rw,nosuid,nodev,noatime shared:91 - f2fs /dev/block/dm-58 rw,lazytime,seclabel,discard,inlinecrypt,fsync_mode=nobarrier
400 1 7:96 / /apex/com.android.art@351011240 ro,nodev,noatime - ext4 /dev/block/loop12 ro,seclabel
311 150 253:58 /user/0/com.acurast.processor.executor.sandbox.proot.core.canary /data/user/0/com.acurast.processor.executor.sandbox.proot.core.canary rw,nosuid,nodev,noatime shared:92 - f2fs /dev/block/dm-58 rw,lazytime,seclabel,discard,inlinecrypt,fsync_mode=nobarrier
";

/// The readback's `thermal_zoneN type [temp]` list. A missing temp is a read
/// that returned nothing.
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
92 battery 29700";

const SOC_SERIAL: &str = "0x9a3c51e7";

/// The Motorola capture as a tree: the files the probe read, in the kernel's
/// own formats, beside files it must never open.
pub(crate) fn motorola() -> FixtureSource {
    let mut source = FixtureSource::empty();
    source.uname = Some((b"5.4.295-moto-gc9355f04a895".to_vec(), b"aarch64".to_vec()));
    source.guest_uid = 0;
    source.file(PROC_STATUS, MOTOROLA_STATUS);
    source.file(PROC_CGROUP, MOTOROLA_CGROUP);
    source.file(PROC_MEMINFO, MOTOROLA_MEMINFO);
    source.file(PROC_MOUNTINFO, MOTOROLA_MOUNTINFO);
    source.file("/proc/mounts", "never read\n");
    // `df -B1 /`: 118581342208 total, 7344947200 used, 111102177280 available.
    source.statvfs = Ok(StatvfsReading {
        blocks: 28_950_523,
        free_blocks: 27_157_323,
        available_blocks: 27_124_555,
        fragment_size: 4_096,
    });
    source.root_device = Ok((253, 58));

    let mut cpu_entries = (0..8).map(|cpu| format!("cpu{cpu}")).collect::<Vec<_>>();
    cpu_entries.extend(
        [
            "cpufreq",
            "cpuidle",
            "online",
            "possible",
            "present",
            "kernel_max",
            "uevent",
            "vulnerabilities",
        ]
        .map(String::from),
    );
    source.directory(CPU_ROOT, cpu_entries);
    source.directory(CPUFREQ_ROOT, ["policy0", "policy6"]);
    for (policy, related, min, max, available) in [
        (
            0,
            "0 1 2 3 4 5",
            "300000",
            "1804800",
            "300000 576000 691200 940800 1113600 1324800 1516800 1651200 1708800 1804800",
        ),
        (
            6,
            "6 7",
            "691200",
            "2016000",
            "691200 940800 1228800 1401600 1516800 1651200 1804800 1900800 2016000",
        ),
    ] {
        let base = format!("{CPUFREQ_ROOT}/policy{policy}");
        source.file(format!("{base}/related_cpus"), format!("{related}\n"));
        source.file(format!("{base}/cpuinfo_min_freq"), format!("{min}\n"));
        source.file(format!("{base}/cpuinfo_max_freq"), format!("{max}\n"));
        source.file(
            format!("{base}/scaling_available_frequencies"),
            format!("{available} \n"),
        );
        source.file(format!("{base}/scaling_governor"), "schedutil\n");
        source.file(format!("{base}/scaling_driver"), "qcom-cpufreq-hw\n");
        // A moment during the probe, not a hardware reading.
        source.file(format!("{base}/scaling_min_freq"), "576000\n");
        source.file(format!("{base}/scaling_cur_freq"), "691200\n");
    }
    for cpu in 0..8 {
        let (midr, capacity) = if cpu < 6 {
            ("0x00000000412fd050", "481")
        } else {
            ("0x00000000411fd411", "1024")
        };
        let base = format!("{CPU_ROOT}/cpu{cpu}");
        source.file(
            format!("{base}/regs/identification/midr_el1"),
            format!("{midr}\n"),
        );
        source.file(format!("{base}/cpu_capacity"), format!("{capacity}\n"));
        let cache = format!("{base}/cache");
        source.directory(
            cache.clone(),
            ["index0", "index1", "index2", "index3", "uevent"],
        );
        let own = cpu.to_string();
        for (index, level, kind, shared) in [
            (0, "1", "Data", own.as_str()),
            (1, "1", "Instruction", own.as_str()),
            (2, "2", "Unified", own.as_str()),
            (3, "3", "Unified", "0-7"),
        ] {
            let dir = format!("{cache}/index{index}");
            source.file(format!("{dir}/level"), format!("{level}\n"));
            source.file(format!("{dir}/type"), format!("{kind}\n"));
            source.file(format!("{dir}/shared_cpu_list"), format!("{shared}\n"));
            source.fail(format!("{dir}/size"), FileReadFailure::PermissionDenied);
        }
    }

    source.file(format!("{SOC_ROOT}/family"), "Snapdragon\n");
    source.file(format!("{SOC_ROOT}/soc_id"), "578\n");
    source.file(
        format!("{SOC_ROOT}/serial_number"),
        format!("{SOC_SERIAL}\n"),
    );
    source.file(format!("{SOC_ROOT}/machine"), "SM4375\n");
    source.file(format!("{KGSL_ROOT}/gpu_model"), "Adreno619v2\n");
    source.file(format!("{KGSL_ROOT}/max_gpuclk"), "700000000\n");
    source.fail(
        format!("{KGSL_ROOT}/gpuclk"),
        FileReadFailure::PermissionDenied,
    );

    let mut thermal_entries = Vec::new();
    for line in MOTOROLA_ZONES.lines() {
        let mut fields = line.split(' ');
        let index = fields.next().unwrap();
        let kind = fields.next().unwrap();
        let dir = format!("{THERMAL_ROOT}/thermal_zone{index}");
        source.file(format!("{dir}/type"), format!("{kind}\n"));
        match fields.next() {
            Some(temp) => source.file(format!("{dir}/temp"), format!("{temp}\n")),
            // Some sensors fail the read, others return nothing.
            None if index.parse::<u32>().unwrap() < 3 => {
                source.fail(format!("{dir}/temp"), FileReadFailure::Unavailable);
            }
            None => source.file(format!("{dir}/temp"), ""),
        }
        thermal_entries.push(format!("thermal_zone{index}"));
    }
    thermal_entries.extend(["cooling_device0", "cooling_device1"].map(String::from));
    source.directory(THERMAL_ROOT, thermal_entries);
    source
}

fn document(source: &FixtureSource) -> Value {
    serde_json::to_value(collect_coverage_hardware(source)).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn copied_contract_files_are_the_pinned_liskov_rs_bytes() {
    assert_eq!(sha256_hex(CATALOG), CATALOG_SHA256);
    assert_eq!(sha256_hex(RESULT_VECTOR), RESULT_VECTOR_SHA256);
    assert_eq!(sha256_hex(PAYLOAD_VECTOR), PAYLOAD_VECTOR_SHA256);
    assert_eq!(
        compiled_coverage_hardware_catalog_digest(),
        format!("sha256:{CATALOG_SHA256}")
    );
    // The baseline catalog is untouched by the new profile.
    assert_eq!(
        crate::processor_facts::compiled_catalog_digest(),
        "sha256:3d66b4cba71a4ab57c197b80b523b2d172981bbf64ba62438ed9fdc0c5c5cb85"
    );

    let catalog: Value = serde_json::from_slice(CATALOG).unwrap();
    assert_eq!(catalog["domain"], "proof.liskov.processor-fact-catalog.v1");
    assert_eq!(catalog["profile"], COVERAGE_HARDWARE_PROFILE);
    assert_eq!(catalog["helperContractEpoch"], HELPER_CONTRACT_EPOCH);
    let facts = catalog["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0]["kind"], "coverage_hardware_raw.v1");
    assert_eq!(facts[0]["capture"], "authorized_due_only");
    assert_eq!(
        serde_json::from_value::<ProcessorFactKind>(facts[0]["kind"].clone()).unwrap(),
        ProcessorFactKind::CoverageHardwareRaw
    );
    assert_eq!(
        ProcessorFactKind::CoverageHardwareRaw.profile(),
        COVERAGE_HARDWARE_PROFILE
    );

    // The helper serializes exactly the catalog's groups, and each group
    // exactly the catalog's fields.
    let fields = facts[0]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let emitted = document(&motorola());
    let keys = |value: &Value| {
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(keys(&emitted), fields);
    assert_eq!(
        keys(&catalog["groups"]),
        fields,
        "catalog groups name every field"
    );
    for (group, spec) in catalog["groups"].as_object().unwrap() {
        let Some(group_fields) = spec.get("fields").and_then(Value::as_array) else {
            continue;
        };
        let expected = group_fields
            .iter()
            .map(|field| field.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let actual = match &emitted[group] {
            // A list group's fields are its entries'.
            Value::Object(map) if map.contains_key("status") => keys(&emitted[group]["value"][0]),
            _ => keys(&emitted[group]),
        };
        assert_eq!(actual, expected, "{group}");
    }
}

#[test]
fn motorola_fixture_emits_the_shared_payload_vector() {
    let payload: Value = serde_json::from_slice(PAYLOAD_VECTOR).unwrap();
    let result: Value = serde_json::from_slice(RESULT_VECTOR).unwrap();
    let emitted = document(&motorola());
    assert_eq!(emitted, payload);
    assert_eq!(emitted, result["result"]["facts"][0]["value"]);

    // The readings the item names, spelled out.
    let policies = emitted["cpuPolicies"]["value"].as_array().unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0]["relatedCpus"]["value"], "0-5");
    assert_eq!(policies[1]["relatedCpus"]["value"], "6-7");
    assert_eq!(policies[0]["midr"]["value"], "0x412fd050");
    assert_eq!(policies[1]["midr"]["value"], "0x411fd411");
    assert_eq!(emitted["soc"]["family"]["value"], "Snapdragon");
    assert_eq!(emitted["soc"]["socId"]["value"], "578");
    assert_eq!(emitted["gpu"]["model"]["value"], "Adreno619v2");
    assert_eq!(emitted["gpu"]["maxClockHz"]["value"], 700_000_000);
    assert_eq!(
        emitted["guestRoot"]["totalBytes"]["value"],
        118_581_342_208_u64
    );
    assert_eq!(emitted["filesystems"]["data"]["value"]["inlinecrypt"], true);
    let zones = emitted["thermalZones"]["value"].as_array().unwrap();
    assert_eq!(zones.len(), 93);
    assert_eq!(zones[0]["temp"], json!({"status": "unread"}));
    assert_eq!(zones[20]["temp"], json!({"status": "unread"}));
    assert_eq!(zones[65]["temp"], json!({"status": "observed", "value": 0}));
    assert_eq!(
        zones[86]["temp"],
        json!({"status": "observed", "value": -40960})
    );
    // `vbat` stays a raw zone reading, not a converted temperature.
    assert_eq!(zones[88]["type"], "vbat");
    assert_eq!(
        zones[88]["temp"],
        json!({"status": "observed", "value": 4434})
    );
}

/// Cross-repo parity anchor: the unsigned body built from this crate's own
/// types canonicalizes to exactly the bytes the `liskov-rs` admission engine
/// recomputes before it verifies a signature.
#[test]
fn matches_the_shared_coverage_hardware_result_vector() {
    let vector: Value = serde_json::from_slice(RESULT_VECTOR).unwrap();
    let expected = &vector["result"];
    let text = |key: &str| expected[key].as_str().unwrap().to_owned();
    let facts = vec![ProcessorFact::CoverageHardwareRaw(
        collect_coverage_hardware(&motorola()),
    )];
    let facts_digest = format!(
        "sha256:{}",
        sha256_hex(&canonical_json_bytes(
            &serde_json::to_value(&facts).unwrap()
        ))
    );
    let catalog_digest = compiled_coverage_hardware_catalog_digest();
    let (authorization_id, challenge, helper_digest) = (
        text("authorizationId"),
        text("challenge"),
        text("helperDigest"),
    );
    let unsigned = UnsignedProcessorFactResult {
        domain: PROCESSOR_FACT_RESULT_DOMAIN,
        authorization_id: &authorization_id,
        challenge: &challenge,
        deployment_id: "deployment-174098",
        job_id: r#"{"id":"174098","origin":{"kind":"Acurast"}}"#,
        processor_id: "5C81qALgzdeYUseGhtWPexwufYY83NcrnTazpFMcTizhuBb2",
        runtime_instance_id: "runtime-instance-174098",
        profile: COVERAGE_HARDWARE_PROFILE,
        catalog_digest: &catalog_digest,
        helper_contract_epoch: HELPER_CONTRACT_EPOCH,
        // A literal, so a release bump cannot move these bytes.
        helper_version: "0.11.0",
        helper_digest: &helper_digest,
        capture_started_at_ms: 1_790_165_966_000,
        capture_completed_at_ms: 1_790_165_967_500,
        facts: &facts,
        facts_digest: &facts_digest,
    };
    let unsigned_value = serde_json::to_value(&unsigned).unwrap();
    assert_eq!(&unsigned_value, expected);
    assert!(expected.get("signature").is_none());
    assert_eq!(expected["factsDigest"], facts_digest);
    assert_eq!(expected["catalogDigest"], catalog_digest);
    // The string, not the `Value`: key order is what a signature sees.
    let canonical = canonical_json_bytes(&unsigned_value);
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        vector["canonicalSigningPayload"].as_str().unwrap(),
    );
    assert!(canonical.len() + 145 <= MAX_RESULT_BYTES);
}

/// A four-core phone with one policy, no `soc0`, no kgsl node and readable
/// cache sizes: nothing of the Motorola may appear, and nothing absent may
/// read as zero.
fn small_device() -> FixtureSource {
    let mut source = FixtureSource::empty();
    source.uname = Some((b"4.19.157-perf+".to_vec(), b"aarch64".to_vec()));
    source.guest_uid = 0;
    source.file(
        PROC_STATUS,
        "Uid:\t10211\t10211\t10211\t10211\nCapEff:\t0000000000000000\n",
    );
    source.file(PROC_CGROUP, "0::/\n");
    source.file(
        PROC_MEMINFO,
        "MemTotal:        1885432 kB\nMemFree:               0 kB\nMemAvailable:     401220 kB\nSwapTotal:             0 kB\n",
    );
    source.file(
        PROC_MOUNTINFO,
        "20 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n",
    );
    source.statvfs = Ok(StatvfsReading {
        blocks: 1_000,
        free_blocks: 1_000,
        available_blocks: 0,
        fragment_size: 4_096,
    });
    source.root_device = Ok((8, 2));
    source.directory(CPU_ROOT, ["cpu0", "cpu1", "cpu2", "cpu3", "cpufreq"]);
    source.directory(CPUFREQ_ROOT, ["policy0"]);
    let base = format!("{CPUFREQ_ROOT}/policy0");
    source.file(format!("{base}/related_cpus"), "0-3\n");
    source.file(format!("{base}/cpuinfo_min_freq"), "614400\n");
    source.file(format!("{base}/cpuinfo_max_freq"), "1363200\n");
    source.fail(
        format!("{base}/scaling_available_frequencies"),
        FileReadFailure::PermissionDenied,
    );
    source.file(format!("{base}/scaling_governor"), "schedutil\n");
    source.file(format!("{base}/scaling_driver"), "cpufreq-dt\n");
    source.file(
        format!("{CPU_ROOT}/cpu0/regs/identification/midr_el1"),
        "0x00000000410fd034\n",
    );
    for cpu in 0..4 {
        let cache = format!("{CPU_ROOT}/cpu{cpu}/cache");
        source.directory(cache.clone(), ["index0", "index1"]);
        source.file(format!("{cache}/index0/level"), "1\n");
        source.file(format!("{cache}/index0/type"), "Data\n");
        source.file(
            format!("{cache}/index0/shared_cpu_list"),
            format!("{cpu}\n"),
        );
        source.file(format!("{cache}/index0/size"), "32K\n");
        source.file(format!("{cache}/index1/level"), "2\n");
        source.file(format!("{cache}/index1/type"), "Unified\n");
        source.file(format!("{cache}/index1/shared_cpu_list"), "0-3\n");
        source.file(format!("{cache}/index1/size"), "512K\n");
    }
    source.directory(THERMAL_ROOT, ["thermal_zone0", "thermal_zone1"]);
    source.file(
        format!("{THERMAL_ROOT}/thermal_zone0/type"),
        "cpu-thermal\n",
    );
    source.file(format!("{THERMAL_ROOT}/thermal_zone0/temp"), "0\n");
    source.file(format!("{THERMAL_ROOT}/thermal_zone1/type"), "battery\n");
    source.fail(
        format!("{THERMAL_ROOT}/thermal_zone1/temp"),
        FileReadFailure::PermissionDenied,
    );
    source
}

#[test]
fn one_policy_no_soc0_and_no_kgsl_emit_explicit_absences() {
    let emitted = document(&small_device());
    let not_present = json!({"status": "not_present"});

    assert_eq!(emitted["soc"]["family"], not_present);
    assert_eq!(emitted["soc"]["socId"], not_present);
    assert_eq!(emitted["gpu"]["model"], not_present);
    assert_eq!(emitted["gpu"]["maxClockHz"], not_present);
    assert_eq!(emitted["cgroupControllers"]["value"], json!(["unified"]));
    assert_eq!(emitted["identity"]["kernelUid"]["value"], 10211);

    let policies = emitted["cpuPolicies"]["value"].as_array().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["policy"], 0);
    assert_eq!(policies[0]["relatedCpus"]["value"], "0-3");
    assert_eq!(policies[0]["midr"]["value"], "0x410fd034");
    assert_eq!(policies[0]["capacity"], not_present);
    assert_eq!(
        policies[0]["availableKhz"],
        json!({"status": "permission_denied"})
    );

    let caches = emitted["caches"]["value"].as_array().unwrap();
    assert_eq!(caches.len(), 5);
    assert_eq!(caches[0]["sizeBytes"]["value"], 32_768);
    assert_eq!(caches[4]["sharedCpuList"], "0-3");
    assert_eq!(caches[4]["sizeBytes"]["value"], 524_288);

    // A kernel that does not print a line is not_present; a printed zero is
    // a zero.
    assert_eq!(emitted["meminfo"]["memTotalKb"]["value"], 1_885_432);
    assert_eq!(
        emitted["meminfo"]["memFreeKb"],
        json!({"status": "observed", "value": 0})
    );
    assert_eq!(emitted["meminfo"]["shadowCallStackKb"], not_present);
    assert_eq!(emitted["meminfo"]["cmaTotalKb"], not_present);
    assert_eq!(
        emitted["guestRoot"]["availableBytes"],
        json!({"status": "observed", "value": 0})
    );
    assert_eq!(emitted["guestRoot"]["usedBytes"]["value"], 0);

    assert_eq!(
        emitted["filesystems"]["guestRoot"]["value"],
        json!({"type": "ext4", "inlinecrypt": false, "discard": false})
    );
    assert_eq!(emitted["filesystems"]["data"], not_present);
    assert_eq!(
        emitted["thermalZones"]["value"],
        json!([
            {"type": "cpu-thermal", "temp": {"status": "observed", "value": 0}},
            {"type": "battery", "temp": {"status": "unread"}},
        ])
    );

    let text = serde_json::to_string(&emitted).unwrap();
    for motorola in ["Snapdragon", "Adreno", "578", "0x412fd050", "f2fs", "10437"] {
        assert!(!text.contains(motorola), "{motorola} leaked");
    }
}

#[test]
fn denied_and_missing_surfaces_stay_distinct_statuses() {
    let mut source = motorola();
    source.fail(PROC_MEMINFO, FileReadFailure::PermissionDenied);
    source.fail(PROC_STATUS, FileReadFailure::PermissionDenied);
    source.files.remove(PROC_CGROUP);
    source.files.remove(&format!("{SOC_ROOT}/family"));
    source.fail(
        format!("{SOC_ROOT}/soc_id"),
        FileReadFailure::PermissionDenied,
    );
    source
        .directories
        .insert(CPUFREQ_ROOT.into(), Err(FileReadFailure::PermissionDenied));
    source.directories.remove(THERMAL_ROOT);
    for cpu in 0..8 {
        source.directories.insert(
            format!("{CPU_ROOT}/cpu{cpu}/cache"),
            Err(FileReadFailure::PermissionDenied),
        );
    }
    source.statvfs = Err(FileReadFailure::PermissionDenied);
    source.files.remove(PROC_MOUNTINFO);
    source.uname = None;

    let emitted = document(&source);
    let denied = json!({"status": "permission_denied"});
    let missing = json!({"status": "not_present"});
    for field in emitted["meminfo"].as_object().unwrap().values() {
        assert_eq!(field, &denied);
    }
    assert_eq!(emitted["identity"]["kernelUid"], denied);
    assert_eq!(emitted["identity"]["capabilityClass"], denied);
    assert_eq!(
        emitted["identity"]["guestUid"],
        json!({"status": "observed", "value": 0})
    );
    assert_eq!(emitted["cgroupControllers"], missing);
    assert_eq!(emitted["soc"]["family"], missing);
    assert_eq!(emitted["soc"]["socId"], denied);
    assert_eq!(emitted["cpuPolicies"], denied);
    assert_eq!(emitted["caches"], denied);
    assert_eq!(emitted["thermalZones"], missing);
    assert_eq!(emitted["guestRoot"]["totalBytes"], denied);
    assert_eq!(emitted["filesystems"]["guestRoot"], missing);
    assert_eq!(emitted["filesystems"]["data"], missing);
    assert_eq!(
        emitted["kernel"]["release"],
        json!({"status": "surface_hidden"})
    );
    // The rest of the reading is unaffected by those failures.
    assert_eq!(emitted["gpu"]["model"]["value"], "Adreno619v2");
}

fn euid_is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The live source, on a real directory: EACCES is `permission_denied`, a
/// missing file is `not_present`, and the two do not collapse.
#[test]
fn system_source_classifies_eacces_enoent_symlink_and_oversize() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = std::env::temp_dir().join(format!(
        "liskov-coverage-hardware-{}-source",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let readable = root.join("readable");
    std::fs::write(&readable, "481\n").unwrap();
    let denied = root.join("denied");
    std::fs::write(&denied, "578\n").unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let link = root.join("link");
    symlink(&readable, &link).unwrap();
    let path = |path: &std::path::Path| path.to_str().unwrap().to_owned();

    let source = SystemHardwareSource;
    assert_eq!(source.read(&path(&readable), 64).unwrap(), b"481\n");
    assert_eq!(
        source.read(&path(&root.join("missing")), 64),
        Err(FileReadFailure::NotFound)
    );
    assert_eq!(
        source.read(&path(&link), 64),
        Err(FileReadFailure::UnsafeFile)
    );
    assert_eq!(
        source.read(&path(&readable), 3),
        Err(FileReadFailure::TooLarge)
    );
    if !euid_is_root() {
        assert_eq!(
            source.read(&path(&denied), 64),
            Err(FileReadFailure::PermissionDenied)
        );
    }
    let mut listed = source.list(&path(&root)).unwrap();
    listed.sort();
    assert_eq!(listed, ["denied", "link", "readable"]);
    assert_eq!(
        source.list(&path(&root.join("missing"))),
        Err(FileReadFailure::NotFound)
    );

    assert_eq!(
        reading::<u64>(Err(FileReadFailure::PermissionDenied.into())),
        Availability::PermissionDenied
    );
    assert_eq!(
        reading::<u64>(Err(FileReadFailure::NotFound.into())),
        Availability::NotPresent
    );
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_dir_all(&root).unwrap();

    // The live syscalls answer without a fixture.
    assert!(source.uname().is_some());
    let statvfs = source.guest_root_statvfs().unwrap();
    assert!(statvfs.fragment_size > 0);
    assert!(source.guest_root_device().is_ok());
}

#[test]
fn the_reading_never_carries_a_mount_source_path_package_serial_or_environment() {
    let emitted = document(&motorola());
    let text = serde_json::to_string(&emitted).unwrap();
    assert!(!text.contains('/'), "a path leaked: {text}");
    for secret in [
        "com.google",
        "android.gms",
        "com.acurast",
        "canary",
        "dm-58",
        "dm-13",
        "block",
        "loop12",
        "apex",
        "uid_10437",
        "pid_28163",
        "top-app",
        "seclabel",
        "lazytime",
        SOC_SERIAL,
        "SM4375",
        "serial",
        "fogo",
        "moto g",
    ] {
        assert!(!text.contains(secret), "{secret} leaked");
    }
    // Environment and customer values have no field to land in: the reading
    // is exactly the catalog's groups.
    assert_eq!(emitted.as_object().unwrap().len(), 11);

    // A mount source or type that names a package is refused, not copied.
    let mut source = motorola();
    source.file(
        PROC_MOUNTINFO,
        "150 1 253:58 / /data rw - fuse.com.example.spy /dev/fuse rw\n\
         151 1 253:58 / /mnt rw - com.example.spy.fs com.example.spy rw\n",
    );
    let emitted = document(&source);
    assert_eq!(
        emitted["filesystems"]["data"]["value"],
        json!({"type": "fuse", "inlinecrypt": false, "discard": false})
    );
    assert_eq!(
        emitted["filesystems"]["guestRoot"],
        json!({"status": "parse_error"})
    );
    assert!(!serde_json::to_string(&emitted).unwrap().contains("spy"));
}

/// The collector opens only the readback's closed file list and lists only
/// the four directories it numbers entries in.
#[test]
fn the_collector_touches_only_the_closed_file_list() {
    let source = motorola();
    collect_coverage_hardware(&source);
    let allowed = |path: &str| {
        let numbered = |rest: &str, prefix: &str| -> Option<String> {
            let rest = rest.strip_prefix(prefix)?;
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            (digits > 0).then(|| rest[digits..].to_owned())
        };
        if [
            PROC_STATUS,
            PROC_CGROUP,
            PROC_MEMINFO,
            PROC_MOUNTINFO,
            "/sys/devices/soc0/family",
            "/sys/devices/soc0/soc_id",
            "/sys/class/kgsl/kgsl-3d0/gpu_model",
            "/sys/class/kgsl/kgsl-3d0/max_gpuclk",
            "/sys/devices/system/cpu/",
            "/sys/devices/system/cpu/cpufreq/",
            "/sys/class/thermal/",
        ]
        .contains(&path)
        {
            return true;
        }
        if let Some(rest) = numbered(path, "/sys/devices/system/cpu/cpufreq/policy") {
            return [
                "/related_cpus",
                "/cpuinfo_min_freq",
                "/cpuinfo_max_freq",
                "/scaling_available_frequencies",
                "/scaling_governor",
                "/scaling_driver",
            ]
            .contains(&rest.as_str());
        }
        if let Some(rest) = numbered(path, "/sys/class/thermal/thermal_zone") {
            return rest == "/type" || rest == "/temp";
        }
        if let Some(rest) = numbered(path, "/sys/devices/system/cpu/cpu") {
            if ["/regs/identification/midr_el1", "/cpu_capacity", "/cache/"]
                .contains(&rest.as_str())
            {
                return true;
            }
            if let Some(rest) = numbered(&rest, "/cache/index") {
                return ["/level", "/type", "/shared_cpu_list", "/size"].contains(&rest.as_str());
            }
        }
        false
    };
    let touched = source.touched();
    assert!(!touched.is_empty());
    for path in &touched {
        assert!(allowed(path), "{path} is outside the closed file list");
    }
    for never in [
        "/proc/mounts",
        "/sys/devices/soc0/serial_number",
        "/sys/devices/soc0/machine",
        "/sys/devices/soc0/",
        "/sys/class/kgsl/kgsl-3d0/gpuclk",
    ] {
        assert!(
            !touched.iter().any(|path| path == never),
            "{never} was read"
        );
    }
    assert!(
        !touched
            .iter()
            .any(|path| path.ends_with("scaling_cur_freq"))
    );
}

/// A reading far larger than the Motorola's: every list stops at its catalog
/// cap, and the whole result no longer fits the 16 KiB envelope.
pub(crate) fn oversized() -> FixtureSource {
    let mut source = motorola();
    let long_type = "x".repeat(48);
    let zones = (0..200)
        .map(|zone| format!("thermal_zone{zone}"))
        .collect::<Vec<_>>();
    for zone in 0..200 {
        let dir = format!("{THERMAL_ROOT}/thermal_zone{zone}");
        source.file(format!("{dir}/type"), format!("{long_type}\n"));
        source.file(format!("{dir}/temp"), "-2147483647\n");
    }
    source.directory(THERMAL_ROOT, zones);
    let cpus = (0..40).map(|cpu| format!("cpu{cpu}")).collect::<Vec<_>>();
    source.directory(CPU_ROOT, cpus);
    for cpu in 0..40 {
        let cache = format!("{CPU_ROOT}/cpu{cpu}/cache");
        source.directory(cache.clone(), ["index0", "index1"]);
        for (index, kind) in [(0, "Data"), (1, "Instruction")] {
            let dir = format!("{cache}/index{index}");
            source.file(format!("{dir}/level"), "1\n");
            source.file(format!("{dir}/type"), format!("{kind}\n"));
            source.file(format!("{dir}/shared_cpu_list"), format!("{cpu}\n"));
            source.file(format!("{dir}/size"), "64K\n");
        }
    }
    let policies = (0..20)
        .map(|policy| format!("policy{policy}"))
        .collect::<Vec<_>>();
    source.directory(CPUFREQ_ROOT, policies);
    let frequencies = (1..=40)
        .map(|step| (step * 100_000).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    for policy in 0..20 {
        source.file(
            format!("{CPUFREQ_ROOT}/policy{policy}/scaling_available_frequencies"),
            frequencies.clone(),
        );
    }
    let cgroup = (0..30)
        .map(|line| format!("{line}:controller_{line}:/"))
        .collect::<Vec<_>>()
        .join("\n");
    source.file(PROC_CGROUP, cgroup);
    source
}

pub(crate) fn oversized_reading() -> CoverageHardwareRawFact {
    collect_coverage_hardware(&oversized())
}

#[test]
fn every_list_stops_at_its_catalog_cap() {
    let emitted = document(&oversized());
    let length = |group: &str| emitted[group]["value"].as_array().unwrap().len();
    assert_eq!(length("thermalZones"), MAX_THERMAL_ZONES);
    assert_eq!(length("caches"), MAX_CACHES);
    assert_eq!(length("cpuPolicies"), MAX_CPU_POLICIES);
    assert_eq!(length("cgroupControllers"), MAX_CGROUP_CONTROLLERS);
    assert_eq!(
        emitted["cpuPolicies"]["value"][0]["availableKhz"]["value"]
            .as_array()
            .unwrap()
            .len(),
        MAX_AVAILABLE_FREQUENCIES
    );
    assert!(canonical_json_bytes(&emitted).len() > MAX_RESULT_BYTES);
}

#[test]
fn parsers_normalize_kernel_formats_and_refuse_the_rest() {
    let list = |text: &str| parse_cpu_list(text).map(|list| (list.text, list.first, list.count));
    assert_eq!(list("0 1 2 3 4 5\n"), Ok(("0-5".into(), 0, 6)));
    assert_eq!(list("6 7"), Ok(("6-7".into(), 6, 2)));
    assert_eq!(list("0-3,5\n"), Ok(("0-3,5".into(), 0, 5)));
    assert_eq!(list("4 0 2"), Ok(("0,2,4".into(), 0, 3)));
    for bad in ["", "\n", "3-1", "a", "0-", "-1", "4096", "0-4096"] {
        assert_eq!(list(bad), Err(Unread::ParseError), "{bad:?}");
    }

    assert_eq!(parse_midr("0x00000000412fd050\n"), Ok("0x412fd050".into()));
    assert_eq!(parse_midr("0x411FD411"), Ok("0x411fd411".into()));
    assert_eq!(
        parse_midr("0x0000000100000001"),
        Ok("0x0000000100000001".into())
    );
    for bad in ["412fd050", "0x", "0xzz", "0x00000000000000000"] {
        assert_eq!(parse_midr(bad), Err(Unread::ParseError), "{bad:?}");
    }

    assert_eq!(parse_cache_size("32K\n"), Ok(32_768));
    assert_eq!(parse_cache_size("2M"), Ok(2_097_152));
    assert_eq!(parse_cache_size("512"), Ok(512));
    for bad in ["K", "", "12Q", "-1K"] {
        assert_eq!(parse_cache_size(bad), Err(Unread::ParseError), "{bad:?}");
    }

    assert_eq!(parse_temp("39100\n"), Some(39_100));
    assert_eq!(parse_temp("-40960"), Some(-40_960));
    assert_eq!(parse_temp(""), None);
    assert_eq!(parse_temp("2147483648"), None);
    assert_eq!(parse_temp("-"), None);

    assert_eq!(
        parse_cgroup_controllers("1:name=systemd:/\n2:cpu,cpuacct:/a\n3:cpu:/b\n0::/c\n"),
        Ok(vec!["cpu".into(), "cpuacct".into(), "unified".into()])
    );
    assert_eq!(
        parse_cgroup_controllers("garbage\n"),
        Err(Unread::ParseError)
    );
    assert_eq!(
        parse_cgroup_controllers("2:Memory:/\n"),
        Err(Unread::ParseError)
    );

    assert_eq!(
        bounded_text("5.4.295-moto-gc9355f04a895\n", 128, printable),
        Ok("5.4.295-moto-gc9355f04a895".into())
    );
    assert_eq!(bounded_text("a/b", 128, printable), Err(Unread::ParseError));
    assert_eq!(
        bounded_text("com.google.android", 128, printable),
        Err(Unread::ParseError)
    );
    assert_eq!(bounded_text("", 128, printable), Err(Unread::ParseError));

    // makedev(253, 58), and a device beyond the old 8-bit split.
    assert_eq!(split_device((253 << 8) | 58), (253, 58));
    assert_eq!(
        split_device((0x1234_5000 << 32) | (0xabcd_e900 << 12) | (0x678 << 8) | 0x9f),
        (0x1234_5678, 0xabcd_e99f)
    );
}
