//! Guest-valid repair of the environment the customer command inherits
//! (`BKLG-20260924-gxb7`).
//!
//! The helper runs inside the Debian rootfs but inherits the processor's
//! Android process environment. Two inherited values name paths that do not
//! exist in the guest and two conventional names may be missing. On 2026-09-23
//! (job 175154) an entrypoint `apt-get` failed under
//! `TMPDIR=/data/user/0/<processor package>/cache` and under an `LD_PRELOAD`
//! the guest loader could not open, while a managed-SSH shell of the same job
//! worked.
//!
//! Only the four names below are touched; every other inherited name, Android
//! or not, passes through. The rules run on the inherited set only: a name the
//! signed runtime environment sets is left to it, because a signed value
//! outranks both the inherited value and these defaults.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const TMPDIR: &str = "TMPDIR";
pub const LD_PRELOAD: &str = "LD_PRELOAD";
pub const PATH: &str = "PATH";
pub const HOME: &str = "HOME";

/// Where `TMPDIR` points when the inherited directory is unusable. The helper
/// already relies on it for managed access setup.
pub const DEFAULT_TMPDIR: &str = "/tmp";
/// The Debian default search path the curated images assume (ADR-0041).
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const DEFAULT_HOME: &str = "/root";

/// One inherited name the helper changed, and why. Values are never recorded:
/// the inherited `TMPDIR` carries the processor package name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Normalization {
    pub name: &'static str,
    pub reason: NormalizationReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationReason {
    /// `TMPDIR` names something that is not a directory in the guest.
    DirectoryMissing,
    /// `TMPDIR` names a directory the customer cannot create files in.
    DirectoryNotWritable,
    /// `LD_PRELOAD` names at least one object that is not a file in the guest.
    /// The loader fails the whole list, so the whole variable is removed.
    ObjectMissing,
    /// `PATH` or `HOME` was not inherited at all.
    Unset,
    /// `PATH` was inherited empty.
    Empty,
}

impl NormalizationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryMissing => "directory_missing",
            Self::DirectoryNotWritable => "directory_not_writable",
            Self::ObjectMissing => "object_missing",
            Self::Unset => "unset",
            Self::Empty => "empty",
        }
    }
}

/// The guest filesystem questions the rules ask, behind a seam so tests run
/// against a fake rootfs.
pub trait GuestFilesystem {
    /// True when `path` resolves, following symlinks, to a directory.
    fn is_directory(&self, path: &Path) -> bool;
    /// True when `path` is a directory the process can create files in.
    fn is_writable_directory(&self, path: &Path) -> bool;
    /// True when `path` resolves, following symlinks, to a regular file.
    fn is_file(&self, path: &Path) -> bool;
    /// Create a world-writable sticky directory (`0o1777`, not narrowed by the
    /// umask).
    fn create_sticky_directory(&self, path: &Path) -> io::Result<()>;
}

/// The filesystem the helper process sees, which inside PRoot is the guest's.
#[derive(Debug, Default)]
pub struct ProcessFilesystem;

impl GuestFilesystem for ProcessFilesystem {
    fn is_directory(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
    }

    fn is_writable_directory(&self, path: &Path) -> bool {
        if !self.is_directory(path) {
            return false;
        }
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `path` is a valid NUL-terminated string that outlives the call.
        unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
    }

    fn is_file(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    fn create_sticky_directory(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o1777))
    }
}

/// Repair the four names in `inherited` that are invalid in the guest, except
/// those `signed` will set, and return what changed in rule order. A processor
/// that already exports guest-valid values gets its environment back unchanged
/// and an empty list.
pub fn normalize_customer_environment(
    mut inherited: Vec<(OsString, OsString)>,
    signed: impl Fn(&str) -> bool,
    guest: &dyn GuestFilesystem,
) -> (Vec<(OsString, OsString)>, Vec<Normalization>) {
    let mut changes = Vec::new();
    let mut record = |name, reason| changes.push(Normalization { name, reason });

    if !signed(TMPDIR) {
        if let Some(value) = lookup(&inherited, TMPDIR) {
            let path = Path::new(value);
            let reason = if guest.is_writable_directory(path) {
                None
            } else if guest.is_directory(path) {
                Some(NormalizationReason::DirectoryNotWritable)
            } else {
                Some(NormalizationReason::DirectoryMissing)
            };
            if let Some(reason) = reason {
                let default = Path::new(DEFAULT_TMPDIR);
                if !guest.is_directory(default) {
                    // Best effort: a customer that never uses TMPDIR must still
                    // start, and one that does now fails on a path it can see.
                    let _ = guest.create_sticky_directory(default);
                }
                set(&mut inherited, TMPDIR, DEFAULT_TMPDIR);
                record(TMPDIR, reason);
            }
        }
    }

    if !signed(LD_PRELOAD) {
        if let Some(value) = lookup(&inherited, LD_PRELOAD) {
            if !preload_resolves(value, guest) {
                inherited.retain(|(name, _)| name != LD_PRELOAD);
                record(LD_PRELOAD, NormalizationReason::ObjectMissing);
            }
        }
    }

    if !signed(PATH) {
        let reason = match lookup(&inherited, PATH) {
            None => Some(NormalizationReason::Unset),
            Some(value) if value.is_empty() => Some(NormalizationReason::Empty),
            Some(_) => None,
        };
        if let Some(reason) = reason {
            set(&mut inherited, PATH, DEFAULT_PATH);
            record(PATH, reason);
        }
    }

    if !signed(HOME) && lookup(&inherited, HOME).is_none() {
        set(&mut inherited, HOME, DEFAULT_HOME);
        record(HOME, NormalizationReason::Unset);
    }

    (inherited, changes)
}

/// Whether the guest loader can open every object `LD_PRELOAD` names. ld.so
/// splits the list on spaces and colons and skips empty entries. A name without
/// a slash is found through the library search path, which this does not
/// replicate, so it is kept rather than dropped on a guess.
fn preload_resolves(value: &OsStr, guest: &dyn GuestFilesystem) -> bool {
    value
        .as_bytes()
        .split(|byte| matches!(byte, b' ' | b':'))
        .filter(|entry| !entry.is_empty())
        .all(|entry| !entry.contains(&b'/') || guest.is_file(Path::new(OsStr::from_bytes(entry))))
}

fn lookup<'a>(environment: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
    environment
        .iter()
        .find(|(existing, _)| existing == name)
        .map(|(_, value)| value.as_os_str())
}

fn set(environment: &mut Vec<(OsString, OsString)>, name: &str, value: &str) {
    match environment
        .iter_mut()
        .find(|(existing, _)| existing == name)
    {
        Some((_, existing)) => *existing = value.into(),
        None => environment.push((name.into(), value.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    const PROCESSOR_TMPDIR: &str =
        "/data/user/0/com.acurast.processor.executor.sandbox.proot.core.canary/cache";
    const PROCESSOR_PRELOAD: &str = "/usr/local/lib/libgetifaddrs_override.so";

    /// A rootfs that holds exactly the paths it is told about.
    #[derive(Default)]
    struct FakeGuest {
        writable_directories: BTreeSet<PathBuf>,
        read_only_directories: BTreeSet<PathBuf>,
        files: BTreeSet<PathBuf>,
        created: RefCell<Vec<(PathBuf, u32)>>,
    }

    impl FakeGuest {
        fn with_tmp() -> Self {
            let mut guest = Self::default();
            guest.writable_directories.insert("/tmp".into());
            guest
        }
    }

    impl GuestFilesystem for FakeGuest {
        fn is_writable_directory(&self, path: &Path) -> bool {
            self.writable_directories.contains(path)
                || self
                    .created
                    .borrow()
                    .iter()
                    .any(|(created, _)| created == path)
        }

        fn is_file(&self, path: &Path) -> bool {
            self.files.contains(path)
        }

        fn is_directory(&self, path: &Path) -> bool {
            self.is_writable_directory(path) || self.read_only_directories.contains(path)
        }

        fn create_sticky_directory(&self, path: &Path) -> io::Result<()> {
            self.created.borrow_mut().push((path.into(), 0o1777));
            Ok(())
        }
    }

    fn env_of(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()))
            .collect()
    }

    fn nothing_signed(_: &str) -> bool {
        false
    }

    fn value<'a>(environment: &'a [(OsString, OsString)], name: &str) -> Option<&'a str> {
        lookup(environment, name).and_then(OsStr::to_str)
    }

    fn guest_valid() -> Vec<(OsString, OsString)> {
        env_of(&[("PATH", "/usr/bin:/bin"), ("HOME", "/home/customer")])
    }

    #[test]
    fn tmpdir_missing_in_the_guest_is_repointed_at_tmp() {
        let guest = FakeGuest::with_tmp();
        let mut inherited = guest_valid();
        inherited.push(("TMPDIR".into(), PROCESSOR_TMPDIR.into()));
        let (environment, changes) =
            normalize_customer_environment(inherited, nothing_signed, &guest);
        assert_eq!(value(&environment, TMPDIR), Some("/tmp"));
        assert_eq!(
            changes,
            [Normalization {
                name: TMPDIR,
                reason: NormalizationReason::DirectoryMissing
            }]
        );
        assert!(
            guest.created.borrow().is_empty(),
            "an existing /tmp is left alone"
        );
    }

    #[test]
    fn tmp_is_created_sticky_and_world_writable_when_the_rootfs_lacks_it() {
        let guest = FakeGuest::default();
        let (environment, _) = normalize_customer_environment(
            env_of(&[("TMPDIR", PROCESSOR_TMPDIR)]),
            nothing_signed,
            &guest,
        );
        assert_eq!(value(&environment, TMPDIR), Some("/tmp"));
        assert_eq!(*guest.created.borrow(), [(PathBuf::from("/tmp"), 0o1777)]);
    }

    #[test]
    fn tmpdir_on_an_existing_writable_directory_is_unchanged() {
        let mut guest = FakeGuest::with_tmp();
        guest.writable_directories.insert("/var/tmp".into());
        let mut inherited = guest_valid();
        inherited.push(("TMPDIR".into(), "/var/tmp".into()));
        let (environment, changes) =
            normalize_customer_environment(inherited.clone(), nothing_signed, &guest);
        assert_eq!(environment, inherited);
        assert!(changes.is_empty());
    }

    #[test]
    fn tmpdir_on_a_read_only_directory_is_repointed_at_tmp() {
        let mut guest = FakeGuest::with_tmp();
        guest.read_only_directories.insert("/sdcard".into());
        let (environment, changes) = normalize_customer_environment(
            env_of(&[("TMPDIR", "/sdcard")]),
            nothing_signed,
            &guest,
        );
        assert_eq!(value(&environment, TMPDIR), Some("/tmp"));
        assert_eq!(changes[0].reason, NormalizationReason::DirectoryNotWritable);
    }

    #[test]
    fn unset_tmpdir_stays_unset() {
        let (environment, changes) =
            normalize_customer_environment(guest_valid(), nothing_signed, &FakeGuest::with_tmp());
        assert_eq!(value(&environment, TMPDIR), None);
        assert!(changes.is_empty());
    }

    #[test]
    fn a_preload_object_missing_in_the_guest_is_removed() {
        let mut inherited = guest_valid();
        inherited.push(("LD_PRELOAD".into(), PROCESSOR_PRELOAD.into()));
        let (environment, changes) =
            normalize_customer_environment(inherited, nothing_signed, &FakeGuest::with_tmp());
        assert_eq!(value(&environment, LD_PRELOAD), None);
        assert_eq!(
            changes,
            [Normalization {
                name: LD_PRELOAD,
                reason: NormalizationReason::ObjectMissing
            }]
        );
    }

    #[test]
    fn a_preload_object_the_guest_can_load_is_kept() {
        let mut guest = FakeGuest::with_tmp();
        guest.files.insert(PROCESSOR_PRELOAD.into());
        let mut inherited = guest_valid();
        inherited.push(("LD_PRELOAD".into(), PROCESSOR_PRELOAD.into()));
        let (environment, changes) =
            normalize_customer_environment(inherited.clone(), nothing_signed, &guest);
        assert_eq!(environment, inherited);
        assert!(changes.is_empty());
    }

    #[test]
    fn one_missing_object_in_a_preload_list_removes_the_whole_list() {
        let mut guest = FakeGuest::with_tmp();
        guest.files.insert("/usr/lib/present.so".into());
        for list in [
            "/usr/lib/present.so:/usr/lib/missing.so",
            "/usr/lib/present.so /usr/lib/missing.so",
        ] {
            let (environment, changes) = normalize_customer_environment(
                env_of(&[("LD_PRELOAD", list), ("PATH", "/bin"), ("HOME", "/root")]),
                nothing_signed,
                &guest,
            );
            assert_eq!(value(&environment, LD_PRELOAD), None, "{list}");
            assert_eq!(changes.len(), 1, "{list}");
        }
        guest.files.insert("/usr/lib/missing.so".into());
        let (environment, changes) = normalize_customer_environment(
            env_of(&[
                ("LD_PRELOAD", "/usr/lib/present.so::/usr/lib/missing.so"),
                ("PATH", "/bin"),
                ("HOME", "/root"),
            ]),
            nothing_signed,
            &guest,
        );
        assert!(value(&environment, LD_PRELOAD).is_some());
        assert!(changes.is_empty());
    }

    #[test]
    fn a_bare_preload_name_is_left_to_the_loader_search_path() {
        let (environment, changes) = normalize_customer_environment(
            env_of(&[
                ("LD_PRELOAD", "libfoo.so"),
                ("PATH", "/bin"),
                ("HOME", "/root"),
            ]),
            nothing_signed,
            &FakeGuest::with_tmp(),
        );
        assert_eq!(value(&environment, LD_PRELOAD), Some("libfoo.so"));
        assert!(changes.is_empty());
    }

    #[test]
    fn path_gets_the_debian_default_when_unset_or_empty_and_is_kept_when_set() {
        let guest = FakeGuest::with_tmp();
        let (environment, changes) =
            normalize_customer_environment(env_of(&[("HOME", "/root")]), nothing_signed, &guest);
        assert_eq!(value(&environment, PATH), Some(DEFAULT_PATH));
        assert_eq!(changes[0].reason, NormalizationReason::Unset);

        let (environment, changes) = normalize_customer_environment(
            env_of(&[("PATH", ""), ("HOME", "/root")]),
            nothing_signed,
            &guest,
        );
        assert_eq!(value(&environment, PATH), Some(DEFAULT_PATH));
        assert_eq!(changes[0].reason, NormalizationReason::Empty);

        let (environment, changes) = normalize_customer_environment(
            env_of(&[("PATH", "/opt/bin"), ("HOME", "/root")]),
            nothing_signed,
            &guest,
        );
        assert_eq!(value(&environment, PATH), Some("/opt/bin"));
        assert!(changes.is_empty());
    }

    #[test]
    fn home_gets_root_when_unset_and_is_kept_when_set() {
        let guest = FakeGuest::with_tmp();
        let (environment, changes) =
            normalize_customer_environment(env_of(&[("PATH", "/bin")]), nothing_signed, &guest);
        assert_eq!(value(&environment, HOME), Some(DEFAULT_HOME));
        assert_eq!(
            changes,
            [Normalization {
                name: HOME,
                reason: NormalizationReason::Unset
            }]
        );

        for home in ["/home/customer", ""] {
            let (environment, changes) = normalize_customer_environment(
                env_of(&[("PATH", "/bin"), ("HOME", home)]),
                nothing_signed,
                &guest,
            );
            assert_eq!(value(&environment, HOME), Some(home));
            assert!(changes.is_empty());
        }
    }

    #[test]
    fn a_guest_valid_processor_environment_is_returned_unchanged() {
        let mut guest = FakeGuest::with_tmp();
        guest.files.insert(PROCESSOR_PRELOAD.into());
        let inherited = env_of(&[
            ("ANDROID_ROOT", "/system"),
            ("TMPDIR", "/tmp"),
            ("LD_PRELOAD", PROCESSOR_PRELOAD),
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/root"),
        ]);
        let (environment, changes) =
            normalize_customer_environment(inherited.clone(), nothing_signed, &guest);
        assert_eq!(environment, inherited);
        assert!(changes.is_empty());
        assert!(guest.created.borrow().is_empty());
    }

    #[test]
    fn names_the_signed_environment_sets_are_left_to_it() {
        let guest = FakeGuest::default();
        let inherited = env_of(&[
            ("TMPDIR", PROCESSOR_TMPDIR),
            ("LD_PRELOAD", PROCESSOR_PRELOAD),
        ]);
        let (environment, changes) = normalize_customer_environment(
            inherited.clone(),
            |name| [TMPDIR, LD_PRELOAD, PATH, HOME].contains(&name),
            &guest,
        );
        assert_eq!(environment, inherited);
        assert!(changes.is_empty());
        assert!(guest.created.borrow().is_empty());
    }

    #[test]
    fn every_change_is_recorded_in_rule_order() {
        let (_, changes) = normalize_customer_environment(
            env_of(&[
                ("TMPDIR", PROCESSOR_TMPDIR),
                ("LD_PRELOAD", PROCESSOR_PRELOAD),
            ]),
            nothing_signed,
            &FakeGuest::with_tmp(),
        );
        let names: Vec<_> = changes.iter().map(|change| change.name).collect();
        assert_eq!(names, [TMPDIR, LD_PRELOAD, PATH, HOME]);
    }

    #[test]
    fn process_filesystem_reads_the_real_tree() {
        let root = std::env::temp_dir().join(format!(
            "liskov-runtime-cargo-guest-fs-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let file = root.join("lib.so");
        std::fs::write(&file, b"").unwrap();
        let guest = ProcessFilesystem;
        assert!(guest.is_directory(&root));
        assert!(!guest.is_directory(&file));
        assert!(guest.is_writable_directory(&root));
        assert!(!guest.is_writable_directory(&file));
        assert!(!guest.is_writable_directory(&root.join("missing")));
        assert!(guest.is_file(&file));
        assert!(!guest.is_file(&root));

        let sticky = root.join("tmp");
        guest.create_sticky_directory(&sticky).unwrap();
        let mode = std::fs::metadata(&sticky).unwrap().permissions().mode();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(mode & 0o7777, 0o1777);
    }
}
