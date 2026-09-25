//! The raw collector's only way to touch the device: bounded file reads,
//! directory listings and four syscalls. Production reads the live system;
//! tests substitute a fixture tree shaped like the probe capture.

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use super::super::{FileReadFailure, classify_file_error};

/// More entries than any listed directory holds on a handset.
const MAX_LISTED_ENTRIES: usize = 4_096;

/// `statvfs` block counts for the guest root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatvfsReading {
    pub(crate) blocks: u64,
    pub(crate) free_blocks: u64,
    pub(crate) available_blocks: u64,
    pub(crate) fragment_size: u64,
}

pub trait HardwareSource: Send + Sync {
    /// One file of at most `cap` bytes; a larger one is `TooLarge`. A final
    /// symlink is not followed.
    fn read(&self, path: &str, cap: usize) -> Result<Vec<u8>, FileReadFailure>;
    /// The entry names of one directory, in no particular order.
    fn list(&self, path: &str) -> Result<Vec<String>, FileReadFailure>;
    /// `uname` release and machine, or `None` when the call fails.
    fn uname(&self) -> Option<(Vec<u8>, Vec<u8>)>;
    /// The uid the guest reports for itself, as `id -u` would.
    fn guest_uid(&self) -> u64;
    fn guest_root_statvfs(&self) -> Result<StatvfsReading, FileReadFailure>;
    /// `(major, minor)` of the device that holds the guest root.
    fn guest_root_device(&self) -> Result<(u64, u64), FileReadFailure>;
}

pub struct SystemHardwareSource;

impl HardwareSource for SystemHardwareSource {
    fn read(&self, path: &str, cap: usize) -> Result<Vec<u8>, FileReadFailure> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(classify_file_error)?;
        // Sysfs and proc files report no length; the cap is enforced on the
        // bytes actually read.
        let bounded = u64::try_from(cap)
            .ok()
            .and_then(|cap| cap.checked_add(1))
            .ok_or(FileReadFailure::TooLarge)?;
        let mut bytes = Vec::new();
        file.take(bounded)
            .read_to_end(&mut bytes)
            .map_err(classify_file_error)?;
        if bytes.len() > cap {
            return Err(FileReadFailure::TooLarge);
        }
        Ok(bytes)
    }

    fn list(&self, path: &str) -> Result<Vec<String>, FileReadFailure> {
        Ok(std::fs::read_dir(path)
            .map_err(classify_file_error)?
            .take(MAX_LISTED_ENTRIES)
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect())
    }

    fn uname(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        // SAFETY: uname initializes the complete utsname on success.
        let mut name = unsafe { std::mem::zeroed::<libc::utsname>() };
        // SAFETY: `name` points to writable storage for one utsname.
        if unsafe { libc::uname(&mut name) } != 0 {
            return None;
        }
        // SAFETY: successful uname returns nul-terminated arrays.
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
        // SAFETY: as above.
        let machine = unsafe { CStr::from_ptr(name.machine.as_ptr()) };
        Some((release.to_bytes().to_vec(), machine.to_bytes().to_vec()))
    }

    fn guest_uid(&self) -> u64 {
        // SAFETY: getuid cannot fail and touches no memory.
        u64::from(unsafe { libc::getuid() })
    }

    fn guest_root_statvfs(&self) -> Result<StatvfsReading, FileReadFailure> {
        // SAFETY: statvfs fills the zeroed struct on success.
        let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
        // SAFETY: the path is a nul-terminated literal and `stat` is writable.
        if unsafe { libc::statvfs(c"/".as_ptr(), &mut stat) } != 0 {
            return Err(classify_file_error(std::io::Error::last_os_error()));
        }
        #[allow(clippy::useless_conversion)]
        let widen = |value| u64::try_from(value).map_err(|_| FileReadFailure::Unavailable);
        let fragment_size = match widen(stat.f_frsize)? {
            0 => widen(stat.f_bsize)?,
            size => size,
        };
        Ok(StatvfsReading {
            blocks: widen(stat.f_blocks)?,
            free_blocks: widen(stat.f_bfree)?,
            available_blocks: widen(stat.f_bavail)?,
            fragment_size,
        })
    }

    fn guest_root_device(&self) -> Result<(u64, u64), FileReadFailure> {
        let device = std::fs::metadata("/").map_err(classify_file_error)?.dev();
        Ok(split_device(device))
    }
}

/// glibc's `gnu_dev_major` / `gnu_dev_minor` encoding, which musl shares.
pub(super) fn split_device(device: u64) -> (u64, u64) {
    let major = ((device >> 32) & 0xffff_f000) | ((device >> 8) & 0x0000_0fff);
    let minor = ((device >> 12) & 0xffff_ff00) | (device & 0x0000_00ff);
    (major, minor)
}
