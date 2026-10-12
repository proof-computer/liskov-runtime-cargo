//! Descriptor-owned custody of the guest-private discovery files.
use crate::customer_environment::{GuestFilesystem, ProcessFilesystem};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub(super) struct Parent {
    path: PathBuf,
    directory: File,
}
pub(super) struct Directory {
    parent: Parent,
    name: CString,
    directory: File,
}

fn basename(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid private basename",
        ));
    }
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private basename"))
}
fn open_at(parent: &File, name: &CString, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: parent is an owned live descriptor; name is a NUL-terminated basename.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new owned descriptor, transferred exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn unlink_at(parent: &File, name: &CString, flags: i32) -> io::Result<()> {
    // SAFETY: live owned descriptor and NUL-terminated basename; no pathname traversal.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}
fn same_directory(left: &File, right: &File) -> io::Result<bool> {
    let a = left.metadata()?;
    let b = right.metadata()?;
    Ok(a.is_dir() && b.is_dir() && a.dev() == b.dev() && a.ino() == b.ino())
}
fn changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "guest discovery custody changed",
    )
}

impl Parent {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || fs::canonicalize(path)? != path
            || !ProcessFilesystem.is_writable_directory(path)
        {
            return Err(changed());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let guard = Self {
            path: path.into(),
            directory,
        };
        guard.validate()?;
        Ok(guard)
    }
    pub(super) fn allocate(self, name: &str) -> io::Result<Directory> {
        self.validate()?;
        let name = basename(name)?;
        // SAFETY: owned parent and basename remain alive. EEXIST refuses collisions.
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = match open_at(
            &self.directory,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(directory) => directory,
            Err(error) => {
                let _ = unlink_at(&self.directory, &name, libc::AT_REMOVEDIR);
                return Err(error);
            }
        };
        let guard = Directory {
            parent: self,
            name,
            directory,
        };
        guard
            .directory
            .set_permissions(fs::Permissions::from_mode(0o700))?;
        guard.validate()?;
        Ok(guard)
    }
    fn validate(&self) -> io::Result<()> {
        // Root/PRoot can pass access(W_OK) despite absent write bits. Helper
        // custody still refuses a parent explicitly configured without writes.
        if self.directory.metadata()?.permissions().mode() & 0o222 == 0 {
            return Err(changed());
        }
        if fs::canonicalize(&self.path)? != self.path {
            return Err(changed());
        }
        let current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        if !same_directory(&self.directory, &current)? {
            return Err(changed());
        }
        Ok(())
    }
}
impl Directory {
    pub(super) fn path(&self) -> PathBuf {
        self.parent
            .path
            .join(self.name.to_str().expect("generated ASCII basename"))
    }
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.directory.metadata()?.permissions().mode() & 0o7777 != 0o700 {
            return Err(changed());
        }
        self.parent.validate()?;
        let current = open_at(
            &self.parent.directory,
            &self.name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        if !same_directory(&self.directory, &current)? {
            return Err(changed());
        }
        Ok(())
    }
    pub(super) fn exists(&self, name: &str) -> io::Result<bool> {
        self.validate()?;
        let name = basename(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat is valid writable storage; descriptor and basename are live.
        let status = unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(error);
        }
        self.validate()?;
        Ok(true)
    }
    pub(super) fn read(&self, name: &str) -> io::Result<File> {
        self.validate()?;
        let file = open_at(
            &self.directory,
            &basename(name)?,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        self.validate()?;
        Ok(file)
    }
    pub(super) fn create(&self, name: &str) -> io::Result<File> {
        self.validate()?;
        let file = open_at(
            &self.directory,
            &basename(name)?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        self.validate()?;
        Ok(file)
    }
    pub(super) fn remove(&self, name: &str) -> io::Result<()> {
        self.validate()?;
        unlink_at(&self.directory, &basename(name)?, 0)?;
        self.validate()
    }
    pub(super) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.validate()?;
        let from = basename(from)?;
        let to = basename(to)?;
        // SAFETY: both entries are basenames in the same owned directory.
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                from.as_ptr(),
                self.directory.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.validate()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Cleanup touches only known entries of the owned descriptor, even when
        // the exported path has been substituted. Never recursively adopt a tree.
        for name in ["advertisement.json", "directory.json", "next-direct.json"] {
            let _ = unlink_at(
                &self.directory,
                &basename(name).expect("constant basename"),
                0,
            );
        }
        // A replacement leaf in the original parent belongs to somebody else.
        if let Ok(current) = open_at(
            &self.parent.directory,
            &self.name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            if same_directory(&self.directory, &current).unwrap_or(false) {
                if let Err(error) =
                    unlink_at(&self.parent.directory, &self.name, libc::AT_REMOVEDIR)
                {
                    eprintln!("liskov direct discovery cleanup failed: {:?}", error.kind());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn parent() -> PathBuf {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).unwrap();
        let path = std::env::temp_dir().join(format!("11fh-parent-{}", hex::encode(bytes)));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn unavailable_and_symlinked_parents_and_collisions_are_refused() {
        let path = parent();
        assert!(Parent::open(&path.join("missing")).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(Parent::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = path.with_extension("link");
        symlink(&path, &linked).unwrap();
        assert!(Parent::open(&linked).is_err());
        fs::remove_file(linked).unwrap();
        fs::create_dir(path.join("collision")).unwrap();
        fs::write(path.join("collision/sentinel"), b"foreign").unwrap();
        assert!(Parent::open(&path).unwrap().allocate("collision").is_err());
        assert_eq!(
            fs::read(path.join("collision/sentinel")).unwrap(),
            b"foreign"
        );
        fs::remove_dir_all(path).unwrap();
    }
}
