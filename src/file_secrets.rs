//! Private file installation before customer execution. Directory descriptors
//! and no-follow opens prevent a symlink from redirecting a declared path.
//! A failed group restores every prior file; deterministic staging names let
//! the next bootstrap recover an interrupted installation before starting work.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum FileSecretError {
    #[error("secret file destination is invalid")]
    InvalidPath,
    #[error("secret file installation failed")]
    Install,
    #[error("secret file rollback failed")]
    Rollback,
}

fn c_name(name: &str) -> Result<CString, FileSecretError> {
    CString::new(name).map_err(|_| FileSecretError::InvalidPath)
}

fn directory(parent: &File, name: &CString) -> Result<File, FileSecretError> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: parent is an owned live directory fd and name is NUL-terminated.
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        // SAFETY: same live directory and validated component; mode is private.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(FileSecretError::Install);
        }
        // SAFETY: the no-follow open also fences a racing symlink after mkdir.
        fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(FileSecretError::InvalidPath);
    }
    // SAFETY: openat returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn regular_file(parent: &File, name: &CString) -> Result<bool, FileSecretError> {
    // SAFETY: stat is plain C output storage; fstatat initializes it on success.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(FileSecretError::Install)
        };
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(FileSecretError::InvalidPath);
    }
    Ok(true)
}

fn rename(
    parent: &File,
    source: &CString,
    target: &CString,
    no_replace: bool,
) -> Result<(), FileSecretError> {
    // SAFETY: both names and the owned directory fd remain live across the call.
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            if no_replace {
                libc::RENAME_NOREPLACE
            } else {
                0
            },
        )
    };
    if result < 0 {
        Err(FileSecretError::Install)
    } else {
        Ok(())
    }
}

fn unlink(parent: &File, name: &CString) -> Result<(), FileSecretError> {
    // SAFETY: unlinkat removes the directory entry, never follows a symlink.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::NotFound
    {
        return Err(FileSecretError::Install);
    }
    Ok(())
}

struct PreparedFile {
    parent: File,
    destination: CString,
    staging: CString,
    backup: CString,
    staged: bool,
    backed_up: bool,
    committed: bool,
}

impl PreparedFile {
    fn prepare(root: &Path, path: &str) -> Result<Self, FileSecretError> {
        if !path.starts_with('/') || path.ends_with('/') || path.len() > 4096 {
            return Err(FileSecretError::InvalidPath);
        }
        let components = Path::new(path).components().collect::<Vec<_>>();
        if components.len() < 2
            || components
                .iter()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(FileSecretError::InvalidPath);
        }
        let mut parent = File::open(root).map_err(|_| FileSecretError::Install)?;
        for component in &components[1..components.len() - 1] {
            let Component::Normal(name) = component else {
                return Err(FileSecretError::InvalidPath);
            };
            parent = directory(
                &parent,
                &c_name(name.to_str().ok_or(FileSecretError::InvalidPath)?)?,
            )?;
        }
        let destination = c_name(
            components
                .last()
                .unwrap()
                .as_os_str()
                .to_str()
                .ok_or(FileSecretError::InvalidPath)?,
        )?;
        if destination.as_bytes().starts_with(b".liskov-secret-") {
            return Err(FileSecretError::InvalidPath);
        }
        let identity = hex::encode(Sha256::digest(path.as_bytes()));
        let staging = c_name(&format!(".liskov-secret-{identity}.pending"))?;
        let backup = c_name(&format!(".liskov-secret-{identity}.previous"))?;
        regular_file(&parent, &destination)?;
        if regular_file(&parent, &backup)? {
            rename(&parent, &backup, &destination, false)?;
        }
        if regular_file(&parent, &staging)? {
            unlink(&parent, &staging)?;
        }
        Ok(Self {
            parent,
            destination,
            staging,
            backup,
            staged: false,
            backed_up: false,
            committed: false,
        })
    }

    fn write(&mut self, value: &[u8]) -> Result<(), FileSecretError> {
        // SAFETY: live directory/name; exclusive, no-follow creation of a private file.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.staging.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(FileSecretError::Install);
        }
        self.staged = true;
        // SAFETY: openat returned a fresh descriptor owned by this File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(value)
            .and_then(|()| file.sync_all())
            .map_err(|_| FileSecretError::Install)
    }

    fn commit(&mut self) -> Result<(), FileSecretError> {
        if regular_file(&self.parent, &self.destination)? {
            rename(&self.parent, &self.destination, &self.backup, true)?;
            self.backed_up = true;
        }
        rename(&self.parent, &self.staging, &self.destination, false)?;
        self.staged = false;
        self.committed = true;
        self.parent.sync_all().map_err(|_| FileSecretError::Install)
    }

    fn rollback(&mut self) -> Result<(), FileSecretError> {
        if self.committed {
            unlink(&self.parent, &self.destination)?;
        }
        if self.backed_up {
            rename(&self.parent, &self.backup, &self.destination, false)?;
        }
        if self.staged {
            unlink(&self.parent, &self.staging)?;
        }
        self.parent
            .sync_all()
            .map_err(|_| FileSecretError::Rollback)
    }
}

/// Install the whole file group. Caller commits its environment map only after
/// this returns success, then invokes the customer command through the supervisor.
pub fn install_secret_files(files: &BTreeMap<String, String>) -> Result<(), FileSecretError> {
    install_at(Path::new("/"), files, |_| Ok(()))
}

pub(crate) fn install_at(
    root: &Path,
    files: &BTreeMap<String, String>,
    before_commit: impl Fn(usize) -> Result<(), FileSecretError>,
) -> Result<(), FileSecretError> {
    let mut prepared = Vec::with_capacity(files.len());
    let outcome = (|| {
        for (path, value) in files {
            prepared.push(PreparedFile::prepare(root, path)?);
            prepared.last_mut().unwrap().write(value.as_bytes())?;
        }
        for (index, file) in prepared.iter_mut().enumerate() {
            before_commit(index)?;
            file.commit()?;
        }
        Ok(())
    })();
    if let Err(error) = outcome {
        let mut rollback_failed = false;
        for file in prepared.iter_mut().rev() {
            rollback_failed |= file.rollback().is_err();
        }
        return Err(if rollback_failed {
            FileSecretError::Rollback
        } else {
            error
        });
    }
    for file in prepared {
        if file.backed_up {
            unlink(&file.parent, &file.backup)?;
        }
        file.parent
            .sync_all()
            .map_err(|_| FileSecretError::Install)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "file_secrets_tests.rs"]
mod tests;
