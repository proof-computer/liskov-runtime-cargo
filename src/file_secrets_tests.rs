use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Root(std::path::PathBuf);
impl Root {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("liskov-e287-{}-{name}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn files_keep_exact_utf8_bytes_private_permissions_and_restart_behavior() {
    let root = Root::new("exact");
    let files = BTreeMap::from([
        ("/run/secrets/config".into(), "  first\nsecond\n".into()),
        ("/run/secrets/empty".into(), String::new()),
    ]);
    install_at(&root.0, &files, |_| Ok(())).unwrap();
    for (path, value) in &files {
        let target = root.0.join(path.trim_start_matches('/'));
        assert_eq!(std::fs::read(&target).unwrap(), value.as_bytes());
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    install_at(&root.0, &files, |_| Ok(())).unwrap();
    assert_eq!(
        std::fs::read_dir(root.0.join("run/secrets"))
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn failure_mid_commit_restores_every_previous_file_and_removes_new_files() {
    let root = Root::new("rollback");
    std::fs::write(root.0.join("a"), "old-a").unwrap();
    let files = BTreeMap::from([("/a".into(), "new-a".into()), ("/b".into(), "new-b".into())]);
    assert!(
        install_at(&root.0, &files, |index| if index == 1 {
            Err(FileSecretError::Install)
        } else {
            Ok(())
        })
        .is_err()
    );
    assert_eq!(std::fs::read(root.0.join("a")).unwrap(), b"old-a");
    assert!(!root.0.join("b").exists());
    assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
}

#[test]
fn next_bootstrap_recovers_an_interrupted_group_before_reinstalling() {
    let root = Root::new("restart");
    std::fs::write(root.0.join("a"), "old-a").unwrap();
    let mut first = PreparedFile::prepare(&root.0, "/a").unwrap();
    first.write(b"new-a").unwrap();
    let mut second = PreparedFile::prepare(&root.0, "/b").unwrap();
    second.write(b"new-b").unwrap();
    first.commit().unwrap();
    // Simulate loss of the process, leaving its on-disk recovery material.
    drop((first, second));
    let files = BTreeMap::from([("/a".into(), "new-a".into()), ("/b".into(), "new-b".into())]);
    install_at(&root.0, &files, |_| Ok(())).unwrap();
    assert_eq!(std::fs::read(root.0.join("a")).unwrap(), b"new-a");
    assert_eq!(std::fs::read(root.0.join("b")).unwrap(), b"new-b");
    assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 2);
}

#[test]
fn traversal_and_symlinks_cannot_redirect_secret_writes() {
    let root = Root::new("paths");
    std::fs::create_dir(root.0.join("outside")).unwrap();
    std::fs::write(root.0.join("outside/sentinel"), "unchanged").unwrap();
    symlink("outside", root.0.join("alias")).unwrap();
    symlink("outside/sentinel", root.0.join("link")).unwrap();
    for path in ["relative", "/", "/../escape", "/alias/secret", "/link"] {
        assert!(
            install_at(
                &root.0,
                &BTreeMap::from([(path.into(), "private".into())]),
                |_| Ok(())
            )
            .is_err(),
            "{path}"
        );
    }
    assert_eq!(
        std::fs::read(root.0.join("outside/sentinel")).unwrap(),
        b"unchanged"
    );
    assert!(!root.0.join("outside/secret").exists());
}
