/*  This file is part of Friends and Family CA.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
//! The state folder: every file the CA keeps, one lock for all of them, and writes that land whole
//! or not at all.
//!
//! `ffca tui`, `ffca serve` and the `crl-refresh` timer run as separate processes against the same
//! folder. Every change takes [`Store::lock`], re-reads what it changes, and writes it back with
//! [`Store::write`], so two processes never lose each other's changes. The lock is an advisory
//! `flock` on a file of its own, released when the [`Lock`] is dropped or the process dies.
//!
//! A write goes to a temporary file in the same folder, is synced, and is renamed over the old
//! file, so a crash or a full disk leaves the previous version intact rather than half a ledger.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Owner read/write only: the CA key, and everything else in the folder that is nobody else's
/// business.
pub const PRIVATE: u32 = 0o600;
/// World-readable: certificates and the CRL, which are public by nature.
pub const PUBLIC: u32 = 0o644;

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

/// Held for as long as one change takes; dropping it releases the lock.
#[must_use = "the lock is released as soon as this is dropped"]
pub struct Lock {
    _file: File,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    /// Creates the folder, owner-only, if it does not exist yet. An existing folder keeps its
    /// permissions: tightening them silently could break a deliberate setup, such as a group that
    /// `ffca serve` reads invites through.
    pub fn create_dir(&self) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))
    }

    /// Creates a subfolder, owner-only, if it does not exist yet.
    pub fn create_subdir(&self, name: &str) -> Result<()> {
        let path = self.path(name);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("cannot create {}", path.display()))
    }

    /// Blocks until no other process is changing the folder.
    pub fn lock(&self) -> Result<Lock> {
        let path = self.path(".lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(PRIVATE)
            .open(&path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        file.lock()
            .with_context(|| format!("cannot lock {}", path.display()))?;
        Ok(Lock { _file: file })
    }

    pub fn read(&self, name: &str) -> Result<String> {
        let path = self.path(name);
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))
    }

    /// Replaces `name` with `contents` atomically, with permissions `mode`.
    pub fn write(&self, name: &str, contents: &[u8], mode: u32) -> Result<()> {
        let path = self.path(name);
        let parent = path.parent().unwrap_or(&self.dir);
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or(name);
        let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(mode)
                .open(&temporary)?;
            // `mode` above is filtered through the umask; this is not.
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.write_all(contents)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.with_context(|| format!("cannot write {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn create_dir_is_owner_only() {
        let parent = crate::test_dir();
        let store = Store::new(parent.path().join("state"));
        store.create_dir().unwrap();
        assert_eq!(mode_of(store.dir()), 0o700);
    }

    #[test]
    fn write_replaces_contents_and_sets_the_mode() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path());
        store.write("key", b"first", PRIVATE).unwrap();
        store.write("key", b"second", PRIVATE).unwrap();
        assert_eq!(store.read("key").unwrap(), "second");
        assert_eq!(mode_of(&store.path("key")), 0o600);
        store.write("cert", b"public", PUBLIC).unwrap();
        assert_eq!(mode_of(&store.path("cert")), 0o644);
    }

    #[test]
    fn write_leaves_no_temporary_file_behind() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path());
        store.write("ledger.toml", b"x", PRIVATE).unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["ledger.toml"]);
    }

    #[test]
    fn write_into_a_missing_folder_fails_and_says_where() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path().join("missing"));
        let error = store.write("ledger.toml", b"x", PRIVATE).unwrap_err();
        assert!(
            format!("{error:#}").contains("missing/ledger.toml"),
            "{error:#}"
        );
    }

    #[test]
    fn a_second_lock_waits_for_the_first() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path());
        let first = store.lock().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let waiter = {
            let store = store.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let _second = store.lock().unwrap();
                store.read("marker").unwrap()
            })
        };
        barrier.wait();
        // The waiter is blocked on the lock; what it reads proves it got in only after this write.
        thread::sleep(Duration::from_millis(50));
        store
            .write("marker", b"written under the first lock", PRIVATE)
            .unwrap();
        drop(first);
        assert_eq!(waiter.join().unwrap(), "written under the first lock");
    }
}
