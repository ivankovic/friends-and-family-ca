/*  This file is part of Friends and Family CA.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
//! Writing an issued certificate, and the key the CA generated for it, to files.
//!
//! The files are created before the CA issues anything, so that a certificate never reaches the
//! ledger without its key reaching someone: a certificate nobody holds is valid and useless.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use time::{Duration, OffsetDateTime};

use crate::ca::{Ca, Issued, Key};
use crate::ledger::Holder;

/// Issues a certificate into `<out>/<name>.crt`, and `.key` if the CA generates the key. The files
/// are created before the CA issues anything: a certificate in the ledger whose key was never
/// written is a valid certificate nobody holds.
pub fn issue_to_files(
    ca: &Ca,
    holder: Holder,
    key: Key,
    out: &Path,
    now: OffsetDateTime,
    validity: Duration,
) -> Result<(Issued, Vec<PathBuf>)> {
    let base = out.join(match holder {
        Holder::Device { person, device } => file_stem(&format!("{person} {device}")),
        Holder::Agent(agent) => file_stem(agent),
    });
    let mut paths = vec![base.with_extension("crt")];
    if matches!(key, Key::Generate) {
        paths.push(base.with_extension("key"));
    }
    // Refusals about the holder (retired, a name of the other kind) come before refusals about
    // files; the CA checks again, under its lock, when it issues.
    ca.ledger()?.place_for_issue(holder)?;
    let mut files = Vec::new();
    let written = (|| {
        files.push(create_new(&paths[0], 0o644)?);
        if let Some(key_path) = paths.get(1) {
            files.push(create_new(key_path, 0o600)?);
        }
        let issued = ca.issue(holder, key, now, validity)?;
        files[0]
            .write_all(issued.certificate_pem.as_bytes())
            .with_context(|| format!("cannot write {}", paths[0].display()))?;
        if let (Some(file), Some(key_pem)) = (files.get_mut(1), &issued.key_pem) {
            file.write_all(key_pem.as_bytes())
                .with_context(|| format!("cannot write {}", paths[1].display()))?;
        }
        // On the disk before the command says so: the ledger already holds the certificate.
        for (file, path) in files.iter().zip(&paths) {
            file.sync_all()
                .with_context(|| format!("cannot write {}", path.display()))?;
        }
        File::open(out)
            .and_then(|folder| folder.sync_all())
            .with_context(|| format!("cannot write {}", out.display()))?;
        Ok(issued)
    })();
    match written {
        Ok(issued) => Ok((issued, paths)),
        Err(error) => {
            // Only the files this call created: the one that was in the way is someone else's.
            for path in paths.iter().take(files.len()) {
                let _ = std::fs::remove_file(path);
            }
            Err(error)
        }
    }
}

/// `Anna work laptop` becomes `anna-work-laptop`: a file name that needs no quoting.
pub fn file_stem(name: &str) -> String {
    let mut stem = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            stem.push(c);
        } else if !stem.is_empty() && !stem.ends_with('-') {
            stem.push('-');
        }
    }
    match stem.trim_end_matches('-') {
        // A name of emoji or punctuation only: an empty stem would make `<out>/.crt`, or worse,
        // a file beside the folder.
        "" => "certificate".to_owned(),
        stem => stem.to_owned(),
    }
}

/// Creates a file that must not exist yet: a key is never silently replaced.
fn create_new(path: &Path, mode: u32) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::store::Store;
    use std::os::unix::fs::PermissionsExt;

    fn ca(dir: &Path) -> Ca {
        Ca::create(
            &Store::new(dir.join("state")),
            "Test",
            OffsetDateTime::now_utc(),
            ca::DEFAULT_CA_VALIDITY,
        )
        .unwrap()
    }

    const ANNA_PHONE: Holder = Holder::Device {
        person: "Anna",
        device: "phone",
    };

    #[test]
    fn file_stem_needs_no_quoting() {
        assert_eq!(file_stem("Anna work laptop"), "anna-work-laptop");
        assert_eq!(
            file_stem("Ana Marija iPhone (old)"),
            "ana-marija-iphone-old"
        );
        assert_eq!(file_stem("Čedo ../phone"), "čedo-phone");
        assert_eq!(file_stem("😀"), "certificate", "never an empty stem");
    }

    #[test]
    fn issue_to_files_writes_the_certificate_and_a_private_key() {
        let dir = crate::test_dir();
        let ca = ca(dir.path());
        let now = OffsetDateTime::now_utc();
        let (issued, paths) = issue_to_files(
            &ca,
            ANNA_PHONE,
            Key::Generate,
            dir.path(),
            now,
            ca::DEFAULT_CLIENT_VALIDITY,
        )
        .unwrap();
        assert_eq!(
            paths,
            [
                dir.path().join("anna-phone.crt"),
                dir.path().join("anna-phone.key")
            ]
        );
        assert_eq!(
            std::fs::read_to_string(&paths[0]).unwrap(),
            issued.certificate_pem
        );
        assert_eq!(
            Some(std::fs::read_to_string(&paths[1]).unwrap()),
            issued.key_pem
        );
        let mode = std::fs::metadata(&paths[1]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn issue_to_files_writes_no_key_for_a_signing_request() {
        let dir = crate::test_dir();
        let ca = ca(dir.path());
        let key = rcgen::KeyPair::generate().unwrap();
        let request = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let now = OffsetDateTime::now_utc();
        let (issued, paths) = issue_to_files(
            &ca,
            Holder::Agent("Backup job"),
            Key::Request(&request),
            dir.path(),
            now,
            ca::DEFAULT_CLIENT_VALIDITY,
        )
        .unwrap();
        assert_eq!(paths, [dir.path().join("backup-job.crt")]);
        assert!(issued.key_pem.is_none());
    }

    #[test]
    fn issue_to_files_issues_nothing_when_a_file_is_in_the_way() {
        let dir = crate::test_dir();
        let ca = ca(dir.path());
        let now = OffsetDateTime::now_utc();
        for existing in ["anna-phone.crt", "anna-phone.key"] {
            let path = dir.path().join(existing);
            std::fs::write(&path, "someone else's").unwrap();
            let result = issue_to_files(
                &ca,
                ANNA_PHONE,
                Key::Generate,
                dir.path(),
                now,
                ca::DEFAULT_CLIENT_VALIDITY,
            );
            assert!(result.is_err());
            assert_eq!(
                ca.ledger().unwrap().certificates().count(),
                0,
                "issued despite {existing}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "someone else's");
            std::fs::remove_file(&path).unwrap();
            let left: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(left, ["state"], "left a file behind");
        }
    }
}
