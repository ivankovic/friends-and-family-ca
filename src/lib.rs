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
//! Friends and Family CA: a small certificate authority for mutual-TLS client certificates.
//!
//! One person runs it, over SSH, in a terminal UI: they create the CA, decide which of the web
//! server's sites demand a client certificate, and issue and revoke certificates for the people
//! and devices allowed in. The people themselves never see the terminal: they collect their
//! certificate from a small web page, through a one-time invite link or by logging in.

pub mod bundle;
pub mod ca;
pub mod config;
pub mod files;
pub mod invite;
pub mod ledger;
pub mod nginx;
pub mod serve;
pub mod store;
pub mod timer;
pub mod tui;
pub mod users;

/// What stands in for `systemd-creds` in a test, as a script written into `dir`: it takes the
/// same arguments, and what it encrypts only it decrypts, under the same name. Returns the
/// command to run it.
#[cfg(test)]
pub(crate) fn test_encrypter(dir: &std::path::Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("creds.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         case \"$1\" in\n\
         encrypt) echo \"encrypted for a test, $2\"; base64 -w0; echo;;\n\
         decrypt) read -r header\n\
           [ \"$header\" = \"encrypted for a test, $2\" ] || { echo 'not encrypted here' >&2; exit 1; }\n\
           base64 -d;;\n\
         *) exit 2;;\n\
         esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script.display().to_string()
}

/// A temporary folder for a test, in memory where the system has `/dev/shm`. [`store::Store`]
/// syncs every write to disk, which on a busy disk makes a test that issues a few certificates
/// take a second; on tmpfs a sync costs nothing. It is its owner's alone, as the folder the CA
/// lives in must be, whatever the umask. A `/dev/shm` mounted `noexec` (a container's) is passed
/// over: some tests run scripts they write there.
#[cfg(test)]
pub(crate) fn test_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let shm = std::path::Path::new("/dev/shm");
    let mut builder = tempfile::Builder::new();
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    let executable = || {
        // SAFETY: statvfs fills the zeroed struct it is given from a NUL-terminated path.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c"/dev/shm".as_ptr(), &mut stat) };
        rc == 0 && stat.f_flag & libc::ST_NOEXEC == 0
    };
    if shm.is_dir() && executable() {
        builder.tempdir_in(shm).unwrap()
    } else {
        builder.tempdir().unwrap()
    }
}
