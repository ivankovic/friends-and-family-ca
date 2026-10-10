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
//! What the end-to-end tests share: a CA folder, the real `ffca` binary, and `openssl`.

#![allow(dead_code)] // Each test binary uses its own part of this.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A temporary folder in memory where the system has `/dev/shm`: the CA syncs every write, and on
/// a busy disk that makes these tests many times slower for nothing they check.
pub fn test_dir() -> tempfile::TempDir {
    match Path::new("/dev/shm").is_dir() {
        true => tempfile::tempdir_in("/dev/shm").unwrap(),
        false => tempfile::tempdir().unwrap(),
    }
}

/// A CA state folder and an output folder, and `ffca` pointed at them.
pub struct Ffca {
    pub dir: tempfile::TempDir,
    pub state: PathBuf,
    pub out: PathBuf,
}

impl Ffca {
    pub fn new() -> Ffca {
        let dir = test_dir();
        let state = dir.path().join("state");
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        Ffca { dir, state, out }
    }

    /// A CA called "Test family", created with `ffca init`.
    pub fn initialised() -> Ffca {
        let ffca = Ffca::new();
        ffca.ok(&["init", "--name", "Test family"]);
        ffca
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ffca"));
        command
            .args(args)
            .env("FFCA_STATE_DIR", &self.state)
            .current_dir(&self.out);
        command
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("ffca runs")
    }

    /// Runs `ffca args`, which must succeed; returns what it printed.
    pub fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "ffca {} failed with {}:\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// Runs `ffca args`, which must fail; returns its exit code and what it printed to stderr.
    pub fn fails(&self, args: &[&str]) -> (i32, String) {
        let output = self.run(args);
        assert!(
            !output.status.success(),
            "ffca {} succeeded:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout)
        );
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8(output.stderr).unwrap(),
        )
    }

    pub fn ca_certificate(&self) -> PathBuf {
        self.state.join("ca.crt")
    }

    pub fn crl(&self) -> PathBuf {
        self.state.join("crl.pem")
    }

    /// The serial `ffca issue` printed: "Issued <serial> to ...".
    pub fn serial(issued: &str) -> String {
        issued
            .split_whitespace()
            .nth(1)
            .expect("Issued <serial> to ...")
            .to_owned()
    }
}

/// `openssl verify` with the CA and its CRL, for a client: what nginx's OpenSSL decides.
pub fn openssl_verify(ffca: &Ffca, certificate: &Path) -> Result<(), String> {
    let output = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(ffca.ca_certificate())
        .arg("-crl_check")
        .arg("-CRLfile")
        .arg(ffca.crl())
        .args(["-purpose", "sslclient"])
        .arg(certificate)
        .output()
        .expect("these tests need the `openssl` command");
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(())
    } else {
        Err(text)
    }
}

/// A key and a signing request made with `openssl req`, as on an agent's own machine.
pub fn openssl_request(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let request = dir.join(format!("{name}.csr"));
    let output = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
        ])
        .args(["-subj", "/CN=whatever"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&request)
        .output()
        .expect("these tests need the `openssl` command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (key, request)
}
