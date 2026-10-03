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
//! The hourly timer that keeps the CA current without anyone at the keyboard: `ffca crl-refresh`
//! re-signs the revocation list long before it expires, records collected invites, revokes the
//! certificates of invites that expired uncollected, and hands the result to nginx.
//!
//! It is a systemd service and timer, which the CA tab writes and enables, naming this very binary
//! and state folder, so that what runs hourly is what the administrator set up.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nginx;
use crate::store::{PUBLIC, Store};

pub const SERVICE: &str = "ffca-crl-refresh.service";
pub const TIMER: &str = "ffca-crl-refresh.timer";
/// Where systemd looks for units an administrator added.
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// The two units, as file name and text, running `binary` on the CA in `state`.
pub fn units(binary: &Path, state: &Path) -> [(&'static str, String); 2] {
    let quote = |path: &Path| {
        format!(
            "\"{}\"",
            path.display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        )
    };
    [
        (
            SERVICE,
            format!(
                "# Written by Friends and Family CA.\n\
                 [Unit]\n\
                 Description=Friends and Family CA: re-sign the revocation list, tidy invites, reload nginx\n\n\
                 [Service]\n\
                 Type=oneshot\n\
                 Environment=FFCA_STATE_DIR={state}\n\
                 ExecStart={binary} crl-refresh\n",
                state = quote(state),
                binary = quote(binary),
            ),
        ),
        (
            TIMER,
            "# Written by Friends and Family CA.\n\
             [Unit]\n\
             Description=Friends and Family CA, hourly\n\n\
             [Timer]\n\
             OnCalendar=hourly\n\
             RandomizedDelaySec=5min\n\
             Persistent=true\n\n\
             [Install]\n\
             WantedBy=timers.target\n"
                .to_owned(),
        ),
    ]
}

/// Writes the units into `unit_dir` and enables the timer with `systemctl` (a command, split at
/// spaces, so that tests can stand in for it).
pub fn install(unit_dir: &Path, systemctl: &str, binary: &Path, state: &Path) -> Result<()> {
    let store = Store::new(unit_dir);
    for (name, text) in units(binary, state) {
        store.write(name, text.as_bytes(), PUBLIC)?;
    }
    nginx::run(&format!("{systemctl} daemon-reload"))?;
    nginx::run(&format!("{systemctl} enable --now {TIMER}"))?;
    Ok(())
}

/// Whether the timer runs: `systemctl is-active`'s answer, or why there is none.
pub fn state(systemctl: &str) -> String {
    match nginx::run(&format!("{systemctl} is-active {TIMER}")) {
        Ok(printed) => printed.trim().to_owned(),
        Err(error) => {
            let printed = format!("{error:#}");
            printed
                .lines()
                .last()
                .unwrap_or("not installed")
                .trim()
                .to_owned()
        }
    }
}

/// This binary, as the units should name it.
pub fn this_binary() -> Result<PathBuf> {
    std::env::current_exe().context("cannot tell where this ffca binary is")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_units_run_this_binary_on_this_ca_hourly() {
        let [(service, service_text), (timer, timer_text)] =
            units(Path::new("/usr/local/bin/ffca"), Path::new("/var/lib/ffca"));
        assert_eq!((service, timer), (SERVICE, TIMER));
        assert!(
            service_text.contains("ExecStart=\"/usr/local/bin/ffca\" crl-refresh\n"),
            "{service_text}"
        );
        assert!(
            service_text.contains("Environment=FFCA_STATE_DIR=\"/var/lib/ffca\"\n"),
            "{service_text}"
        );
        assert!(
            timer_text.contains("OnCalendar=hourly\n") && timer_text.contains("Persistent=true\n")
        );
    }

    #[test]
    fn install_writes_the_units_and_enables_the_timer() {
        let dir = crate::test_dir();
        let log = dir.path().join("systemctl");
        // A stand-in that records how it was called.
        let script = dir.path().join("systemctl.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        install(
            dir.path(),
            script.to_str().unwrap(),
            Path::new("/usr/local/bin/ffca"),
            Path::new("/var/lib/ffca"),
        )
        .unwrap();
        assert!(dir.path().join(SERVICE).exists() && dir.path().join(TIMER).exists());
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            format!("daemon-reload\nenable --now {TIMER}\n")
        );
    }

    #[test]
    fn the_state_is_systemctls_answer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_dir();
        for (name, body, expected) in [
            ("on.sh", "echo active", "active"),
            ("off.sh", "echo inactive; exit 3", "inactive"),
        ] {
            let script = dir.path().join(name);
            std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(state(script.to_str().unwrap()), expected);
        }
    }
}
