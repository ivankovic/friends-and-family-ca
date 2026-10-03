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
//! `ffca tui` on a real terminal: the event loop, raw mode and the alternate screen, which the
//! in-process UI tests (a `TestBackend`) never reach. util-linux `script` provides the
//! pseudo-terminal, as omnidiff's terminal tests do, and the `vt100` crate plays the terminal: the
//! UI redraws only the cells that change, so the screen exists only once the output is replayed.

#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::Ffca;

const TIMEOUT: Duration = Duration::from_secs(30);
const ROWS: u16 = 30;
const COLUMNS: u16 = 120;
/// Leaving the alternate screen: the terminal is handed back as it was.
const LEAVE_ALTERNATE_SCREEN: &str = "\u{1b}[?1049l";

/// `ffca tui` running under a pseudo-terminal, its output replayed on an emulated screen.
struct Terminal {
    child: Child,
    chunks: mpsc::Receiver<Vec<u8>>,
    output: Vec<u8>,
    screen: vt100::Parser,
}

impl Terminal {
    fn start(ffca: &Ffca) -> Terminal {
        Terminal::start_with(ffca, r#"tui --out "$OUT""#)
    }

    /// Runs `ffca <arguments>`, as a shell reads them.
    fn start_with(ffca: &Ffca, arguments: &str) -> Terminal {
        let mut child = Command::new("script")
            // -q: no banner, -f: flush every write, -e: exit with ffca's status, -c: the command.
            .args([
                "-qfec",
                &format!(r#"stty cols {COLUMNS} rows {ROWS}; exec "$FFCA" {arguments}"#),
                "/dev/null",
            ])
            .env("FFCA", env!("CARGO_BIN_EXE_ffca"))
            .env("FFCA_STATE_DIR", &ffca.state)
            .env("OUT", &ffca.out)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("util-linux `script` provides the pseudo-terminal; is it installed?");
        let mut stdout = child.stdout.take().unwrap();
        let (sender, chunks) = mpsc::channel();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(read) = stdout.read(&mut chunk) {
                if read == 0 || sender.send(chunk[..read].to_vec()).is_err() {
                    break;
                }
            }
        });
        Terminal {
            child,
            chunks,
            output: Vec::new(),
            screen: vt100::Parser::new(ROWS, COLUMNS, 0),
        }
    }

    /// What the terminal shows now.
    fn screen(&self) -> String {
        self.screen.screen().contents()
    }

    fn receive(&mut self, chunk: Vec<u8>) {
        self.screen.process(&chunk);
        self.output.extend(chunk);
    }

    /// Waits until the screen shows `expected`.
    fn wait_for(&mut self, expected: &str) {
        let deadline = Instant::now() + TIMEOUT;
        while !self.screen().contains(expected) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.chunks.recv_timeout(remaining) {
                Ok(chunk) => self.receive(chunk),
                Err(_) => {
                    let _ = self.child.kill();
                    panic!(
                        "no {expected:?} on the terminal; it shows:\n{}",
                        self.screen()
                    );
                }
            }
        }
    }

    fn send(&mut self, keys: &str) {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(keys.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Waits for ffca to exit; returns whether it succeeded and everything it wrote.
    fn finish(mut self) -> (bool, String) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            match self
                .chunks
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(chunk) => self.receive(chunk),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = self.child.kill();
                    panic!("ffca did not exit; it shows:\n{}", self.screen());
                }
            }
        }
        let status = self.child.wait().unwrap();
        (
            status.success(),
            String::from_utf8_lossy(&self.output).into_owned(),
        )
    }
}

#[test]
fn issuing_from_the_terminal_ui_writes_the_files_and_q_restores_the_terminal() {
    let ffca = Ffca::initialised();
    let mut terminal = Terminal::start(&ffca);
    terminal.wait_for("No one has a certificate yet");
    terminal.send("p");
    terminal.wait_for("New person");
    terminal.send("Anna\rphone\r");
    terminal.wait_for("Issued to Anna (phone)");
    terminal.send("\r");
    terminal.wait_for("● phone");
    terminal.send("q");

    let (success, output) = terminal.finish();
    assert!(success, "ffca tui failed:\n{}", output.escape_debug());
    assert!(
        output.contains(LEAVE_ALTERNATE_SCREEN),
        "the terminal was not restored"
    );
    assert!(ffca.out.join("anna-phone.crt").exists());
    assert!(ffca.out.join("anna-phone.key").exists());
    assert!(ffca.ok(&["list"]).contains("Anna"));
}

#[test]
fn control_c_inside_a_dialog_still_quits_cleanly() {
    let ffca = Ffca::initialised();
    let mut terminal = Terminal::start(&ffca);
    terminal.wait_for("Friends and Family CA");
    terminal.send("a");
    terminal.wait_for("New agent");
    terminal.send("\u{3}");
    let (success, output) = terminal.finish();
    assert!(success, "ffca tui failed:\n{}", output.escape_debug());
    assert!(
        output.contains(LEAVE_ALTERNATE_SCREEN),
        "the terminal was not restored"
    );
}

#[test]
fn changes_made_elsewhere_appear_without_a_key_press() {
    let ffca = Ffca::initialised();
    let mut terminal = Terminal::start(&ffca);
    terminal.wait_for("No one has a certificate yet");
    ffca.ok(&["issue", "--agent", "backup"]);
    terminal.wait_for("● backup");
    terminal.send("q");
    assert!(terminal.finish().0);
}

#[test]
fn without_a_ca_the_terminal_ui_sets_one_up() {
    let ffca = Ffca::new();
    let mut terminal = Terminal::start(&ffca);
    terminal.wait_for("There is no CA in");
    terminal.wait_for("Create the CA");
    // Replace the suggested name.
    terminal.send(&"\u{7f}".repeat(40));
    terminal.send("Test family\r\r");
    terminal.wait_for("Test family is ready");
    terminal.wait_for("Nginx tab");
    terminal.send("\r");
    terminal.wait_for("No one has a certificate yet");
    terminal.send("q");
    assert!(terminal.finish().0);
    assert!(
        ffca.ok(&["list"]).contains("No certificates yet"),
        "the CA is there for the CLI too"
    );
}

#[test]
fn ffca_alone_opens_the_terminal_ui() {
    let ffca = Ffca::initialised();
    let mut terminal = Terminal::start_with(&ffca, "");
    terminal.wait_for("Friends and Family CA · Test family");
    terminal.send("q");
    assert!(terminal.finish().0);
}

#[test]
fn without_a_terminal_it_says_so_instead_of_crashing() {
    let ffca = Ffca::initialised();
    let output = ffca.run(&["tui"]);
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("needs a terminal"), "{error}");
}
