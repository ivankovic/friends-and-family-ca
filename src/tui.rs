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
//! `ffca tui`: the administrator's terminal UI.
//!
//! It follows the component architecture: each component ([`components`]) owns its state, turns
//! keys into [`action::Action`]s and draws itself, and the [`app::App`] carries the actions out
//! against the CA and decides which component sees the next key. Only the `App` touches the CA,
//! so every change goes through the same locks and checks as the command line.
//!
//! Other processes change the CA too (`crl-refresh` from its timer, the command line, later the
//! enrollment page), so the UI re-reads the ledger after every action and every few seconds.

pub mod action;
pub mod app;
pub mod components;
pub mod session;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyEventKind};
use time::OffsetDateTime;

use crate::store::Store;
use session::Session;

/// How often the UI re-reads the ledger when nobody presses a key.
const RELOAD_INTERVAL: Duration = Duration::from_secs(2);

/// Runs the UI on the CA in `store` - or its setup, if there is none yet - until the
/// administrator quits. Certificates issued from it are written to `out`.
pub fn run(store: Store, out: PathBuf) -> Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "the terminal UI needs a terminal; for scripts, use the commands in `ffca --help`"
        );
    }
    let mut session = Session::new(store, out, OffsetDateTime::now_utc());
    ratatui::run(|terminal| -> Result<()> {
        loop {
            terminal.draw(|frame| session.draw(frame))?;
            if event::poll(RELOAD_INTERVAL)? {
                if let Event::Key(key) = event::read()?
                    && key.kind == KeyEventKind::Press
                {
                    session.handle_key(key, OffsetDateTime::now_utc());
                }
            } else {
                session.reload(OffsetDateTime::now_utc());
            }
            if session.should_quit() {
                return Ok(());
            }
        }
    })
}

/// A date as people write it: "3 Oct 2026".
pub fn date(time: OffsetDateTime) -> String {
    let format = time::macros::format_description!("[day padding:none] [month repr:short] [year]");
    time.format(&format).unwrap_or_default()
}
