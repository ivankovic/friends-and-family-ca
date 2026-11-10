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
//! Choosing a site's HTTP auth - off, passthrough or on - and who may log in, with the lines that
//! will change shown first, worked out again at every key.
//!
//! One cursor runs down the three kinds and, under `on`, ffca's users, each ticked or not with
//! Space: a name that is not a user cannot be chosen, so it cannot be misspelt. `passthrough` names
//! are the site's own users, which ffca does not know, so they are typed.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;

use super::mode_dialog::diff;
use super::{Component, Scroll, hang, step, text_dialog, text_width};
use crate::config;
use crate::nginx::{self, Auth, Site};
use crate::tui::action::Action;

const DESCRIPTIONS: [&str; 3] = [
    "no login asked for",
    "a login is asked for; the site behind checks the password",
    "nginx checks the login against ffca's users (the Users tab)",
];

#[derive(Debug, Clone)]
pub struct AuthDialog {
    site: Site,
    /// The site's file as it is, or why it cannot be read.
    original: Result<String, String>,
    settings: config::Nginx,
    /// ffca's users, for `on`, and whether each is ticked.
    users: Vec<(String, bool)>,
    /// Why no login may be asked for here, if that is so: the enrollment site.
    refused: Option<String>,
    kind: usize,
    /// The row the cursor is on: a kind, then (under `on`) a user.
    cursor: usize,
    /// The names for `passthrough`, as typed: separated by commas or spaces.
    names: String,
    scroll: Scroll,
}

/// The kinds' indexes in [`Auth::KINDS`].
const PASSTHROUGH: usize = 1;
const ON: usize = 2;

impl AuthDialog {
    pub fn new(
        site: Site,
        original: Result<String, String>,
        settings: config::Nginx,
        users: Vec<String>,
        refused: Option<String>,
    ) -> AuthDialog {
        let kind = site.auth.kind();
        let (names, ticked): (String, &[String]) = match &site.auth {
            Auth::Passthrough(names) => (names.join(", "), &[]),
            Auth::On(names) => (String::new(), names),
            Auth::Off => (String::new(), &[]),
        };
        let users = users
            .into_iter()
            .map(|user| {
                let on = ticked.contains(&user);
                (user, on)
            })
            .collect();
        AuthDialog {
            site,
            original,
            settings,
            users,
            refused,
            kind,
            cursor: kind,
            names,
            scroll: Scroll::default(),
        }
    }

    /// How many rows the cursor runs over.
    fn rows(&self) -> usize {
        Auth::KINDS.len() + if self.kind == ON { self.users.len() } else { 0 }
    }

    fn move_cursor(&mut self, down: bool) {
        self.cursor = step(self.cursor, down, self.rows());
        if self.cursor < Auth::KINDS.len() {
            self.kind = self.cursor;
        }
    }

    /// What is chosen, as the site's new HTTP auth.
    fn auth(&self) -> Auth {
        match self.kind {
            PASSTHROUGH => Auth::Passthrough(
                self.names
                    .split([',', ' '])
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_owned)
                    .collect(),
            ),
            ON => Auth::On(
                self.users
                    .iter()
                    .filter(|(_, on)| *on)
                    .map(|(user, _)| user.clone())
                    .collect(),
            ),
            _ => Auth::Off,
        }
    }

    /// What the choice would change in the file, or why it cannot be.
    fn change(&self) -> Result<super::mode_dialog::Change, String> {
        let auth = self.auth();
        if let Some(reason) = &self.refused
            && auth != Auth::Off
        {
            return Err(reason.clone());
        }
        if let Auth::On(names) = &auth
            && names.is_empty()
        {
            return Err(if self.users.is_empty() {
                "ffca has no users yet: add them on the Users tab first.".into()
            } else {
                "Tick at least one user with Space: nobody else gets in.".into()
            });
        }
        let original = self.original.clone()?;
        let planned = nginx::plan_auth(&original, self.site.index, &auth, &self.settings)
            .map_err(|e| format!("{e:#}"))?;
        Ok(diff(&original, &planned))
    }
}

impl Component for AuthDialog {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => return Some(Action::CloseDialog),
            KeyCode::Up => self.move_cursor(false),
            KeyCode::Down => self.move_cursor(true),
            KeyCode::Backspace if self.kind == PASSTHROUGH => {
                self.names.pop();
            }
            KeyCode::Char(c) if self.kind == PASSTHROUGH => self.names.push(c),
            KeyCode::Char('q') => return Some(Action::CloseDialog),
            KeyCode::Char('k') => self.move_cursor(false),
            KeyCode::Char('j') => self.move_cursor(true),
            KeyCode::Char(' ') => {
                let user = self.cursor.checked_sub(Auth::KINDS.len());
                if let Some((_, on)) = user.and_then(|u| self.users.get_mut(u)) {
                    *on = !*on;
                }
            }
            KeyCode::Enter if self.change().is_ok() => {
                return Some(Action::SetSiteAuth(self.site.clone(), self.auth()));
            }
            code => {
                self.scroll.handle(code, false);
            }
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        const WIDTH: u16 = 92;
        let width = text_width(WIDTH, area);
        let mut lines: Vec<Line> = vec!["HTTP login".bold().into()];
        for (i, (kind, description)) in Auth::KINDS.iter().zip(DESCRIPTIONS).enumerate() {
            let marker = if i == self.cursor { "› " } else { "  " };
            let name = format!("{kind:<13}");
            let name = if i == self.kind {
                name.bold()
            } else {
                name.into()
            };
            let now = if i == self.site.auth.kind() {
                "  (now)"
            } else {
                ""
            };
            let line: Line = vec![marker.into(), name, description.dim(), now.dim()].into();
            lines.extend(hang(line, 15, width));
        }
        lines.push(Line::default());
        if self.kind == PASSTHROUGH {
            lines.push(
                vec![
                    "Users: ".bold(),
                    self.names.clone().into(),
                    "▏".into(),
                    "  (none: any name may try)".dim(),
                ]
                .into(),
            );
            lines.push(Line::default());
        }
        if self.kind == ON && !self.users.is_empty() {
            lines.push("Who may log in:".bold().into());
            for (i, (user, on)) in self.users.iter().enumerate() {
                let here = self.cursor == Auth::KINDS.len() + i;
                let marker = if here { "› " } else { "  " };
                let tick = if *on { "[x] " } else { "[ ] " };
                let user = if here {
                    user.clone().bold()
                } else {
                    user.clone().into()
                };
                lines.push(vec![marker.into(), tick.into(), user].into());
            }
            lines.push(Line::default());
        }
        match self.change() {
            Err(reason) => lines.push(reason.fg(Color::Red).into()),
            Ok(change) if change.removed.is_empty() && change.added.is_empty() => {
                lines.push("Nothing to change in the site.".dim().into());
            }
            Ok(change) => {
                lines.push(format!("In {}:", self.site.file.display()).into());
                lines.extend(
                    change
                        .removed
                        .iter()
                        .map(|l| Line::from(format!("- {l}").fg(Color::Red))),
                );
                lines.extend(
                    change
                        .added
                        .iter()
                        .map(|l| Line::from(format!("+ {l}").fg(Color::Green))),
                );
                lines.push(Line::default());
                lines.push(
                    "Then nginx -t; if nginx refuses it, the file is put back. Then a reload."
                        .dim()
                        .into(),
                );
            }
        }
        text_dialog(
            frame,
            area,
            self.site.name().to_string(),
            WIDTH,
            lines,
            match self.kind {
                PASSTHROUGH => &[
                    ("↑ ↓", "kind"),
                    ("type", "users"),
                    ("Enter", "apply"),
                    ("Esc", "back"),
                ],
                // With no users there is nothing to tick: Space is not offered.
                ON if self.users.is_empty() => {
                    &[("↑ ↓", "kind"), ("Enter", "apply"), ("Esc", "back")]
                }
                ON => &[
                    ("↑ ↓", "move"),
                    ("Space", "tick a user"),
                    ("Enter", "apply"),
                    ("Esc", "back"),
                ],
                _ => &[("↑ ↓", "kind"), ("Enter", "apply"), ("Esc", "back")],
            },
            &mut self.scroll,
        );
    }
}
