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
//! will change shown first, worked out again as the names are typed.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::mode_dialog::diff;
use super::{Component, dialog, hint_line, step};
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
    /// ffca's users, for `on`.
    users: Vec<String>,
    /// Why no login may be asked for here, if that is so: the enrollment site.
    refused: Option<String>,
    kind: usize,
    /// The names, as typed: separated by commas or spaces.
    names: String,
}

impl AuthDialog {
    pub fn new(
        site: Site,
        original: Result<String, String>,
        settings: config::Nginx,
        users: Vec<String>,
        refused: Option<String>,
    ) -> AuthDialog {
        let kind = site.auth.kind();
        let names = site.auth.names().join(", ");
        AuthDialog {
            site,
            original,
            settings,
            users,
            refused,
            kind,
            names,
        }
    }

    /// What is chosen, as the site's new HTTP auth.
    fn auth(&self) -> Auth {
        let names: Vec<String> = self
            .names
            .split([',', ' '])
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_owned)
            .collect();
        match self.kind {
            1 => Auth::Passthrough(names),
            2 => Auth::On(names),
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
        if let Auth::On(names) = &auth {
            if names.is_empty() {
                return Err("Name at least one user: nobody else gets in.".into());
            }
            if let Some(unknown) = names.iter().find(|n| !self.users.contains(n)) {
                return Err(format!(
                    "There is no user {unknown}: add them on the Users tab first."
                ));
            }
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
            KeyCode::Up => self.kind = step(self.kind, false, Auth::KINDS.len()),
            KeyCode::Down => self.kind = step(self.kind, true, Auth::KINDS.len()),
            KeyCode::Backspace => {
                self.names.pop();
            }
            KeyCode::Char(c) => self.names.push(c),
            KeyCode::Enter if self.change().is_ok() => {
                return Some(Action::SetSiteAuth(self.site.clone(), self.auth()));
            }
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let mut lines: Vec<Line> = vec!["HTTP login".bold().into()];
        for (i, (kind, description)) in Auth::KINDS.iter().zip(DESCRIPTIONS).enumerate() {
            let marker = if i == self.kind { "› " } else { "  " };
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
            lines.push(vec![marker.into(), name, description.dim(), now.dim()].into());
        }
        lines.push(Line::default());
        if self.kind != 0 {
            let help = if self.kind == 1 {
                "  (none: any name may try)"
            } else {
                "  (ffca's users)"
            };
            lines.push(
                vec![
                    "Users: ".bold(),
                    self.names.clone().into(),
                    "▏".into(),
                    help.dim(),
                ]
                .into(),
            );
            if self.kind == 2 {
                let known = if self.users.is_empty() {
                    "none yet: add them on the Users tab".to_owned()
                } else {
                    self.users.join(", ")
                };
                lines.push(vec!["ffca's users: ".dim(), known.dim()].into());
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
        let height = lines.len() as u16 + 4;
        let inner = dialog(frame, area, self.site.name().to_string(), 92, height);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        let hints = Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        };
        frame.render_widget(
            Paragraph::new(hint_line(&[
                ("↑ ↓", "kind"),
                ("type", "users"),
                ("Enter", "apply"),
                ("Esc", "back"),
            ])),
            hints,
        );
    }
}
