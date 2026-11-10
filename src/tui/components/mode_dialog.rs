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
//! Choosing a site's client-certificate mode, with the lines that will change shown first.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;

use super::{Component, Scroll, hang, step, text_dialog, text_width};
use crate::nginx::{Mode, Site};
use crate::tui::action::Action;

const DESCRIPTIONS: [&str; 3] = [
    "no certificate asked for",
    "asked for; without one you get in, a revoked or broken one is refused",
    "nobody gets in without a valid certificate from this CA",
];

/// What setting a mode changes in the file: lines that go and lines that come.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Change {
    pub removed: Vec<String>,
    pub added: Vec<String>,
}

/// The lines `planned` has that `original` does not, and the other way round.
pub fn diff(original: &str, planned: &str) -> Change {
    let before: Vec<&str> = original.lines().collect();
    let after: Vec<&str> = planned.lines().collect();
    // A blank line carries nothing worth reading: a bare "+" would only puzzle.
    let removed = before
        .iter()
        .filter(|l| !l.trim().is_empty() && !after.contains(l))
        .map(|l| l.trim().to_owned())
        .collect();
    let added = after
        .iter()
        .filter(|l| !l.trim().is_empty() && !before.contains(l))
        .map(|l| l.trim().to_owned())
        .collect();
    Change { removed, added }
}

#[derive(Debug, Clone)]
pub struct ModeDialog {
    site: Site,
    /// For each mode in `Mode::ALL`: what it would change, or why it cannot.
    changes: Vec<Result<Change, String>>,
    /// How many devices and agents hold a valid certificate from this CA: who still gets in
    /// once one is required.
    holders: usize,
    /// How many more have one still in an open invite: they get in once they collect it.
    waiting: usize,
    selected: usize,
    scroll: Scroll,
}

impl ModeDialog {
    pub fn new(
        site: Site,
        changes: Vec<Result<Change, String>>,
        holders: usize,
        waiting: usize,
    ) -> ModeDialog {
        let selected = Mode::ALL.iter().position(|m| *m == site.mode).unwrap_or(0);
        ModeDialog {
            site,
            changes,
            holders,
            waiting,
            selected,
            scroll: Scroll::default(),
        }
    }
}

impl Component for ModeDialog {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Some(Action::CloseDialog),
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, false, Mode::ALL.len())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, true, Mode::ALL.len())
            }
            KeyCode::Enter => {
                return Some(Action::SetSiteMode(
                    self.site.clone(),
                    Mode::ALL[self.selected],
                ));
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
        let mut lines: Vec<Line> = vec!["Client certificate".bold().into()];
        for (i, (mode, description)) in Mode::ALL.iter().zip(DESCRIPTIONS).enumerate() {
            let marker = if i == self.selected { "› " } else { "  " };
            let name = format!("{:<10}", mode.to_string());
            let name = if i == self.selected {
                name.bold()
            } else {
                name.into()
            };
            let now = if *mode == self.site.mode {
                "  (now)"
            } else {
                ""
            };
            let line: Line = vec![marker.into(), name, description.dim(), now.dim()].into();
            lines.extend(hang(line, 12, width));
        }
        lines.push(Line::default());
        // Requiring a certificate before anyone has one locks everyone out, the administrator
        // too: say who will still get in.
        if Mode::ALL[self.selected] == Mode::Required && self.site.mode != Mode::Required {
            let line = match self.holders {
                0 => "No device or agent has a valid certificate from this CA yet: nobody gets in, you included."
                    .fg(Color::Red),
                1 => "1 device or agent has a valid certificate from this CA: it alone gets in."
                    .fg(Color::Yellow),
                n => format!("{n} devices and agents have a valid certificate from this CA: everyone else is refused.")
                    .dim(),
            };
            lines.push(line.into());
            if self.waiting > 0 {
                lines.push(
                    format!(
                        "{} more {} an invite still open: they get in once it is collected.",
                        self.waiting,
                        if self.waiting == 1 { "has" } else { "have" }
                    )
                    .dim()
                    .into(),
                );
            }
            lines.push(Line::default());
        }
        match &self.changes[self.selected] {
            Err(reason) => lines.push(reason.clone().fg(Color::Red).into()),
            Ok(change) if change.removed.is_empty() && change.added.is_empty() => {
                lines.push("Nothing to change.".dim().into());
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
            &[("Enter", "apply"), ("Esc", "back")],
            &mut self.scroll,
        );
    }
}
