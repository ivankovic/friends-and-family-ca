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
//! Choosing a site's client-certificate mode, with the lines that will change shown first.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{Component, dialog, hint_line, step};
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

#[derive(Debug, Clone)]
pub struct ModeDialog {
    site: Site,
    /// For each mode in `Mode::ALL`: what it would change, or why it cannot.
    changes: Vec<Result<Change, String>>,
    selected: usize,
}

impl ModeDialog {
    pub fn new(site: Site, changes: Vec<Result<Change, String>>) -> ModeDialog {
        let selected = Mode::ALL.iter().position(|m| *m == site.mode).unwrap_or(0);
        ModeDialog {
            site,
            changes,
            selected,
        }
    }
}

impl Component for ModeDialog {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => return Some(Action::CloseDialog),
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
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
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
            lines.push(vec![marker.into(), name, description.dim(), now.dim()].into());
        }
        lines.push(Line::default());
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
        let height = lines.len() as u16 + 4;
        let inner = dialog(frame, area, self.site.name().to_string(), 92, height);
        frame.render_widget(Paragraph::new(lines), inner);
        let hints = Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        };
        frame.render_widget(
            Paragraph::new(hint_line(&[("Enter", "apply"), ("Esc", "back")])),
            hints,
        );
    }
}
