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
//! The revoke dialog: why, and what that will reach.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;

use super::{Component, Scroll, step, text_dialog};
use crate::ledger::Reason;
use crate::tui::action::{Action, Selection};

const REASONS: [(Reason, &str, &str); 3] = [
    (Reason::Lost, "Lost or stolen", "someone else may have it"),
    (
        Reason::Replaced,
        "Replaced",
        "a newer certificate is already installed",
    ),
    (
        Reason::Retired,
        "Retired",
        "gone for good; nothing more is issued to it",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeDialog {
    selection: Selection,
    /// The valid certificates a revocation can reach, one line each, and whether each is its
    /// holder's newest - which "replaced" keeps.
    reaches: Vec<(String, bool)>,
    selected: usize,
    scroll: Scroll,
}

impl RevokeDialog {
    /// Preselects "replaced" when a device or agent has a newer certificate beside older ones.
    pub fn new(selection: Selection, reaches: Vec<(String, bool)>) -> RevokeDialog {
        let replacing = !matches!(selection, Selection::Person(_)) && reaches.len() > 1;
        RevokeDialog {
            selection,
            reaches,
            selected: if replacing { 1 } else { 0 },
            scroll: Scroll::default(),
        }
    }
}

impl Component for RevokeDialog {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => return Some(Action::CloseDialog),
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, false, REASONS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, true, REASONS.len());
            }
            KeyCode::Enter => {
                return Some(Action::Revoke(
                    self.selection.clone(),
                    REASONS[self.selected].0,
                ));
            }
            code => {
                self.scroll.handle(code, false);
            }
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let mut lines = vec!["Why?".bold().into()];
        for (i, (_, name, description)) in REASONS.iter().enumerate() {
            let marker = if i == self.selected { "› " } else { "  " };
            let name = format!("{name:<16}");
            let name = if i == self.selected {
                name.bold()
            } else {
                name.into()
            };
            lines.push(vec![marker.into(), name, description.dim()].into());
        }
        lines.push(Line::default());
        let replacing = REASONS[self.selected].0 == Reason::Replaced;
        let (kept, revoked): (Vec<_>, Vec<_>) = self
            .reaches
            .iter()
            .partition(|(_, newest)| replacing && *newest);
        if revoked.is_empty() {
            lines.push(
                "Nothing: there is no older certificate to replace."
                    .fg(Color::Yellow)
                    .into(),
            );
        } else {
            lines.push("This revokes:".into());
            lines.extend(revoked.iter().map(|(r, _)| Line::from(format!("  {r}"))));
        }
        if !kept.is_empty() {
            lines.push("and keeps the newest:".dim().into());
            lines.extend(kept.iter().map(|(r, _)| Line::from(format!("  {r}").dim())));
        }
        lines.push(Line::default());
        lines.push(
            "The web server refuses it as soon as you press Enter."
                .dim()
                .into(),
        );
        text_dialog(
            frame,
            area,
            format!("Revoke {}", self.selection),
            72,
            lines,
            &[("Enter", "revoke"), ("Esc", "back")],
            &mut self.scroll,
        );
    }
}
