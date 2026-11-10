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
//!
//! A revocation cannot be taken back, and the dialog says so. Revoking one device or agent takes
//! Enter. Revoking a person reaches every device they have, so Enter only asks, and `y` - a key
//! that nothing else in the dialog uses, and that a habit of pressing Enter does not reach -
//! does it.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;

use super::{Component, Hint, Scroll, hang, step, text_dialog, text_width};
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

const WIDTH: u16 = 72;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeDialog {
    selection: Selection,
    /// The valid certificates a revocation can reach, one line each, and whether each is its
    /// holder's newest - which "replaced" keeps.
    reaches: Vec<(String, bool)>,
    selected: usize,
    /// A person's revocation, after Enter: waiting for `y`.
    asked: bool,
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
            asked: false,
            scroll: Scroll::default(),
        }
    }

    /// Whether this revokes a person, with every device they have.
    fn everyone(&self) -> bool {
        matches!(self.selection, Selection::Person(_))
    }

    /// The certificates the chosen reason keeps, and the ones it revokes.
    fn parts(&self) -> (Vec<&str>, Vec<&str>) {
        let replacing = REASONS[self.selected].0 == Reason::Replaced;
        let (mut kept, mut revoked) = (Vec::new(), Vec::new());
        for (certificate, newest) in &self.reaches {
            if replacing && *newest {
                kept.push(certificate.as_str());
            } else {
                revoked.push(certificate.as_str());
            }
        }
        (kept, revoked)
    }

    fn revoke(&self) -> Action {
        Action::Revoke(self.selection.clone(), REASONS[self.selected].0)
    }
}

impl Component for RevokeDialog {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Some(Action::CloseDialog),
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, false, REASONS.len());
                self.asked = false;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, true, REASONS.len());
                self.asked = false;
            }
            // With nothing to revoke there is nothing to ask about, or to do.
            KeyCode::Enter if self.everyone() => {
                self.asked = !self.parts().1.is_empty();
                self.scroll.reset();
            }
            KeyCode::Enter => return Some(self.revoke()),
            KeyCode::Char('y') if self.asked => return Some(self.revoke()),
            code => {
                self.scroll.handle(code, false);
            }
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let width = text_width(WIDTH, area);
        let (kept, revoked) = self.parts();
        let mut lines: Vec<Line> = Vec::new();
        // Above everything else, where a list longer than the screen cannot scroll it away.
        if self.asked {
            let all = match revoked.len() {
                1 => "Revoke this 1 certificate".to_owned(),
                n => format!("Revoke all {n} certificates"),
            };
            lines.push(
                format!(
                    "{all} of {}? Press y to revoke, Esc to go back.",
                    self.selection
                )
                .fg(Color::Red)
                .bold()
                .into(),
            );
            lines.push(Line::default());
        }
        lines.push("Why?".bold().into());
        for (i, (_, name, description)) in REASONS.iter().enumerate() {
            let marker = if i == self.selected { "› " } else { "  " };
            let name = format!("{name:<16}");
            let name = if i == self.selected {
                name.bold()
            } else {
                name.into()
            };
            let line: Line = vec![marker.into(), name, description.dim()].into();
            lines.extend(hang(line, 18, width));
        }
        lines.push(Line::default());
        if revoked.is_empty() {
            lines.push(
                "Nothing: there is no older certificate to replace."
                    .fg(Color::Yellow)
                    .into(),
            );
        } else {
            lines.push("This revokes:".into());
            lines.extend(revoked.iter().map(|r| Line::from(format!("  {r}"))));
        }
        if !kept.is_empty() {
            lines.push("and keeps the newest:".dim().into());
            lines.extend(kept.iter().map(|r| Line::from(format!("  {r}").dim())));
        }
        lines.push(Line::default());
        let key = if self.everyone() { "y" } else { "Enter" };
        lines.push(
            format!(
                "It cannot be undone: a revoked certificate stays revoked, and the device needs a new one. The web server refuses it as soon as you press {key}."
            )
            .dim()
            .into(),
        );
        let hints: &[Hint] = match (self.everyone(), self.asked) {
            (true, true) => &[("y", "revoke"), ("Esc", "back")],
            (true, false) if revoked.is_empty() => &[("Esc", "back")],
            (true, false) => &[("Enter", "continue"), ("Esc", "back")],
            (false, _) => &[("Enter", "revoke"), ("Esc", "back")],
        };
        text_dialog(
            frame,
            area,
            format!("Revoke {}", self.selection),
            WIDTH,
            lines,
            hints,
            &mut self.scroll,
        );
    }
}
