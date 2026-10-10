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
//! The CA tab: the CA itself, its files, and its revocation list.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::{Component, Hint};
use crate::tui::action::Action;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CaInfo {
    lines: Vec<Line<'static>>,
}

impl CaInfo {
    pub fn update(&mut self, lines: Vec<Line<'static>>) {
        self.lines = lines;
    }

    pub fn hints(&self) -> Vec<Hint> {
        vec![
            ("c", "sign a new CRL now"),
            ("T", "set up the refresh timer"),
        ]
    }
}

impl Component for CaInfo {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('c') => Some(Action::RefreshCrl),
            KeyCode::Char('T') => Some(Action::AskTimer),
            _ => None,
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let mut lines = vec![Line::default()];
        lines.extend(self.lines.iter().cloned());
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}
