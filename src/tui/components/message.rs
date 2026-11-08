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
//! A dialog that tells: what was issued and where its files are, the help - or what is about to
//! happen, for Enter to confirm.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;

use super::{Component, Hint, Scroll, text_dialog};
use crate::tui::action::Action;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    title: String,
    lines: Vec<Line<'static>>,
    /// What Enter does, if it does more than close: the dialog asks before it.
    confirm: Option<(Action, &'static str)>,
    scroll: Scroll,
}

impl Message {
    pub fn new(title: impl Into<String>, lines: Vec<Line<'static>>) -> Message {
        Message {
            title: title.into(),
            lines,
            confirm: None,
            scroll: Scroll::default(),
        }
    }

    /// A message that asks: Enter does `action`, described in the hint as `what`.
    pub fn confirm(
        title: impl Into<String>,
        lines: Vec<Line<'static>>,
        action: Action,
        what: &'static str,
    ) -> Message {
        Message {
            confirm: Some((action, what)),
            ..Message::new(title, lines)
        }
    }
}

impl Component for Message {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Enter => Some(
                self.confirm
                    .as_ref()
                    .map_or(Action::CloseDialog, |(a, _)| a.clone()),
            ),
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::CloseDialog),
            code => {
                self.scroll.handle(code, true);
                None
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let mut lines = vec![Line::default()];
        lines.extend(self.lines.iter().cloned());
        let keys: &[Hint] = match &self.confirm {
            Some((_, what)) => &[("Enter", what), ("Esc", "back")],
            None => &[("Enter", "close")],
        };
        text_dialog(
            frame,
            area,
            self.title.clone(),
            76,
            lines,
            keys,
            &mut self.scroll,
        );
    }
}
