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
//! A dialog that tells: what was issued and where its files are, the help - or what is about to
//! happen, for Enter to confirm.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::{Component, Hint, dialog, hint_line};
use crate::tui::action::Action;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    title: String,
    lines: Vec<Line<'static>>,
    /// What Enter does, if it does more than close: the dialog asks before it.
    confirm: Option<(Action, &'static str)>,
}

impl Message {
    pub fn new(title: impl Into<String>, lines: Vec<Line<'static>>) -> Message {
        Message {
            title: title.into(),
            lines,
            confirm: None,
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
            _ => None,
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let width = 76;
        let wrapped: usize = self
            .lines
            .iter()
            .map(|l| l.width().div_ceil(usize::from(width) - 4).max(1))
            .sum();
        let height = wrapped as u16 + 5;
        let inner = dialog(frame, area, self.title.clone(), width, height);
        let mut lines = vec![Line::default()];
        lines.extend(self.lines.iter().cloned());
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        let hints = Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        };
        let keys: &[Hint] = match &self.confirm {
            Some((_, what)) => &[("Enter", what), ("Esc", "back")],
            None => &[("Enter", "close")],
        };
        frame.render_widget(Paragraph::new(hint_line(keys)), hints);
    }
}
