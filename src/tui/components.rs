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
//! The UI's components, and what they share.

pub mod ca_info;
pub mod form;
pub mod invite_dialog;
pub mod invites_tab;
pub mod message;
pub mod mode_dialog;
pub mod nginx_tab;
pub mod people;
pub mod revoke_dialog;

use crossterm::event::KeyEvent;
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding};

use super::action::Action;

pub trait Component {
    /// Turns a key into an action, if it means one here.
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action>;

    fn draw(&mut self, frame: &mut Frame, area: Rect);
}

/// A key and what it does, as the hint line shows it.
pub type Hint = (&'static str, &'static str);

/// Hints as one line: each key bold, each description dim.
pub fn hint_line(hints: &[Hint]) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, (key, what)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push("  ".into());
        }
        spans.push(key.bold());
        spans.push(Span::from(format!(" {what}")).dim());
    }
    spans.into()
}

/// Clears and frames a dialog of `width` by `height`, centred in `area`; returns its inside,
/// padded by a column on each side so that wrapped text keeps its margin.
pub fn dialog(frame: &mut Frame, area: Rect, title: String, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(format!(" {title} ").bold())
        .borders(Borders::ALL)
        .border_set(border::ROUNDED)
        .border_style(Style::new().fg(Color::Cyan))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

/// Moves a selection by one within `len` entries, staying in bounds.
pub fn step(selected: usize, down: bool, len: usize) -> usize {
    if down {
        (selected + 1).min(len.saturating_sub(1))
    } else {
        selected.saturating_sub(1)
    }
}
