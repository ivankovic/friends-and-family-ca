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
//! The UI's components, and what they share.
//!
//! Every dialog fits the screen it is drawn on, down to the 80 by 24 of a plain SSH session: one
//! taller than that scrolls ([`Scroll`]) rather than running off the bottom, and its row of key
//! hints has a line of its own, never drawn over its text.

pub mod auth_dialog;
pub mod ca_info;
pub mod form;
pub mod invite_dialog;
pub mod invites_tab;
pub mod message;
pub mod mode_dialog;
pub mod nginx_tab;
pub mod people;
pub mod revoke_dialog;
pub mod users_tab;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

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

/// Hints as one line no wider than `width`: the tab's own hints as far as they fit, then
/// `always`, which every tab shares and are never dropped.
pub fn fitted_hint_line(hints: &[Hint], always: &[Hint], width: usize) -> Line<'static> {
    let width_of = |hints: &[Hint]| -> usize {
        hints
            .iter()
            .map(|(key, what)| key.chars().count() + 1 + what.chars().count() + 2)
            .sum()
    };
    let room = width.saturating_sub(width_of(always));
    let mut shown: Vec<Hint> = Vec::new();
    for hint in hints {
        if width_of(&shown) + width_of(&[*hint]) > room {
            break;
        }
        shown.push(*hint);
    }
    shown.extend_from_slice(always);
    hint_line(&shown)
}

/// How far a dialog's text is scrolled, for a dialog that may be taller than the screen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Scroll {
    offset: u16,
    /// How far it can scroll, and how many rows show at once: as of the last draw.
    max: u16,
    page: u16,
}

impl Scroll {
    /// Moves for a scrolling key: PgUp, PgDn, and with `arrows` also ↑ ↓ j k Home End, which
    /// a dialog that chooses with the arrows keeps for itself. Returns whether `key` was one.
    pub fn handle(&mut self, key: KeyCode, arrows: bool) -> bool {
        let page = self.page.max(1);
        let offset = match key {
            KeyCode::PageDown => self.offset.saturating_add(page),
            KeyCode::PageUp => self.offset.saturating_sub(page),
            KeyCode::Down | KeyCode::Char('j') if arrows => self.offset.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') if arrows => self.offset.saturating_sub(1),
            KeyCode::Home | KeyCode::Char('g') if arrows => 0,
            KeyCode::End | KeyCode::Char('G') if arrows => self.max,
            _ => return false,
        };
        self.offset = offset.min(self.max);
        true
    }
}

/// A dialog of `lines` with `hints` under them: `width` wide and as tall as its wrapped text, but
/// never more than `area`. Text that does not fit scrolls by `scroll`, and the row above the hints
/// says there is more.
pub fn text_dialog(
    frame: &mut Frame,
    area: Rect,
    title: String,
    width: u16,
    lines: Vec<Line<'static>>,
    hints: &[Hint],
    scroll: &mut Scroll,
) {
    // Borders and padding take two columns each side; borders, the gap and the hints, four rows.
    let width = width.min(area.width);
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let rows = paragraph.line_count(width.saturating_sub(4)) as u16;
    let inner = dialog(frame, area, title, width, rows.saturating_add(4));
    let page = inner.height.saturating_sub(2);
    scroll.page = page;
    scroll.max = rows.saturating_sub(page);
    scroll.offset = scroll.offset.min(scroll.max);
    let text = Rect {
        height: page,
        ..inner
    };
    frame.render_widget(paragraph.scroll((scroll.offset, 0)), text);
    if scroll.max > 0 {
        let more = match (scroll.offset > 0, scroll.offset < scroll.max) {
            (true, true) => "↑ ↓ more · PgUp PgDn",
            (false, _) => "↓ more · PgDn",
            (true, false) => "↑ more · PgUp",
        };
        let gap = Rect {
            y: inner.bottom().saturating_sub(2),
            height: 1,
            ..inner
        };
        frame.render_widget(Paragraph::new(Line::from(more.dim()).right_aligned()), gap);
    }
    let row = Rect {
        y: inner.bottom().saturating_sub(1),
        height: 1,
        ..inner
    };
    frame.render_widget(Paragraph::new(hint_line(hints)), row);
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
