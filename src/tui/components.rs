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
//! hints has a line of its own, never drawn over its text. A dialog that would leave only a sliver
//! of the screen beside it takes the whole width instead ([`dialog_width`]): a few columns of the
//! tab behind it read as noise.
//!
//! Text that wraps keeps its column: [`hang`] wraps a line by words and indents the rows that
//! follow, so that a description beside a key or an option stays beside it.

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

/// How many columns [`hint_line`] takes for `hints`.
pub fn hints_width(hints: &[Hint]) -> usize {
    let texts: usize = hints
        .iter()
        .map(|(key, what)| key.chars().count() + 1 + what.chars().count())
        .sum();
    texts + 2 * hints.len().saturating_sub(1)
}

/// Hints as one line no wider than `width`: the tab's own hints as far as they fit, then
/// `always`, which are never dropped.
pub fn fitted_hint_line(hints: &[Hint], always: &[Hint], width: usize) -> Line<'static> {
    let mut shown: Vec<Hint> = Vec::new();
    for hint in hints {
        let mut with = shown.clone();
        with.push(*hint);
        with.extend_from_slice(always);
        if hints_width(&with) > width {
            break;
        }
        shown.push(*hint);
    }
    shown.extend_from_slice(always);
    hint_line(&shown)
}

/// How far a text is scrolled: a dialog's, or a pane's, that may be taller than its room.
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

    /// Takes in what is drawn - `rows` of text, `page` of them showing - and returns how far the
    /// text is scrolled, which is never past its end.
    pub fn fit(&mut self, rows: u16, page: u16) -> u16 {
        self.page = page;
        self.max = rows.saturating_sub(page);
        self.offset = self.offset.min(self.max);
        self.offset
    }

    /// Back to the top: for a text that is another one now.
    pub fn reset(&mut self) {
        self.offset = 0;
    }

    /// What to say where the text is cut, if it is: which way there is more, and the keys.
    pub fn more(&self) -> Option<&'static str> {
        (self.max > 0).then_some(match (self.offset > 0, self.offset < self.max) {
            (true, true) => "↑ ↓ more · PgUp PgDn",
            (false, _) => "↓ more · PgDn",
            (true, false) => "↑ more · PgUp",
        })
    }
}

/// A dialog is as wide as it asks to be, unless fewer than this many columns of its area would be
/// left beside it, both sides together: then it takes them all.
const SLIVER: u16 = 10;

/// How wide a dialog that asks for `width` is drawn in `area`.
pub fn dialog_width(width: u16, area: Rect) -> u16 {
    if area.width < width.saturating_add(SLIVER) {
        area.width
    } else {
        width
    }
}

/// How many columns of text a dialog that asks for `width` has in `area`: inside its borders and
/// its padding.
pub fn text_width(width: u16, area: Rect) -> usize {
    usize::from(dialog_width(width, area).saturating_sub(4))
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
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let rows = paragraph.line_count(text_width(width, area) as u16) as u16;
    let inner = dialog(frame, area, title, width, rows.saturating_add(4));
    let page = inner.height.saturating_sub(2);
    let offset = scroll.fit(rows, page);
    let text = Rect {
        height: page,
        ..inner
    };
    frame.render_widget(paragraph.scroll((offset, 0)), text);
    if let Some(more) = scroll.more() {
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
    let [area] = Layout::horizontal([Constraint::Length(dialog_width(width, area))])
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

/// `text`, cut to `width` characters with an ellipsis if it is longer.
pub fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// A character with its style: what [`hang`] moves between rows.
type Cell = (char, Style);

fn columns(cells: &[Cell]) -> usize {
    cells
        .iter()
        .map(|(c, _)| Span::raw(c.to_string()).width())
        .sum()
}

/// `line` wrapped by words to `width` columns, every row after the first indented by `indent`:
/// "  optional  asked for; without one you get in" continues under "asked", not at the margin.
/// Styles are kept; a word wider than a row is cut where the row ends.
pub fn hang(line: Line<'static>, indent: usize, width: usize) -> Vec<Line<'static>> {
    if line.width() <= width || width == 0 {
        return vec![line];
    }
    let indent = if indent < width { indent } else { 0 };
    let cells: Vec<Cell> = line
        .spans
        .iter()
        .flat_map(|span| span.content.chars().map(|c| (c, span.style)))
        .collect();
    // Runs of spaces and runs of anything else, in turn.
    let mut tokens: Vec<&[Cell]> = Vec::new();
    let mut start = 0;
    for i in 1..=cells.len() {
        if i == cells.len() || (cells[i].0 == ' ') != (cells[start].0 == ' ') {
            tokens.push(&cells[start..i]);
            start = i;
        }
    }
    let margin = || vec![(' ', Style::default()); indent];
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    let mut row: Vec<Cell> = Vec::new();
    let mut gap: &[Cell] = &[];
    // Whether the row holds a word yet, beyond its margin.
    let mut filled = false;
    for token in tokens {
        if token[0].0 == ' ' {
            // The spaces a row would begin with after a break are the break itself.
            if filled || rows.is_empty() {
                gap = token;
            }
            continue;
        }
        if columns(&row) + columns(gap) + columns(token) <= width {
            row.extend_from_slice(gap);
            row.extend_from_slice(token);
        } else {
            if filled {
                rows.push(std::mem::replace(&mut row, margin()));
            } else {
                row.extend_from_slice(gap);
            }
            for cell in token {
                if columns(&row) + columns(&[*cell]) > width {
                    rows.push(std::mem::replace(&mut row, margin()));
                }
                row.push(*cell);
            }
        }
        gap = &[];
        filled = true;
    }
    rows.push(row);
    rows.into_iter()
        .map(|row| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut text = String::new();
            let mut style = Style::default();
            for (c, cell_style) in row {
                if cell_style != style && !text.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut text), style));
                }
                style = cell_style;
                text.push(c);
            }
            spans.push(Span::styled(text, style));
            Line::from(spans).style(line.style)
        })
        .collect()
}

/// Each of `lines` wrapped by [`hang`] with its own indent, to `width` columns.
pub fn hang_all(lines: Vec<(usize, Line<'static>)>, width: usize) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .flat_map(|(indent, line)| hang(line, indent, width))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(lines: &[Line]) -> Vec<String> {
        lines.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_wrapped_line_continues_under_its_text() {
        let line: Line = vec![
            "  optional  ".bold(),
            "asked for; a broken one is refused".dim(),
        ]
        .into();
        let rows = hang(line, 12, 30);
        assert_eq!(
            texts(&rows),
            [
                "  optional  asked for; a",
                "            broken one is",
                "            refused"
            ]
        );
        assert_eq!(rows[1].spans.last().unwrap().style, Style::new().dim());
    }

    #[test]
    fn a_line_that_fits_is_left_alone() {
        let line = Line::from("short");
        assert_eq!(hang(line.clone(), 4, 10), vec![line]);
    }

    #[test]
    fn a_word_wider_than_a_row_is_cut_at_its_end() {
        let rows = hang(Line::from("see /a/very/long/path now"), 2, 10);
        assert_eq!(texts(&rows), ["see", "  /a/very/", "  long/pat", "  h now"]);
    }

    #[test]
    fn hints_drop_from_the_end_and_always_stay() {
        let line = fitted_hint_line(&[("a", "one"), ("b", "two")], &[("q", "quit")], 14);
        assert_eq!(line.to_string(), "a one  q quit");
    }
}
