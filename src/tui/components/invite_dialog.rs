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
//! An invite's QR code and link, for the device to scan or the person to be sent.

use crossterm::event::{KeyCode, KeyEvent};
use qrcode::{Color as Module, EcLevel, QrCode};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::{Component, dialog, hint_line};
use crate::tui::action::Action;

/// Light modules around the code, which scanners need to find it.
const QUIET_ZONE: usize = 2;

#[derive(Debug, Clone)]
pub struct InviteDialog {
    holder: String,
    link: String,
    /// What the invite's state is in words: "Works once · expires 4 Oct 14:02".
    status: String,
    /// The code, a row of terminal lines with two modules to a character.
    code: Vec<Line<'static>>,
}

impl InviteDialog {
    pub fn new(holder: String, link: String, status: String) -> InviteDialog {
        let code = render(&link);
        InviteDialog {
            holder,
            link,
            status,
            code,
        }
    }

    fn code_width(&self) -> u16 {
        self.code.first().map_or(0, |l| l.width() as u16)
    }
}

/// The QR code for `text` in half blocks: each character is two modules, the top one its
/// foreground, the bottom one its background. Black on white whatever the terminal's theme:
/// scanners look for dark modules on a light ground.
fn render(text: &str) -> Vec<Line<'static>> {
    let Ok(code) = QrCode::with_error_correction_level(text, EcLevel::L) else {
        return vec![Line::from("(too long for a QR code)")];
    };
    let width = code.width();
    let colors = code.to_colors();
    let full = width + 2 * QUIET_ZONE;
    let dark = |x: usize, y: usize| -> bool {
        let (Some(x), Some(y)) = (x.checked_sub(QUIET_ZONE), y.checked_sub(QUIET_ZONE)) else {
            return false;
        };
        x < width && y < width && colors[y * width + x] == Module::Dark
    };
    let shade = |dark: bool| if dark { Color::Black } else { Color::White };
    (0..full.div_ceil(2))
        .map(|row| {
            let spans: Vec<Span> = (0..full)
                .map(|x| {
                    let (top, bottom) = (dark(x, 2 * row), dark(x, 2 * row + 1));
                    Span::styled("▀", Style::new().fg(shade(top)).bg(shade(bottom)))
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

impl Component for InviteDialog {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Some(Action::CloseDialog),
            KeyCode::Char('c') => Some(Action::Copy(self.link.clone())),
            _ => None,
        }
    }

    /// `area` is the whole screen: the code is drawn beside its explanation where there is room,
    /// and otherwise with only the link and the status under it, which fits a link of the usual
    /// length (a version 4 code) in 80 by 24.
    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        // The link has a line of its own, unwrapped: it is copied from the terminal into a
        // message, and a wrapped one would come out in pieces.
        let code_width = self.code_width();
        let code_height = self.code.len() as u16;
        let link_width = self.link.chars().count() as u16;
        let title = format!("Invite for {}", self.holder);
        let hints = hint_line(&[("c", "copy link"), ("Enter", "close")]);
        let hint_row = |inner: Rect| Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        };

        let beside = ((code_width + 48).max(link_width + 4), code_height + 8);
        if beside.0 <= area.width && beside.1 <= area.height {
            let inner = dialog(frame, area, title, beside.0, beside.1);
            let [top, below] =
                Layout::vertical([Constraint::Length(code_height), Constraint::Min(4)])
                    .areas(inner);
            let [code, _, text] = Layout::horizontal([
                Constraint::Length(code_width),
                Constraint::Length(2),
                Constraint::Min(20),
            ])
            .areas(top);
            frame.render_widget(Paragraph::new(self.code.clone()), code);
            let explained: Vec<Line> = vec![
                "Scan it with the device, or send it the link below.".into(),
                Line::default(),
                self.status.clone().into(),
                Line::default(),
                "It opens a page that hands the certificate over, with how to install it."
                    .dim()
                    .into(),
            ];
            frame.render_widget(Paragraph::new(explained).wrap(Wrap { trim: false }), text);
            let lines: Vec<Line> = vec![Line::default(), self.link.clone().cyan().into()];
            frame.render_widget(Paragraph::new(lines), below);
            frame.render_widget(Paragraph::new(hints), hint_row(inner));
            return;
        }

        // The code, then the link, the status and the hints: one row each, inside the frame.
        let stacked = (code_width.max(link_width) + 4, code_height + 5);
        if stacked.0 <= area.width && stacked.1 <= area.height {
            let inner = dialog(frame, area, title, stacked.0, stacked.1);
            let [code, link, status] = Layout::vertical([
                Constraint::Length(code_height),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .areas(inner);
            let code = Rect {
                x: inner.x + (inner.width.saturating_sub(code_width)) / 2,
                width: code_width.min(inner.width),
                ..code
            };
            frame.render_widget(Paragraph::new(self.code.clone()), code);
            frame.render_widget(Paragraph::new(self.link.clone().cyan()), link);
            frame.render_widget(Paragraph::new(self.status.clone().dim()), status);
            frame.render_widget(Paragraph::new(hints), hint_row(inner));
            return;
        }

        // A clipped code does not scan: show none rather than half of one.
        let inner = dialog(frame, area, title, link_width + 4, 11);
        let lines: Vec<Line> = vec![
            "Send the device this link:".into(),
            Line::default(),
            self.link.clone().cyan().into(),
            Line::default(),
            self.status.clone().into(),
            Line::default(),
            format!(
                "Make the terminal at least {} by {} to see its QR code.",
                stacked.0, stacked.1
            )
            .fg(Color::Yellow)
            .into(),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
        frame.render_widget(Paragraph::new(hints), hint_row(inner));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn screen(width: u16, height: u16) -> String {
        let link = "https://k.domaci.ivankovic.me/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .to_owned();
        let mut dialog = InviteDialog::new("Anna (phone)".into(), link, "Works once".into());
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| dialog.draw(frame, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_link_is_whole_on_one_line() {
        let screen = screen(100, 40);
        assert!(
            screen.contains(
                "https://k.domaci.ivankovic.me/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            "{screen}"
        );
        assert!(screen.contains("▀▀▀"), "{screen}");
    }

    /// 80 by 24 is what an SSH session opens at: the code fits, with the link whole under it.
    #[test]
    fn the_code_fits_a_plain_80_by_24_terminal() {
        let screen = screen(80, 24);
        assert!(screen.contains("▀▀▀"), "{screen}");
        assert!(
            screen.contains(
                "https://k.domaci.ivankovic.me/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            "{screen}"
        );
        assert!(screen.contains("Works once"), "{screen}");
        assert!(screen.contains("Enter close"), "{screen}");
    }

    #[test]
    fn a_terminal_too_small_for_the_code_gets_the_link_and_why() {
        let screen = screen(80, 20);
        assert!(!screen.contains('▀'), "no clipped code:\n{screen}");
        assert!(
            screen.contains(
                "https://k.domaci.ivankovic.me/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            "{screen}"
        );
        assert!(screen.contains("Make the terminal at least"), "{screen}");
    }

    /// The rendered code, read back module by module, is the code for the link: a scanner sees
    /// what was encoded.
    #[test]
    fn the_drawing_is_the_code() {
        let link = "https://k.example.org/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let lines = render(link);
        let code = QrCode::with_error_correction_level(link, EcLevel::L).unwrap();
        let width = code.width();
        assert_eq!(lines.len(), (width + 2 * QUIET_ZONE).div_ceil(2));
        let colors = code.to_colors();
        for y in 0..width {
            for x in 0..width {
                let row = (y + QUIET_ZONE) / 2;
                let span = &lines[row].spans[x + QUIET_ZONE];
                let shade = if (y + QUIET_ZONE).is_multiple_of(2) {
                    span.style.fg
                } else {
                    span.style.bg
                };
                let expected = if colors[y * width + x] == Module::Dark {
                    Color::Black
                } else {
                    Color::White
                };
                assert_eq!(shade, Some(expected), "module {x},{y}");
            }
        }
        let first = &lines[0].spans[0].style;
        assert_eq!(
            (first.fg, first.bg),
            (Some(Color::White), Some(Color::White)),
            "a light quiet zone"
        );
    }
}
