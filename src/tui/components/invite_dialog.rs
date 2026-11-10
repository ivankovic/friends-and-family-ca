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
//!
//! The dialog has the whole screen, and three ways to use it. With room to spare it is framed:
//! the code, what to do with it beside it, the link under both. On a screen no larger than the
//! code needs - 80 by 24 for a link of up to 106 characters, a version 5 code - the frame goes
//! and the same parts fill the screen edge to edge. Smaller than that, the code is left out
//! rather than clipped, since half a code does not scan.
//!
//! The link is never cut: one wider than its row continues on the next, and the dialog says that
//! `c` copies it whole. The text beside the code is a list of lines, each optional - the
//! password, what the last key did - so another line is another entry in [`InviteDialog::side`].
//!
//! While the dialog is open the invite can stop being open - the device collects it, most
//! likely. The dialog then says so in place of the code, which no longer leads anywhere.

use crossterm::event::{KeyCode, KeyEvent};
use qrcode::{Color as Module, EcLevel, QrCode};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::{Component, Hint, dialog, hint_line};
use crate::ledger::Serial;
use crate::tui::action::Action;

/// Light modules around the code, which scanners need to find it.
const QUIET_ZONE: usize = 2;

/// The narrowest the text beside the code can be and still read.
const SIDE_MIN: u16 = 24;

const LINK_COPIED: &str = "✓ Link copied, if your terminal allows it (OSC 52).";
const PASSWORD_COPIED: &str = "✓ Password copied, if your terminal allows it (OSC 52).";

#[derive(Debug, Clone)]
pub struct InviteDialog {
    /// The certificate the invite hands over: what the ledger knows the invite by.
    serial: Serial,
    holder: String,
    link: String,
    /// What the invite's state is in words: "Works once · expires 4 Oct 14:02".
    status: String,
    /// A password the device is asked for, if the invite has one: sent apart from the link.
    password: Option<String>,
    /// The code, a row of terminal lines with two modules to a character.
    code: Vec<Line<'static>>,
    /// What the last key did, said under the explanation: the dialog covers the notice line.
    said: Option<&'static str>,
    /// What became of the invite, once it is no longer open: shown in place of the code.
    closed: Option<String>,
}

impl InviteDialog {
    pub fn new(serial: Serial, holder: String, link: String, status: String) -> InviteDialog {
        let code = render(&link);
        InviteDialog {
            serial,
            holder,
            link,
            status,
            password: None,
            code,
            said: None,
            closed: None,
        }
    }

    /// The dialog showing `password` too, with `p` to copy it.
    pub fn with_password(mut self, password: Option<String>) -> InviteDialog {
        self.password = password;
        self
    }

    /// The certificate of the invite shown.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// The invite is no longer open: `what` became of it is shown in place of its code.
    pub fn close(&mut self, what: String) {
        self.closed = Some(what);
    }

    fn code_width(&self) -> u16 {
        self.code.first().map_or(0, |l| l.width() as u16)
    }

    fn hints(&self) -> Vec<Hint> {
        let mut hints = Vec::new();
        if self.closed.is_none() {
            hints.push(("c", "copy link"));
            if self.password.is_some() {
                hints.push(("p", "copy password"));
            }
        }
        hints.push(("Enter", "close"));
        hints
    }

    /// The text that goes with the code: what to do with it, how long it works, and each line
    /// that applies - the password, that the link is on several rows, what the last key did.
    fn side(&self, title: bool, link_rows: usize) -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::new();
        if title {
            lines.push(format!("Invite for {}", self.holder).bold().into());
            lines.push(Line::default());
        }
        lines.push("Scan it with the device, or send it the link below.".into());
        lines.push(Line::default());
        lines.push(self.status.clone().into());
        if let Some(password) = &self.password {
            lines.push(Line::default());
            lines.push(
                vec![
                    "Password: ".into(),
                    password.clone().bold(),
                    " (send it separately)".dim(),
                ]
                .into(),
            );
        }
        if link_rows > 1 {
            lines.push(Line::default());
            lines.push(
                format!("The link takes {link_rows} rows here: c copies it whole.")
                    .fg(Color::Yellow)
                    .into(),
            );
        }
        if let Some(said) = self.said {
            lines.push(Line::default());
            lines.push(said.into());
        }
        lines
    }

    /// The code with its text beside it and the link under both, in `inner`; `spaced` leaves a
    /// blank row above and below the link.
    fn draw_code(&self, frame: &mut Frame, inner: Rect, title: bool, spaced: bool) {
        let code_width = self.code_width();
        let code_height = self.code.len() as u16;
        let link = rows_of(&self.link, inner.width.into());
        let code = Rect {
            width: code_width,
            height: code_height,
            ..inner
        };
        frame.render_widget(Paragraph::new(self.code.clone()), code);
        // Two columns from the code, and one from the edge.
        let side = Rect {
            x: inner.x + code_width + 2,
            width: inner.width.saturating_sub(code_width + 3),
            height: code_height,
            ..inner
        };
        let text = Paragraph::new(self.side(title, link.len())).wrap(Wrap { trim: false });
        frame.render_widget(text, side);
        let below = Rect {
            y: inner.y + code_height + u16::from(spaced),
            height: link.len() as u16,
            ..inner
        };
        let link: Vec<Line> = link.into_iter().map(|row| row.cyan().into()).collect();
        frame.render_widget(Paragraph::new(link), below);
        frame.render_widget(Paragraph::new(hint_line(&self.hints())), last_row(inner));
    }
}

fn last_row(inner: Rect) -> Rect {
    Rect {
        y: inner.bottom().saturating_sub(1),
        height: 1,
        ..inner
    }
}

/// `link` in rows of `width` characters: cut where a row ends, never shortened.
fn rows_of(link: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = link.chars().collect();
    chars
        .chunks(width.max(1))
        .map(|row| row.iter().collect())
        .collect()
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
            KeyCode::Char('c') if self.closed.is_none() => {
                self.said = Some(LINK_COPIED);
                Some(Action::Copy(self.link.clone()))
            }
            KeyCode::Char('p') if self.closed.is_none() => {
                let password = self.password.clone()?;
                self.said = Some(PASSWORD_COPIED);
                Some(Action::Copy(password))
            }
            _ => None,
        }
    }

    /// `area` is the whole screen.
    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let title = format!("Invite for {}", self.holder);
        if let Some(closed) = &self.closed {
            let text = Paragraph::new(closed.clone()).wrap(Wrap { trim: false });
            let rows = text.line_count(super::text_width(72, area) as u16) as u16;
            let inner = dialog(frame, area, title, 72, rows + 5);
            let body = Rect {
                y: inner.y + 1,
                height: inner.height.saturating_sub(2),
                ..inner
            };
            frame.render_widget(text, body);
            frame.render_widget(Paragraph::new(hint_line(&self.hints())), last_row(inner));
            return;
        }
        let code_width = self.code_width();
        let code_height = self.code.len() as u16;
        let link_width = self.link.chars().count() as u16;

        // Framed: the link has a row of its own, between two blank ones.
        let framed = ((code_width + 48).max(link_width + 4), code_height + 6);
        if framed.0 <= area.width && framed.1 <= area.height {
            let inner = dialog(frame, area, title, framed.0, framed.1);
            return self.draw_code(frame, inner, false, true);
        }

        // Edge to edge: the title moves beside the code, and the link takes the rows it needs.
        let bare_width = code_width + 3 + SIDE_MIN;
        let bare_height =
            |width: u16| code_height + rows_of(&self.link, width.into()).len() as u16 + 1;
        if bare_width <= area.width && bare_height(area.width) <= area.height {
            return self.draw_code(frame, area, true, false);
        }

        // A clipped code does not scan: show none rather than half of one.
        let width = (link_width + 4).max(60);
        let link = rows_of(&self.link, super::text_width(width, area));
        let mut lines: Vec<Line> = vec!["Send the device this link:".into(), Line::default()];
        let link_rows = link.len();
        lines.extend(link.into_iter().map(|row| Line::from(row.cyan())));
        lines.push(Line::default());
        // The explanation, without the line about scanning: there is nothing to scan.
        lines.extend(self.side(false, link_rows).into_iter().skip(2));
        lines.push(Line::default());
        lines.push(
            format!(
                "Make the terminal at least {} by {} to see its QR code.",
                bare_width,
                bare_height(area.width.max(bare_width))
            )
            .fg(Color::Yellow)
            .into(),
        );
        let text = Paragraph::new(lines).wrap(Wrap { trim: false });
        let rows = text.line_count(super::text_width(width, area) as u16) as u16;
        let inner = dialog(frame, area, title, width, rows + 4);
        let body = Rect {
            height: inner.height.saturating_sub(1),
            ..inner
        };
        frame.render_widget(text, body);
        frame.render_widget(Paragraph::new(hint_line(&self.hints())), last_row(inner));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    const LINK: &str =
        "https://k.domaci.ivankovic.me/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn dialog_for(link: &str) -> InviteDialog {
        InviteDialog::new(
            Serial([1; 16]),
            "Anna (phone)".into(),
            link.to_owned(),
            "Works once".into(),
        )
    }

    fn drawn(dialog: &mut InviteDialog, width: u16, height: u16) -> String {
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

    fn screen(width: u16, height: u16) -> String {
        drawn(&mut dialog_for(LINK), width, height)
    }

    fn press(dialog: &mut InviteDialog, c: char) -> Option<Action> {
        dialog.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    #[test]
    fn the_link_is_whole_on_one_line() {
        let screen = screen(100, 40);
        assert!(screen.contains(LINK), "{screen}");
        assert!(screen.contains("▀▀▀"), "{screen}");
        assert!(screen.contains("╭ Invite for Anna (phone)"), "{screen}");
    }

    /// 80 by 24 is what an SSH session opens at: the code fits, with the link whole under it.
    #[test]
    fn the_code_fits_a_plain_80_by_24_terminal() {
        let screen = screen(80, 24);
        assert!(screen.contains("▀▀▀"), "{screen}");
        assert!(screen.contains(LINK), "{screen}");
        assert!(screen.contains("Invite for Anna (phone)"), "{screen}");
        assert!(screen.contains("Works once"), "{screen}");
        assert!(screen.contains("Enter close"), "{screen}");
    }

    /// A longer host name makes a longer link and a larger code: 80 by 24 still shows both, the
    /// link on two rows and nothing of it lost.
    #[test]
    fn a_link_wider_than_the_screen_continues_on_the_next_row() {
        let link = "https://enrollment.family-name.example.org/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(link.len() > 80);
        let screen = drawn(&mut dialog_for(link), 80, 24);
        assert!(screen.contains("▀▀▀"), "{screen}");
        let rows: Vec<&str> = screen.lines().collect();
        let first = rows.iter().position(|r| r.starts_with("https://")).unwrap();
        let shown = format!("{}{}", rows[first], rows[first + 1].trim_end());
        assert_eq!(shown, link, "{screen}");
        assert!(screen.contains("The link takes 2 rows here"), "{screen}");
        assert!(screen.contains("Enter close"), "{screen}");
    }

    #[test]
    fn a_terminal_too_small_for_the_code_gets_the_link_and_why() {
        let screen = screen(80, 20);
        assert!(!screen.contains('▀'), "no clipped code:\n{screen}");
        assert!(screen.contains(LINK), "{screen}");
        assert!(
            screen.contains("Make the terminal at least 64 by 21"),
            "{screen}"
        );
        assert!(screen.contains("Enter close"), "{screen}");
    }

    /// Without the code, a link wider than the dialog is still shown whole, over two rows.
    #[test]
    fn without_the_code_a_long_link_is_still_whole() {
        let screen = screen(60, 20);
        assert!(!screen.contains('▀'), "{screen}");
        let shown: String = screen
            .lines()
            .filter_map(|row| row.strip_prefix("│ "))
            .map(|row| row.trim_end_matches(['│', ' ']))
            .filter(|row| row.starts_with("https://") || row.starts_with('A'))
            .collect();
        assert_eq!(shown, LINK, "{screen}");
        assert!(screen.contains("The link takes 2 rows here"), "{screen}");
    }

    /// The dialog covers the line that says what a key did, so it says so itself.
    #[test]
    fn copying_says_so_in_the_dialog() {
        let mut dialog = dialog_for(LINK);
        assert!(!drawn(&mut dialog, 80, 24).contains("copied"));
        assert_eq!(press(&mut dialog, 'c'), Some(Action::Copy(LINK.to_owned())));
        let screen = drawn(&mut dialog, 80, 24);
        assert!(screen.contains("✓ Link copied"), "{screen}");
    }

    #[test]
    fn a_password_is_shown_and_copied_with_p() {
        let mut dialog = dialog_for(LINK);
        assert_eq!(press(&mut dialog, 'p'), None, "no password, no key for it");
        assert!(!drawn(&mut dialog, 80, 24).contains("p copy password"));
        let mut dialog = dialog_for(LINK).with_password(Some("abcd-efgh-ijkl-mnop".into()));
        for (width, height) in [(80, 24), (100, 40), (80, 20)] {
            let screen = drawn(&mut dialog, width, height);
            assert!(screen.contains("Password: abcd-efgh-ijkl-mnop"), "{screen}");
            assert!(
                screen.contains("c copy link  p copy password  Enter close"),
                "{screen}"
            );
        }
        assert_eq!(
            press(&mut dialog, 'p'),
            Some(Action::Copy("abcd-efgh-ijkl-mnop".into()))
        );
        let screen = drawn(&mut dialog, 80, 24);
        assert!(screen.contains("✓ Password copied"), "{screen}");
    }

    /// A collected invite's code leads nowhere: the dialog says what happened instead.
    #[test]
    fn a_closed_invite_shows_what_became_of_it_instead_of_the_code() {
        let mut dialog = dialog_for(LINK);
        dialog.close("Collected just now, from iPhone at 203.0.113.7.".into());
        let screen = drawn(&mut dialog, 80, 24);
        assert!(!screen.contains('▀'), "{screen}");
        assert!(!screen.contains("https://"), "{screen}");
        assert!(
            screen.contains("Collected just now, from iPhone at 203.0.113.7."),
            "{screen}"
        );
        assert!(!screen.contains("copy link"), "{screen}");
        assert_eq!(press(&mut dialog, 'c'), None);
        assert_eq!(press(&mut dialog, 'q'), Some(Action::CloseDialog));
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
