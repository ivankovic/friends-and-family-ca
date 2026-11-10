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
//! A dialog of one or more text fields: a new device, a new agent, a new name.
//!
//! A field has one row, however long its value: a value wider than its row shows the part around
//! the cursor, with an ellipsis where it is cut. The message under the fields - the note, or why
//! the last submission was refused - has rows of its own, kept even on a screen too short for
//! every field.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::{Component, dialog, hint_line, text_width};
use crate::tui::action::{Action, Selection};

/// What the form is for, which decides the action its fields become.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    CreateCa,
    NginxSettings,
    NewPerson,
    NewDevice,
    NewAgent,
    Rename(Selection),
    NewUser,
    /// A new password for this user.
    NewPassword(String),
}

/// How a device's certificate reaches it.
const PASSWORD_NOTE: &str = "Leave the password empty to have one made up: 24 letters and digits, shown once. One typed here is at least 12 characters, and should be used nowhere else: nginx's password files are readable on this machine.";

const DELIVERY: &str = "With an enrollment site (on the Nginx tab), the device gets an invite to scan; without one, the certificate and its key are written to files.";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    label: &'static str,
    value: String,
    /// In characters, not bytes: names are not ASCII.
    cursor: usize,
    /// A password: shown as dots, and taken as typed, spaces and all.
    secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    title: String,
    purpose: Purpose,
    fields: Vec<Field>,
    focus: usize,
    note: Option<String>,
    error: Option<String>,
}

impl Form {
    /// The CA's name and validity; `note` says where it will live.
    pub fn create_ca(name: &str, note: String) -> Form {
        let mut form = Form::new(
            "Create the CA".into(),
            Purpose::CreateCa,
            &[("Name", name), ("Valid for, in years", "10")],
        );
        form.note = Some(note);
        form
    }

    /// How to reach nginx, and the enrollment site; starts from `values`, in the fields' order.
    pub fn nginx_settings(values: [String; 8]) -> Form {
        let labels = [
            "Site configs",
            "CA files, here",
            "CA files, in nginx",
            "Test command",
            "Reload command",
            "Enrollment site",
            "Enrollment page at",
            "Page runs as",
        ];
        let fields: Vec<(&'static str, &str)> = labels
            .iter()
            .copied()
            .zip(values.iter().map(String::as_str))
            .collect();
        let mut form = Form::new("nginx".into(), Purpose::NginxSettings, &fields);
        form.note = Some(
            "If nginx runs in a container, give the CA files' folder as this machine sees it and as nginx does. The enrollment site is a host name, such as k.example.org; the page is where nginx finds ffca serve, running as uid:gid."
                .into(),
        );
        form
    }

    pub fn new_person() -> Form {
        let mut form = Form::new(
            "New person".into(),
            Purpose::NewPerson,
            &[("Person", ""), ("First device", "")],
        );
        form.note = Some(DELIVERY.into());
        form
    }

    pub fn new_device(person: &str) -> Form {
        let mut form = Form::new(
            "New device".into(),
            Purpose::NewDevice,
            &[("Person", person), ("Device", "")],
        );
        form.focus = usize::from(!person.is_empty());
        form.note = Some(DELIVERY.into());
        form
    }

    pub fn new_agent() -> Form {
        let mut form = Form::new("New agent".into(), Purpose::NewAgent, &[("Agent", "")]);
        form.note = Some("A program or machine that signs in as itself. To keep its key on its own machine, use `ffca issue --agent … --csr` instead.".into());
        form
    }

    pub fn rename(selection: Selection) -> Form {
        let title = format!("Rename {selection}");
        let name = selection.name().to_owned();
        let mut form = Form::new(title, Purpose::Rename(selection), &[("New name", &name)]);
        form.note = Some("Certificates already issued keep the old name.".into());
        form
    }

    /// A new HTTP login: its name, and a password or none to have one made up.
    pub fn new_user() -> Form {
        let mut form = Form::new(
            "New user".into(),
            Purpose::NewUser,
            &[("Name", ""), ("Password", "")],
        );
        form.fields[1].secret = true;
        form.note = Some(PASSWORD_NOTE.into());
        form
    }

    pub fn new_password(name: &str) -> Form {
        let mut form = Form::new(
            format!("New password for {name}"),
            Purpose::NewPassword(name.to_owned()),
            &[("Password", "")],
        );
        form.fields[0].secret = true;
        form.note = Some(PASSWORD_NOTE.into());
        form
    }

    fn new(title: String, purpose: Purpose, fields: &[(&'static str, &str)]) -> Form {
        Form {
            title,
            purpose,
            fields: fields
                .iter()
                .map(|(label, value)| Field {
                    label,
                    value: (*value).to_owned(),
                    cursor: value.chars().count(),
                    secret: false,
                })
                .collect(),
            focus: 0,
            note: None,
            error: None,
        }
    }

    /// Shows why the last submission was refused; the form stays open to fix it.
    pub fn set_error(&mut self, error: String) {
        self.error = Some(error);
    }

    pub fn purpose(&self) -> &Purpose {
        &self.purpose
    }

    fn submit(&self) -> Action {
        let value = |i: usize| self.fields[i].value.trim().to_owned();
        match &self.purpose {
            Purpose::CreateCa => Action::CreateCa {
                name: value(0),
                years: value(1),
            },
            Purpose::NginxSettings => {
                Action::SaveNginxSettings((0..self.fields.len()).map(value).collect())
            }
            Purpose::NewPerson => Action::IssueToNewPerson(Selection::Device {
                person: value(0),
                device: value(1),
            }),
            Purpose::NewDevice => Action::Issue(Selection::Device {
                person: value(0),
                device: value(1),
            }),
            Purpose::NewAgent => Action::Issue(Selection::Agent(value(0))),
            Purpose::Rename(selection) => Action::Rename(selection.clone(), value(0)),
            Purpose::NewUser => Action::AddUser {
                name: value(0),
                password: self.fields[1].value.clone(),
            },
            Purpose::NewPassword(name) => Action::SetPassword {
                name: name.clone(),
                password: self.fields[0].value.clone(),
            },
        }
    }

    fn field(&mut self) -> &mut Field {
        &mut self.fields[self.focus]
    }
}

impl Field {
    fn byte_at(&self, cursor: usize) -> usize {
        self.value
            .char_indices()
            .nth(cursor)
            .map_or(self.value.len(), |(i, _)| i)
    }

    /// What shows of the value in `room` columns, and how many of the characters shown come
    /// before the cursor. The last column is kept for a cursor past the end; a value longer than
    /// the rest shows the part around the cursor - its start, when the field is not `focused` -
    /// with an ellipsis at each end that is cut.
    fn window(&self, room: usize, focused: bool) -> (String, usize) {
        let chars: Vec<char> = if self.secret {
            vec!['•'; self.value.chars().count()]
        } else {
            self.value.chars().collect()
        };
        let visible = room.saturating_sub(1);
        if chars.len() <= visible {
            return (chars.into_iter().collect(), self.cursor);
        }
        if visible == 0 {
            return (String::new(), 0);
        }
        let cursor = if focused { self.cursor } else { 0 };
        let last_start = chars.len() - visible;
        // A character still shows after the cursor, before the ellipsis.
        let start = if cursor + 2 <= visible {
            0
        } else if cursor == chars.len() {
            last_start
        } else {
            (cursor + 2 - visible).min(last_start)
        };
        let mut shown = chars[start..start + visible].to_vec();
        if start > 0 {
            shown[0] = '…';
        }
        if start < last_start {
            shown[visible - 1] = '…';
        }
        (shown.into_iter().collect(), cursor - start)
    }
}

impl Component for Form {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            // The line-editing keys of a shell: a default path is cleared with one, not dozens.
            if key.code == KeyCode::Char('s') {
                return Some(self.submit());
            }
            let field = self.field();
            match key.code {
                KeyCode::Char('a') => field.cursor = 0,
                KeyCode::Char('e') => field.cursor = field.value.chars().count(),
                KeyCode::Char('u') => {
                    let at = field.byte_at(field.cursor);
                    field.value.replace_range(..at, "");
                    field.cursor = 0;
                }
                KeyCode::Char('w') => {
                    let before: Vec<char> = field.value.chars().take(field.cursor).collect();
                    let kept = before.len()
                        - before
                            .iter()
                            .rev()
                            .take_while(|c| c.is_whitespace())
                            .count();
                    let word = before[..kept]
                        .iter()
                        .rev()
                        .take_while(|c| !c.is_whitespace() && **c != '/')
                        .count();
                    // A word ends at a slash too, so a path loses one folder at a time.
                    let start = if word == 0 && kept > 0 {
                        kept - 1
                    } else {
                        kept - word
                    };
                    let (from, to) = (field.byte_at(start), field.byte_at(field.cursor));
                    field.value.replace_range(from..to, "");
                    field.cursor = start;
                }
                _ => {}
            }
            return None;
        }
        match key.code {
            KeyCode::Esc => return Some(Action::CloseDialog),
            KeyCode::Enter if self.focus + 1 < self.fields.len() => self.focus += 1,
            KeyCode::Enter => return Some(self.submit()),
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % self.fields.len(),
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.fields.len() - 1) % self.fields.len();
            }
            KeyCode::Left => self.field().cursor = self.field().cursor.saturating_sub(1),
            KeyCode::Right => {
                let field = self.field();
                field.cursor = (field.cursor + 1).min(field.value.chars().count());
            }
            KeyCode::Home => self.field().cursor = 0,
            KeyCode::End => {
                let field = self.field();
                field.cursor = field.value.chars().count();
            }
            KeyCode::Backspace => {
                let field = self.field();
                if field.cursor > 0 {
                    let at = field.byte_at(field.cursor - 1);
                    field.value.remove(at);
                    field.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                let field = self.field();
                if field.cursor < field.value.chars().count() {
                    let at = field.byte_at(field.cursor);
                    field.value.remove(at);
                }
            }
            KeyCode::Char(c) => {
                let field = self.field();
                let at = field.byte_at(field.cursor);
                field.value.insert(at, c);
                field.cursor += 1;
                self.error = None;
            }
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        const WIDTH: u16 = 72;
        // The message under the fields wraps; the dialog grows to show all of it.
        let message: Line = match (&self.error, &self.note) {
            (Some(error), _) => format!("✕ {error}").fg(Color::Red).into(),
            (None, Some(note)) => note.clone().dim().into(),
            (None, None) => Line::default(),
        };
        let message = Paragraph::new(message).wrap(Wrap { trim: false });
        let message_rows = (message.line_count(text_width(WIDTH, area) as u16) as u16).max(1);
        let fields = self.fields.len() as u16;
        // On a short screen the fields lose the blank rows between them, so that the message and
        // the hints still show.
        let spaced = 2 * fields + 5 + message_rows <= area.height;
        let rows_per_field: u16 = if spaced { 2 } else { 1 };
        let height = rows_per_field * fields + 5 + message_rows;
        let inner = dialog(frame, area, self.title.clone(), WIDTH, height);
        let hints = Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        };
        // Spaced, the message follows the last field's blank row and a blank row follows it;
        // otherwise it ends where the hints begin, and on a screen too short for all of this it
        // is the fields that give way.
        let message_y = if spaced {
            inner.y + 1 + rows_per_field * fields
        } else {
            hints.y.saturating_sub(message_rows).max(inner.y)
        };
        let message_area = Rect {
            y: message_y,
            height: message_rows.min(hints.y.saturating_sub(message_y)),
            ..inner
        };
        let label_width = self.fields.iter().map(|f| f.label.len()).max().unwrap_or(0) + 2;
        let room = usize::from(inner.width).saturating_sub(label_width);
        for (i, field) in self.fields.iter().enumerate() {
            let y = inner.y + 1 + rows_per_field * i as u16;
            if y >= message_area.y {
                break;
            }
            let label = format!("{:<label_width$}", field.label);
            let focused = i == self.focus;
            let label = if focused { label.bold() } else { label.dim() };
            let (shown, before) = field.window(room, focused);
            if focused {
                let before: String = shown.chars().take(before).collect();
                let x = inner.x + label_width as u16 + unicode_width(&before);
                frame.set_cursor_position(Position::new(x.min(inner.right().saturating_sub(1)), y));
            }
            let row = Rect {
                y,
                height: 1,
                ..inner
            };
            frame.render_widget(Paragraph::new(Line::from(vec![label, shown.into()])), row);
        }
        frame.render_widget(message, message_area);
        // Without a CA there is nothing to go back to: Esc leaves.
        let escape = if self.purpose == Purpose::CreateCa {
            "quit"
        } else {
            "cancel"
        };
        let enter = if self.focus + 1 < self.fields.len() {
            "next"
        } else {
            "done"
        };
        let mut keys = vec![("Enter", enter)];
        if enter == "next" {
            keys.push(("Ctrl-S", "done"));
        }
        keys.extend([("Tab", "field"), ("Esc", escape)]);
        frame.render_widget(Paragraph::new(hint_line(&keys)), hints);
    }
}

fn unicode_width(text: &str) -> u16 {
    ratatui::text::Span::from(text).width() as u16
}
