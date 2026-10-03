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
//! A dialog of one or more text fields: a new device, a new agent, a new name.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{Component, dialog, hint_line};
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
}

/// How a device's certificate reaches it.
const DELIVERY: &str = "With an enrollment site (on the Nginx tab), the device gets an invite to scan; without one, the certificate and its key are written to files.";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    label: &'static str,
    value: String,
    /// In characters, not bytes: names are not ASCII.
    cursor: usize,
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
}

impl Component for Form {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
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
        // The message under the fields wraps; the dialog grows to show all of it. Inside are the
        // borders and a column of padding on each side.
        let message = self.error.as_ref().or(self.note.as_ref());
        let message_lines = message.map_or(1, |m| {
            ratatui::text::Span::from(m.as_str())
                .width()
                .div_ceil(usize::from(WIDTH) - 4)
                .max(1)
        });
        let height = 2 * self.fields.len() as u16 + 5 + message_lines as u16;
        let inner = dialog(frame, area, self.title.clone(), WIDTH, height);
        let label_width = self.fields.iter().map(|f| f.label.len()).max().unwrap_or(0) + 2;
        let mut lines = vec![Line::default()];
        for (i, field) in self.fields.iter().enumerate() {
            let label = format!("{:<label_width$}", field.label);
            let label = if i == self.focus {
                label.bold()
            } else {
                label.dim()
            };
            lines.push(vec![label, field.value.clone().into()].into());
            lines.push(Line::default());
        }
        match (&self.error, &self.note) {
            (Some(error), _) => lines.push(error.clone().fg(Color::Red).into()),
            (None, Some(note)) => lines.push(note.clone().dim().into()),
            (None, None) => lines.push(Line::default()),
        }
        let paragraph = Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false });
        frame.render_widget(paragraph, inner);
        let hints = Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        };
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
        frame.render_widget(
            Paragraph::new(hint_line(&[
                ("Enter", enter),
                ("Tab", "field"),
                ("Esc", escape),
            ])),
            hints,
        );
        let field = &self.fields[self.focus];
        let before: String = field.value.chars().take(field.cursor).collect();
        let x = inner.x + label_width as u16 + unicode_width(&before);
        let y = inner.y + 1 + 2 * self.focus as u16;
        frame.set_cursor_position(Position::new(x.min(inner.right().saturating_sub(1)), y));
    }
}

fn unicode_width(text: &str) -> u16 {
    ratatui::text::Span::from(text).width() as u16
}
