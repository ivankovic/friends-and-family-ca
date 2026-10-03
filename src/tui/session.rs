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
//! What the UI shows from start to finish: setting up the CA when there is none, the CA once
//! there is one, or what keeps it from opening. `ffca tui` always opens; the administrator never
//! needs the command line to get started.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};
use time::OffsetDateTime;

use super::action::Action;
use super::app::App;
use super::components::form::Form;
use super::components::{Component, hint_line};
use crate::ca::{self, Ca};
use crate::store::Store;

enum Stage {
    /// No CA yet: the form that creates one.
    Setup(Form),
    /// A CA that cannot be opened, and why.
    Unusable(String),
    Ready(Box<App>),
}

pub struct Session {
    store: Store,
    out: PathBuf,
    now: OffsetDateTime,
    stage: Stage,
    quit: bool,
}

impl Session {
    pub fn new(store: Store, out: PathBuf, now: OffsetDateTime) -> Session {
        let stage = if !store.exists(ca::CERTIFICATE_FILE) {
            Stage::Setup(Form::create_ca(&default_name(), setup_note(&store)))
        } else {
            match Ca::open(&store) {
                Ok(ca) => Stage::Ready(Box::new(App::new(ca, out.clone(), now))),
                Err(error) => Stage::Unusable(format!("{error:#}")),
            }
        };
        Session {
            store,
            out,
            now,
            stage,
            quit: false,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.quit || matches!(&self.stage, Stage::Ready(app) if app.should_quit())
    }

    pub fn reload(&mut self, now: OffsetDateTime) {
        self.now = now;
        if let Stage::Ready(app) = &mut self.stage {
            app.reload(now);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, now: OffsetDateTime) {
        self.now = now;
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        match &mut self.stage {
            Stage::Ready(app) => app.handle_key(key, now),
            Stage::Unusable(_) => {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                    self.quit = true;
                }
            }
            Stage::Setup(form) => match form.handle_key_event(key) {
                Some(Action::CloseDialog) => self.quit = true,
                Some(Action::CreateCa { name, years }) => self.create(name, &years),
                _ => {}
            },
        }
    }

    fn create(&mut self, name: String, years: &str) {
        let Stage::Setup(form) = &mut self.stage else {
            return;
        };
        let years = match years.parse::<u16>() {
            Ok(years) if (1..=ca::MAX_CA_YEARS).contains(&years) => years,
            _ => {
                return form.set_error(format!(
                    "The validity is a whole number of years, 1 to {}.",
                    ca::MAX_CA_YEARS
                ));
            }
        };
        match Ca::create(&self.store, &name, self.now, ca::years(years)) {
            Ok(ca) => {
                let mut app = App::new(ca, self.out.clone(), self.now);
                app.welcome();
                self.stage = Stage::Ready(Box::new(app));
            }
            Err(error) => {
                let denied = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
                });
                let mut text = format!("{error:#}");
                if denied {
                    text.push_str(
                        ". Run ffca as root (sudo), or give it a folder you own with --state-dir or FFCA_STATE_DIR.",
                    );
                }
                form.set_error(text);
            }
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        if let Stage::Ready(app) = &mut self.stage {
            return app.draw(frame);
        }
        let [title, body, hints] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        frame.render_widget(Paragraph::new(" Friends and Family CA".bold()), title);
        let hints = ratatui::layout::Rect {
            x: hints.x + 1,
            width: hints.width.saturating_sub(1),
            ..hints
        };
        match &mut self.stage {
            Stage::Setup(form) => {
                let text = vec![
                    Line::default(),
                    format!("  There is no CA in {} yet.", self.store.dir().display()).into(),
                    Line::default(),
                    "  Name it the way devices will show it among their installed certificates. Every".into(),
                    "  certificate it issues expires by the end of its validity.".into(),
                ];
                frame.render_widget(Paragraph::new(text), body);
                let [_, below] =
                    Layout::vertical([Constraint::Length(6), Constraint::Min(3)]).areas(body);
                form.draw(frame, below);
                frame.render_widget(Paragraph::new(hint_line(&[("Esc", "quit")])), hints);
            }
            Stage::Unusable(error) => {
                let text = vec![
                    Line::default(),
                    format!("  The CA in {} cannot be opened:", self.store.dir().display()).into(),
                    Line::default(),
                    format!("  {error}").fg(Color::Red).into(),
                    Line::default(),
                    "  ffca changes nothing here. Restore the folder from a backup, or move it away to start a new CA."
                        .into(),
                ];
                frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), body);
                frame.render_widget(Paragraph::new(hint_line(&[("q", "quit")])), hints);
            }
            Stage::Ready(_) => unreachable!("drawn above"),
        }
    }

    #[cfg(test)]
    fn app(&mut self) -> Option<&mut App> {
        match &mut self.stage {
            Stage::Ready(app) => Some(app),
            _ => None,
        }
    }
}

/// Where the CA will be created, and how to choose another place.
fn setup_note(store: &Store) -> String {
    format!(
        "Creates the CA's key and certificate in {}. Another folder: --state-dir or FFCA_STATE_DIR.",
        store.dir().display()
    )
}

/// The machine's name, capitalised: "domaci" becomes "Domaci". Only a suggestion.
fn default_name() -> String {
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let host = host.trim();
    let mut chars = host.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Family".to_owned(),
    }
}

#[cfg(test)]
mod tests;
