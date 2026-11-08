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
//! The Users tab: the HTTP logins nginx checks itself, and the sites that let each in.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use super::{Component, Hint, step};
use crate::tui::action::Action;

/// A user as the tab shows them: name, when the password last changed, and the sites that let
/// them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub changed: String,
    pub sites: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct UsersTab {
    rows: Vec<Row>,
    selected: usize,
}

impl UsersTab {
    pub fn update(&mut self, rows: Vec<Row>) {
        self.rows = rows;
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
    }

    /// Moves the selection to `name`, if there is such a user.
    pub fn select(&mut self, name: &str) {
        if let Some(i) = self.rows.iter().position(|r| r.name == name) {
            self.selected = i;
        }
    }

    fn selected(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    pub fn hints(&self) -> Vec<Hint> {
        let mut hints = vec![("n", "new user")];
        if self.selected().is_some() {
            hints.push(("c", "change password"));
            hints.push(("d", "delete"));
        }
        hints
    }
}

impl Component for UsersTab {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('n') => return Some(Action::AskNewUser),
            KeyCode::Char('c') => {
                return self
                    .selected()
                    .map(|r| Action::AskNewPassword(r.name.clone()));
            }
            KeyCode::Char('d') => {
                return self
                    .selected()
                    .map(|r| Action::AskDeleteUser(r.name.clone()));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, false, self.rows.len())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, true, self.rows.len())
            }
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let about: Vec<Line> = vec![
            Line::default(),
            "  Logins nginx checks itself, on a site whose HTTP login is on (the Nginx tab, l)."
                .into(),
            "  A site that passes logins through checks them itself: its users are its own."
                .dim()
                .into(),
        ];
        let [top, list] = Layout::vertical([
            Constraint::Length(about.len() as u16 + 1),
            Constraint::Min(3),
        ])
        .areas(area);
        frame.render_widget(Paragraph::new(about), top);
        let block = Block::default()
            .title(" Users ")
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .border_style(Style::new().dim());
        let items: Vec<ListItem> = if self.rows.is_empty() {
            vec![ListItem::new(" No users yet: n adds one.".dim())]
        } else {
            self.rows
                .iter()
                .map(|row| {
                    let sites = if row.sites.is_empty() {
                        "no site lets them in".to_owned()
                    } else {
                        row.sites.join(", ")
                    };
                    ListItem::new(Line::from(vec![
                        format!(" {:<24}", row.name).into(),
                        format!("password from {:<14}", row.changed).dim(),
                        sites.into(),
                    ]))
                })
                .collect()
        };
        let selected = (!self.rows.is_empty()).then_some(self.selected);
        frame.render_stateful_widget(
            List::new(items)
                .block(block)
                .highlight_style(Style::new().reversed()),
            list,
            &mut ListState::default().with_selected(selected),
        );
    }
}
