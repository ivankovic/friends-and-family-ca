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
//! The Nginx tab: how ffca reaches nginx, the enrollment site, and every site's client-certificate
//! mode.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use super::{Component, Hint, step};
use crate::config;
use crate::nginx::{Mode, Site, Survey};
use crate::tui::action::Action;

/// What the tab shows: the settings, what DNS says about the enrollment site, and the sites.
#[derive(Debug, Default, Clone)]
pub struct NginxTab {
    settings: Option<config::Nginx>,
    enrollment: Option<String>,
    /// The enrollment site's addresses, or why it has none.
    dns: Option<Result<String, String>>,
    survey: Option<Result<Survey, String>>,
    selected: usize,
}

impl NginxTab {
    pub fn update(
        &mut self,
        settings: Option<config::Nginx>,
        enrollment: Option<String>,
        dns: Option<Result<String, String>>,
        survey: Option<Result<Survey, String>>,
    ) {
        self.settings = settings;
        self.enrollment = enrollment;
        self.dns = dns;
        self.survey = survey;
        self.selected = self.selected.min(self.sites().len().saturating_sub(1));
    }

    fn sites(&self) -> &[Site] {
        match &self.survey {
            Some(Ok(survey)) => &survey.sites,
            _ => &[],
        }
    }

    pub fn selected_site(&self) -> Option<&Site> {
        self.sites().get(self.selected)
    }

    pub fn hints(&self) -> Vec<Hint> {
        let mut hints = vec![("e", "settings")];
        if self.settings.is_some() {
            if !self.sites().is_empty() {
                hints.push(("s", "client certificate"));
            }
            hints.push(("t", "test"));
            let written = self.sites().iter().any(|s| self.is_enrollment(s));
            if self.enrollment.is_some() {
                hints.push((
                    "w",
                    if written {
                        "rewrite enrollment site"
                    } else {
                        "write enrollment site"
                    },
                ));
            }
        }
        hints
    }

    fn is_enrollment(&self, site: &Site) -> bool {
        self.enrollment
            .as_deref()
            .is_some_and(|host| site.serves(host))
    }

    fn summary(&self) -> Vec<Line<'static>> {
        let row = |label: &str, value: String| -> Line<'static> {
            vec![format!("  {label:<16}").dim(), value.into()].into()
        };
        let Some(settings) = &self.settings else {
            return vec![
                Line::default(),
                "  ffca does not know where nginx is yet.".into(),
                Line::default(),
                vec![
                    "  Press ".into(),
                    "e".bold(),
                    " to say where its sites are and how to reload it. Until then, a revoked"
                        .into(),
                ]
                .into(),
                "  certificate stays valid for nginx: it never sees the new revocation list."
                    .into(),
            ];
        };
        let mut lines = vec![
            Line::default(),
            row("Sites", format!("{}/*.conf", settings.sites.display())),
            row(
                "CA files",
                format!(
                    "{}  (nginx reads {})",
                    settings.ca_files.display(),
                    settings.ca_files_in_nginx.display()
                ),
            ),
            row("Test", settings.test.clone()),
            row("Reload", settings.reload.clone()),
        ];
        let enrollment = match (&self.enrollment, &self.dns) {
            (None, _) => Line::from(vec![
                "  Enrollment      ".dim(),
                "not chosen: press e and name the site invites will open".fg(Color::Yellow),
            ]),
            (Some(host), Some(Ok(addresses))) => Line::from(vec![
                "  Enrollment      ".dim(),
                host.clone().into(),
                format!("  resolves to {addresses}").dim(),
            ]),
            (Some(host), Some(Err(error))) => Line::from(vec![
                "  Enrollment      ".dim(),
                host.clone().into(),
                format!("  {error}").fg(Color::Yellow),
            ]),
            (Some(host), None) => Line::from(vec!["  Enrollment      ".dim(), host.clone().into()]),
        };
        lines.push(enrollment);
        lines
    }

    fn item(&self, site: &Site) -> ListItem<'static> {
        let (symbol, color) = match site.mode {
            Mode::Off => ("○", Color::DarkGray),
            Mode::Optional => ("◐", Color::Yellow),
            Mode::Required => ("●", Color::Green),
        };
        let mut note = String::new();
        if self.is_enrollment(site) {
            note.push_str("  enrollment site: never asks");
        } else if site.mode != Mode::Off && !site.uses_ca {
            note.push_str("  another CA's certificate");
        }
        if site.any_issuer {
            note.push_str("  optional_no_ca: any issuer gets in");
        }
        if site.duplicate {
            note.push_str("  another block has this name: nginx ignores one");
        }
        ListItem::new(Line::from(vec![
            format!(" {:<34}", site.name()).into(),
            format!("{:<22}", site.file_name()).dim(),
            Span::styled(symbol, Style::new().fg(color)),
            format!(" {}", site.mode).into(),
            note.dim(),
        ]))
    }
}

impl Component for NginxTab {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('e') => return Some(Action::AskNginxSettings),
            KeyCode::Char('t') if self.settings.is_some() => return Some(Action::TestNginx),
            KeyCode::Char('w') if self.settings.is_some() && self.enrollment.is_some() => {
                return Some(Action::AskEnrollmentSite);
            }
            KeyCode::Char('s') => return self.selected_site().cloned().map(Action::AskSiteMode),
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, false, self.sites().len())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, true, self.sites().len())
            }
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        let summary = self.summary();
        let [top, sites] = Layout::vertical([
            Constraint::Length(summary.len() as u16 + 1),
            Constraint::Min(3),
        ])
        .areas(area);
        frame.render_widget(Paragraph::new(summary), top);
        if self.settings.is_none() {
            return;
        }
        let block = Block::default()
            .title(" Sites ")
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .border_style(Style::new().dim());
        match &self.survey {
            Some(Ok(survey)) => {
                let mut items: Vec<ListItem> = survey.sites.iter().map(|s| self.item(s)).collect();
                if items.is_empty() {
                    items.push(ListItem::new(
                        " No HTTPS server blocks in these files.".dim(),
                    ));
                }
                items.extend(
                    survey
                        .problems
                        .iter()
                        .map(|p| ListItem::new(Line::from(format!(" {p}").fg(Color::Red)))),
                );
                let list = List::new(items)
                    .block(block)
                    .highlight_style(Style::new().reversed());
                let selected = (!survey.sites.is_empty()).then_some(self.selected);
                frame.render_stateful_widget(
                    list,
                    sites,
                    &mut ListState::default().with_selected(selected),
                );
            }
            Some(Err(error)) => {
                let text = Paragraph::new(Line::from(format!(" {error}").fg(Color::Red)))
                    .block(block)
                    .wrap(Wrap { trim: false });
                frame.render_widget(text, sites);
            }
            None => frame.render_widget(block, sites),
        }
    }
}
