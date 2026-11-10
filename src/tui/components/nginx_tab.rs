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
//! The Nginx tab: how ffca reaches nginx, the enrollment site, and every site's two gates: its
//! client-certificate mode and its HTTP login.
//!
//! What is unusual about a site is a word or two in its row, and a sentence under the list while
//! the site is selected: the row has no room for the sentence on 80 columns.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use super::{Component, Hint, fit, hang, step};
use crate::config;
use crate::nginx::{Auth, Mode, Site, Survey};
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
    /// How far the list is scrolled, kept between draws.
    list: ListState,
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
                hints.push(("l", "login"));
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

    /// What is unusual about a site: a word or two for its row, and the sentence that explains
    /// them.
    fn notes(&self, site: &Site) -> Vec<(&'static str, String)> {
        let name = site.name();
        let mut notes = Vec::new();
        if self.is_enrollment(site) {
            notes.push((
                "enrollment site",
                format!(
                    "{name} is the enrollment site: it never asks for a certificate or a login."
                ),
            ));
        } else if site.mode != Mode::Off && !site.uses_ca {
            notes.push((
                "another CA",
                format!("{name} asks for a certificate of another CA, not this one's."),
            ));
        }
        if site.any_issuer {
            notes.push((
                "any issuer",
                format!("{name} has optional_no_ca: a certificate of any issuer gets in."),
            ));
        }
        if site.foreign_auth {
            notes.push((
                "own login",
                format!("{name} has a login that ffca did not write."),
            ));
        }
        if site.duplicate {
            notes.push((
                "duplicate",
                format!("Another server block has the name {name}: nginx ignores one of them."),
            ));
        }
        notes
    }

    /// A site's row in a list `width` wide: its file's name is left out when the row would not
    /// otherwise have room for its notes, which matter more.
    fn item(&self, site: &Site, width: usize) -> ListItem<'static> {
        let (symbol, color) = match site.mode {
            Mode::Off => ("○", Color::DarkGray),
            Mode::Optional => ("◐", Color::Yellow),
            Mode::Required => ("●", Color::Green),
        };
        let note: String = self
            .notes(site)
            .iter()
            .map(|(word, _)| format!("  {word}"))
            .collect();
        let name_width = self
            .sites()
            .iter()
            .map(|s| s.name().chars().count() + 2)
            .max()
            .unwrap_or(0)
            .min(if width >= 100 { 34 } else { 30 });
        let file = if width >= 100 {
            format!("{:<22}", site.file_name())
        } else {
            String::new()
        };
        ListItem::new(Line::from(vec![
            format!(
                " {:<name_width$}",
                fit(site.name(), name_width.saturating_sub(1))
            )
            .into(),
            file.dim(),
            Span::styled(symbol, Style::new().fg(color)),
            format!(" {:<10}", site.mode.to_string()).into(),
            match site.auth {
                Auth::Off => "login off".dim(),
                _ => format!("login {}", site.auth).into(),
            },
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
            KeyCode::Char('l') => return self.selected_site().cloned().map(Action::AskSiteAuth),
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
        let columns = usize::from(area.width);
        // A long path continues under its start, beside the labels.
        let summary: Vec<Line> = self
            .summary()
            .into_iter()
            .flat_map(|line| hang(line, 18, columns))
            .collect();
        let notes: Vec<Line> = self
            .selected_site()
            .map(|site| self.notes(site))
            .unwrap_or_default()
            .into_iter()
            .flat_map(|(_, sentence)| hang(format!(" {sentence}").dim().into(), 1, columns))
            .collect();
        let [top, sites, below] = Layout::vertical([
            Constraint::Length(summary.len() as u16 + 1),
            Constraint::Min(3),
            Constraint::Length(notes.len() as u16),
        ])
        .areas(area);
        frame.render_widget(Paragraph::new(summary), top);
        frame.render_widget(Paragraph::new(notes), below);
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
                let width = usize::from(sites.width.saturating_sub(2));
                let mut items: Vec<ListItem> =
                    survey.sites.iter().map(|s| self.item(s, width)).collect();
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
                self.list
                    .select((!survey.sites.is_empty()).then_some(self.selected));
                frame.render_stateful_widget(list, sites, &mut self.list);
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
