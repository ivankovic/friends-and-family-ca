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
//! The People & agents tab: a tree of people with their devices, then agents, on the left; the
//! selected one's certificates on the right.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use time::{Duration, OffsetDateTime};

use super::{Component, Hint};
use crate::ledger::{Certificate, Invite, InviteState, KeyHolder, Ledger, Serial, Status};
use crate::tui::action::{Action, Selection};
use crate::tui::date;

/// A certificate this close to expiring is marked, so that it is replaced before it stops working.
pub const EXPIRY_WARNING: Duration = Duration::days(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    Person(usize),
    Device(usize, usize),
    AgentsHeading,
    Agent(usize),
}

pub struct People {
    ledger: Ledger,
    /// Each current certificate's subject as issued, which the ledger does not keep.
    subjects: HashMap<Serial, String>,
    now: OffsetDateTime,
    rows: Vec<Row>,
    selected: usize,
}

impl Default for People {
    fn default() -> Self {
        People {
            ledger: Ledger::default(),
            subjects: HashMap::new(),
            now: OffsetDateTime::UNIX_EPOCH,
            rows: Vec::new(),
            selected: 0,
        }
    }
}

impl People {
    /// Shows `ledger` as of `now`, keeping the selection on the same person, device or agent if
    /// it is still there.
    pub fn update(
        &mut self,
        ledger: Ledger,
        subjects: HashMap<Serial, String>,
        now: OffsetDateTime,
    ) {
        let kept = self.selection();
        self.ledger = ledger;
        self.subjects = subjects;
        self.now = now;
        self.rows = rows(&self.ledger);
        self.selected = kept
            .and_then(|kept| {
                (0..self.rows.len()).find(|&i| self.selection_at(i).as_ref() == Some(&kept))
            })
            .or_else(|| self.rows.iter().position(|r| *r != Row::AgentsHeading))
            .unwrap_or(0);
    }

    /// Moves the selection to `selection`, if it is shown.
    pub fn select(&mut self, selection: &Selection) {
        if let Some(i) =
            (0..self.rows.len()).find(|&i| self.selection_at(i).as_ref() == Some(selection))
        {
            self.selected = i;
        }
    }

    pub fn selection(&self) -> Option<Selection> {
        self.selection_at(self.selected)
    }

    fn selection_at(&self, index: usize) -> Option<Selection> {
        let ledger = &self.ledger;
        Some(match *self.rows.get(index)? {
            Row::Person(p) => Selection::Person(ledger.people[p].name.clone()),
            Row::Device(p, d) => Selection::Device {
                person: ledger.people[p].name.clone(),
                device: ledger.people[p].devices[d].name.clone(),
            },
            Row::AgentsHeading => return None,
            Row::Agent(a) => Selection::Agent(ledger.agents[a].name.clone()),
        })
    }

    fn selected_holder(&self) -> Option<&KeyHolder> {
        match *self.rows.get(self.selected)? {
            Row::Device(p, d) => Some(&self.ledger.people[p].devices[d]),
            Row::Agent(a) => Some(&self.ledger.agents[a]),
            Row::Person(_) | Row::AgentsHeading => None,
        }
    }

    /// The keys that do something for the current selection.
    pub fn hints(&self) -> Vec<Hint> {
        let mut hints = vec![("p", "new person")];
        if matches!(
            self.rows.get(self.selected),
            Some(Row::Person(_) | Row::Device(..))
        ) {
            hints.push(("n", "new device"));
        }
        hints.push(("a", "new agent"));
        match self.rows.get(self.selected) {
            Some(Row::Person(_)) => hints.extend([("r", "revoke all devices"), ("R", "rename")]),
            Some(Row::Device(..) | Row::Agent(_)) => {
                if self.selected_holder().is_some_and(|h| h.retired.is_none()) {
                    hints.extend([("u", "renew"), ("r", "revoke")]);
                }
                hints.push(("R", "rename"));
            }
            _ => {}
        }
        hints
    }

    /// How many devices and agents have a current certificate that expires within
    /// [`EXPIRY_WARNING`]: they need renewing.
    pub fn expiring(&self) -> usize {
        self.holders()
            .filter(|h| h.retired.is_none())
            .filter_map(|h| h.current(self.now))
            .filter(|c| c.not_after - self.now < EXPIRY_WARNING)
            .count()
    }

    fn move_selection(&mut self, down: bool) {
        let mut next = self.selected;
        loop {
            let candidate = super::step(next, down, self.rows.len());
            if candidate == next {
                return;
            }
            next = candidate;
            if self.rows[next] != Row::AgentsHeading {
                self.selected = next;
                return;
            }
        }
    }

    fn item(&self, row: Row, width: usize) -> ListItem<'static> {
        let line: Line = match row {
            Row::Person(p) => {
                let name = fit(&self.ledger.people[p].name, width.saturating_sub(2));
                vec!["▾ ".dim(), name.bold()].into()
            }
            Row::AgentsHeading => vec!["▾ ".dim(), "Agents".bold().italic()].into(),
            Row::Device(p, d) => self.holder_line(&self.ledger.people[p].devices[d], width),
            Row::Agent(a) => self.holder_line(&self.ledger.agents[a], width),
        };
        ListItem::new(line)
    }

    /// The holders shown, devices and agents alike.
    fn holders(&self) -> impl Iterator<Item = &KeyHolder> {
        let devices = self.ledger.people.iter().flat_map(|p| &p.devices);
        devices.chain(&self.ledger.agents)
    }

    /// How wide a holder's name is in a list `width` wide: as wide as the longest (and at least
    /// 14, so that the states line up as a column), less if that would push the states out.
    fn name_width(&self, width: usize) -> usize {
        let longest = self.holders().map(|h| h.name.chars().count()).max();
        let label = self
            .holders()
            .map(|h| {
                holder_state(h, &self.ledger.invites, self.now)
                    .1
                    .chars()
                    .count()
            })
            .max()
            .unwrap_or(0);
        // "  ● " before the name, a space after it.
        let room = width.saturating_sub(5 + label);
        longest.unwrap_or(0).max(14).min(room).max(6)
    }

    fn holder_line(&self, holder: &KeyHolder, width: usize) -> Line<'static> {
        let (symbol, label, color) = holder_state(holder, &self.ledger.invites, self.now);
        let name_width = self.name_width(width);
        vec![
            "  ".into(),
            Span::styled(symbol, Style::new().fg(color)),
            format!(" {:<name_width$} ", fit(&holder.name, name_width)).into(),
            Span::from(label).dim(),
        ]
        .into()
    }

    fn details(&self) -> Vec<Line<'static>> {
        let Some(selection) = self.selection() else {
            return Vec::new();
        };
        let mut lines = vec![Line::from(selection.to_string().bold()), Line::default()];
        match *self.rows.get(self.selected).expect("a selection is a row") {
            Row::Person(p) => {
                let person = &self.ledger.people[p];
                for device in &person.devices {
                    let (symbol, label, color) =
                        holder_state(device, &self.ledger.invites, self.now);
                    lines.push(
                        vec![
                            Span::styled(symbol, Style::new().fg(color)),
                            format!(" {:<14} ", device.name).into(),
                            Span::from(label).dim(),
                        ]
                        .into(),
                    );
                }
                lines.push(Line::default());
                lines.push(
                    "r revokes every one of these devices; n adds another."
                        .dim()
                        .into(),
                );
            }
            _ => {
                let holder = self.selected_holder().expect("a device or an agent");
                if let Some(when) = holder.retired {
                    lines.push(
                        format!(
                            "Retired {}: nothing more is issued under this name.",
                            date(when)
                        )
                        .into(),
                    );
                    lines.push(Line::default());
                }
                let current = holder.current(self.now).map(|c| c.serial);
                let mut certificates: Vec<&Certificate> = holder.certificates.iter().collect();
                certificates
                    .sort_by_key(|c| (Some(c.serial) != current, std::cmp::Reverse(c.not_before)));
                let mut others = 0;
                for certificate in &certificates {
                    let heading = if Some(certificate.serial) == current {
                        "Current"
                    } else {
                        others += 1;
                        match (current.is_some(), others) {
                            (true, 1) | (false, 2) => "Earlier",
                            (false, 1) => "Last",
                            _ => "",
                        }
                    };
                    lines.push(
                        vec![
                            format!("{heading:<10}").dim(),
                            certificate.serial.to_string()[..8].to_owned().into(),
                            format!("   {}", certificate_state(certificate, self.now)).into(),
                        ]
                        .into(),
                    );
                    let indent = || -> Span<'static> { " ".repeat(10).into() };
                    if Some(certificate.serial) == current {
                        let mut about = format!("issued {}", date(certificate.not_before));
                        if let Some(subject) = self.subjects.get(&certificate.serial) {
                            about.push_str(" · ");
                            about.push_str(subject);
                        }
                        lines.push(vec![indent(), about.dim()].into());
                    }
                    if let Some(invite) = invite_of(&self.ledger.invites, certificate.serial) {
                        let state = invite_state(invite);
                        let state = match invite.state {
                            InviteState::Open => state.fg(Color::Cyan),
                            _ => state.dim(),
                        };
                        lines.push(vec![indent(), state].into());
                    }
                }
                if certificates.len() > 1 && holder.current(self.now).is_some() {
                    let valid = certificates
                        .iter()
                        .filter(|c| c.status(self.now) == Status::Valid)
                        .count();
                    if valid > 1 {
                        lines.push(Line::default());
                        lines.push(
                            format!("{valid} valid certificates: once the new one is installed, revoke the others as replaced.")
                                .fg(Color::Yellow)
                                .into(),
                        );
                    }
                }
            }
        }
        lines
    }
}

impl Component for People {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        let selection = self.selection();
        let active = self.selected_holder().is_some_and(|h| h.retired.is_none());
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(false),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(true),
            KeyCode::Home | KeyCode::Char('g') => {
                self.selected = 0;
                if self.rows.first() == Some(&Row::AgentsHeading) {
                    self.move_selection(true);
                }
            }
            KeyCode::End | KeyCode::Char('G') => self.selected = self.rows.len().saturating_sub(1),
            KeyCode::Char('p') => return Some(Action::AskNewPerson),
            // Another device for the selected person; with nobody selected, a new person.
            KeyCode::Char('n') => {
                return Some(match &selection {
                    Some(Selection::Person(person) | Selection::Device { person, .. }) => {
                        Action::AskNewDevice {
                            person: person.clone(),
                        }
                    }
                    _ => Action::AskNewPerson,
                });
            }
            KeyCode::Char('a') => return Some(Action::AskNewAgent),
            KeyCode::Char('u') if active => return selection.map(Action::Issue),
            KeyCode::Char('r') => match &selection {
                Some(Selection::Person(_)) => return selection.map(Action::AskRevoke),
                Some(_) if active => return selection.map(Action::AskRevoke),
                _ => {}
            },
            KeyCode::Char('R') => return selection.map(Action::AskRename),
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        if self.rows.is_empty() {
            let text = vec![
                Line::default(),
                "  No one has a certificate yet.".into(),
                Line::default(),
                vec![
                    "  Press ".into(),
                    "p".bold(),
                    " to add a person and their first device, or ".into(),
                    "a".bold(),
                    " to add an agent.".into(),
                ]
                .into(),
            ];
            frame.render_widget(Paragraph::new(text), area);
            return;
        }
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(40), Constraint::Min(30)]).areas(area);
        let block = |title: &'static str| {
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_set(border::ROUNDED)
                .border_style(Style::new().dim())
        };
        let width = usize::from(left.width.saturating_sub(2));
        let items: Vec<ListItem> = self.rows.iter().map(|&row| self.item(row, width)).collect();
        let list = List::new(items)
            .block(block(""))
            .highlight_style(Style::new().reversed());
        let mut state = ListState::default().with_selected(Some(self.selected));
        frame.render_stateful_widget(list, left, &mut state);
        let details = Paragraph::new(self.details())
            .block(block("").padding(ratatui::widgets::Padding::horizontal(1)))
            .wrap(Wrap { trim: false });
        frame.render_widget(details, right);
    }
}

/// `text`, cut to `width` characters with an ellipsis if it is longer.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

fn rows(ledger: &Ledger) -> Vec<Row> {
    let mut rows = Vec::new();
    for (p, person) in ledger.people.iter().enumerate() {
        rows.push(Row::Person(p));
        rows.extend((0..person.devices.len()).map(|d| Row::Device(p, d)));
    }
    if !ledger.agents.is_empty() {
        rows.push(Row::AgentsHeading);
        rows.extend((0..ledger.agents.len()).map(Row::Agent));
    }
    rows
}

/// A holder at a glance: a symbol, a few words, and the symbol's colour.
fn holder_state(
    holder: &KeyHolder,
    invites: &[Invite],
    now: OffsetDateTime,
) -> (&'static str, String, Color) {
    if holder.retired.is_some() {
        return ("✕", "retired".into(), Color::Red);
    }
    if let Some(current) = holder.current(now) {
        // Issued, but still in its invite: the device does not have it yet.
        if invite_of(invites, current.serial).is_some_and(|i| i.state == InviteState::Open) {
            return ("◌", "invite open".into(), Color::Cyan);
        }
        let left = current.not_after - now;
        return if left < EXPIRY_WARNING {
            (
                "◐",
                format!("expires in {} d", left.whole_days()),
                Color::Yellow,
            )
        } else {
            (
                "●",
                format!("until {}", current.not_after.year()),
                Color::Green,
            )
        };
    }
    match holder.certificates.iter().max_by_key(|c| c.not_before) {
        Some(last) if last.revoked.is_some() => ("✕", "revoked".into(), Color::Red),
        Some(_) => ("○", "expired".into(), Color::DarkGray),
        None => ("○", "no certificate".into(), Color::DarkGray),
    }
}

/// The invite that handed `serial` over, if it was handed over by one.
pub fn invite_of(invites: &[Invite], serial: Serial) -> Option<&Invite> {
    invites.iter().find(|i| i.serial == serial)
}

/// How an invite stands, for the line under its certificate.
fn invite_state(invite: &Invite) -> String {
    let when = invite.closed.map(date).unwrap_or_default();
    match invite.state {
        InviteState::Open => format!(
            "invite open until {}: not on the device yet",
            date(invite.expires)
        ),
        InviteState::Collected => match &invite.collected_by {
            Some(by) => format!("collected {when} by {by}"),
            None => format!("collected {when}"),
        },
        InviteState::Expired => format!("invite expired {when}, never collected"),
        InviteState::Cancelled => format!("invite cancelled {when}"),
    }
}

fn certificate_state(certificate: &Certificate, now: OffsetDateTime) -> String {
    match certificate.status(now) {
        Status::Valid => format!("valid until {}", date(certificate.not_after)),
        Status::Expired => format!("expired {}", date(certificate.not_after)),
        Status::Revoked => {
            let when = certificate.revoked.map(date).unwrap_or_default();
            match certificate.reason {
                Some(reason) => {
                    format!("revoked {when} · {}", format!("{reason:?}").to_lowercase())
                }
                None => format!("revoked {when}"),
            }
        }
    }
}
