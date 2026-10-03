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
//! The Invites tab: the links handed out, open ones first.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use time::OffsetDateTime;

use super::{Component, Hint, step};
use crate::ledger::{Invite, InviteState};
use crate::tui::action::Action;
use crate::tui::date;

/// How many closed invites the tab still shows, newest first.
const CLOSED_SHOWN: usize = 20;

#[derive(Debug, Clone)]
pub struct InvitesTab {
    invites: Vec<Invite>,
    /// Whether invites can be made: the enrollment site is set.
    enabled: bool,
    now: OffsetDateTime,
    selected: usize,
}

impl Default for InvitesTab {
    fn default() -> Self {
        InvitesTab {
            invites: Vec::new(),
            enabled: false,
            now: OffsetDateTime::UNIX_EPOCH,
            selected: 0,
        }
    }
}

impl InvitesTab {
    /// Shows `invites`: the open ones, soonest to expire first, then the closed ones, newest first.
    pub fn update(&mut self, invites: &[Invite], enabled: bool, now: OffsetDateTime) {
        let kept = self.selected_invite().map(|i| i.serial);
        let mut open: Vec<Invite> = invites
            .iter()
            .filter(|i| i.state == InviteState::Open)
            .cloned()
            .collect();
        open.sort_by_key(|i| i.expires);
        let mut closed: Vec<Invite> = invites
            .iter()
            .filter(|i| i.state != InviteState::Open)
            .cloned()
            .collect();
        closed.sort_by_key(|i| std::cmp::Reverse(i.closed.unwrap_or(i.created)));
        closed.truncate(CLOSED_SHOWN);
        open.extend(closed);
        self.invites = open;
        self.enabled = enabled;
        self.now = now;
        self.selected = kept
            .and_then(|serial| self.invites.iter().position(|i| i.serial == serial))
            .unwrap_or(self.selected)
            .min(self.invites.len().saturating_sub(1));
    }

    pub fn selected_invite(&self) -> Option<&Invite> {
        self.invites.get(self.selected)
    }

    pub fn hints(&self) -> Vec<Hint> {
        match self.selected_invite() {
            Some(invite) if invite.state == InviteState::Open => {
                vec![("Enter", "show"), ("x", "cancel")]
            }
            _ => Vec::new(),
        }
    }

    fn item(&self, invite: &Invite) -> ListItem<'static> {
        let (symbol, color, state) = match invite.state {
            InviteState::Open => {
                let left = invite.expires - self.now;
                let left = if left.whole_hours() >= 1 {
                    format!("{} h", left.whole_hours())
                } else {
                    format!("{} min", left.whole_minutes().max(0))
                };
                ("◐", Color::Yellow, format!("open, {left} left"))
            }
            InviteState::Collected => (
                "●",
                Color::Green,
                format!(
                    "collected {} by {}",
                    invite.closed.map(date).unwrap_or_default(),
                    invite.collected_by.as_deref().unwrap_or("?")
                ),
            ),
            InviteState::Expired => (
                "○",
                Color::DarkGray,
                format!("expired {}", invite.closed.map(date).unwrap_or_default()),
            ),
            InviteState::Cancelled => (
                "✕",
                Color::Red,
                format!("cancelled {}", invite.closed.map(date).unwrap_or_default()),
            ),
        };
        ListItem::new(Line::from(vec![
            " ".into(),
            Span::styled(symbol, Style::new().fg(color)),
            format!(" {:<30} ", invite.holder).into(),
            Span::from(state).dim(),
        ]))
    }
}

impl Component for InvitesTab {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<Action> {
        let open = self
            .selected_invite()
            .filter(|i| i.state == InviteState::Open)
            .cloned();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, false, self.invites.len())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, true, self.invites.len())
            }
            KeyCode::Enter => return open.map(Action::ShowInvite),
            KeyCode::Char('x') => return open.map(|i| Action::CancelInvite(i.serial)),
            _ => {}
        }
        None
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        if self.invites.is_empty() {
            let text: Vec<Line> = if self.enabled {
                vec![
                    Line::default(),
                    "  No invites yet.".into(),
                    Line::default(),
                    vec![
                        "  On People & agents, ".into(),
                        "p".bold(),
                        ", ".into(),
                        "n".bold(),
                        " and ".into(),
                        "u".bold(),
                        " make one: a link, and its QR code, that hands a device its certificate."
                            .into(),
                    ]
                    .into(),
                ]
            } else {
                vec![
                    Line::default(),
                    "  Invites need the enrollment site: set it on the Nginx tab with e.".into(),
                    "  Until then, certificates are written to files."
                        .dim()
                        .into(),
                ]
            };
            frame.render_widget(Paragraph::new(text), area);
            return;
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .border_style(Style::new().dim());
        let items: Vec<ListItem> = self.invites.iter().map(|i| self.item(i)).collect();
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::new().reversed());
        frame.render_stateful_widget(
            list,
            area,
            &mut ListState::default().with_selected(Some(self.selected)),
        );
    }
}
