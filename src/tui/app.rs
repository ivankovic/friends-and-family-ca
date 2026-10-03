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
//! The application: which tab and dialog are showing, and carrying out what they ask for.

use std::collections::HashMap;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Tabs};
use time::{Duration, OffsetDateTime};

use super::action::{Action, Selection};
use super::components::ca_info::CaInfo;
use super::components::form::Form;
use super::components::invite_dialog::InviteDialog;
use super::components::invites_tab::InvitesTab;
use super::components::message::Message;
use super::components::mode_dialog::{Change, ModeDialog};
use super::components::nginx_tab::NginxTab;
use super::components::people::People;
use super::components::revoke_dialog::RevokeDialog;
use super::components::{Component, Hint, hint_line};
use super::date;
use crate::ca::{self, Ca, CrlStatus, Key};
use crate::config::{self, Config};
use crate::files::issue_to_files;
use crate::invite;
use crate::ledger::{Invite, Ledger, Place, Status, Target};
use crate::nginx::{self, Mode, Site};
use crate::store::PRIVATE;
use crate::timer;

/// A CRL this close to expiring means the refresh timer is not running: say so on every screen.
const CRL_WARNING: Duration = Duration::days(7);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    People,
    Invites,
    Nginx,
    Ca,
}

const TABS: [(Tab, &str); 4] = [
    (Tab::People, "People & agents"),
    (Tab::Invites, "Invites"),
    (Tab::Nginx, "Nginx"),
    (Tab::Ca, "CA"),
];

enum Dialog {
    Form(Form),
    Revoke(RevokeDialog),
    Mode(ModeDialog),
    Invite(InviteDialog),
    Message(Message),
}

/// The line above the key hints: what the last action did, or why it failed.
struct Notice {
    text: String,
    error: bool,
}

pub struct App {
    ca: Ca,
    out: PathBuf,
    now: OffsetDateTime,
    ledger: Ledger,
    crl: Option<CrlStatus>,
    config: Config,
    /// The enrollment site's addresses, or why there are none: looked up when it is set, not on
    /// every reload.
    dns: Option<Result<String, String>>,
    /// The refresh timer's state, as `systemctl is-active` says it; asked when the UI opens and
    /// after it is set up, not on every reload.
    timer: String,
    /// How the UI reaches systemd: replaced in tests.
    pub(crate) systemctl: String,
    pub(crate) unit_dir: PathBuf,
    tab: Tab,
    people: People,
    invites: InvitesTab,
    nginx: NginxTab,
    ca_info: CaInfo,
    dialog: Option<Dialog>,
    notice: Option<Notice>,
    quit: bool,
}

impl App {
    pub fn new(ca: Ca, out: PathBuf, now: OffsetDateTime) -> App {
        let mut app = App {
            ca,
            out,
            now,
            ledger: Ledger::default(),
            crl: None,
            config: Config::default(),
            dns: None,
            timer: timer::state("systemctl"),
            systemctl: "systemctl".into(),
            unit_dir: timer::UNIT_DIR.into(),
            tab: Tab::People,
            people: People::default(),
            invites: InvitesTab::default(),
            nginx: NginxTab::default(),
            ca_info: CaInfo::default(),
            dialog: None,
            notice: None,
            quit: false,
        };
        app.reload(now);
        app.look_up_enrollment();
        app.reload(now);
        app
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Greets a CA that was just created: where to point the web server, and what to do next.
    pub fn welcome(&mut self) {
        let lines: Vec<Line> = vec![
            format!(
                "{} is ready, valid until {}.",
                self.ca.name(),
                date(self.ca.not_after())
            )
            .into(),
            Line::default(),
            vec![
                "Next, on the ".into(),
                "Nginx".bold(),
                " tab, tell it where nginx is: it then keeps the CA's certificate and".into(),
            ]
            .into(),
            "revocation list where nginx reads them, and sets your sites to ask for certificates."
                .into(),
            Line::default(),
            "Back up the state folder: without the key, every certificate has to be issued again."
                .fg(Color::Yellow)
                .into(),
            Line::default(),
            vec![
                "Then press ".into(),
                "p".bold(),
                " to add the first person.".into(),
            ]
            .into(),
        ];
        self.dialog = Some(Dialog::Message(Message::new("CA created", lines)));
        self.tell(format!("Created the CA {}.", self.ca.name()));
    }

    /// Re-reads the CA's state, which other processes change too.
    pub fn reload(&mut self, now: OffsetDateTime) {
        self.now = now;
        let result = (|| -> anyhow::Result<()> {
            self.ledger = self.ca.ledger()?;
            self.crl = Some(self.ca.crl_status()?);
            self.config = Config::load(self.ca.store())?;
            if self.tend_invites() {
                self.ledger = self.ca.ledger()?;
                self.crl = Some(self.ca.crl_status()?);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.notice = Some(Notice {
                text: format!("{error:#}"),
                error: true,
            });
        }
        let subjects: HashMap<_, _> = self
            .ledger
            .certificates()
            .filter(|(_, c)| c.status(now) == Status::Valid)
            .filter_map(|(_, c)| Some((c.serial, self.ca.subject(c.serial).ok()?)))
            .collect();
        self.people.update(self.ledger.clone(), subjects, now);
        let survey = self
            .config
            .nginx
            .as_ref()
            .map(|settings| nginx::survey(settings).map_err(|e| format!("{e:#}")));
        let enrollment = self.config.enrollment.as_ref().map(|e| e.host.clone());
        self.invites
            .update(&self.ledger.invites, enrollment.is_some(), now);
        self.nginx.update(
            self.config.nginx.clone(),
            enrollment,
            self.dns.clone(),
            survey,
        );
        self.ca_info.update(self.ca_lines());
    }

    pub fn handle_key(&mut self, key: KeyEvent, now: OffsetDateTime) {
        self.now = now;
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        let action = match &mut self.dialog {
            Some(Dialog::Form(form)) => form.handle_key_event(key),
            Some(Dialog::Revoke(dialog)) => dialog.handle_key_event(key),
            Some(Dialog::Mode(dialog)) => dialog.handle_key_event(key),
            Some(Dialog::Invite(dialog)) => dialog.handle_key_event(key),
            Some(Dialog::Message(message)) => message.handle_key_event(key),
            None => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
                KeyCode::Tab => Some(Action::NextTab),
                KeyCode::BackTab => Some(Action::PreviousTab),
                KeyCode::Char('?') => Some(Action::Help),
                _ => match self.tab {
                    Tab::People => self.people.handle_key_event(key),
                    Tab::Invites => self.invites.handle_key_event(key),
                    Tab::Nginx => self.nginx.handle_key_event(key),
                    Tab::Ca => self.ca_info.handle_key_event(key),
                },
            },
        };
        if let Some(action) = action {
            self.perform(action);
        }
    }

    fn perform(&mut self, action: Action) {
        match action {
            Action::Quit => self.quit = true,
            // Only the setup screen creates a CA; see `Session`.
            Action::CreateCa { .. } => {}
            Action::NextTab | Action::PreviousTab => {
                let at = TABS
                    .iter()
                    .position(|(tab, _)| *tab == self.tab)
                    .unwrap_or(0);
                let step = if action == Action::NextTab {
                    1
                } else {
                    TABS.len() - 1
                };
                self.tab = TABS[(at + step) % TABS.len()].0;
            }
            Action::Help => self.dialog = Some(Dialog::Message(help())),
            Action::CloseDialog => self.dialog = None,
            Action::AskNewPerson => self.dialog = Some(Dialog::Form(Form::new_person())),
            Action::AskNewDevice { person } => {
                self.dialog = Some(Dialog::Form(Form::new_device(&person)))
            }
            Action::AskNewAgent => self.dialog = Some(Dialog::Form(Form::new_agent())),
            Action::AskRename(selection) => {
                self.dialog = Some(Dialog::Form(Form::rename(selection)))
            }
            Action::AskRevoke(selection) => {
                let reaches = self.reaches(&selection);
                if reaches.is_empty() {
                    self.fail(format!("{selection} has no valid certificate to revoke"));
                } else {
                    self.dialog = Some(Dialog::Revoke(RevokeDialog::new(selection, reaches)));
                }
            }
            Action::Issue(selection) => self.issue(selection),
            Action::IssueToNewPerson(selection) => {
                let name = match &selection {
                    Selection::Device { person, .. } => person.as_str(),
                    _ => "",
                };
                match self.ledger.person(name) {
                    Some(existing) => self.refuse(format!(
                        "{} is already here: select them and press n to add a device.",
                        existing.name
                    )),
                    None => self.issue(selection),
                }
            }
            Action::Revoke(selection, reason) => {
                self.dialog = None;
                match self.ca.revoke(selection.target(), reason, self.now) {
                    Ok(revoked) => {
                        let what: Vec<String> = revoked.iter().map(|r| r.holder.clone()).collect();
                        self.tell(match what.is_empty() {
                            true => format!("Retired {selection}."),
                            false => format!("Revoked {}. The new CRL is signed.", what.join(", ")),
                        });
                        self.reach_nginx();
                    }
                    Err(error) => self.fail(format!("{error:#}")),
                }
                self.reload(self.now);
            }
            Action::Rename(selection, to) => match self.ca.rename(selection.target(), &to) {
                Ok(()) => {
                    self.dialog = None;
                    self.tell(format!("Renamed {selection} to {}.", to.trim()));
                    self.reload(self.now);
                    let renamed = match selection {
                        Selection::Person(_) => Selection::Person(to.trim().to_owned()),
                        Selection::Device { person, .. } => Selection::Device {
                            person,
                            device: to.trim().to_owned(),
                        },
                        Selection::Agent(_) => Selection::Agent(to.trim().to_owned()),
                    };
                    self.people.select(&renamed);
                }
                Err(error) => self.refuse(format!("{error:#}")),
            },
            Action::RefreshCrl => {
                match self.ca.refresh_crl(self.now) {
                    Ok(()) => {
                        self.tell(format!(
                            "Signed a new CRL, valid until {}.",
                            date(self.now + ca::CRL_VALIDITY)
                        ));
                        self.reach_nginx();
                    }
                    Err(error) => self.fail(format!("{error:#}")),
                }
                self.reload(self.now);
            }
            Action::AskNginxSettings => {
                let settings = self.config.nginx.clone().unwrap_or_default();
                let (host, upstream, user) = match &self.config.enrollment {
                    Some(e) => (e.host.clone(), e.upstream.clone(), e.user.clone()),
                    None => (
                        String::new(),
                        config::default_upstream(),
                        config::default_page_user(),
                    ),
                };
                self.dialog = Some(Dialog::Form(Form::nginx_settings([
                    settings.sites.display().to_string(),
                    settings.ca_files.display().to_string(),
                    settings.ca_files_in_nginx.display().to_string(),
                    settings.test,
                    settings.reload,
                    host,
                    upstream,
                    user,
                ])));
            }
            Action::SaveNginxSettings(values) => self.save_nginx_settings(&values),
            Action::AskEnrollmentSite => self.ask_enrollment_site(),
            Action::AskTimer => {
                let binary = timer::this_binary().unwrap_or_default();
                let mut lines: Vec<Line> = Vec::new();
                for (name, text) in timer::units(&binary, self.ca.store().dir()) {
                    lines.push(format!("{}:", self.unit_dir.join(name).display()).into());
                    lines.extend(text.lines().map(|l| Line::from(format!("  {l}")).dim()));
                    lines.push(Line::default());
                }
                lines.push(
                    format!(
                        "Then {0} daemon-reload and {0} enable --now {1}.",
                        self.systemctl,
                        timer::TIMER
                    )
                    .into(),
                );
                self.dialog = Some(Dialog::Message(Message::confirm(
                    "The refresh timer",
                    lines,
                    Action::InstallTimer,
                    "set it up",
                )));
            }
            Action::InstallTimer => {
                self.dialog = None;
                let installed = timer::this_binary().and_then(|binary| {
                    timer::install(
                        &self.unit_dir,
                        &self.systemctl,
                        &binary,
                        self.ca.store().dir(),
                    )
                });
                match installed {
                    Ok(()) => self.tell("The refresh timer is set up: hourly.".into()),
                    Err(error) => {
                        let lines = format!("{error:#}")
                            .lines()
                            .map(|l| Line::from(l.to_owned()))
                            .collect();
                        self.dialog = Some(Dialog::Message(Message::new(
                            "The timer is not set up",
                            lines,
                        )));
                    }
                }
                self.timer = timer::state(&self.systemctl);
                self.reload(self.now);
            }
            Action::WriteEnrollmentSite => self.write_enrollment_site(),
            Action::ShowInvite(invite) => self.show_invite(&invite),
            Action::CancelInvite(serial) => {
                match invite::cancel(&self.ca, &invite::dir(self.ca.store()), serial, self.now) {
                    Ok(()) => {
                        self.tell("Cancelled the invite; its certificate is revoked.".into());
                        self.reach_nginx();
                    }
                    Err(error) => self.fail(format!("{error:#}")),
                }
                self.reload(self.now);
            }
            Action::AskSiteMode(site) => self.ask_site_mode(site),
            Action::SetSiteMode(site, mode) => self.set_site_mode(&site, mode),
            Action::TestNginx => {
                let Some(settings) = &self.config.nginx else {
                    return;
                };
                let (title, text) = match nginx::publish(settings, &self.ca)
                    .and_then(|()| nginx::run(&settings.test))
                {
                    Ok(printed) => ("nginx accepts its configuration", printed),
                    Err(error) => ("nginx refuses its configuration", format!("{error:#}")),
                };
                let lines = text.lines().map(|l| Line::from(l.to_owned())).collect();
                self.dialog = Some(Dialog::Message(Message::new(title, lines)));
            }
        }
    }

    /// Hands a new CRL to nginx, if ffca knows how to reach it; says how that went.
    fn reach_nginx(&mut self) {
        let Some(settings) = &self.config.nginx else {
            return;
        };
        match nginx::publish_and_reload(settings, &self.ca) {
            Ok(()) => {
                if let Some(notice) = &mut self.notice {
                    notice.text.push_str(" nginx reloaded with it.");
                }
            }
            Err(error) => {
                let mut lines = vec![
                    "The CRL is signed, but nginx still has the previous one: until it reloads, it accepts what the new one revokes."
                        .fg(Color::Red)
                        .into(),
                    Line::default(),
                ];
                lines.extend(
                    format!("{error:#}")
                        .lines()
                        .map(|l| Line::from(l.to_owned())),
                );
                self.dialog = Some(Dialog::Message(Message::new("nginx did not reload", lines)));
            }
        }
    }

    fn save_nginx_settings(&mut self, values: &[String]) {
        let result = (|| -> anyhow::Result<Config> {
            let [
                sites,
                ca_files,
                in_nginx,
                test,
                reload,
                host,
                upstream,
                user,
            ] = values
            else {
                anyhow::bail!("the form has the wrong number of fields");
            };
            for (value, what) in [
                (sites, "site configs"),
                (ca_files, "CA files"),
                (in_nginx, "CA files in nginx"),
                (test, "test command"),
                (reload, "reload command"),
            ] {
                anyhow::ensure!(!value.is_empty(), "the {what} cannot be empty");
            }
            let settings = config::Nginx {
                sites: sites.into(),
                ca_files: ca_files.into(),
                ca_files_in_nginx: in_nginx.into(),
                test: test.clone(),
                reload: reload.clone(),
            };
            std::fs::read_dir(&settings.sites)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", settings.sites.display()))?;
            let enrollment = match host.is_empty() {
                true => None,
                false => Some(config::Enrollment {
                    host: config::checked_host(host)?,
                    upstream: config::checked_upstream(upstream)?,
                    user: user.trim().to_owned(),
                }),
            };
            if let Some(enrollment) = &enrollment {
                let (uid, gid) = config::checked_user(&enrollment.user)?;
                invite::hand_over_folder(&invite::dir(self.ca.store()), uid, gid)?;
            }
            // Proves the folder is writable, and gives nginx something to read straight away.
            nginx::publish(&settings, &self.ca)?;
            Ok(Config {
                nginx: Some(settings),
                enrollment,
            })
        })();
        match result.and_then(|config| config.save(self.ca.store()).map(|()| config)) {
            Ok(config) => {
                self.config = config;
                self.dialog = None;
                self.tell("Saved. The CA's certificate and CRL are where nginx reads them.".into());
                self.look_up_enrollment();
                self.reload(self.now);
            }
            Err(error) => self.refuse(format!("{error:#}")),
        }
    }

    /// Asks DNS for the enrollment site, for the Nginx tab.
    fn look_up_enrollment(&mut self) {
        use std::net::ToSocketAddrs;
        self.dns = self.config.enrollment.as_ref().map(|e| {
            match (e.host.as_str(), 443).to_socket_addrs() {
                Ok(addresses) => {
                    let mut ips: Vec<String> = addresses.map(|a| a.ip().to_string()).collect();
                    ips.dedup();
                    match ips.is_empty() {
                        true => Err("does not resolve: it needs a DNS record".to_owned()),
                        false => Ok(ips.join(", ")),
                    }
                }
                Err(_) => Err("does not resolve: it needs a DNS record".to_owned()),
            }
        });
    }

    fn is_enrollment(&self, site: &Site) -> bool {
        self.config
            .enrollment
            .as_ref()
            .is_some_and(|e| site.serves(&e.host))
    }

    fn ask_site_mode(&mut self, site: Site) {
        let Some(settings) = &self.config.nginx else {
            return;
        };
        let original = std::fs::read_to_string(&site.file)
            .map_err(|e| format!("cannot read {}: {e}", site.file.display()));
        let enrollment = self.is_enrollment(&site);
        let changes = Mode::ALL
            .iter()
            .map(|&mode| {
                if enrollment && mode != Mode::Off {
                    return Err("This is the enrollment site: whoever opens an invite has no certificate yet.".to_owned());
                }
                let original = original.clone()?;
                let planned = nginx::plan(&original, site.index, mode, settings).map_err(|e| format!("{e:#}"))?;
                Ok(diff(&original, &planned))
            })
            .collect();
        self.dialog = Some(Dialog::Mode(ModeDialog::new(site, changes)));
    }

    fn set_site_mode(&mut self, site: &Site, mode: Mode) {
        self.dialog = None;
        let Some(settings) = self.config.nginx.clone() else {
            return;
        };
        if self.is_enrollment(site) && mode != Mode::Off {
            return self.fail(format!(
                "{} is the enrollment site: it never asks for a certificate.",
                site.name()
            ));
        }
        match nginx::set_mode(&settings, &self.ca, site, mode) {
            Ok(true) => self.tell(format!("{} is now {mode}; nginx reloaded.", site.name())),
            Ok(false) => self.tell(format!("{} was already {mode}.", site.name())),
            Err(error) => {
                let lines = format!("{error:#}")
                    .lines()
                    .map(|l| Line::from(l.to_owned()))
                    .collect();
                self.dialog = Some(Dialog::Message(Message::new(
                    format!("{} is unchanged", site.name()),
                    lines,
                )));
            }
        }
        self.reload(self.now);
    }

    /// Issues to a device or agent and writes the files; a refusal stays in the form that asked.
    fn issue(&mut self, selection: Selection) {
        let Some(holder) = selection.holder() else {
            return self.refuse("a person needs a device to hold the certificate".into());
        };
        // A device gets an invite once there is an enrollment site; an agent, files.
        if let (Selection::Device { .. }, Some(enrollment)) =
            (&selection, self.config.enrollment.clone())
        {
            match invite::make(
                &self.ca,
                &invite::dir(self.ca.store()),
                holder,
                &enrollment.host,
                self.now,
            ) {
                Ok(made) => {
                    self.tell(format!("Invited {}.", made.invite.holder));
                    self.reload(self.now);
                    self.people.select(
                        &selection_of(&self.ledger, &made.invite.holder).unwrap_or(selection),
                    );
                    self.show_invite(&made.invite);
                }
                Err(error) => self.refuse(format!("{error:#}")),
            }
            return;
        }
        let validity = ca::DEFAULT_CLIENT_VALIDITY;
        match issue_to_files(
            &self.ca,
            holder,
            Key::Generate,
            &self.out,
            self.now,
            validity,
        ) {
            Ok((issued, paths)) => {
                let mut lines: Vec<Line> = vec![
                    format!(
                        "Issued to {}, valid until {}.",
                        issued.holder,
                        date(issued.certificate.not_after)
                    )
                    .into(),
                    Line::default(),
                    vec!["Certificate  ".dim(), paths[0].display().to_string().into()].into(),
                ];
                if let Some(key) = paths.get(1) {
                    lines
                        .push(vec!["Key          ".dim(), key.display().to_string().into()].into());
                    lines.push(Line::default());
                    lines.push(
                        "Hand both to the device, then delete the key file: the CA keeps the certificate, never the key."
                            .into(),
                    );
                }
                self.dialog = Some(Dialog::Message(Message::new("Issued", lines)));
                self.tell(format!(
                    "Issued {} to {}.",
                    &issued.certificate.serial.to_string()[..8],
                    issued.holder
                ));
                self.reload(self.now);
                self.people
                    .select(&selection_of(&self.ledger, &issued.holder).unwrap_or(selection));
            }
            Err(error) => self.refuse(format!("{error:#}")),
        }
    }

    fn show_invite(&mut self, invite: &Invite) {
        let Some(enrollment) = &self.config.enrollment else {
            return self.fail("Set the enrollment site on the Nginx tab to show invites.".into());
        };
        let status = format!(
            "Works once · expires {} {}",
            date(invite.expires),
            clock(invite.expires)
        );
        let link = invite::link(&enrollment.host, &invite.token);
        self.dialog = Some(Dialog::Invite(InviteDialog::new(
            invite.holder.clone(),
            link,
            status,
        )));
    }

    /// Records collected invites and closes the rest that are due; a revocation reaches nginx.
    /// Returns whether the ledger changed.
    fn tend_invites(&mut self) -> bool {
        match invite::tend(&self.ca, &invite::dir(self.ca.store()), self.now) {
            Ok(tended) => {
                for holder in &tended.collected {
                    self.tell(format!("{holder} collected their invite."));
                }
                if tended.revoked {
                    self.reach_nginx();
                }
                !tended.collected.is_empty() || !tended.closed.is_empty()
            }
            Err(error) => {
                self.fail(format!("{error:#}"));
                false
            }
        }
    }

    fn ask_enrollment_site(&mut self) {
        let (Some(settings), Some(enrollment)) = (&self.config.nginx, &self.config.enrollment)
        else {
            return self.fail("Set the enrollment site first, with e.".into());
        };
        match nginx::enrollment_site(settings, enrollment) {
            Ok((file, text)) => {
                let mut lines: Vec<Line> = vec![
                    format!("ffca writes {}:", file.display()).into(),
                    Line::default(),
                ];
                lines.extend(text.lines().map(|l| Line::from(l.to_owned()).dim()));
                lines.push(Line::default());
                lines.push(
                    "Then nginx -t; if nginx refuses it, it is not written. Then a reload.".into(),
                );
                self.dialog = Some(Dialog::Message(Message::confirm(
                    "The enrollment site",
                    lines,
                    Action::WriteEnrollmentSite,
                    "write",
                )));
            }
            Err(error) => self.fail(format!("{error:#}")),
        }
    }

    fn write_enrollment_site(&mut self) {
        self.dialog = None;
        let (Some(settings), Some(enrollment)) =
            (self.config.nginx.clone(), self.config.enrollment.clone())
        else {
            return;
        };
        let written = nginx::enrollment_site(&settings, &enrollment).and_then(|(file, text)| {
            nginx::write_enrollment_site(&settings, &self.ca, &file, &text)
        });
        match written {
            Ok(()) => self.tell(format!("{} is up; nginx reloaded.", enrollment.host)),
            Err(error) => {
                let lines = format!("{error:#}")
                    .lines()
                    .map(|l| Line::from(l.to_owned()))
                    .collect();
                self.dialog = Some(Dialog::Message(Message::new(
                    "The enrollment site is not written",
                    lines,
                )));
            }
        }
        self.reload(self.now);
    }

    /// The valid certificates revoking `selection` can reach, one line each, and whether each is
    /// its holder's newest.
    fn reaches(&self, selection: &Selection) -> Vec<(String, bool)> {
        let now = self.now;
        let valid = |place: Place| -> Vec<(String, bool)> {
            let holder = self.ledger.at(place);
            let newest = holder.current(now).map(|c| c.serial);
            holder
                .certificates
                .iter()
                .filter(|c| c.status(now) == Status::Valid)
                .map(|c| {
                    let line = format!(
                        "{}  {}  valid until {}",
                        self.ledger.holder_at(place),
                        &c.serial.to_string()[..8],
                        date(c.not_after)
                    );
                    (line, Some(c.serial) == newest)
                })
                .collect()
        };
        match selection.target() {
            Target::Person(name) => match self.ledger.people.iter().position(|p| p.name == name) {
                Some(p) => (0..self.ledger.people[p].devices.len())
                    .flat_map(|d| valid(Place::Device(p, d)))
                    .collect(),
                None => Vec::new(),
            },
            Target::Holder(holder) => self.ledger.place(holder).map(valid).unwrap_or_default(),
            Target::Certificate(_) => Vec::new(),
        }
    }

    fn tell(&mut self, text: String) {
        self.notice = Some(Notice { text, error: false });
    }

    fn fail(&mut self, text: String) {
        self.notice = Some(Notice { text, error: true });
    }

    /// A refusal: shown in the open form, which stays open, or as a notice.
    fn refuse(&mut self, text: String) {
        match &mut self.dialog {
            Some(Dialog::Form(form)) => form.set_error(text),
            _ => self.fail(text),
        }
    }

    fn ca_lines(&self) -> Vec<Line<'static>> {
        let store = self.ca.store();
        let row = |label: &str, value: String| -> Line<'static> {
            vec![format!("  {label:<14}").dim(), value.into()].into()
        };
        let key_mode = std::fs::metadata(store.path(ca::KEY_FILE))
            .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777);
        let key_note = match key_mode {
            Ok(PRIVATE) => "owner only".to_owned(),
            Ok(mode) => format!("readable beyond its owner ({mode:o}): chmod 600 it"),
            Err(error) => error.to_string(),
        };
        let people = self.ledger.people.len();
        let devices: usize = self.ledger.people.iter().map(|p| p.devices.len()).sum();
        let agents = self.ledger.agents.len();
        let valid = self
            .ledger
            .certificates()
            .filter(|(_, c)| c.status(self.now) == Status::Valid)
            .count();
        let mut lines = vec![
            row("Name", self.ca.name().to_owned()),
            row("Valid until", date(self.ca.not_after())),
            Line::default(),
            row("State folder", store.dir().display().to_string()),
            row(
                "Key",
                format!("{}  ({key_note})", store.path(ca::KEY_FILE).display()),
            ),
            row(
                "Certificate",
                store.path(ca::CERTIFICATE_FILE).display().to_string(),
            ),
            row("CRL", store.path(ca::CRL_FILE).display().to_string()),
        ];
        if let Some(crl) = self.crl {
            lines.push(row(
                "",
                format!(
                    "number {}, valid until {}",
                    crl.number,
                    date(crl.next_update)
                ),
            ));
        }
        let timer = match self.timer.as_str() {
            "active" => Line::from(vec!["  Refresh timer ".dim(), "active, hourly".into()]),
            other => Line::from(vec![
                "  Refresh timer ".dim(),
                format!("{other}: press T to set it up, or the CRL expires in a month")
                    .fg(Color::Yellow),
            ]),
        };
        lines.push(timer);
        lines.extend([
            Line::default(),
            row(
                "Issued to",
                format!(
                    "{people} {}, {devices} {}, {agents} {}; {valid} valid {}",
                    plural(people, "person", "people"),
                    plural(devices, "device", "devices"),
                    plural(agents, "agent", "agents"),
                    plural(valid, "certificate", "certificates"),
                ),
            ),
            Line::default(),
            "  Back up the state folder: without the key, every certificate has to be issued again.".fg(Color::Yellow).into(),
        ]);
        lines
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let [title, tabs, body, notice, hints] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        self.draw_title(frame, title);
        let titles: Vec<Line> = TABS.iter().map(|(_, name)| Line::from(*name)).collect();
        let selected = TABS
            .iter()
            .position(|(tab, _)| *tab == self.tab)
            .unwrap_or(0);
        frame.render_widget(
            Tabs::new(titles)
                .select(selected)
                .highlight_style(Color::Cyan)
                .bold(),
            tabs,
        );
        match self.tab {
            Tab::People => self.people.draw(frame, body),
            Tab::Invites => self.invites.draw(frame, body),
            Tab::Nginx => self.nginx.draw(frame, body),
            Tab::Ca => self.ca_info.draw(frame, body),
        }
        if let Some(n) = &self.notice {
            let text = Span::from(format!(" {}", n.text));
            let text = if n.error { text.fg(Color::Red) } else { text };
            frame.render_widget(Paragraph::new(Line::from(text)), notice);
        }
        let mut keys: Vec<Hint> = match self.tab {
            Tab::People => self.people.hints(),
            Tab::Invites => self.invites.hints(),
            Tab::Nginx => self.nginx.hints(),
            Tab::Ca => self.ca_info.hints(),
        };
        keys.extend([("Tab", "switch"), ("?", "help"), ("q", "quit")]);
        let hints = Rect {
            x: hints.x + 1,
            width: hints.width.saturating_sub(1),
            ..hints
        };
        frame.render_widget(Paragraph::new(hint_line(&keys)), hints);
        match &mut self.dialog {
            Some(Dialog::Form(form)) => form.draw(frame, body),
            Some(Dialog::Revoke(dialog)) => dialog.draw(frame, body),
            Some(Dialog::Mode(dialog)) => dialog.draw(frame, body),
            Some(Dialog::Invite(dialog)) => dialog.draw(frame, body),
            Some(Dialog::Message(message)) => message.draw(frame, body),
            None => {}
        }
    }

    fn draw_title(&self, frame: &mut Frame, area: Rect) {
        let left = Line::from(vec![
            " Friends and Family CA".bold(),
            format!(" · {}", self.ca.name()).into(),
        ]);
        let right: Span = match self.crl {
            Some(crl) if crl.next_update <= self.now => {
                "CRL EXPIRED: the web server refuses every client. Press c on the CA tab "
                    .fg(Color::Red)
                    .bold()
            }
            Some(crl) if crl.next_update - self.now < CRL_WARNING => Span::from(format!(
                "CRL expires in {} d: is the refresh timer running? ",
                (crl.next_update - self.now).whole_days()
            ))
            .fg(Color::Yellow),
            Some(crl) => Span::from(format!("CRL valid until {} ", date(crl.next_update))).dim(),
            None => "CRL unreadable ".fg(Color::Red),
        };
        frame.render_widget(Paragraph::new(left), area);
        frame.render_widget(Paragraph::new(Line::from(right).right_aligned()), area);
    }

    #[cfg(test)]
    pub(crate) fn form_purpose(&self) -> Option<&super::components::form::Purpose> {
        match &self.dialog {
            Some(Dialog::Form(form)) => Some(form.purpose()),
            _ => None,
        }
    }
}

/// The selection for a holder described as `Holder`'s `Display` writes it.
fn selection_of(ledger: &Ledger, holder: &str) -> Option<Selection> {
    ledger
        .certificates()
        .find(|(h, _)| h.to_string() == holder)
        .map(|(h, _)| match h {
            crate::ledger::Holder::Device { person, device } => Selection::Device {
                person: person.to_owned(),
                device: device.to_owned(),
            },
            crate::ledger::Holder::Agent(agent) => Selection::Agent(agent.to_owned()),
        })
}

/// The lines `planned` drops from `original`, and the lines it adds, in order: setting a mode only
/// adds, removes and comments out whole lines.
fn diff(original: &str, planned: &str) -> Change {
    let before: Vec<&str> = original.lines().collect();
    let after: Vec<&str> = planned.lines().collect();
    let removed = before
        .iter()
        .filter(|l| !after.contains(l))
        .map(|l| l.trim().to_owned())
        .collect();
    let added = after
        .iter()
        .filter(|l| !before.contains(l))
        .map(|l| l.trim().to_owned())
        .collect();
    Change { removed, added }
}

/// The time of day, in UTC: "14:02 UTC".
fn clock(time: OffsetDateTime) -> String {
    format!("{:02}:{:02} UTC", time.hour(), time.minute())
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

fn help() -> Message {
    let key = |key: &'static str, what: &'static str| -> Line<'static> {
        vec![format!("{key:<12}").bold(), what.into()].into()
    };
    Message::new(
        "Keys",
        vec![
            key("↑ ↓  j k", "move"),
            key("Tab", "switch between People & agents, Invites, Nginx and CA"),
            key("p", "add a person, with a certificate for their first device"),
            key("n", "add a device to the selected person"),
            key("a", "issue a certificate to a new agent"),
            key(
                "u",
                "renew: a new certificate for the selected device or agent",
            ),
            key(
                "r",
                "revoke the selected device or agent, or every device of a person",
            ),
            key("R", "rename the selected person, device or agent"),
            key("e", "on the Nginx tab: where nginx is, and the enrollment site"),
            key("s", "on the Nginx tab: a site's client certificate: off, optional, required"),
            key("t", "on the Nginx tab: test nginx's configuration"),
            key("w", "on the Nginx tab: write the enrollment site"),
            key("Enter  x", "on the Invites tab: show an invite's QR code again, cancel it"),
            key("c", "on the CA tab: sign a new CRL now"),
            key("T", "on the CA tab: set up the hourly refresh timer"),
            key("q  Esc", "quit, or close a dialog"),
            Line::default(),
            "After a renewal, revoke the device again as \"replaced\": that revokes every certificate but the newest."
                .into(),
        ],
    )
}

#[cfg(test)]
mod tests;
