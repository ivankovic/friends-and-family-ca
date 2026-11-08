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
use super::components::auth_dialog::AuthDialog;
use super::components::ca_info::CaInfo;
use super::components::form::Form;
use super::components::invite_dialog::InviteDialog;
use super::components::invites_tab::InvitesTab;
use super::components::message::Message;
use super::components::mode_dialog::{ModeDialog, diff};
use super::components::nginx_tab::NginxTab;
use super::components::people::{People, invite_of};
use super::components::revoke_dialog::RevokeDialog;
use super::components::users_tab::{self, UsersTab};
use super::components::{Component, Hint, fitted_hint_line};
use super::date;
use crate::ca::{self, Ca, CrlStatus, Key};
use crate::config::{self, Config};
use crate::files::issue_to_files;
use crate::invite;
use crate::ledger::{Invite, InviteState, Ledger, Place, Status, Target};
use crate::nginx::{self, Auth, Mode, Site};
use crate::store::PRIVATE;
use crate::timer;
use crate::users::Users;

/// A CRL this close to expiring means the refresh timer is not running: say so on every screen.
const CRL_WARNING: Duration = Duration::days(7);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    People,
    Invites,
    Nginx,
    Users,
    Ca,
}

const TABS: [(Tab, &str); 5] = [
    (Tab::People, "People & agents"),
    (Tab::Invites, "Invites"),
    (Tab::Nginx, "Nginx"),
    (Tab::Users, "Users"),
    (Tab::Ca, "CA"),
];

enum Dialog {
    Form(Form),
    Revoke(RevokeDialog),
    Mode(ModeDialog),
    Auth(AuthDialog),
    Invite(InviteDialog),
    Message(Message),
}

/// How long the line above the key hints keeps saying what happened, and why something failed:
/// after that it says nothing, rather than reporting an old change as news on every tab.
const NOTICE_SHOWN: Duration = Duration::seconds(20);
const ERROR_SHOWN: Duration = Duration::seconds(60);

/// The line above the key hints: what the last action did, or why it failed.
struct Notice {
    text: String,
    error: bool,
    at: OffsetDateTime,
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
    /// The binary the timer runs: this one.
    pub(crate) binary: PathBuf,
    tab: Tab,
    people: People,
    invites: InvitesTab,
    nginx: NginxTab,
    users_tab: UsersTab,
    /// The HTTP logins nginx checks itself, as `users.toml` holds them.
    users: Users,
    ca_info: CaInfo,
    dialog: Option<Dialog>,
    notice: Option<Notice>,
    /// Text to put on the clipboard of the administrator's terminal: the event loop sends it as
    /// an OSC 52 sequence, which travels over SSH to the terminal itself.
    clipboard: Option<String>,
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
            binary: timer::this_binary().unwrap_or_default(),
            tab: Tab::People,
            people: People::default(),
            invites: InvitesTab::default(),
            nginx: NginxTab::default(),
            users_tab: UsersTab::default(),
            users: Users::default(),
            ca_info: CaInfo::default(),
            dialog: None,
            notice: None,
            clipboard: None,
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

    /// What is waiting to go on the terminal's clipboard, once.
    pub fn take_clipboard(&mut self) -> Option<String> {
        self.clipboard.take()
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
            self.users = Users::load(self.ca.store())?;
            if self.tend_invites() {
                self.ledger = self.ca.ledger()?;
                self.crl = Some(self.ca.crl_status()?);
            }
            Ok(())
        })();
        if let Some(notice) = &self.notice {
            let shown = if notice.error {
                ERROR_SHOWN
            } else {
                NOTICE_SHOWN
            };
            if now - notice.at > shown {
                self.notice = None;
            }
        }
        if let Err(error) = result {
            self.fail(format!("{error:#}"));
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
        let rows = self
            .users
            .users
            .iter()
            .map(|user| users_tab::Row {
                name: user.name.clone(),
                changed: date(user.changed),
                sites: match &survey {
                    Some(Ok(survey)) => survey
                        .sites
                        .iter()
                        .filter(
                            |s| matches!(&s.auth, Auth::On(names) if names.contains(&user.name)),
                        )
                        .map(|s| s.name().to_owned())
                        .collect(),
                    _ => Vec::new(),
                },
            })
            .collect();
        self.users_tab.update(rows);
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
            Some(Dialog::Auth(dialog)) => dialog.handle_key_event(key),
            Some(Dialog::Invite(dialog)) => dialog.handle_key_event(key),
            Some(Dialog::Message(message)) => message.handle_key_event(key),
            None if self.tab == Tab::People && self.people.wants(&key) => {
                self.people.handle_key_event(key)
            }
            None => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
                KeyCode::Tab => Some(Action::NextTab),
                KeyCode::BackTab => Some(Action::PreviousTab),
                KeyCode::Char('?') => Some(Action::Help),
                _ => match self.tab {
                    Tab::People => self.people.handle_key_event(key),
                    Tab::Invites => self.invites.handle_key_event(key),
                    Tab::Nginx => self.nginx.handle_key_event(key),
                    Tab::Users => self.users_tab.handle_key_event(key),
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
                let mut lines: Vec<Line> = Vec::new();
                for (name, text) in timer::units(&self.binary, self.ca.store().dir()) {
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
                let installed = timer::install(
                    &self.unit_dir,
                    &self.systemctl,
                    &self.binary,
                    self.ca.store().dir(),
                );
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
            Action::AskCancelInvite(invite) => {
                self.dialog = Some(Dialog::Message(Message::confirm(
                    format!("Cancel the invite for {}", invite.holder),
                    vec![
                        "Its link stops working, and the certificate it holds is revoked.".into(),
                        "To give the device a certificate after all, renew it with u on People & agents."
                            .dim()
                            .into(),
                    ],
                    Action::CancelInvite(invite.serial),
                    "cancel the invite",
                )));
            }
            Action::CopyInvite(invite) => {
                if let Some(enrollment) = &self.config.enrollment {
                    let link = invite::link(&enrollment.host, &invite.token);
                    self.perform(Action::Copy(link));
                }
            }
            Action::Copy(text) => {
                self.clipboard = Some(text);
                self.tell(
                    "Sent the link to your terminal's clipboard (if it allows OSC 52; the link is also on screen)."
                        .into(),
                );
            }
            Action::CancelInvite(serial) => {
                self.dialog = None;
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
            Action::AskSiteAuth(site) => self.ask_site_auth(site),
            Action::SetSiteAuth(site, auth) => self.set_site_auth(&site, &auth),
            Action::AskNewUser => self.dialog = Some(Dialog::Form(Form::new_user())),
            Action::AddUser { name, password } => self.add_user(&name, &password),
            Action::AskNewPassword(name) => {
                self.dialog = Some(Dialog::Form(Form::new_password(&name)));
            }
            Action::SetPassword { name, password } => self.set_password(&name, &password),
            Action::AskDeleteUser(name) => self.ask_delete_user(&name),
            Action::DeleteUser(name) => self.delete_user(&name),
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
                ca_files_in_nginx: config::checked_folder_in_nginx(std::path::Path::new(in_nginx))?,
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
        // A certificate still in an open invite is not on its device yet: it lets nobody in.
        let mut holders = std::collections::HashSet::new();
        let mut waiting = std::collections::HashSet::new();
        for (holder, certificate) in self.ledger.certificates() {
            if certificate.status(self.now) != Status::Valid {
                continue;
            }
            let open = invite_of(&self.ledger.invites, certificate.serial)
                .is_some_and(|i| i.state == InviteState::Open);
            if open {
                waiting.insert(holder.to_string());
            } else {
                holders.insert(holder.to_string());
            }
        }
        let waiting = waiting.difference(&holders).count();
        self.dialog = Some(Dialog::Mode(ModeDialog::new(
            site,
            changes,
            holders.len(),
            waiting,
        )));
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

    fn ask_site_auth(&mut self, site: Site) {
        let Some(settings) = &self.config.nginx else {
            return;
        };
        let original = std::fs::read_to_string(&site.file)
            .map_err(|e| format!("cannot read {}: {e}", site.file.display()));
        let refused = self.is_enrollment(&site).then(|| {
            "This is the enrollment site: whoever opens an invite has no login yet.".to_owned()
        });
        let users = self.users.names().map(str::to_owned).collect();
        self.dialog = Some(Dialog::Auth(AuthDialog::new(
            site,
            original,
            settings.clone(),
            users,
            refused,
        )));
    }

    fn set_site_auth(&mut self, site: &Site, auth: &Auth) {
        self.dialog = None;
        let Some(settings) = self.config.nginx.clone() else {
            return;
        };
        if self.is_enrollment(site) && *auth != Auth::Off {
            return self.fail(format!(
                "{} is the enrollment site: it never asks for a login.",
                site.name()
            ));
        }
        match nginx::set_auth(&settings, &self.ca, &self.users, site, auth) {
            Ok(true) => self.tell(format!(
                "{}'s login is now {auth}; nginx reloaded.",
                site.name()
            )),
            Ok(false) => self.tell(format!("{}'s login was already {auth}.", site.name())),
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

    /// Saves the users and rewrites the password files of the sites that use them; the lines that
    /// say what changed there.
    fn save_users(&mut self, users: &Users) -> anyhow::Result<Vec<Line<'static>>> {
        users.save(self.ca.store())?;
        self.users = users.clone();
        let Some(settings) = &self.config.nginx else {
            return Ok(Vec::new());
        };
        let mut lines = Vec::new();
        for (site, left) in nginx::publish_users(settings, &self.ca, users)? {
            lines.push(if left == 0 {
                format!("{site}: nobody can log in now; name a user with l on the Nginx tab.")
                    .fg(Color::Yellow)
                    .into()
            } else {
                format!("{site}: its password file is rewritten; nginx reloaded.").into()
            });
        }
        Ok(lines)
    }

    /// Shows a password once, with what else changed.
    fn show_password(
        &mut self,
        title: String,
        name: &str,
        password: &str,
        mut more: Vec<Line<'static>>,
    ) {
        let mut lines: Vec<Line> = vec![
            Line::default(),
            vec![
                "  ".into(),
                name.to_owned().bold(),
                "  ".into(),
                password.to_owned().bold(),
            ]
            .into(),
            Line::default(),
            "It is not shown again: ffca keeps only its hash."
                .dim()
                .into(),
        ];
        if !more.is_empty() {
            lines.push(Line::default());
            lines.append(&mut more);
        }
        self.dialog = Some(Dialog::Message(Message::new(title, lines)));
    }

    /// Adds a user; with no password typed, ffca makes one up and shows it once.
    fn add_user(&mut self, name: &str, password: &str) {
        let mut users = self.users.clone();
        let made_up = password.is_empty();
        let added = users
            .add(name, (!made_up).then_some(password))
            .and_then(|password| self.save_users(&users).map(|more| (password, more)));
        match added {
            Ok((password, more)) => {
                let name = crate::users::checked_name(name).unwrap_or_default();
                self.reload(self.now);
                self.users_tab.select(&name);
                self.tell(format!("Added {name}."));
                if made_up {
                    self.show_password(format!("{name}'s password"), &name, &password, more);
                } else {
                    self.dialog = None;
                }
            }
            Err(error) => self.refuse(format!("{error:#}")),
        }
    }

    /// A new password, typed or made up; the sites that let the user in get it at once.
    fn set_password(&mut self, name: &str, password: &str) {
        let mut users = self.users.clone();
        let made_up = password.is_empty();
        let changed = users
            .set_password(name, (!made_up).then_some(password))
            .and_then(|password| self.save_users(&users).map(|more| (password, more)));
        match changed {
            Ok((password, more)) => {
                self.tell(format!("{name} has a new password."));
                if made_up {
                    self.show_password(format!("{name}'s new password"), name, &password, more);
                } else if more.is_empty() {
                    self.dialog = None;
                } else {
                    self.dialog = Some(Dialog::Message(Message::new(
                        format!("{name}'s new password"),
                        more,
                    )));
                }
                self.reload(self.now);
            }
            Err(error) => self.refuse(format!("{error:#}")),
        }
    }

    fn ask_delete_user(&mut self, name: &str) {
        let sites: Vec<String> = match self.config.nginx.as_ref().map(nginx::survey) {
            Some(Ok(survey)) => survey
                .sites
                .iter()
                .filter(|s| matches!(&s.auth, Auth::On(names) if names.iter().any(|n| n == name)))
                .map(|s| s.name().to_owned())
                .collect(),
            _ => Vec::new(),
        };
        let mut lines: Vec<Line> = vec![format!("{name} can no longer log in anywhere.").into()];
        if !sites.is_empty() {
            lines.push(
                format!("Sites that let them in now: {}.", sites.join(", "))
                    .dim()
                    .into(),
            );
        }
        self.dialog = Some(Dialog::Message(Message::confirm(
            format!("Delete {name}"),
            lines,
            Action::DeleteUser(name.to_owned()),
            "delete",
        )));
    }

    fn delete_user(&mut self, name: &str) {
        self.dialog = None;
        let mut users = self.users.clone();
        match users.remove(name).and_then(|()| self.save_users(&users)) {
            Ok(more) => {
                self.tell(format!("Deleted {name}."));
                if !more.is_empty() {
                    self.dialog = Some(Dialog::Message(Message::new(
                        format!("{name} is deleted"),
                        more,
                    )));
                }
            }
            Err(error) => self.fail(format!("{error:#}")),
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
            let check = self.check_site();
            match invite::make_with_check(
                &self.ca,
                &invite::dir(self.ca.store()),
                holder,
                &enrollment.host,
                check.as_deref(),
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

    /// The site an invite sends its person to, to see that the certificate works: one that requires
    /// this CA's certificate, else one that accepts it, by its first plain name.
    fn check_site(&self) -> Option<String> {
        let survey = nginx::survey(self.config.nginx.as_ref()?).ok()?;
        let candidates = |mode: Mode| {
            survey
                .sites
                .iter()
                .filter(move |s| s.mode == mode && s.uses_ca && !s.duplicate)
                .filter(|s| !self.is_enrollment(s))
                .map(|s| s.name())
                .find(|n| !n.contains(['*', '~']) && *n != "_" && n.contains('.'))
        };
        let name = candidates(Mode::Required).or_else(|| candidates(Mode::Optional))?;
        Some(format!("https://{name}/"))
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
                match tended.collected.as_slice() {
                    [] => {}
                    [holder] => self.tell(format!("{holder} collected their invite.")),
                    holders => {
                        self.tell(format!("{} collected their invites.", holders.join(", ")))
                    }
                }
                if !tended.problems.is_empty() {
                    self.fail(format!(
                        "In the invites folder: {}",
                        tended.problems.join("; ")
                    ));
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
        self.notice = Some(Notice {
            text,
            error: false,
            at: self.now,
        });
    }

    fn fail(&mut self, text: String) {
        self.notice = Some(Notice {
            text,
            error: true,
            at: self.now,
        });
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
        let titles: Vec<Line> = TABS
            .iter()
            .map(|(tab, name)| match self.tab_count(*tab) {
                Some(count) => Line::from(vec![(*name).into(), format!(" · {count}").dim()]),
                None => Line::from(*name),
            })
            .collect();
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
            Tab::Users => self.users_tab.draw(frame, body),
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
            Tab::Users => self.users_tab.hints(),
            Tab::Ca => self.ca_info.hints(),
        };
        // While the People filter is typed, the shared keys are text: they are not offered.
        let typing = self.tab == Tab::People && self.people.typing();
        let always: &[Hint] = if typing {
            &[]
        } else {
            keys.push(("Tab", "switch"));
            &[("?", "help"), ("q", "quit")]
        };
        let hints = Rect {
            x: hints.x + 1,
            width: hints.width.saturating_sub(1),
            ..hints
        };
        let line = fitted_hint_line(&keys, always, hints.width.into());
        frame.render_widget(Paragraph::new(line), hints);
        match &mut self.dialog {
            Some(Dialog::Form(form)) => form.draw(frame, body),
            Some(Dialog::Revoke(dialog)) => dialog.draw(frame, body),
            Some(Dialog::Mode(dialog)) => dialog.draw(frame, body),
            Some(Dialog::Auth(dialog)) => dialog.draw(frame, body),
            // The QR code needs every row the terminal has: on 80 by 24 it covers the whole screen.
            Some(Dialog::Invite(dialog)) => {
                frame.render_widget(ratatui::widgets::Clear, frame.area());
                dialog.draw(frame, frame.area());
            }
            Some(Dialog::Message(message)) => message.draw(frame, body),
            None => {}
        }
    }

    /// What a tab's title counts, if anything needs looking at there: open invites, and devices
    /// and agents whose certificate expires soon.
    fn tab_count(&self, tab: Tab) -> Option<String> {
        let count = match tab {
            Tab::Invites => {
                let open = self
                    .ledger
                    .invites
                    .iter()
                    .filter(|i| i.state == InviteState::Open)
                    .count();
                return (open > 0).then(|| format!("{open} open"));
            }
            Tab::People => self.people.expiring(),
            _ => 0,
        };
        (count > 0).then(|| format!("{count} expiring"))
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
            key("Tab", "switch between People & agents, Invites, Nginx, Users and CA"),
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
            key("/", "narrow People & agents to the names that contain what is typed"),
            key("e", "on the Nginx tab: where nginx is, and the enrollment site"),
            key("s", "on the Nginx tab: a site's client certificate: off, optional, required"),
            key("l", "on the Nginx tab: a site's HTTP login: off, passthrough, on, and who"),
            key("n  c  d", "on the Users tab: a new user, change a password, delete"),
            key("t", "on the Nginx tab: test nginx's configuration"),
            key("w", "on the Nginx tab: write the enrollment site"),
            key(
                "Enter  c  x",
                "on the Invites tab: show an invite's QR code again, copy its link, cancel it",
            ),
            key("c", "on the CA tab: sign a new CRL now"),
            key("T", "on the CA tab: set up the hourly refresh timer"),
            key("PgUp PgDn", "scroll a dialog taller than the screen"),
            key("Ctrl-U  W", "in a form: clear the field, delete a word (Ctrl-A, E: start, end)"),
            key("Ctrl-S", "in a form: done, from any field"),
            key("q  Esc", "quit, or close a dialog"),
            Line::default(),
            "After a renewal, revoke the device again as \"replaced\": that revokes every certificate but the newest."
                .into(),
        ],
    )
}

#[cfg(test)]
mod tests;
