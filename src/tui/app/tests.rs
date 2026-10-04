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
//! The UI driven the way the administrator drives it - keys in, screen out - against a real CA in
//! a temporary folder.

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use time::macros::datetime;

use super::*;
use crate::config;
use crate::ledger::{Holder, Reason};
use crate::store::Store;

const NOW: OffsetDateTime = datetime!(2026-10-03 12:00 UTC);

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    out: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = crate::test_dir();
        let store = Store::new(dir.path().join("state"));
        Ca::create(&store, "Test family", NOW, ca::DEFAULT_CA_VALIDITY).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        Fixture {
            _dir: dir,
            store,
            out,
        }
    }

    /// The CA as another process sees it.
    fn ca(&self) -> Ca {
        Ca::open(&self.store).unwrap()
    }

    fn app(&self, now: OffsetDateTime) -> App {
        App::new(self.ca(), self.out.clone(), now)
    }

    fn issue(&self, holder: Holder, now: OffsetDateTime, days: i64) {
        self.ca()
            .issue(holder, Key::Generate, now, Duration::days(days))
            .unwrap();
    }
}

const ANNA_PHONE: Holder = Holder::Device {
    person: "Anna",
    device: "phone",
};
const ANNA_LAPTOP: Holder = Holder::Device {
    person: "Anna",
    device: "laptop",
};

fn screen(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(110, 40)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn key(app: &mut App, code: KeyCode) {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE), app.now);
}

fn type_text(app: &mut App, text: &str) {
    text.chars().for_each(|c| key(app, KeyCode::Char(c)));
}

fn assert_shows(app: &mut App, expected: &str) {
    let screen = screen(app);
    assert!(screen.contains(expected), "no {expected:?} on\n{screen}");
}

#[test]
fn an_empty_ca_says_how_to_start() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    assert_shows(&mut app, "No one has a certificate yet");
    assert_shows(&mut app, "Press p to add a person");
    assert_shows(&mut app, "p new person");
    assert_shows(&mut app, "Friends and Family CA · Test family");
}

#[test]
fn issuing_to_a_new_person_writes_the_files_and_shows_them_in_the_tree() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('p'));
    type_text(&mut app, "Anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "phone");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Issued to Anna (phone), valid until 2 Oct 2028.");
    assert!(fixture.out.join("anna-phone.crt").exists());
    assert!(fixture.out.join("anna-phone.key").exists());
    key(&mut app, KeyCode::Enter);
    let screen = screen(&mut app);
    assert!(screen.contains("▾ Anna"), "{screen}");
    assert!(screen.contains("● phone          until 2028"), "{screen}");
    assert!(
        screen.contains("CN=Anna (phone),OU=people"),
        "the details show the subject:\n{screen}"
    );
    assert_eq!(
        app.people.selection(),
        Some(Selection::Device {
            person: "Anna".into(),
            device: "phone".into()
        })
    );
}

#[test]
fn a_new_device_form_starts_from_the_selected_person() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "laptop");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Issued to Anna (laptop)");
}

#[test]
fn keys_typed_into_a_form_are_text_not_commands() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('a'));
    type_text(&mut app, "q?r");
    assert!(!app.should_quit());
    assert_shows(&mut app, "Agent  q?r");
}

#[test]
fn a_refused_name_keeps_the_form_open_with_the_reason() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('a'));
    type_text(&mut app, "anna");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.form_purpose(),
        Some(&super::super::components::form::Purpose::NewAgent)
    );
    assert_shows(&mut app, "anna is a person's name; an agent needs another");
    assert_eq!(fixture.ca().ledger().unwrap().agents.len(), 0);
}

#[test]
fn revoking_a_device_reaches_that_device_only() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture.issue(ANNA_LAPTOP, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('r'));
    let screen = screen(&mut app);
    assert!(screen.contains("Revoke Anna · phone"), "{screen}");
    assert!(!screen.contains("keeps the newest"), "{screen}");
    assert!(
        screen.contains("› Lost or stolen"),
        "lost is the default for one certificate:\n{screen}"
    );
    assert!(screen.contains("Anna (phone)  "), "{screen}");
    assert!(!screen.contains("Anna (laptop)  "), "{screen}");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Revoked Anna (phone). The new CRL is signed.");
    assert_shows(&mut app, "✕ phone          revoked");
    assert_shows(&mut app, "● laptop         until");
}

#[test]
fn revoking_a_person_lists_and_retires_every_device() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture.issue(ANNA_LAPTOP, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('r'));
    let screen = screen(&mut app);
    assert!(screen.contains("Revoke Anna "), "{screen}");
    assert!(
        screen.contains("Anna (phone)") && screen.contains("Anna (laptop)"),
        "{screen}"
    );
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    let ledger = fixture.ca().ledger().unwrap();
    assert!(
        ledger.people[0]
            .devices
            .iter()
            .all(|d| d.retired == Some(NOW))
    );
    assert_shows(&mut app, "✕ laptop         retired");
}

#[test]
fn renewing_then_revoking_as_replaced_keeps_the_new_certificate() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW - Duration::days(300), 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('u'));
    assert_shows(&mut app, "Issued to Anna (phone)");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "2 valid certificates");
    key(&mut app, KeyCode::Char('r'));
    let screen = screen(&mut app);
    assert!(screen.contains("› Replaced"), "{screen}");
    let revokes = screen.find("This revokes:").expect(&screen);
    let keeps = screen.find("and keeps the newest:").expect(&screen);
    assert!(
        screen[revokes..keeps].contains("valid until 7 Dec 2026"),
        "the old one goes:\n{screen}"
    );
    assert!(
        screen[keeps..].contains("valid until 2 Oct 2028"),
        "the new one stays:\n{screen}"
    );
    key(&mut app, KeyCode::Enter);
    let ledger = fixture.ca().ledger().unwrap();
    let phone = &ledger.people[0].devices[0];
    assert_eq!(phone.certificates.len(), 2);
    assert_eq!(
        phone.current(NOW).unwrap().not_before,
        NOW - Duration::hours(1)
    );
    assert_eq!(phone.certificates[0].reason, Some(Reason::Replaced));
}

#[test]
fn renaming_keeps_the_selection_on_the_renamed() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture.issue(
        Holder::Device {
            person: "Ben",
            device: "tablet",
        },
        NOW,
        365,
    );
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('R'));
    assert_shows(&mut app, "New name  Anna");
    (0..4).for_each(|_| key(&mut app, KeyCode::Backspace));
    type_text(&mut app, "Zora");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.people.selection(),
        Some(Selection::Person("Zora".into()))
    );
    assert_shows(&mut app, "Renamed Anna to Zora.");
}

#[test]
fn a_retired_device_offers_only_a_rename() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture
        .ca()
        .revoke(Target::Holder(ANNA_PHONE), Reason::Retired, NOW)
        .unwrap();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    let screen = screen(&mut app);
    assert!(
        !screen.contains("u renew") && !screen.contains("r revoke"),
        "{screen}"
    );
    assert!(screen.contains("Retired 3 Oct 2026"), "{screen}");
    key(&mut app, KeyCode::Char('u'));
    key(&mut app, KeyCode::Char('r'));
    assert!(app.dialog.is_none());
    assert_eq!(fixture.ca().ledger().unwrap().certificates().count(), 1);
}

#[test]
fn a_certificate_close_to_expiry_is_marked() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 10);
    let mut app = fixture.app(NOW);
    assert_shows(&mut app, "◐ phone          expires in 10 d");
}

#[test]
fn the_ca_tab_shows_the_crl_and_signs_a_new_one() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::BackTab);
    assert_shows(&mut app, "number 1, valid until 2 Nov 2026");
    assert_shows(&mut app, "owner only");
    key(&mut app, KeyCode::Char('c'));
    assert_shows(&mut app, "number 2");
    assert_shows(&mut app, "Signed a new CRL");
}

#[test]
fn an_ageing_crl_is_flagged_on_every_screen() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW + Duration::days(25));
    assert_shows(
        &mut app,
        "CRL expires in 5 d: is the refresh timer running?",
    );
    let mut app = fixture.app(NOW + Duration::days(31));
    assert_shows(&mut app, "CRL EXPIRED");
}

#[test]
fn the_selection_survives_changes_by_other_processes() {
    let fixture = Fixture::new();
    fixture.issue(
        Holder::Device {
            person: "Ben",
            device: "tablet",
        },
        NOW,
        365,
    );
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    let selected = app.people.selection();
    fixture.issue(ANNA_PHONE, NOW, 365);
    app.reload(NOW);
    assert_eq!(app.people.selection(), selected);
    assert_shows(&mut app, "▾ Anna");
}

#[test]
fn the_cursor_moves_past_the_agents_heading() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture.issue(Holder::Agent("backup"), NOW, 365);
    let mut app = fixture.app(NOW);
    (0..2).for_each(|_| key(&mut app, KeyCode::Down));
    assert_eq!(
        app.people.selection(),
        Some(Selection::Agent("backup".into()))
    );
    key(&mut app, KeyCode::Up);
    assert_eq!(
        app.people.selection(),
        Some(Selection::Device {
            person: "Anna".into(),
            device: "phone".into()
        })
    );
}

#[test]
fn help_quit_and_control_c() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('?'));
    assert_shows(&mut app, "revoke the selected device or agent");
    key(&mut app, KeyCode::Esc);
    assert!(!app.should_quit(), "Esc closes the dialog first");
    key(&mut app, KeyCode::Char('a'));
    app.handle_key(
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        NOW,
    );
    assert!(app.should_quit(), "Ctrl-C quits from inside a form");
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit());
}

#[test]
fn files_are_written_where_asked() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('a'));
    type_text(&mut app, "Backup job");
    key(&mut app, KeyCode::Enter);
    assert!(Path::new(&fixture.out.join("backup-job.key")).exists());
}

/// Not a check: prints the main screens, for a person to look at with `--nocapture`.
#[test]
#[ignore]
fn print_screens() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW - Duration::days(300), 365);
    fixture.issue(ANNA_PHONE, NOW, 730);
    fixture.issue(ANNA_LAPTOP, NOW, 730);
    fixture.issue(
        Holder::Device {
            person: "Ben",
            device: "tablet",
        },
        NOW,
        730,
    );
    fixture
        .ca()
        .revoke(Target::Person("Ben"), Reason::Retired, NOW)
        .unwrap();
    fixture.issue(Holder::Agent("backup"), NOW, 730);
    fixture.issue(Holder::Agent("monitoring"), NOW, 12);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    println!("{}\n", screen(&mut app));
    key(&mut app, KeyCode::Char('r'));
    println!("{}\n", screen(&mut app));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('n'));
    println!("{}\n", screen(&mut app));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Tab);
    println!("{}", screen(&mut app));
}

#[test]
fn p_adds_a_new_person_even_with_someone_selected() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('p'));
    let screen = screen(&mut app);
    assert!(screen.contains("New person"), "{screen}");
    assert!(
        !screen.contains("Person        Anna"),
        "the form starts empty:\n{screen}"
    );
    type_text(&mut app, "Ben");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "tablet");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Issued to Ben (tablet)");
}

#[test]
fn p_refuses_a_person_who_is_already_there() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('p'));
    type_text(&mut app, "anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "laptop");
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "Anna is already here: select them and press n to add a device.",
    );
    assert_eq!(fixture.ca().ledger().unwrap().certificates().count(), 1);
}

#[test]
fn n_is_offered_only_where_there_is_a_person_to_add_to() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture.issue(Holder::Agent("backup"), NOW, 365);
    let mut app = fixture.app(NOW);
    assert_shows(&mut app, "n new device");
    (0..2).for_each(|_| key(&mut app, KeyCode::Down));
    let screen = screen(&mut app);
    assert!(
        !screen.contains("n new device"),
        "an agent is selected:\n{screen}"
    );
    assert!(screen.contains("p new person"), "{screen}");
}

/// A folder for sites, which ffca writes into only while nobody else can change it, whatever the
/// umask would have made it.
fn sites_folder(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A site folder with one HTTPS site, and settings that reach it with `test` and `reload`.
fn with_nginx(
    fixture: &Fixture,
    test: &str,
    reload: &str,
    enrollment: Option<&str>,
) -> config::Nginx {
    let root = fixture.out.parent().unwrap().join("nginx");
    sites_folder(&root.join("conf.d"));
    for (file, name) in [
        ("books.conf", "books.example.org"),
        ("enroll.conf", "k.example.invalid"),
    ] {
        std::fs::write(
            root.join("conf.d").join(file),
            format!("server {{\n    listen 443 ssl;\n    server_name {name};\n}}\n"),
        )
        .unwrap();
    }
    let settings = config::Nginx {
        sites: root.join("conf.d"),
        ca_files: root.join("certs"),
        ca_files_in_nginx: "/etc/nginx/certs".into(),
        test: test.into(),
        reload: reload.into(),
    };
    Config {
        nginx: Some(settings.clone()),
        enrollment: enrollment.map(|host| config::Enrollment {
            host: host.into(),
            upstream: config::default_upstream(),
            user: config::default_page_user(),
        }),
    }
    .save(&fixture.store)
    .unwrap();
    settings
}

/// Presses Tab until `tab` shows, as the administrator would.
fn go_to(app: &mut App, tab: Tab) {
    for _ in 0..TABS.len() {
        if app.tab == tab {
            return;
        }
        key(app, KeyCode::Tab);
    }
    panic!("Tab never reaches {tab:?}");
}

/// This process's `uid:gid`, read off a file it makes.
fn own_user() -> String {
    use std::os::unix::fs::MetadataExt;
    let probe = tempfile::NamedTempFile::new().unwrap();
    let metadata = probe.as_file().metadata().unwrap();
    format!("{}:{}", metadata.uid(), metadata.gid())
}

/// Replaces the focused field's text.
fn retype(app: &mut App, text: &str) {
    (0..200).for_each(|_| key(app, KeyCode::Backspace));
    type_text(app, text);
}

#[test]
fn the_nginx_tab_says_what_is_missing_until_it_is_set_up() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    assert_shows(&mut app, "ffca does not know where nginx is yet.");
    assert_shows(&mut app, "e settings");
}

#[test]
fn the_settings_form_saves_publishes_and_lists_the_sites() {
    let fixture = Fixture::new();
    let root = fixture.out.parent().unwrap().join("nginx");
    sites_folder(&root.join("conf.d"));
    std::fs::write(
        root.join("conf.d/books.conf"),
        "server {\n    listen 443 ssl;\n    server_name books.example.org;\n}\n",
    )
    .unwrap();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('e'));
    assert_shows(&mut app, "Site configs        /etc/nginx/conf.d");
    for value in [
        root.join("conf.d").display().to_string(),
        root.join("certs").display().to_string(),
        "/etc/nginx/certs".into(),
        "true".into(),
        "true".into(),
        "K.Example.Invalid".into(),
    ] {
        retype(&mut app, &value);
        key(&mut app, KeyCode::Enter);
    }
    // The page's address keeps its suggestion; it runs as this test does, which owns its folder.
    assert_shows(&mut app, "Enrollment page at  http://ffca:8080");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Page runs as        65534:65534");
    retype(&mut app, &own_user());
    key(&mut app, KeyCode::Enter);
    let screen = screen(&mut app);
    assert!(screen.contains("Saved."), "{screen}");
    assert!(
        screen.contains("k.example.invalid  does not resolve: it needs a DNS record"),
        "{screen}"
    );
    assert!(screen.contains("books.example.org"), "{screen}");
    assert!(root.join("certs/ffca-ca.crt").exists() && root.join("certs/ffca.crl").exists());
    let saved = Config::load(&fixture.store).unwrap();
    assert_eq!(saved.enrollment.unwrap().host, "k.example.invalid");
    assert_eq!(saved.nginx.unwrap().test, "true");
}

#[test]
fn settings_that_cannot_work_keep_the_form_open() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('e'));
    retype(&mut app, "/nonexistent/conf.d");
    (0..8).for_each(|_| key(&mut app, KeyCode::Enter));
    assert_shows(&mut app, "cannot read /nonexistent/conf.d");
    assert!(app.form_purpose().is_some());
    assert!(!fixture.store.exists(config::FILE));
}

#[test]
fn a_site_is_set_to_required_after_its_change_is_shown() {
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "true", "true", None);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    assert_shows(&mut app, "books.example.org");
    key(&mut app, KeyCode::Char('s'));
    assert_shows(&mut app, "› off");
    assert_shows(&mut app, "Nothing to change.");
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    let screen = screen(&mut app);
    assert!(screen.contains("+ ssl_verify_client on;"), "{screen}");
    assert!(
        screen.contains("+ ssl_crl /etc/nginx/certs/ffca.crl;"),
        "{screen}"
    );
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "books.example.org is now required; nginx reloaded.",
    );
    assert_shows(&mut app, "● required");
    let file = std::fs::read_to_string(settings.sites.join("books.conf")).unwrap();
    assert!(file.contains("ssl_verify_client on;"), "{file}");
}

#[test]
fn the_enrollment_site_never_asks_for_a_certificate() {
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "true", "true", Some("k.example.invalid"));
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    assert_shows(&mut app, "enrollment site: never asks");
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert_shows(&mut app, "This is the enrollment site");
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "k.example.invalid is the enrollment site: it never asks for a certificate.",
    );
    let file = std::fs::read_to_string(settings.sites.join("enroll.conf")).unwrap();
    assert!(!file.contains("ssl_verify_client"), "{file}");
}

#[test]
fn a_change_nginx_refuses_is_reported_and_undone() {
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "false", "true", None);
    let before = std::fs::read_to_string(settings.sites.join("books.conf")).unwrap();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "books.example.org is unchanged");
    assert_shows(&mut app, "is back as it was");
    assert_eq!(
        std::fs::read_to_string(settings.sites.join("books.conf")).unwrap(),
        before
    );
}

#[test]
fn a_revocation_reaches_nginx() {
    let fixture = Fixture::new();
    let reloaded = fixture.out.join("reloaded");
    let settings = with_nginx(
        &fixture,
        "true",
        &format!("touch {}", reloaded.display()),
        None,
    );
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('r'));
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "Revoked Anna (phone). The new CRL is signed. nginx reloaded with it.",
    );
    assert!(reloaded.exists());
    assert_eq!(
        std::fs::read_to_string(settings.ca_files.join("ffca.crl")).unwrap(),
        fixture.store.read(ca::CRL_FILE).unwrap()
    );
}

#[test]
fn a_reload_that_fails_after_a_revocation_says_nginx_still_has_the_old_crl() {
    let fixture = Fixture::new();
    with_nginx(&fixture, "true", "false", None);
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('r'));
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "nginx did not reload");
    assert_shows(&mut app, "nginx still has the previous one");
}

#[test]
fn t_shows_what_nginx_says_about_its_configuration() {
    let fixture = Fixture::new();
    with_nginx(&fixture, "echo syntax is ok", "true", None);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('t'));
    assert_shows(&mut app, "nginx accepts its configuration");
    assert_shows(&mut app, "syntax is ok");
}

/// Settings with an enrollment site and nothing else of nginx: what invites need.
fn with_enrollment(fixture: &Fixture) {
    with_nginx(fixture, "true", "true", Some("k.example.invalid"));
}

fn invites_folder(fixture: &Fixture) -> std::path::PathBuf {
    invite::dir(&fixture.store)
}

fn token_on_screen(screen: &str) -> String {
    let start = screen.find("https://k.example.invalid/i/").expect(screen)
        + "https://k.example.invalid/i/".len();
    screen[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

#[test]
fn a_new_device_gets_an_invite_with_its_qr_code() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('p'));
    type_text(&mut app, "Anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "phone");
    key(&mut app, KeyCode::Enter);
    let screen = screen(&mut app);
    assert!(screen.contains("Invite for Anna (phone)"), "{screen}");
    assert!(
        screen.contains("Works once · expires 4 Oct 2026 12:00 UTC"),
        "{screen}"
    );
    assert!(screen.contains("▀▀▀"), "a QR code:\n{screen}");
    let token = token_on_screen(&screen);
    assert_eq!(token.len(), 43, "{screen}");
    assert!(
        std::fs::read_dir(fixture.out.clone())
            .unwrap()
            .next()
            .is_none(),
        "no files are written"
    );
    let payload = invite::open(&invites_folder(&fixture), &token, NOW).unwrap();
    assert_eq!(payload.holder, "Anna (phone)");
}

#[test]
fn the_invites_tab_shows_an_invite_again_and_cancels_it() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let made = invite::make(
        &fixture.ca(),
        &invites_folder(&fixture),
        ANNA_PHONE,
        "k.example.invalid",
        NOW,
    )
    .unwrap();
    let mut app = fixture.app(NOW + Duration::hours(3));
    go_to(&mut app, Tab::Invites);
    assert_shows(&mut app, "◐ Anna (phone)                   open, 21 h left");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        format!(
            "https://k.example.invalid/i/{}",
            token_on_screen(&screen(&mut app))
        ),
        made.link
    );
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Char('x'));
    assert_shows(
        &mut app,
        "Cancelled the invite; its certificate is revoked.",
    );
    assert_shows(
        &mut app,
        "✕ Anna (phone)                   cancelled 3 Oct 2026",
    );
    let ledger = fixture.ca().ledger().unwrap();
    assert_eq!(
        ledger
            .find(&made.invite.serial.to_string())
            .unwrap()
            .1
            .status(NOW),
        Status::Revoked
    );
}

#[test]
fn a_collected_invite_shows_up_by_itself() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let made = invite::make(
        &fixture.ca(),
        &invites_folder(&fixture),
        ANNA_PHONE,
        "k.example.invalid",
        NOW,
    )
    .unwrap();
    let mut app = fixture.app(NOW);
    let token = made.link.rsplit('/').next().unwrap();
    invite::collect(
        &invites_folder(&fixture),
        token,
        NOW + Duration::minutes(5),
        "203.0.113.7, iPhone",
    )
    .unwrap();
    app.reload(NOW + Duration::minutes(6));
    assert_shows(&mut app, "Anna (phone) collected their invite.");
    go_to(&mut app, Tab::Invites);
    assert_shows(
        &mut app,
        "● Anna (phone)                   collected 3 Oct 2026 by 203.0.113.7, iPhone",
    );
}

#[test]
fn an_invite_never_collected_expires_and_its_certificate_goes() {
    let fixture = Fixture::new();
    let reloaded = fixture.out.join("reloaded");
    with_nginx(
        &fixture,
        "true",
        &format!("touch {}", reloaded.display()),
        Some("k.example.invalid"),
    );
    let made = invite::make(
        &fixture.ca(),
        &invites_folder(&fixture),
        ANNA_PHONE,
        "k.example.invalid",
        NOW,
    )
    .unwrap();
    let later = NOW + invite::VALIDITY + Duration::minutes(1);
    let mut app = fixture.app(later);
    go_to(&mut app, Tab::Invites);
    assert_shows(
        &mut app,
        "○ Anna (phone)                   expired 4 Oct 2026",
    );
    let ledger = fixture.ca().ledger().unwrap();
    assert_eq!(
        ledger
            .find(&made.invite.serial.to_string())
            .unwrap()
            .1
            .status(later),
        Status::Revoked
    );
    assert!(reloaded.exists(), "the new CRL reached nginx");
}

#[test]
fn an_agent_still_gets_files() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('a'));
    type_text(&mut app, "backup");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Issued to backup (agent)");
    assert!(fixture.out.join("backup.key").exists());
}

#[test]
fn w_writes_the_enrollment_site_after_showing_it() {
    let fixture = Fixture::new();
    let root = fixture.out.parent().unwrap().join("nginx");
    sites_folder(&root.join("conf.d"));
    std::fs::write(
        root.join("conf.d/cloud.conf"),
        "server {\n    listen 443 ssl default_server;\n    http2 on;\n    server_name cloud.example.org;\n    ssl_certificate /etc/le/example/fullchain.pem;\n    ssl_certificate_key /etc/le/example/privkey.pem;\n    include /etc/nginx/ssl-params.inc;\n    location / { return 200; }\n}\n",
    )
    .unwrap();
    let settings = config::Nginx {
        sites: root.join("conf.d"),
        ca_files: root.join("certs"),
        ca_files_in_nginx: "/etc/nginx/certs".into(),
        test: "true".into(),
        reload: "true".into(),
    };
    Config {
        nginx: Some(settings.clone()),
        enrollment: Some(config::Enrollment {
            host: "k.example.org".into(),
            upstream: "http://ffca:8080".into(),
            user: config::default_page_user(),
        }),
    }
    .save(&fixture.store)
    .unwrap();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    assert_shows(&mut app, "w write enrollment site");
    key(&mut app, KeyCode::Char('w'));
    let screen = screen(&mut app);
    assert!(screen.contains("server_name k.example.org;"), "{screen}");
    assert!(
        screen.contains("listen 443 ssl;"),
        "default_server stays with its site:\n{screen}"
    );
    assert!(
        screen.contains("ssl_certificate /etc/le/example/fullchain.pem;"),
        "{screen}"
    );
    assert!(screen.contains("Enter write"), "{screen}");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "k.example.org is up; nginx reloaded.");
    assert_shows(&mut app, "enrollment site: never asks");
    let written = std::fs::read_to_string(settings.sites.join(nginx::ENROLLMENT_FILE)).unwrap();
    assert!(
        written.contains("set $ffca_enrollment http://ffca:8080;"),
        "{written}"
    );
    assert!(
        written.contains("include /etc/nginx/ssl-params.inc;"),
        "{written}"
    );
    assert!(
        written.contains("ssl_verify_client off;") && !written.contains("ssl_verify_client on"),
        "{written}"
    );
}

#[test]
fn t_sets_up_the_refresh_timer_after_showing_its_units() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let units = fixture.out.join("units");
    std::fs::create_dir(&units).unwrap();
    let log = fixture.out.join("systemctl.log");
    let systemctl = fixture.out.join("systemctl.sh");
    std::fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$@\" >> {}\ncase \"$1\" in is-active) echo active;; esac\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut app = fixture.app(NOW);
    app.systemctl = systemctl.display().to_string();
    app.unit_dir = units.clone();
    // As `make install` leaves it: the test's own, writable by nobody else.
    let bin = fixture.out.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(bin.join("ffca"), "").unwrap();
    std::fs::set_permissions(bin.join("ffca"), std::fs::Permissions::from_mode(0o755)).unwrap();
    app.binary = bin.join("ffca");
    go_to(&mut app, Tab::Ca);
    key(&mut app, KeyCode::Char('T'));
    let screen = screen(&mut app);
    assert!(screen.contains("ffca-crl-refresh.timer:"), "{screen}");
    assert!(screen.contains("OnCalendar=hourly"), "{screen}");
    assert!(
        screen.contains(&format!(
            "Environment=FFCA_STATE_DIR=\"{}\"",
            fixture.store.dir().display()
        )),
        "{screen}"
    );
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "The refresh timer is set up: hourly.");
    assert_shows(&mut app, "Refresh timer active, hourly");
    assert!(units.join(timer::SERVICE).exists() && units.join(timer::TIMER).exists());
    let calls = std::fs::read_to_string(log).unwrap();
    assert!(
        calls.contains("daemon-reload\nenable --now ffca-crl-refresh.timer\n"),
        "{calls}"
    );
}
