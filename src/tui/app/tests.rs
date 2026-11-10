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
    screen_of(app, 110, 40)
}

/// The screen on a terminal of `width` by `height`: 80 by 24 is a plain SSH session's.
fn screen_of(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
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
    assert!(screen.contains("│ Anna"), "{screen}");
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
    key(&mut app, KeyCode::Char('y'));
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
    key(&mut app, KeyCode::Enter);
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
    assert_shows(&mut app, "◐ phone          10 d left");
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
    assert_shows(&mut app, "│ Anna");
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
        users_group: None,
    };
    Config {
        nginx: Some(settings.clone()),
        enrollment: enrollment.map(|host| config::Enrollment {
            host: host.into(),
            upstream: config::default_upstream(),
            user: config::default_page_user(),
            password: Default::default(),
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
    assert!(
        screen.contains("No device or agent has a valid certificate from this CA yet"),
        "requiring one before anyone has one locks everybody out:\n{screen}"
    );
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
    assert_shows(&mut app, "login off  enrollment site");
    key(&mut app, KeyCode::Down);
    assert_shows(
        &mut app,
        "k.example.invalid is the enrollment site: it never asks for a certificate or a login.",
    );
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
    assert_shows(&mut app, "◌ Anna (phone)   open, 21 h left");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        format!(
            "https://k.example.invalid/i/{}",
            token_on_screen(&screen(&mut app))
        ),
        made.link
    );
    key(&mut app, KeyCode::Char('c'));
    assert_eq!(app.take_clipboard().as_deref(), Some(made.link.as_str()));
    // The dialog covers the line that would say so, and says so itself.
    assert_shows(&mut app, "✓ Link copied, if your terminal allows it");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Char('c'));
    assert_eq!(
        app.take_clipboard().as_deref(),
        Some(made.link.as_str()),
        "the tab copies the selected invite's link too"
    );
    // On the tab no link is on screen: the notice says whose was copied, and how to see it.
    assert_shows(
        &mut app,
        "Link for Anna (phone) copied, if your terminal allows it (OSC 52). Enter shows it.",
    );
    // Cancelling revokes a certificate: it asks first, and Esc leaves the invite open.
    key(&mut app, KeyCode::Char('x'));
    assert_shows(&mut app, "Cancel the invite for Anna (phone)");
    key(&mut app, KeyCode::Esc);
    assert_shows(&mut app, "open, 21 h left");
    key(&mut app, KeyCode::Char('x'));
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "Cancelled the invite; its certificate is revoked.",
    );
    assert_shows(&mut app, "✕ Anna (phone)   cancelled 3 Oct 2026");
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
        "● Anna (phone)   collected 3 Oct 2026 by iPhone at 203.0.113.7",
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
    assert_shows(&mut app, "○ Anna (phone)   expired 4 Oct 2026");
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
        users_group: None,
    };
    Config {
        nginx: Some(settings.clone()),
        enrollment: Some(config::Enrollment {
            host: "k.example.org".into(),
            upstream: "http://ffca:8080".into(),
            user: config::default_page_user(),
            password: Default::default(),
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
    assert_shows(&mut app, "login off  enrollment site");
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

/// The password a dialog shows once, on the line that starts with the user's name.
fn password_on_screen(screen: &str, name: &str) -> String {
    screen
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace().skip_while(|w| *w != name);
            words.next()?;
            words
                .next()
                .filter(|w| w.len() == crate::users::GENERATED_LENGTH)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("no password for {name} on\n{screen}"))
}

fn users(fixture: &Fixture) -> Users {
    Users::load(&fixture.store).unwrap()
}

/// Adds a user from the Users tab with a made-up password, which it returns.
fn add_user(app: &mut App, name: &str) -> String {
    go_to(app, Tab::Users);
    key(app, KeyCode::Char('n'));
    type_text(app, name);
    key(app, KeyCode::Enter);
    key(app, KeyCode::Enter);
    let password = password_on_screen(&screen(app), name);
    key(app, KeyCode::Esc);
    password
}

#[test]
fn a_new_user_gets_a_password_shown_once_then_a_new_one_then_is_deleted() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Users);
    assert_shows(&mut app, "No users yet");
    let first = add_user(&mut app, "boox");
    assert!(crate::users::verify(
        &first,
        &users(&fixture).get("boox").unwrap().hash
    ));
    assert_shows(&mut app, "no site lets them in");
    assert!(!screen(&mut app).contains(&first));

    key(&mut app, KeyCode::Char('c'));
    key(&mut app, KeyCode::Enter);
    let second = password_on_screen(&screen(&mut app), "boox");
    key(&mut app, KeyCode::Esc);
    let hash = users(&fixture).get("boox").unwrap().hash.clone();
    assert!(crate::users::verify(&second, &hash));
    assert!(!crate::users::verify(&first, &hash));

    key(&mut app, KeyCode::Char('d'));
    assert_shows(&mut app, "boox can no longer log in anywhere.");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "Deleted boox.");
    assert!(users(&fixture).get("boox").is_none());
}

#[test]
fn a_typed_password_too_short_keeps_the_form_open() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Users);
    key(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "short");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "12");
    assert_shows(&mut app, "•••••");
    assert!(users(&fixture).get("anna").is_none());
}

#[test]
fn a_site_s_login_is_turned_on_for_its_users_and_follows_their_passwords() {
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "true", "true", None);
    let mut app = fixture.app(NOW);
    add_user(&mut app, "anna");
    go_to(&mut app, Tab::Nginx);
    assert_shows(&mut app, "login off");
    key(&mut app, KeyCode::Char('l'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert_shows(&mut app, "Tick at least one user with Space");
    assert_shows(&mut app, "[ ] anna");
    // Typed letters are not names here: only ffca's users can be ticked.
    type_text(&mut app, "ben");
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char(' '));
    assert_shows(&mut app, "› [x] anna");
    let screen = screen(&mut app);
    assert!(
        screen.contains("+ auth_basic books.example.org;"),
        "{screen}"
    );
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "books.example.org's login is now on (anna); nginx reloaded.",
    );
    assert_shows(&mut app, "login on (anna)");
    let site = std::fs::read_to_string(settings.sites.join("books.conf")).unwrap();
    assert!(
        site.contains("auth_basic_user_file /etc/nginx/certs/ffca-users-books.example.org;"),
        "{site}"
    );
    let file = settings.ca_files.join("ffca-users-books.example.org");
    let hash = users(&fixture).get("anna").unwrap().hash.clone();
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("anna:{hash}\n")
    );

    // A new password reaches the site's file at once.
    go_to(&mut app, Tab::Users);
    assert_shows(&mut app, "books.example.org");
    key(&mut app, KeyCode::Char('c'));
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        "books.example.org: its password file is rewritten",
    );
    key(&mut app, KeyCode::Esc);
    let hash = users(&fixture).get("anna").unwrap().hash.clone();
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("anna:{hash}\n")
    );

    // Deleting the only user leaves a site nobody gets into, and says so.
    key(&mut app, KeyCode::Char('d'));
    assert_shows(&mut app, "Sites that let them in now: books.example.org.");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "books.example.org: nobody can log in now");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "");

    // Off takes the login and its file away.
    key(&mut app, KeyCode::Esc);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('l'));
    key(&mut app, KeyCode::Up);
    key(&mut app, KeyCode::Up);
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "login off");
    assert!(!file.exists());
    let site = std::fs::read_to_string(settings.sites.join("books.conf")).unwrap();
    assert!(!site.contains("auth_basic"), "{site}");
}

#[test]
fn passthrough_asks_for_a_login_and_names_who_may_pass() {
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "true", "true", None);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('l'));
    key(&mut app, KeyCode::Down);
    assert_shows(&mut app, "+ if ($remote_user = \"\") {");
    type_text(&mut app, "boox");
    assert_shows(&mut app, "+ if ($remote_user !~ \"^(?:boox)$\") {");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "login passthrough (boox)");
    let site = std::fs::read_to_string(settings.sites.join("books.conf")).unwrap();
    assert!(site.contains("location @ffca_login {"), "{site}");
    assert!(!site.contains("auth_basic"), "{site}");
}

#[test]
fn the_enrollment_site_never_asks_for_a_login() {
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "true", "true", Some("k.example.invalid"));
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('l'));
    key(&mut app, KeyCode::Down);
    assert_shows(&mut app, "This is the enrollment site");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "This is the enrollment site");
    let file = std::fs::read_to_string(settings.sites.join("enroll.conf")).unwrap();
    assert!(!file.contains("remote_user"), "{file}");
}

#[test]
fn help_scrolls_on_80_by_24_down_to_its_last_line() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('?'));
    let first = screen_of(&mut app, 80, 24);
    assert!(first.contains("↓ more"), "{first}");
    assert!(first.contains("Enter close"), "{first}");
    assert!(!first.contains("hourly refresh timer"), "{first}");
    key(&mut app, KeyCode::End);
    let last = screen_of(&mut app, 80, 24);
    assert!(
        last.contains("T               set up the hourly refresh timer, after showing it"),
        "{last}"
    );
    assert!(last.contains("↑ more"), "{last}");
    assert!(last.contains("Enter close"), "{last}");
}

/// The help opens on the keys of the tab that shows, and lists every key there is - the ones
/// the hint line has no room for most of all.
#[test]
fn help_starts_with_the_tab_that_shows_and_lists_every_key() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('?'));
    let first = screen(&mut app);
    let heading = |title: &str| {
        first
            .find(title)
            .unwrap_or_else(|| panic!("{title}:\n{first}"))
    };
    assert!(
        heading("Nginx - this tab") < heading("Everywhere"),
        "{first}"
    );
    assert!(
        heading("Everywhere") < heading("│ People & agents "),
        "{first}"
    );
    let mut all = first.clone();
    for _ in 0..6 {
        key(&mut app, KeyCode::PageDown);
        all.push_str(&screen(&mut app));
    }
    for expected in [
        "K               encrypt the key to this machine, or decrypt it",
        "P               where new invites' passwords go",
        "g               the group that reads the password files",
        "Tab  Shift-Tab  the next tab, the previous one",
        "1 2 3 4 5       People & agents, Invites, Nginx, Users, CA",
        "Home End  g G   to the first, to the last",
        "Space           in a site's login: tick or untick the selected user",
        "PgUp PgDn       scroll the details",
        "Esc  q          close it, changing nothing",
        "Enter           show an open invite's QR code again, or a closed one's",
        "x               cancel an open invite, after asking",
    ] {
        assert!(all.contains(expected), "no {expected:?} in\n{all}");
    }
}

#[test]
fn the_nginx_settings_form_fits_80_by_24_with_its_note() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('e'));
    let screen = screen_of(&mut app, 80, 24);
    for expected in [
        "Site configs",
        "Page runs as",
        "running as uid:gid.",
        "Esc cancel",
    ] {
        assert!(screen.contains(expected), "no {expected:?} on\n{screen}");
    }
}

#[test]
fn control_u_and_w_clear_a_form_field() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('e'));
    let control = |app: &mut App, c: char| {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL), NOW)
    };
    control(&mut app, 'w');
    assert_shows(&mut app, "Site configs        /etc/nginx/ ");
    control(&mut app, 'w');
    assert_shows(&mut app, "Site configs        /etc/nginx ");
    control(&mut app, 'u');
    type_text(&mut app, "/srv/sites");
    assert_shows(&mut app, "Site configs        /srv/sites ");
}

/// 80 by 24 with a device selected, which has the most keys: all of them are on the hint line,
/// and the keys every tab shares are at the end of the tab row.
#[test]
fn every_key_is_offered_on_80_columns() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 700);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    let screen = screen_of(&mut app, 80, 24);
    let rows: Vec<&str> = screen.lines().collect();
    assert_eq!(
        rows[23],
        " p new person  n new device  a new agent  u renew  r revoke  R rename  / filter"
    );
    assert!(
        rows[1].starts_with(" People & agents │ Invites"),
        "{screen}"
    );
    assert!(
        rows[1].ends_with("CA      Tab switch  ? help  q quit"),
        "{screen}"
    );
    key(&mut app, KeyCode::Up);
    let screen = screen_of(&mut app, 80, 24);
    assert_eq!(
        screen.lines().last().unwrap(),
        " p new person  n new device  a new agent  r revoke all  R rename  / filter"
    );
    go_to(&mut app, Tab::Nginx);
    with_enrollment(&fixture);
    app.reload(NOW);
    let screen = screen_of(&mut app, 80, 24);
    assert_eq!(
        screen.lines().last().unwrap(),
        " e settings  s client certificate  l login  t test  w rewrite enrollment site"
    );
}

/// What the tabs count takes room from the shared keys: they go one by one, the help last, and
/// where the tab row has no room at all the help is on the hint line.
#[test]
fn the_way_to_the_help_is_never_dropped() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    fixture.issue(ANNA_LAPTOP, NOW, 10);
    invite::make(
        &fixture.ca(),
        &invites_folder(&fixture),
        ANNA_PHONE,
        "k.example.invalid",
        NOW,
    )
    .unwrap();
    let mut app = fixture.app(NOW);
    let screen = screen_of(&mut app, 80, 24);
    let tabs = screen.lines().nth(1).unwrap();
    assert!(
        tabs.starts_with(" People & agents · 1 expiring │ Invites · 1 open │ Nginx"),
        "{screen}"
    );
    assert!(tabs.ends_with("CA    ? help"), "{screen}");
    let narrow = screen_of(&mut app, 60, 20);
    assert!(
        narrow.lines().last().unwrap().ends_with("? help"),
        "{narrow}"
    );
    // While the filter is typed, ? is text like any other key: it is not offered.
    key(&mut app, KeyCode::Char('/'));
    let typing = screen_of(&mut app, 80, 24);
    assert!(!typing.contains("? help"), "{typing}");
}

#[test]
fn digits_go_straight_to_a_tab() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 700);
    let mut app = fixture.app(NOW);
    for (digit, tab) in [
        ('3', Tab::Nginx),
        ('5', Tab::Ca),
        ('2', Tab::Invites),
        ('4', Tab::Users),
        ('1', Tab::People),
    ] {
        key(&mut app, KeyCode::Char(digit));
        assert_eq!(app.tab, tab, "after {digit}");
    }
    key(&mut app, KeyCode::BackTab);
    assert_eq!(app.tab, Tab::Ca);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('/'));
    key(&mut app, KeyCode::Char('3'));
    assert_eq!(
        app.tab,
        Tab::People,
        "typed into the filter, a digit is text"
    );
    assert_shows(&mut app, "/3");
}

/// The cells of a drawn screen: for what its text alone does not show.
fn cells(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal.backend().buffer().clone()
}

/// On a terminal without colour, or with a faint cyan, the tab that shows still stands out.
#[test]
fn the_tab_that_shows_is_marked_by_more_than_colour() {
    use ratatui::style::Modifier;
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    let tabs = screen(&mut app).lines().nth(1).unwrap().to_owned();
    let column = |title: &str| tabs[..tabs.find(title).unwrap()].chars().count() as u16;
    let buffer = cells(&mut app, 110, 40);
    let style = |title: &str| buffer[(column(title), 1)].modifier;
    assert!(style("Nginx").contains(Modifier::REVERSED));
    assert!(style("Nginx").contains(Modifier::BOLD));
    for other in ["People", "Invites", "Users", "CA"] {
        assert!(
            !style(other).intersects(Modifier::REVERSED | Modifier::BOLD),
            "{other}"
        );
    }
}

/// Esc closes what is open and drops the filter, and stops there: a press too many does not
/// end the session. `q` closes the dialogs that take no text.
#[test]
fn esc_closes_and_clears_but_never_quits() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 700);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Esc);
    assert!(!app.should_quit());
    key(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "an");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "╭ /an ");
    assert_shows(&mut app, "Esc clear");
    key(&mut app, KeyCode::Esc);
    let screen = screen(&mut app);
    assert!(!screen.contains("/an"), "{screen}");
    key(&mut app, KeyCode::Esc);
    assert!(!app.should_quit());

    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('r'));
    assert_shows(&mut app, "Why?");
    key(&mut app, KeyCode::Char('q'));
    let screen = self::screen(&mut app);
    assert!(!screen.contains("Why?"), "q closes the dialog:\n{screen}");
    assert!(!app.should_quit());
    key(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit());
}

/// Renewing issues a certificate at once, and an invite or a key file with it: it asks first.
#[test]
fn renewing_asks_first() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW - Duration::days(300), 365);
    let certificates = || {
        fixture.ca().ledger().unwrap().people[0].devices[0]
            .certificates
            .len()
    };
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('u'));
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("Renew Anna · phone"), "{screen}");
    assert!(
        screen.contains("A new certificate, written with its key to files in"),
        "{screen}"
    );
    assert!(screen.contains("until you revoke"), "{screen}");
    assert!(screen.contains("Enter renew  Esc back"), "{screen}");
    assert_eq!(certificates(), 1, "nothing is issued by asking");
    key(&mut app, KeyCode::Esc);
    assert_eq!(certificates(), 1);
    key(&mut app, KeyCode::Char('u'));
    key(&mut app, KeyCode::Enter);
    assert_eq!(certificates(), 2);
    assert_shows(&mut app, "Issued to Anna (phone)");
}

/// A revocation cannot be taken back, and the dialog says so. A person's reaches every device
/// they have: Enter alone does not do it.
#[test]
fn revoking_a_person_takes_a_key_that_habit_does_not_press() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture.issue(ANNA_LAPTOP, NOW, 365);
    let revoked = || {
        let ledger = fixture.ca().ledger().unwrap();
        ledger
            .certificates()
            .filter(|(_, c)| c.status(NOW) == Status::Revoked)
            .count()
    };
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('r'));
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("It cannot be undone"), "{screen}");
    assert!(screen.contains("Enter continue  Esc back"), "{screen}");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    assert_eq!(revoked(), 0, "Enter, however often, revokes nobody");
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains("Revoke all 2 certificates of Anna? Press y to revoke, Esc to go back."),
        "{screen}"
    );
    assert!(screen.contains("y revoke  Esc back"), "{screen}");
    // Choosing another reason is thinking again: the question is asked anew.
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('y'));
    assert_eq!(revoked(), 0);
    // "Replaced" keeps each device's only certificate: nothing to revoke, nothing to ask.
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains("Nothing: there is no older certificate"),
        "{screen}"
    );
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Char('y'));
    assert_eq!(revoked(), 0);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Char('y'));
    assert_eq!(revoked(), 2);
}

/// On 80 columns the CRL's warning is as wide as most of the row: the CA's name gives way to
/// it, visibly, and an expired CRL has a row of its own on every tab.
#[test]
fn what_the_crl_says_never_writes_over_the_title() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 700);
    let mut app = fixture.app(NOW + Duration::days(25));
    let screen = screen_of(&mut app, 80, 24);
    assert_eq!(
        screen.lines().next().unwrap(),
        " Friends and Family CA · Tes… CRL expires in 5 d: is the refresh timer running?"
    );
    let mut app = fixture.app(NOW + Duration::days(40));
    for tab in [Tab::People, Tab::Ca] {
        go_to(&mut app, tab);
        let screen = screen_of(&mut app, 80, 24);
        let rows: Vec<&str> = screen.lines().collect();
        assert!(
            rows[0].starts_with(" Friends and Family CA · Test family "),
            "{screen}"
        );
        assert_eq!(
            rows[1],
            " CRL EXPIRED: everyone is refused. Press c on the CA tab."
        );
        assert!(rows[2].starts_with(" People & agents"), "{screen}");
    }
    key(&mut app, KeyCode::Char('c'));
    let screen = screen_of(&mut app, 80, 24);
    assert!(!screen.contains("CRL EXPIRED"), "{screen}");
    assert!(
        screen
            .lines()
            .nth(1)
            .unwrap()
            .starts_with(" People & agents")
    );
}

/// A notice longer than the screen is wide takes a second row instead of losing its end.
#[test]
fn a_long_notice_wraps_on_80_columns() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    for (person, device) in [
        ("Anna", "phone"),
        (
            "Maria-Magdalena Ivankovic-Horvat",
            "Samsung Galaxy Tab S9 Ultra",
        ),
    ] {
        let made = invite::make(
            &fixture.ca(),
            &invites_folder(&fixture),
            Holder::Device { person, device },
            "k.example.invalid",
            NOW,
        )
        .unwrap();
        let token = made.link.rsplit('/').next().unwrap();
        invite::collect(&invites_folder(&fixture), token, NOW, "203.0.113.7, iPhone").unwrap();
    }
    app.reload(NOW + Duration::minutes(1));
    let screen = screen_of(&mut app, 80, 24);
    let rows: Vec<&str> = screen.lines().collect();
    assert!(
        rows[21].starts_with(" Anna (phone), Maria-Magdalena"),
        "{screen}"
    );
    assert_eq!(rows[22], " collected their invites.");
    assert!(rows[23].starts_with(" p new person"), "{screen}");
}

#[test]
fn an_error_on_the_notice_line_is_marked_as_one() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    fixture
        .ca()
        .revoke(Target::Person("Anna"), Reason::Retired, NOW)
        .unwrap();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('r'));
    assert_shows(&mut app, " ✕ Anna has no valid certificate to revoke");
}

/// Why something asked for did not happen is shown whole and stays: in a dialog, not on a line
/// that ends where the screen does.
#[test]
fn a_failure_is_shown_whole_on_80_columns() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('w'));
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains("╭ The enrollment site cannot be written "),
        "{screen}"
    );
    assert!(screen.contains("has no ssl_certificate of its"), "{screen}");
    assert!(screen.contains("own to copy"), "{screen}");
    assert!(screen.contains("Enter close"), "{screen}");
}

/// The dialog that shows an invite covers the notice line, and the device may collect the
/// invite while it is up: the dialog says so, in place of a code that leads nowhere now.
#[test]
fn an_invite_collected_while_its_code_is_up_says_so_there() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('p'));
    type_text(&mut app, "Anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "phone");
    key(&mut app, KeyCode::Enter);
    let shown = screen_of(&mut app, 80, 24);
    assert!(shown.contains("▀▀▀"), "{shown}");
    let token = token_on_screen(&shown);
    app.reload(NOW + Duration::seconds(30));
    assert!(screen_of(&mut app, 80, 24).contains("▀▀▀"), "still open");
    invite::collect(
        &invites_folder(&fixture),
        &token,
        NOW + Duration::minutes(1),
        "203.0.113.7, iPhone",
    )
    .unwrap();
    app.reload(NOW + Duration::minutes(1));
    let screen = screen_of(&mut app, 80, 24);
    assert!(!screen.contains('▀'), "{screen}");
    assert!(
        screen.contains("Collected just now, from iPhone at 203.0.113.7."),
        "{screen}"
    );
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "● phone          until 2028");
}

/// A longer host name makes a longer link and a larger code. 80 by 24 still shows the code, and
/// the link whole, over two rows.
#[test]
fn a_long_enrollment_host_still_gets_its_code_on_80_by_24() {
    let fixture = Fixture::new();
    let host = "enrollment.family-name.example.org";
    with_nginx(&fixture, "true", "true", Some(host));
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('p'));
    type_text(&mut app, "Anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "phone");
    key(&mut app, KeyCode::Enter);
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("▀▀▀"), "{screen}");
    assert!(screen.contains("Invite for Anna (phone)"), "{screen}");
    assert!(screen.contains("The link takes 2 rows here"), "{screen}");
    let rows: Vec<&str> = screen.lines().collect();
    let first = rows.iter().position(|r| r.starts_with("https://")).unwrap();
    let link = format!("{}{}", rows[first], rows[first + 1]);
    let token = link
        .strip_prefix(&format!("https://{host}/i/"))
        .expect(&screen);
    assert_eq!(token.len(), 43, "{screen}");
    assert_eq!(
        invite::open(&invites_folder(&fixture), token, NOW)
            .unwrap()
            .holder,
        "Anna (phone)"
    );
    assert_eq!(rows[23], "c copy link  Enter close");
}

/// A value longer than its row - a `docker compose` command, a deep path - stays on its row:
/// the fields under it, the cursor and the message keep their places.
#[test]
fn a_long_value_keeps_its_row_and_the_form_its_message() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('e'));
    (0..3).for_each(|_| key(&mut app, KeyCode::Down));
    retype(
        &mut app,
        "docker compose -f /srv/domaci/docker-compose.yml exec nginx nginx -t",
    );
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let cursor = terminal.get_cursor_position().unwrap();
    let screen = screen_of(&mut app, 80, 24);
    let rows: Vec<&str> = screen.lines().collect();
    let row = rows
        .iter()
        .position(|r| r.contains("Test command"))
        .unwrap();
    assert!(
        rows[row].contains("Test command        …") && rows[row].contains("exec nginx nginx -t"),
        "the end, where the cursor is:\n{screen}"
    );
    assert!(
        rows[row + 1].contains("Reload command      nginx -s reload"),
        "{screen}"
    );
    assert_eq!(usize::from(cursor.y), row, "{screen}");
    assert!(screen.contains("serve, running as uid:gid."), "{screen}");
    // Left behind, the field shows its start.
    key(&mut app, KeyCode::Up);
    assert!(
        screen_of(&mut app, 80, 24).contains("Test command        docker compose -f"),
        "{screen}"
    );
    (0..2).for_each(|_| key(&mut app, KeyCode::Up));
    retype(
        &mut app,
        "/nonexistent/folder/that/is/rather/long/to/make/the/error/wrap/conf.d",
    );
    app.handle_key(
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        NOW,
    );
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("✕ cannot read"), "{screen}");
    assert!(screen.contains("(os error 2)"), "{screen}");
    assert!(screen.contains("Page runs as"), "{screen}");
    assert!(screen.contains("Esc cancel"), "{screen}");
}

/// On 80 columns the tree is as wide as the details allow, and what a device's state is takes
/// few words: a name of fifteen characters is whole.
#[test]
fn the_tree_gives_names_the_room_there_is_on_80_columns() {
    let fixture = Fixture::new();
    fixture.issue(
        Holder::Device {
            person: "Anna",
            device: "work laptop XPS",
        },
        NOW,
        700,
    );
    fixture.issue(ANNA_PHONE, NOW, 10);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("● work laptop XPS until 2028"), "{screen}");
    assert!(screen.contains("◐ phone           10 d left"), "{screen}");
    assert!(
        screen.contains("valid until 2 Sep 2028"),
        "the details keep their line whole:\n{screen}"
    );
}

/// Smaller than the UI can draw itself, it says so, and takes no key for what it does not
/// show.
#[test]
fn a_terminal_too_small_says_so_and_takes_no_keys() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    let screen = screen_of(&mut app, 50, 12);
    assert!(screen.contains("This terminal is 50 by 12"), "{screen}");
    assert!(screen.contains("60 by 16 or more"), "{screen}");
    assert!(!screen.contains("phone"), "{screen}");
    key(&mut app, KeyCode::Char('r'));
    key(&mut app, KeyCode::Enter);
    let ledger = fixture.ca().ledger().unwrap();
    assert_eq!(
        ledger.people[0].devices[0].certificates[0].status(NOW),
        Status::Valid
    );
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains("● phone") && !screen.contains("Why?"),
        "{screen}"
    );
    screen_of(&mut app, 50, 12);
    key(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit());
}

/// The Invites tab on 80 columns: a long holder is cut where its column ends, an open invite
/// has the mark it has in the tree, and of where an invite was collected the kind of device
/// comes first - it is the address that the row may have no room for.
#[test]
fn the_invites_tab_fits_80_columns_and_tells_the_device_first() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let invite = |person: &str, device: &str| {
        invite::make(
            &fixture.ca(),
            &invites_folder(&fixture),
            Holder::Device { person, device },
            "k.example.invalid",
            NOW,
        )
        .unwrap()
    };
    invite(
        "Maria-Magdalena Ivankovic-Horvat",
        "Samsung Galaxy Tab S9 Ultra",
    );
    let made = invite("Anna", "phone");
    invite::collect(
        &invites_folder(&fixture),
        made.link.rsplit('/').next().unwrap(),
        NOW,
        "2a02:8108:1234:5678:9abc:def0:1234:5678, iPhone",
    )
    .unwrap();
    let mut app = fixture.app(NOW + Duration::hours(1));
    go_to(&mut app, Tab::Invites);
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains("│ ◌ Maria-Magdalena Ivankovic-Hor… open, 23 h left"),
        "{screen}"
    );
    assert!(
        screen.contains(
            "│ ● Anna (phone)                   collected 3 Oct 2026 by iPhone at 2a02:8108…│"
        ),
        "{screen}"
    );
    assert!(
        screen.contains("Enter show  c copy link  x cancel"),
        "{screen}"
    );
    // A closed invite has nothing to show again, but when and from where it was collected.
    key(&mut app, KeyCode::Down);
    assert!(screen_of(&mut app, 80, 24).contains(" Enter details"));
    key(&mut app, KeyCode::Enter);
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("╭ Invite for Anna (phone) "), "{screen}");
    assert!(
        screen.contains("Collected 3 Oct 2026 12:00 UTC by iPhone at"),
        "{screen}"
    );
    assert!(
        screen.contains("2a02:8108:1234:5678:9abc:def0:1234:5678."),
        "{screen}"
    );
    assert!(
        screen.contains("Made         3 Oct 2026 12:00 UTC"),
        "{screen}"
    );
    assert!(!screen.contains('▀'), "{screen}");
}

/// A device renewed many times has more certificates than the details have rows.
#[test]
fn details_taller_than_their_pane_scroll() {
    let fixture = Fixture::new();
    for day in 0..14 {
        fixture.issue(ANNA_PHONE, NOW - Duration::days(day), 365);
    }
    fixture.issue(ANNA_LAPTOP, NOW, 365);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Down);
    let top = screen_of(&mut app, 80, 24);
    assert!(top.contains("Anna · phone"), "{top}");
    assert!(top.contains("↓ more · PgDn"), "{top}");
    assert!(!top.contains("as replaced."), "{top}");
    key(&mut app, KeyCode::PageDown);
    let end = screen_of(&mut app, 80, 24);
    assert!(end.contains("as replaced."), "{end}");
    assert!(end.contains("↑ more · PgUp"), "{end}");
    // Another device's details start at their top.
    key(&mut app, KeyCode::Down);
    let other = screen_of(&mut app, 80, 24);
    assert!(other.contains("Anna · laptop"), "{other}");
    assert!(!other.contains("more ·"), "{other}");
}

/// The tree scrolls only when the selection would leave it: moving back up among the rows that
/// show leaves them where they are.
#[test]
fn the_tree_stays_put_while_the_selection_moves_within_it() {
    let fixture = Fixture::new();
    for person in 0..8 {
        for device in ["phone", "laptop", "tablet"] {
            fixture.issue(
                Holder::Device {
                    person: &format!("Person{person}"),
                    device,
                },
                NOW,
                365,
            );
        }
    }
    let mut app = fixture.app(NOW);
    let tree = |screen: &str| -> Vec<String> {
        screen
            .lines()
            .skip(3)
            .take(18)
            .map(|row| row.chars().take(30).collect())
            .collect()
    };
    (0..25).for_each(|_| key(&mut app, KeyCode::Down));
    let down = tree(&screen_of(&mut app, 80, 24));
    assert!(down[17].contains("phone"), "{down:?}");
    (0..5).for_each(|_| key(&mut app, KeyCode::Up));
    assert_eq!(tree(&screen_of(&mut app, 80, 24)), down);
}

/// What 80 columns used to cut: the Users tab's first line, a site's note, a wrapped option.
#[test]
fn text_keeps_to_80_columns_and_wraps_under_itself() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Users);
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("is on (Nginx tab, l)."), "{screen}");
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Down);
    let screen = screen_of(&mut app, 80, 24);
    assert!(screen.contains("login off  enrollment site  "), "{screen}");
    assert!(
        screen.contains(
            " k.example.invalid is the enrollment site: it never asks for a certificate or a"
        ),
        "{screen}"
    );
    key(&mut app, KeyCode::Up);
    key(&mut app, KeyCode::Char('s'));
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains(
            "│   optional  asked for; without one you get in, a revoked or broken one is"
        ),
        "{screen}"
    );
    assert!(screen.contains("│             refused"), "{screen}");
    // A dialog that would leave a few columns of the tab beside it takes the whole width.
    assert!(
        screen
            .lines()
            .any(|row| row.starts_with("╭ books.example.org ─")),
        "{screen}"
    );
    key(&mut app, KeyCode::Esc);
    go_to(&mut app, Tab::Ca);
    let screen = screen_of(&mut app, 80, 24);
    assert!(
        screen.contains("has to be issued\n  again."),
        "the warning wraps under its margin:\n{screen}"
    );
}

#[test]
fn tab_titles_count_what_needs_looking_at() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    fixture.issue(ANNA_LAPTOP, NOW, 10);
    invite::make(
        &fixture.ca(),
        &invites_folder(&fixture),
        ANNA_PHONE,
        "k.example.invalid",
        NOW,
    )
    .unwrap();
    let mut app = fixture.app(NOW);
    assert_shows(
        &mut app,
        "People & agents · 1 expiring │ Invites · 1 open │ Nginx",
    );
}

#[test]
fn a_notice_goes_after_a_while() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Ca);
    key(&mut app, KeyCode::Char('c'));
    assert_shows(&mut app, "Signed a new CRL");
    app.reload(NOW + Duration::seconds(10));
    assert_shows(&mut app, "Signed a new CRL");
    app.reload(NOW + Duration::seconds(30));
    let screen = screen(&mut app);
    assert!(!screen.contains("Signed a new CRL"), "{screen}");
}

#[test]
fn requiring_a_certificate_says_who_still_gets_in() {
    let fixture = Fixture::new();
    with_nginx(&fixture, "true", "true", None);
    fixture.issue(ANNA_PHONE, NOW, 700);
    fixture.issue(ANNA_LAPTOP, NOW, 700);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Down);
    let screen = screen(&mut app);
    assert!(
        !screen.contains("everyone else is refused"),
        "only for required:\n{screen}"
    );
    key(&mut app, KeyCode::Down);
    assert_shows(
        &mut app,
        "2 devices and agents have a valid certificate from this CA: everyone else is refused.",
    );
}

/// An invite sends its person to a site that requires this CA's certificate, to see that it
/// works; with no such site, nowhere. The enrollment site never counts.
#[test]
fn an_invite_names_a_site_that_requires_the_certificate_to_check_it_on() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let invite_for = |app: &mut App, device: &str| {
        key(app, KeyCode::Char('p'));
        type_text(app, &format!("Anna {device}"));
        key(app, KeyCode::Enter);
        type_text(app, device);
        key(app, KeyCode::Enter);
        let token = token_on_screen(&screen(app));
        key(app, KeyCode::Enter);
        invite::open(&invites_folder(&fixture), &token, NOW).unwrap()
    };
    let mut app = fixture.app(NOW);
    assert_eq!(invite_for(&mut app, "phone").check, None);

    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "books.example.org is now required");
    go_to(&mut app, Tab::People);
    assert_eq!(
        invite_for(&mut app, "laptop").check.as_deref(),
        Some("https://books.example.org/")
    );
}

/// A device whose certificate is still in an open invite does not have it yet: the tree says so,
/// and once it is collected the details say when and from where.
#[test]
fn the_tree_shows_an_invite_waiting_then_collected() {
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
    assert_shows(&mut app, "◌ phone          invite open");
    key(&mut app, KeyCode::Down);
    assert_shows(
        &mut app,
        "invite open until 4 Oct 2026: not on the device yet",
    );
    let token = made.link.rsplit('/').next().unwrap();
    invite::collect(
        &invites_folder(&fixture),
        token,
        NOW + Duration::minutes(5),
        "203.0.113.7, iPhone",
    )
    .unwrap();
    app.reload(NOW + Duration::minutes(6));
    assert_shows(&mut app, "● phone          until 2028");
    assert_shows(&mut app, "collected 3 Oct 2026 by iPhone at 203.0.113.7");
    assert_shows(&mut app, "issued 3 Oct 2026");
}

/// A certificate still in its invite lets nobody in yet: requiring one counts it apart.
#[test]
fn requiring_a_certificate_does_not_count_invites_not_collected() {
    let fixture = Fixture::new();
    with_nginx(&fixture, "true", "true", Some("k.example.invalid"));
    invite::make(
        &fixture.ca(),
        &invites_folder(&fixture),
        ANNA_PHONE,
        "k.example.invalid",
        NOW,
    )
    .unwrap();
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert_shows(
        &mut app,
        "No device or agent has a valid certificate from this CA yet",
    );
    assert_shows(
        &mut app,
        "1 more has an invite still open: they get in once it is collected.",
    );
}

#[test]
fn slash_narrows_the_tree_and_keys_typed_are_text() {
    let fixture = Fixture::new();
    fixture.issue(ANNA_PHONE, NOW, 700);
    fixture.issue(ANNA_LAPTOP, NOW, 700);
    fixture.issue(
        Holder::Device {
            person: "Ben",
            device: "tablet",
        },
        NOW,
        700,
    );
    fixture.issue(Holder::Agent("backup"), NOW, 700);
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('/'));
    // q and Tab are text here, not quit and the next tab.
    type_text(&mut app, "TABq");
    key(&mut app, KeyCode::Backspace);
    key(&mut app, KeyCode::Tab);
    let shown = screen(&mut app);
    assert!(shown.contains(" /TAB▏ "), "{shown}");
    assert!(
        !shown.contains("q quit"),
        "q is text while typing:\n{shown}"
    );
    assert!(shown.contains("tablet") && shown.contains("Ben"), "{shown}");
    assert!(
        !shown.contains("phone") && !shown.contains("backup"),
        "{shown}"
    );
    assert!(!app.should_quit());
    key(&mut app, KeyCode::Enter);
    // A person whose own name matches keeps every device.
    key(&mut app, KeyCode::Char('/'));
    (0..3).for_each(|_| key(&mut app, KeyCode::Backspace));
    type_text(&mut app, "anna");
    key(&mut app, KeyCode::Enter);
    let shown = screen(&mut app);
    assert!(
        shown.contains("phone") && shown.contains("laptop"),
        "{shown}"
    );
    assert!(!shown.contains("tablet"), "{shown}");
    assert_shows(&mut app, "Esc clear");
    // Esc drops the filter rather than quitting.
    key(&mut app, KeyCode::Esc);
    assert!(!app.should_quit());
    assert_shows(&mut app, "backup");
    key(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "nobody");
    assert_shows(&mut app, "Nothing matches.");
}

#[test]
fn control_s_is_done_from_any_field() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    key(&mut app, KeyCode::Char('p'));
    assert_shows(&mut app, "Ctrl-S done");
    type_text(&mut app, "Anna");
    key(&mut app, KeyCode::Tab);
    type_text(&mut app, "phone");
    key(&mut app, KeyCode::BackTab);
    app.handle_key(
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        NOW,
    );
    assert_shows(&mut app, "Issued to Anna (phone)");
}

#[test]
fn with_no_users_the_login_dialog_offers_nothing_to_tick() {
    let fixture = Fixture::new();
    with_nginx(&fixture, "true", "true", None);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Nginx);
    key(&mut app, KeyCode::Char('l'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    let shown = screen(&mut app);
    assert!(shown.contains("ffca has no users yet"), "{shown}");
    assert!(!shown.contains("Space tick a user"), "{shown}");
}

/// K on the CA tab encrypts the key to the machine after saying what that costs, and K again
/// puts it back; the tab says which of the two the key is.
#[test]
fn k_encrypts_the_key_to_this_machine_and_back_after_asking() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    app.encrypter = crate::test_encrypter(&fixture.out);
    go_to(&mut app, Tab::Ca);
    let before = screen_of(&mut app, 80, 24);
    assert!(before.contains("ca.key  (owner only)"), "{before}");
    assert!(before.contains("K encrypt or decrypt the key"), "{before}");

    key(&mut app, KeyCode::Char('K'));
    let asked = screen_of(&mut app, 80, 24);
    assert!(
        asked.contains("Encrypt the CA's key to this machine"),
        "{asked}"
    );
    assert!(asked.contains("keep a copy of the plain key"), "{asked}");
    key(&mut app, KeyCode::Esc);
    assert!(fixture.store.exists(ca::KEY_FILE), "Esc changes nothing");

    key(&mut app, KeyCode::Char('K'));
    key(&mut app, KeyCode::Enter);
    assert!(!fixture.store.exists(ca::KEY_FILE));
    assert!(fixture.store.exists(ca::ENCRYPTED_KEY_FILE));
    let after = screen(&mut app);
    assert!(
        after.contains("The key is encrypted to this machine."),
        "{after}"
    );
    assert!(
        after.contains("ca.key.cred  (encrypted to this machine)"),
        "{after}"
    );
    assert!(
        after.contains("keep the plain key you copied offline"),
        "{after}"
    );
    // It still signs.
    key(&mut app, KeyCode::Char('c'));
    assert_shows(&mut app, "number 2");

    key(&mut app, KeyCode::Char('K'));
    assert_shows(&mut app, "Decrypt the CA's key");
    key(&mut app, KeyCode::Enter);
    assert!(fixture.store.exists(ca::KEY_FILE));
    assert!(!fixture.store.exists(ca::ENCRYPTED_KEY_FILE));
    assert_shows(&mut app, "The key is a plain file again.");
    fixture.ca();
}

/// A machine that cannot encrypt says why, in full, and the key stays as it was.
#[test]
fn a_key_that_cannot_be_encrypted_says_why() {
    let fixture = Fixture::new();
    let mut app = fixture.app(NOW);
    app.encrypter = "/nonexistent/systemd-creds".into();
    go_to(&mut app, Tab::Ca);
    key(&mut app, KeyCode::Char('K'));
    key(&mut app, KeyCode::Enter);
    let shown = screen_of(&mut app, 80, 24);
    assert!(shown.contains("The key is not encrypted"), "{shown}");
    assert!(shown.contains("it is left as it was"), "{shown}");
    assert!(fixture.store.exists(ca::KEY_FILE));
}

/// P on the Invites tab moves the password off the enrollment page: the next invite shows it
/// to the administrator, who copies it with p, and the page is given none.
#[test]
fn a_password_sent_separately_is_shown_in_the_invite_and_copied_with_p() {
    let fixture = Fixture::new();
    with_enrollment(&fixture);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Invites);
    assert_shows(&mut app, "P where passwords go");
    key(&mut app, KeyCode::Char('P'));
    let asked = screen_of(&mut app, 80, 24);
    assert!(asked.contains("Where certificate passwords go"), "{asked}");
    assert!(asked.contains("Enter send passwords myself"), "{asked}");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "New invites keep their password off the page");
    assert_eq!(
        Config::load(&fixture.store)
            .unwrap()
            .enrollment
            .unwrap()
            .password,
        invite::Delivery::Separate
    );

    go_to(&mut app, Tab::People);
    key(&mut app, KeyCode::Char('p'));
    type_text(&mut app, "Anna");
    key(&mut app, KeyCode::Enter);
    type_text(&mut app, "phone");
    key(&mut app, KeyCode::Enter);
    let password = fixture.ca().ledger().unwrap().invites[0]
        .password
        .clone()
        .expect("kept for the administrator");
    let shown = screen_of(&mut app, 80, 24);
    assert!(shown.contains(&format!("Password: {password}")), "{shown}");
    assert!(shown.contains("p copy password"), "{shown}");
    key(&mut app, KeyCode::Char('p'));
    assert_eq!(app.take_clipboard(), Some(password.clone()));

    let token = token_on_screen(&screen(&mut app));
    let payload = invite::open(&invites_folder(&fixture), &token, NOW).unwrap();
    assert_eq!(payload.password, None, "the page has no password to show");

    // Shown again from the Invites tab, while the invite is open.
    key(&mut app, KeyCode::Enter);
    go_to(&mut app, Tab::Invites);
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, &format!("Password: {password}"));
    key(&mut app, KeyCode::Enter);

    // And back: the next invite's password is the page's to show.
    key(&mut app, KeyCode::Char('P'));
    assert_shows(&mut app, "Enter show passwords on the page");
    key(&mut app, KeyCode::Enter);
    go_to(&mut app, Tab::People);
    key(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "laptop");
    key(&mut app, KeyCode::Enter);
    let shown = screen_of(&mut app, 80, 24);
    assert!(shown.contains("Invite for Anna (laptop)"), "{shown}");
    assert!(!shown.contains("Password:"), "{shown}");
}

/// g on the Users tab gives the password files to nginx's group, rewriting the ones that are
/// there; an empty field gives them back to everyone, and what is not a number is refused.
#[test]
fn g_gives_the_password_files_to_nginxs_group() {
    use std::os::unix::fs::MetadataExt;
    let fixture = Fixture::new();
    let settings = with_nginx(&fixture, "true", "true", None);
    let mut app = fixture.app(NOW);
    go_to(&mut app, Tab::Users);
    key(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "anna");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    let books = nginx::survey(&settings).unwrap().sites.remove(0);
    nginx::set_auth(
        &settings,
        &fixture.ca(),
        &users(&fixture),
        &books,
        &Auth::On(vec!["anna".into()]),
    )
    .unwrap();
    let file = settings.ca_files.join("ffca-users-books.example.org");
    let mode = |path: &std::path::Path| std::fs::metadata(path).unwrap().mode() & 0o777;
    assert_eq!(mode(&file), 0o644);

    assert_shows(&mut app, "g who reads the files");
    key(&mut app, KeyCode::Char('g'));
    let asked = screen_of(&mut app, 80, 24);
    assert!(asked.contains("Who reads the password files"), "{asked}");
    type_text(&mut app, "nginx");
    key(&mut app, KeyCode::Enter);
    assert_shows(&mut app, "nginx is not a group's number");
    assert_eq!(mode(&file), 0o644);

    // The test's own group stands in for nginx's: only root can give a file to another.
    let group = std::fs::metadata(&fixture.out).unwrap().gid();
    app.handle_key(
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        NOW,
    );
    type_text(&mut app, &group.to_string());
    key(&mut app, KeyCode::Enter);
    assert_shows(
        &mut app,
        &format!("Password files are for group {group} only."),
    );
    assert_eq!(mode(&file), 0o640);
    assert_eq!(
        Config::load(&fixture.store)
            .unwrap()
            .nginx
            .unwrap()
            .users_group,
        Some(group)
    );

    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Char('g'));
    assert_shows(&mut app, &group.to_string());
    app.handle_key(
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        NOW,
    );
    key(&mut app, KeyCode::Enter);
    assert_eq!(mode(&file), 0o644);
    assert_eq!(
        Config::load(&fixture.store)
            .unwrap()
            .nginx
            .unwrap()
            .users_group,
        None
    );
}
