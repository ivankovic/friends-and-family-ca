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
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use time::OffsetDateTime;

use super::*;

/// A site the way a real one looks: a bot filter of `if` blocks full of quoted regular expressions
/// and braces first, client-certificate lines commented out, and a second server for plain HTTP.
const BOOKS: &str = r#"server {
    # BEGIN stop-bots (DO NOT EDIT)
    set $stop_bots_block 0;
    if ($http_user_agent ~* "1h4x\.com|A6-Indexer|Ab{2,}ot|semi;colon|\"quoted\"") {
        set $stop_bots_block 1;
    }
    if ($stop_bots_block) {
        return 444;
    }
    # END stop-bots

    listen 443 ssl;
    http2 on;

    server_name books.example.org;

    ssl_certificate     /etc/letsencrypt/live/example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example/privkey.pem;

    # ssl_client_certificate /etc/nginx/certs/ca.cert.pem;
    # ssl_verify_client on;

    include /etc/nginx/conf.d/ssl-params.inc;
    client_max_body_size 500M;                     # uploads

    location / {
        proxy_pass http://books:8083;
        proxy_set_header Host ${host};
    }
}

server {
    listen 80;
    server_name books.example.org;
    return 301 https://$host$request_uri;
}
"#;

/// A site with an older CA's certificate active and verification commented out.
const PHOTOS: &str = "server {
    listen 443 ssl;
    server_name photos.example.org www.photos.example.org;
    ssl_certificate     /etc/letsencrypt/live/example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example/privkey.pem;

    ssl_client_certificate /etc/nginx/certs/ca.cert.pem;
    #ssl_verify_client on;

    location / { proxy_pass http://photos:2283; }
}
";

fn settings(dir: &Path) -> config::Nginx {
    config::Nginx {
        sites: dir.join("conf.d"),
        ca_files: dir.join("certs"),
        ca_files_in_nginx: "/etc/nginx/certs".into(),
        test: "true".into(),
        reload: "true".into(),
    }
}

fn folder(files: &[(&str, &str)]) -> (tempfile::TempDir, config::Nginx) {
    let dir = crate::test_dir();
    let nginx = settings(dir.path());
    fs::create_dir(&nginx.sites).unwrap();
    for (name, text) in files {
        fs::write(nginx.sites.join(name), text).unwrap();
    }
    (dir, nginx)
}

fn ca(dir: &Path) -> Ca {
    Ca::create(
        &Store::new(dir.join("state")),
        "Test",
        OffsetDateTime::now_utc(),
        ca::DEFAULT_CA_VALIDITY,
    )
    .unwrap()
}

fn only_site(nginx: &config::Nginx) -> Site {
    let survey = survey(nginx).unwrap();
    assert_eq!(survey.sites.len(), 1, "{survey:?}");
    survey.sites[0].clone()
}

#[test]
fn the_survey_finds_https_sites_and_their_modes() {
    let (_dir, nginx) = folder(&[
        ("books.conf", BOOKS),
        ("photos.conf", PHOTOS),
        ("ssl-params.inc", "ssl_protocols TLSv1.3;\n"),
        (
            "00-log-format.conf",
            "log_format main '$remote_addr \"$request\"';\n",
        ),
    ]);
    let survey = survey(&nginx).unwrap();
    assert!(survey.problems.is_empty(), "{:?}", survey.problems);
    let found: Vec<(String, String, usize, Mode, bool)> = survey
        .sites
        .iter()
        .map(|s| {
            (
                s.file_name(),
                s.name().to_owned(),
                s.index,
                s.mode,
                s.uses_ca,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (
                "books.conf".into(),
                "books.example.org".into(),
                0,
                Mode::Off,
                false
            ),
            (
                "photos.conf".into(),
                "photos.example.org".into(),
                0,
                Mode::Off,
                false
            ),
        ],
        "the port-80 server and the files that are not *.conf are not sites"
    );
    assert!(survey.sites[1].serves("WWW.photos.example.org"));
}

#[test]
fn a_file_nginx_could_not_read_is_reported_and_the_others_still_listed() {
    let (_dir, nginx) = folder(&[
        ("books.conf", BOOKS),
        ("broken.conf", "server {\n    listen 443 ssl;\n"),
    ]);
    let survey = survey(&nginx).unwrap();
    assert_eq!(survey.sites.len(), 1);
    assert_eq!(survey.problems.len(), 1);
    assert!(
        survey.problems[0].contains("broken.conf") && survey.problems[0].contains("not closed"),
        "{:?}",
        survey.problems
    );
}

#[test]
fn requiring_a_certificate_adds_ffcas_block_after_the_server_name() {
    let (_dir, nginx) = folder(&[]);
    let planned = plan(BOOKS, 0, Mode::Required, &nginx).unwrap();
    let expected_block = "    server_name books.example.org;

    # BEGIN ffca - client certificates, managed by Friends and Family CA
    ssl_client_certificate /etc/nginx/certs/ffca-ca.crt;
    ssl_crl /etc/nginx/certs/ffca.crl;
    ssl_verify_client on;
    # END ffca

    ssl_certificate ";
    assert!(planned.contains(expected_block), "{planned}");
    assert_eq!(
        planned.len(),
        BOOKS.len() + expected_block.len()
            - "    server_name books.example.org;\n\n    ssl_certificate ".len()
    );
    let site = &sites_in(Path::new("books.conf"), &planned, &nginx).unwrap()[0];
    assert_eq!((site.mode, site.uses_ca), (Mode::Required, true));
}

#[test]
fn turning_it_off_again_gives_back_the_file_as_it_was() {
    let (_dir, nginx) = folder(&[]);
    for mode in [Mode::Optional, Mode::Required] {
        let on = plan(BOOKS, 0, mode, &nginx).unwrap();
        assert_eq!(
            plan(&on, 0, mode, &nginx).unwrap(),
            on,
            "setting {mode} twice changes nothing more"
        );
        assert_eq!(plan(&on, 0, Mode::Off, &nginx).unwrap(), BOOKS);
    }
    assert_eq!(
        plan(BOOKS, 0, Mode::Off, &nginx).unwrap(),
        BOOKS,
        "off on an untouched site changes nothing"
    );
}

#[test]
fn optional_asks_without_requiring() {
    let (_dir, nginx) = folder(&[]);
    let planned = plan(BOOKS, 0, Mode::Optional, &nginx).unwrap();
    assert!(
        planned.contains("    ssl_verify_client optional;\n"),
        "{planned}"
    );
    assert_eq!(
        sites_in(Path::new("x.conf"), &planned, &nginx).unwrap()[0].mode,
        Mode::Optional
    );
}

#[test]
fn another_cas_active_lines_are_commented_out_not_deleted() {
    let (_dir, nginx) = folder(&[]);
    let planned = plan(PHOTOS, 0, Mode::Required, &nginx).unwrap();
    assert!(
        planned.contains("    # ffca: ssl_client_certificate /etc/nginx/certs/ca.cert.pem;\n"),
        "{planned}"
    );
    assert!(
        planned.contains("    #ssl_verify_client on;\n"),
        "already commented lines stay as they are"
    );
    let site = &sites_in(Path::new("photos.conf"), &planned, &nginx).unwrap()[0];
    assert!(site.uses_ca);
    let off = plan(&planned, 0, Mode::Off, &nginx).unwrap();
    assert!(off.contains("# ffca: ssl_client_certificate"), "{off}");
    assert_eq!(
        sites_in(Path::new("photos.conf"), &off, &nginx).unwrap()[0].mode,
        Mode::Off
    );
}

#[test]
fn a_line_holding_more_than_the_directive_is_left_to_a_person() {
    let (_dir, nginx) = folder(&[]);
    let crowded = "server {\n    listen 443 ssl; server_name a.example.org;\n    ssl_verify_client on; ssl_verify_depth 2;\n}\n";
    let error = plan(crowded, 0, Mode::Required, &nginx).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("line 3 holds more than `ssl_verify_client`"),
        "{error}"
    );
}

#[test]
fn the_right_server_block_is_changed_when_a_file_has_several() {
    let (_dir, nginx) = folder(&[]);
    let two = "server {\n    listen 443 ssl;\n    server_name a.example.org;\n}\nserver {\n    listen 443 ssl;\n    server_name b.example.org;\n}\n";
    let planned = plan(two, 1, Mode::Required, &nginx).unwrap();
    let sites = sites_in(Path::new("two.conf"), &planned, &nginx).unwrap();
    assert_eq!(
        (sites[0].name(), sites[0].mode),
        ("a.example.org", Mode::Off)
    );
    assert_eq!(
        (sites[1].name(), sites[1].mode),
        ("b.example.org", Mode::Required)
    );
    assert!(plan(two, 2, Mode::Required, &nginx).is_err());
}

#[test]
fn a_server_without_a_name_gets_the_block_at_its_top() {
    let (_dir, nginx) = folder(&[]);
    let planned = plan(
        "server {\n    listen 443 ssl;\n}\n",
        0,
        Mode::Required,
        &nginx,
    )
    .unwrap();
    assert!(
        planned.starts_with("server {\n\n    # BEGIN ffca"),
        "{planned}"
    );
    assert_eq!(
        plan(&planned, 0, Mode::Off, &nginx).unwrap(),
        "server {\n    listen 443 ssl;\n}\n"
    );
}

#[test]
fn the_parser_reads_what_nginx_reads() {
    for (text, problem) in [
        ("server {\n listen 443 ssl;\n", "not closed"),
        ("server {\n listen 443 ssl\n}\n", "unexpected `}`"),
        ("listen 443 ssl", "is not ended with `;`"),
        ("}\n", "closes nothing"),
        ("set $a \"unclosed;\n", "not closed"),
    ] {
        let error = Parsed::new(text)
            .err()
            .unwrap_or_else(|| panic!("{text:?} parsed"));
        assert!(
            format!("{error:#}").contains(problem),
            "{text:?}: {error:#}"
        );
    }
    let parsed =
        Parsed::new("set $x \"a { b ; c\"; # } not a brace\nset ${y}z 'q\\'s';\n").unwrap();
    let args: Vec<_> = parsed.statements.iter().map(|s| s.args.clone()).collect();
    assert_eq!(
        args,
        [
            vec!["$x".to_owned(), "a { b ; c".into()],
            vec!["${y}z".into(), "q\\'s".into()]
        ]
    );
}

#[test]
fn an_ffca_block_without_its_end_is_refused() {
    let (_dir, nginx) = folder(&[]);
    let damaged = "server {\n    listen 443 ssl;\n    # BEGIN ffca\n    ssl_verify_client on;\n}\n";
    assert!(
        plan(damaged, 0, Mode::Off, &nginx)
            .unwrap_err()
            .to_string()
            .contains("without its # END ffca")
    );
}

#[test]
fn set_mode_writes_tests_and_reloads_and_keeps_the_files_permissions() {
    let (dir, nginx) = folder(&[("books.conf", BOOKS)]);
    let file = nginx.sites.join("books.conf");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    let ca = ca(dir.path());
    let site = only_site(&nginx);
    assert!(set_mode(&nginx, &ca, &site, Mode::Required).unwrap());
    assert_eq!(only_site(&nginx).mode, Mode::Required);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert!(
        !set_mode(&nginx, &ca, &only_site(&nginx), Mode::Required).unwrap(),
        "nothing to change"
    );
    assert_eq!(
        fs::read_to_string(nginx.ca_files.join(CA_FILE)).unwrap(),
        ca.certificate_pem()
    );
    assert_eq!(
        fs::read_to_string(nginx.ca_files.join(CRL_FILE)).unwrap(),
        ca.store().read(ca::CRL_FILE).unwrap()
    );
}

#[test]
fn a_change_nginx_refuses_is_put_back() {
    let (dir, mut nginx) = folder(&[("books.conf", BOOKS)]);
    let ca = ca(dir.path());
    let site = only_site(&nginx);
    nginx.test = "false".into();
    let error = set_mode(&nginx, &ca, &site, Mode::Required).unwrap_err();
    assert!(
        error.to_string().contains("nginx refused the change, so"),
        "{error:#}"
    );
    assert!(format!("{error:#}").contains("`false` failed"), "{error:#}");
    assert_eq!(
        fs::read_to_string(nginx.sites.join("books.conf")).unwrap(),
        BOOKS
    );

    nginx.test = "true".into();
    nginx.reload = "false".into();
    let error = set_mode(&nginx, &ca, &site, Mode::Required).unwrap_err();
    assert!(
        error.to_string().contains("nginx did not reload"),
        "{error:#}"
    );
    assert_eq!(
        fs::read_to_string(nginx.sites.join("books.conf")).unwrap(),
        BOOKS
    );
}

#[test]
fn a_file_changed_since_it_was_read_is_not_touched() {
    let (dir, nginx) = folder(&[("books.conf", BOOKS)]);
    let ca = ca(dir.path());
    let site = only_site(&nginx);
    let edited = BOOKS.replace(
        "server_name books.example.org;\n\n    ssl",
        "server_name library.example.org;\n\n    ssl",
    );
    fs::write(nginx.sites.join("books.conf"), &edited).unwrap();
    let error = set_mode(&nginx, &ca, &site, Mode::Required).unwrap_err();
    assert!(
        error.to_string().contains("changed since it was read"),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(nginx.sites.join("books.conf")).unwrap(),
        edited
    );
}

#[test]
fn commands_report_what_they_printed() {
    assert_eq!(
        run("echo nginx: syntax is ok").unwrap(),
        "nginx: syntax is ok\n"
    );
    let error = run("sh -c exit_3").unwrap_err().to_string();
    assert!(error.contains("`sh -c exit_3` failed"), "{error}");
    assert!(run("").unwrap_err().to_string().contains("empty"));
    assert!(
        run("no-such-program-ffca")
            .unwrap_err()
            .to_string()
            .contains("cannot run")
    );
}

#[test]
fn publish_and_reload_tests_before_it_reloads() {
    let dir = crate::test_dir();
    let mut nginx = settings(dir.path());
    let ca = ca(dir.path());
    let marker = dir.path().join("reloaded");
    nginx.reload = format!("touch {}", marker.display());
    nginx.test = "false".into();
    assert!(publish_and_reload(&nginx, &ca).is_err());
    assert!(
        !marker.exists(),
        "a configuration nginx refuses is not loaded"
    );
    nginx.test = "true".into();
    publish_and_reload(&nginx, &ca).unwrap();
    assert!(marker.exists());
    let mode = fs::metadata(nginx.ca_files.join(CRL_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644, "nginx's workers read it");
}

/// Off on a site that is off changes nothing, even with another CA's certificate line active: only
/// `ssl_verify_client` makes nginx ask.
#[test]
fn off_comments_out_only_what_asks_for_a_certificate() {
    let (_dir, nginx) = folder(&[]);
    assert_eq!(plan(PHOTOS, 0, Mode::Off, &nginx).unwrap(), PHOTOS);
    let asking = PHOTOS.replace("    #ssl_verify_client on;", "    ssl_verify_client on;");
    let off = plan(&asking, 0, Mode::Off, &nginx).unwrap();
    assert!(off.contains("    # ffca: ssl_verify_client on;\n"), "{off}");
    assert!(
        off.contains("    ssl_client_certificate /etc/nginx/certs/ca.cert.pem;\n"),
        "{off}"
    );
    assert_eq!(
        sites_in(Path::new("photos.conf"), &off, &nginx).unwrap()[0].mode,
        Mode::Off
    );
}
