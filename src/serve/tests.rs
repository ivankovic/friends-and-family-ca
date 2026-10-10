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
use std::path::Path;

use time::macros::datetime;

use super::*;
use crate::ca::{self, Ca};
use crate::ledger::{Holder, InviteState};
use crate::store::Store;

const NOW: OffsetDateTime = datetime!(2026-10-03 12:00 UTC);

/// A CA with one invite for Anna's phone: the page over its folder, and the invite's token.
fn page_with_invite(dir: &Path) -> (Ca, Page, String) {
    let ca = Ca::create(
        &Store::new(dir.join("state")),
        "Test & family",
        NOW,
        ca::DEFAULT_CA_VALIDITY,
    )
    .unwrap();
    let folder = dir.join("invites");
    let made = invite::make(
        &ca,
        &folder,
        Holder::Device {
            person: "Anna",
            device: "phone",
        },
        "k.example.org",
        NOW,
    )
    .unwrap();
    let token = made.link.rsplit('/').next().unwrap().to_owned();
    (ca, Page::new(folder), token)
}

fn text(reply: &Reply) -> String {
    String::from_utf8(reply.body.clone()).unwrap()
}

/// The download address the installation page links to, for `extension`.
fn link(page: &str, extension: &str) -> String {
    let end = page.find(&format!(".{extension}\"")).expect(extension) + extension.len() + 1;
    let start = page[..end].rfind("href=\"").unwrap() + 6;
    page[start..end].to_owned()
}

#[test]
fn opening_the_link_shows_whose_it_is_and_uses_nothing_up() {
    let dir = crate::test_dir();
    let (_ca, mut page, token) = page_with_invite(dir.path());
    for _ in 0..3 {
        let reply = page.answer("GET", &format!("/i/{token}"), "a preview bot", NOW);
        assert_eq!(reply.status, 200);
        let body = text(&reply);
        assert!(body.contains("A certificate for Anna (phone)"), "{body}");
        assert!(
            body.contains("From <b>Test &amp; family</b>"),
            "escaped: {body}"
        );
        assert!(
            body.contains(&format!(r#"<form method="post" action="/i/{token}">"#)),
            "{body}"
        );
        assert!(!body.contains("<script"), "no scripts");
    }
}

#[test]
fn the_button_collects_the_invite_and_serves_both_files_for_a_while() {
    let dir = crate::test_dir();
    let (ca, mut page, token) = page_with_invite(dir.path());
    let reply = page.answer("POST", &format!("/i/{token}"), "203.0.113.7, iPhone", NOW);
    assert_eq!(reply.status, 200);
    let body = text(&reply);
    let ledger_invite = ca.ledger().unwrap().invites[0].clone();
    let payload_password = body
        .split("<code>")
        .nth(1)
        .unwrap()
        .split("</code>")
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(payload_password.len(), 19, "{body}");

    let profile = page.answer(
        "GET",
        &link(&body, "mobileconfig"),
        "x",
        NOW + Duration::minutes(5),
    );
    assert_eq!(
        (profile.status, profile.content_type),
        (200, "application/x-apple-aspen-config")
    );
    assert_eq!(
        profile.attachment.as_deref(),
        Some("anna-phone.mobileconfig")
    );
    assert!(text(&profile).contains("com.apple.security.pkcs12"));
    let p12 = page.answer("GET", &link(&body, "p12"), "x", NOW + Duration::minutes(9));
    assert_eq!(
        (p12.status, p12.content_type),
        (200, "application/x-pkcs12")
    );
    assert!(!p12.body.is_empty());

    let late = page.answer(
        "GET",
        &link(&body, "p12"),
        "x",
        NOW + DOWNLOAD_WINDOW + Duration::seconds(1),
    );
    assert_eq!(late.status, 404, "the files are gone after the window");

    let again = page.answer("POST", &format!("/i/{token}"), "someone else", NOW);
    assert_eq!(again.status, 404);
    assert!(text(&again).contains("has been used or cancelled"));
    assert_eq!(
        ledger_invite.state,
        InviteState::Open,
        "the ledger learns of it when tended"
    );
    let tended = invite::tend(&ca, &dir.path().join("invites"), NOW).unwrap();
    assert_eq!(tended.collected, ["Anna (phone)"]);
    assert_eq!(
        ca.ledger().unwrap().invites[0].collected_by.as_deref(),
        Some("203.0.113.7, iPhone")
    );
}

#[test]
fn an_expired_or_unknown_invite_says_so() {
    let dir = crate::test_dir();
    let (_ca, mut page, token) = page_with_invite(dir.path());
    let expired = page.answer("GET", &format!("/i/{token}"), "x", NOW + invite::VALIDITY);
    assert_eq!(expired.status, 410);
    assert!(text(&expired).contains("This invite has expired"));
    let unknown = page.answer(
        "GET",
        "/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "x",
        NOW,
    );
    assert_eq!(unknown.status, 404);
    assert!(text(&unknown).contains("used or cancelled"));
    assert_eq!(
        page.answer("GET", "/i/../../state/ca.key", "x", NOW).status,
        404
    );
    assert_eq!(
        page.answer("GET", "/d/nothing/anna-phone.p12", "x", NOW)
            .status,
        404
    );
    assert_eq!(
        page.answer("DELETE", &format!("/i/{token}"), "x", NOW)
            .status,
        404
    );
    assert_eq!(page.answer("GET", "/healthz", "x", NOW).status, 200);
}

#[test]
fn the_log_never_shows_a_token() {
    assert_eq!(
        redact("/i/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"),
        "/i/…"
    );
    assert_eq!(redact("/d/secret/anna-phone.p12"), "/d/…/anna-phone.p12");
    assert_eq!(redact("/healthz"), "/healthz");
}

#[test]
fn devices_are_named_from_their_browsers() {
    assert_eq!(
        device("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"),
        "iPhone"
    );
    assert_eq!(
        device("Mozilla/5.0 (Linux; Android 11; NoteAir4C)"),
        "Android"
    );
    assert_eq!(
        device("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"),
        "Linux"
    );
    assert_eq!(device("curl/8.5.0"), "an unknown device");
}

/// However a path is written - a trailing slash, a query, percent-encoding - the log never shows
/// the secret in it, because it reads the path as the page does.
#[test]
fn no_way_of_writing_a_path_puts_a_secret_in_the_log() {
    let token = "lKrtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANdr8";
    for path in [
        format!("/i/{token}"),
        format!("/i/{token}/"),
        format!("//i//{token}"),
        format!("/i/{token}?x=1"),
        format!("/%69/{token}"),
    ] {
        assert_eq!(redact(&path), "/i/…", "{path}");
    }
    assert_eq!(redact("/d/secret/anna-phone.p12/"), "/d/…/anna-phone.p12");
    assert_eq!(
        redact("/a\u{1b}[31m%0Ab"),
        "/a[31mb",
        "nothing that forges a log line"
    );
}

/// Paths the page does not answer by - a dot segment, an escaped slash, a token spelled twice
/// over - are not shown whole, however much of a token they carry.
#[test]
fn a_path_the_page_does_not_answer_is_not_shown_whole() {
    let token = "lKrtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANdr8";
    let id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for path in [
        format!("/i/./{token}"),
        format!("/x/../i/{token}"),
        format!("/i%2F{token}"),
        format!("/i/{token}/more"),
        format!("/{token}"),
        format!("/d/./{id}/anna-phone.p12"),
        format!("/{id}"),
        format!("/i/%25{}", token.replace('A', "%41")),
    ] {
        let shown = redact(&path);
        assert!(
            !shown.contains("AAAAAAAA") && !shown.contains("%41%41"),
            "{path} -> {shown}"
        );
    }
    assert_eq!(redact("/robots.txt"), "/robots.txt");
    assert_eq!(
        redact("/.well-known/security.txt"),
        "/.well-known/security.txt"
    );
}

fn request(headers: &[(&str, &str)]) -> http::Request {
    http::Request {
        method: "GET".to_owned(),
        target: "/".to_owned(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        peer: "172.18.0.5:41000".parse().unwrap(),
    }
}

/// The address an invite is collected from is nginx's word for it, or the connection's: never
/// text a client made up.
#[test]
fn the_client_address_is_an_address() {
    assert_eq!(
        client_address(&request(&[("x-real-ip", "203.0.113.7")])).to_string(),
        "203.0.113.7"
    );
    assert_eq!(
        client_address(&request(&[("X-Real-IP", "2001:db8::1")])).to_string(),
        "2001:db8::1"
    );
    for forged in ["9.9.9.9\nPOST /i/x 200 (", "evil", ""] {
        assert_eq!(
            client_address(&request(&[("X-Real-IP", forged)])).to_string(),
            "172.18.0.5",
            "{forged:?}"
        );
    }
    assert_eq!(client_address(&request(&[])).to_string(), "172.18.0.5");
}

#[test]
fn a_log_line_is_one_line() {
    let line = log_line(
        "GET",
        "/x\n%0A\u{1b}[2K",
        404,
        "203.0.113.7".parse().unwrap(),
        "iPhone",
    );
    assert_eq!(line, "GET /x[2K 404 (203.0.113.7, iPhone)");
}

/// The whole page, through its HTTP server: the security headers on every answer, and a download
/// named for the person.
#[test]
fn every_answer_forbids_caching_and_scripts() {
    let dir = crate::test_dir();
    let (_ca, page, token) = page_with_invite(dir.path());
    let page = Mutex::new(page);
    let mut post = request(&[("X-Real-IP", "203.0.113.7"), ("User-Agent", "iPhone")]);
    post.method = "POST".to_owned();
    post.target = format!("/i/{token}");
    let answer = handle(&post, &page, NOW);
    assert_eq!(answer.status, 200);
    let body = String::from_utf8(answer.body.clone()).unwrap();
    let mut get = request(&[]);
    get.target = link(&body, "p12");
    let file = handle(&get, &page, NOW);
    for response in [&answer, &file] {
        let header = |name: &str| {
            response
                .headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header("Cache-Control"), Some("no-store"));
        assert_eq!(header("Referrer-Policy"), Some("no-referrer"));
        assert!(
            header("Content-Security-Policy")
                .unwrap()
                .starts_with("default-src 'none'")
        );
    }
    assert_eq!(file.status, 200);
    assert!(
        file.headers
            .iter()
            .any(|(n, v)| *n == "Content-Disposition" && v.contains("anna-phone.p12"))
    );
}

/// The password is on the page once, for both downloads: the profile no longer carries it.
#[test]
fn the_password_is_shown_for_both_downloads() {
    let dir = crate::test_dir();
    let (_ca, mut page, token) = page_with_invite(dir.path());
    let body = text(&page.answer("POST", &format!("/i/{token}"), "x", NOW));
    assert_eq!(body.matches("<code>").count(), 1, "{body}");
    let password = body.find("<code>").unwrap();
    assert!(password < body.find(".mobileconfig").unwrap());
    assert!(password < body.find(".p12").unwrap());
    assert!(body.contains("type the password when it asks"), "{body}");
}

/// Browsers percent-encode what is not ASCII: a Croatian name's files still download.
#[test]
fn a_name_that_is_not_ascii_still_downloads() {
    let dir = crate::test_dir();
    let ca = Ca::create(
        &Store::new(dir.path().join("state")),
        "Test",
        NOW,
        ca::DEFAULT_CA_VALIDITY,
    )
    .unwrap();
    let folder = dir.path().join("invites");
    let made = invite::make(
        &ca,
        &folder,
        Holder::Device {
            person: "Čedo",
            device: "mobitel",
        },
        "k.example.org",
        NOW,
    )
    .unwrap();
    let token = made.link.rsplit('/').next().unwrap();
    let mut page = Page::new(folder);
    let body = text(&page.answer("POST", &format!("/i/{token}/"), "x", NOW));
    let address = link(&body, "p12");
    assert!(address.ends_with("/čedo-mobitel.p12"), "{address}");
    let encoded = address.replace("čedo", "%C4%8Dedo");
    let reply = page.answer("GET", &encoded, "x", NOW);
    assert_eq!(reply.status, 200);
    assert_eq!(
        disposition(reply.attachment.as_deref().unwrap()),
        "attachment; filename=\"_edo-mobitel.p12\"; filename*=UTF-8''%C4%8Dedo-mobitel.p12"
    );
}

#[test]
fn percent_decoding_leaves_what_is_not_an_escape() {
    assert_eq!(percent_decode("a%20b%zz%4"), "a b%zz%4");
    assert_eq!(route("/i//x/?q=/y"), ["i", "x"]);
}

#[test]
fn the_root_says_what_the_site_is() {
    let dir = crate::test_dir();
    let mut page = Page::new(dir.path().to_owned());
    for path in ["/", "", "//", "/?x"] {
        let reply = page.answer("GET", path, "x", NOW);
        assert_eq!(reply.status, 200, "{path:?}");
        assert!(text(&reply).contains("Invites are collected here"));
    }
}
