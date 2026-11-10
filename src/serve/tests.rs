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

/// Presses the button at `path` as `client`, follows the browser to the installation page and
/// returns it.
fn collect(page: &mut Page, path: &str, client: &str) -> String {
    let reply = page.answer("POST", path, client, NOW);
    assert_eq!(reply.status, 303, "{}", text(&reply));
    let location = reply.location.expect("a redirect names where to");
    assert!(location.starts_with("/d/"), "{location}");
    let installation = page.answer("GET", &location, client, NOW);
    assert_eq!(installation.status, 200);
    text(&installation)
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
    let body = collect(&mut page, &format!("/i/{token}"), "203.0.113.7, iPhone");
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

    let later = NOW + DOWNLOAD_WINDOW + Duration::seconds(1);
    let again = page.answer("POST", &format!("/i/{token}"), "someone else", later);
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
    assert!(text(&unknown).contains("copied whole"));
    assert_eq!(
        page.answer("GET", "/i/../../state/ca.key", "x", NOW).status,
        404
    );
    assert_eq!(page.answer("GET", "/d/nothing", "x", NOW).status, 404);
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
    let redirect = handle(&post, &page, NOW);
    assert_eq!(redirect.status, 303);
    let mut get = request(&[("User-Agent", "iPhone")]);
    get.target = redirect
        .headers
        .iter()
        .find(|(n, _)| *n == "Location")
        .map(|(_, v)| v.clone())
        .expect("the button sends the browser on");
    let answer = handle(&get, &page, NOW);
    assert_eq!(answer.status, 200);
    let body = String::from_utf8(answer.body.clone()).unwrap();
    let mut get = request(&[]);
    get.target = link(&body, "p12");
    let file = handle(&get, &page, NOW);
    for response in [&redirect, &answer, &file] {
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
    let body = collect(&mut page, &format!("/i/{token}"), "x");
    assert_eq!(body.matches("<code").count(), 1, "{body}");
    let password = body.find("<code").unwrap();
    assert!(password < body.find(".mobileconfig").unwrap());
    assert!(password < body.find(".p12").unwrap());
    assert!(body.contains("Copy the password above"), "{body}");
    assert!(body.contains("paste the password when it asks"), "{body}");
}

fn invite_for_the_laptop(ca: &Ca, dir: &Path, options: invite::Options) -> (invite::Made, String) {
    let made = invite::make_with(
        ca,
        &dir.join("invites"),
        Holder::Device {
            person: "Anna",
            device: "laptop",
        },
        "k.example.org",
        options,
        NOW,
    )
    .unwrap();
    let token = made.link.rsplit('/').next().unwrap().to_owned();
    (made, token)
}

/// A password the administrator sends another way is nowhere on the page, which says so; the
/// file it hands over is locked with it all the same.
#[test]
fn a_password_sent_separately_is_not_on_the_page() {
    let dir = crate::test_dir();
    let (ca, mut page, _) = page_with_invite(dir.path());
    let options = invite::Options {
        password: invite::Delivery::Separate,
        ..Default::default()
    };
    let (made, token) = invite_for_the_laptop(&ca, dir.path(), options);
    let password = made.invite.password.clone().expect("kept for the UI");
    assert_eq!(password.len(), 19);

    let body = collect(&mut page, &format!("/i/{token}"), "203.0.113.7, Android");
    assert!(!body.contains(&password), "{body}");
    assert!(!body.contains("<code"), "{body}");
    assert!(body.contains("which is not on this page"), "{body}");
    assert!(
        body.contains("type the password you were sent when it asks"),
        "{body}"
    );

    let p12 = page.answer("GET", &link(&body, "p12"), "x", NOW);
    let file = dir.path().join("laptop.p12");
    std::fs::write(&file, &p12.body).unwrap();
    let opens_with = |password: &str| {
        std::process::Command::new("openssl")
            .args(["pkcs12", "-noout", "-in"])
            .arg(&file)
            .args(["-passin", &format!("pass:{password}")])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(opens_with(&password));
    assert!(!opens_with("a guess"));
}

/// The page with the password and the downloads can be loaded again - a phone reloads a tab it
/// put aside for the installer - and the invite's own link, opened again, says where they are.
#[test]
fn the_installation_page_can_be_opened_again() {
    let dir = crate::test_dir();
    let (_ca, mut page, token) = page_with_invite(dir.path());
    let reply = page.answer("POST", &format!("/i/{token}"), "203.0.113.7, iPhone", NOW);
    let location = reply.location.unwrap();
    let first = text(&page.answer("GET", &location, "x", NOW));
    let again = text(&page.answer("GET", &location, "x", NOW + Duration::minutes(9)));
    assert_eq!(first, again);
    assert!(first.contains("<code>"), "{first}");

    for method in ["GET", "POST"] {
        let back = page.answer(
            method,
            &format!("/i/{token}"),
            "x",
            NOW + Duration::minutes(1),
        );
        assert_eq!(back.status, 410, "{method}");
        let body = text(&back);
        assert!(body.contains("collected a few minutes ago"), "{body}");
        assert!(!body.contains("<code>"), "the link alone shows no password");
        assert!(!body.contains(&location), "nor where the files are");
    }

    let over = page.answer("GET", &location, "x", NOW + DOWNLOAD_WINDOW);
    assert_eq!(over.status, 404);
    assert!(text(&over).contains("This download is over"));
}

/// A link cut short on its way is told apart from an invite someone used.
#[test]
fn a_link_that_is_not_whole_says_so() {
    let dir = crate::test_dir();
    let (_ca, mut page, token) = page_with_invite(dir.path());
    for cut in [&token[..40], "x", &format!("{token}A")] {
        for method in ["GET", "POST"] {
            let reply = page.answer(method, &format!("/i/{cut}"), "x", NOW);
            assert_eq!(reply.status, 404, "{cut}");
            let body = text(&reply);
            assert!(body.contains("This link is incomplete"), "{body}");
            assert!(!body.contains("someone else"), "{body}");
        }
    }
    assert_eq!(
        page.answer("GET", &format!("/i/{token}"), "x", NOW).status,
        200,
        "and the whole link still works"
    );
}

fn browser(target: &str) -> http::Request {
    let mut request = request(&[
        (
            "User-Agent",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Dest", "document"),
    ]);
    request.target = target.to_owned();
    request
}

fn with_header(mut request: http::Request, name: &str, value: &str) -> http::Request {
    request
        .headers
        .retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    request.headers.push((name.to_owned(), value.to_owned()));
    request
}

/// A chat app fetching the link to preview it, a scanner, a script: none is shown whose invite
/// it is, or whether there is one. A person's browser is.
#[test]
fn a_preview_is_shown_nothing_of_the_invite() {
    let dir = crate::test_dir();
    let (_ca, page, token) = page_with_invite(dir.path());
    let page = Mutex::new(page);
    let link = format!("/i/{token}");
    let body = |response: &http::Response| String::from_utf8(response.body.clone()).unwrap();

    let person = handle(&browser(&link), &page, NOW);
    assert_eq!(person.status, 200);
    assert!(body(&person).contains("A certificate for Anna (phone)"));

    let unknown = "/i/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let programs = [
        with_header(browser(&link), "User-Agent", "WhatsApp/2.23.20.0 A"),
        with_header(
            browser(&link),
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like \
             Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0",
        ),
        with_header(
            browser(&link),
            "User-Agent",
            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        ),
        with_header(
            browser(&link),
            "User-Agent",
            "TelegramBot (like TwitterBot)",
        ),
        with_header(browser(&link), "User-Agent", "curl/8.10.1"),
        with_header(browser(&link), "User-Agent", ""),
        with_header(browser(&link), "Accept", "*/*"),
        with_header(browser(&link), "Sec-Purpose", "prefetch;prerender"),
        with_header(browser(&link), "Sec-Fetch-Mode", "no-cors"),
        with_header(browser(&link), "Sec-Fetch-Dest", "image"),
        with_header(browser(unknown), "User-Agent", "Discordbot/2.0"),
    ];
    let mut answers = Vec::new();
    for program in &programs {
        assert!(automated(program), "{:?}", program.headers);
        let answer = handle(program, &page, NOW);
        assert_eq!(answer.status, 403, "{:?}", program.headers);
        let text = body(&answer);
        assert!(!text.contains("Anna"), "{text}");
        assert!(!text.contains("Test"), "{text}");
        answers.push(text.replace(unknown, &link));
    }
    answers.dedup();
    assert_eq!(answers.len(), 1, "an invite and none look the same");

    // A person taken for a program has a way on, which shows the invite and still spends nothing.
    let on = format!("{link}/open");
    assert!(
        answers[0].contains(&format!("href=\"{on}\"")),
        "{}",
        answers[0]
    );
    let through = handle(
        &with_header(browser(&on), "User-Agent", "an odd browser bot"),
        &page,
        NOW,
    );
    assert_eq!(through.status, 200);
    assert!(body(&through).contains("A certificate for Anna (phone)"));
    assert_eq!(handle(&browser(&link), &page, NOW).status, 200);
}

/// Browsers older than the `Sec-Fetch` headers are people too, and so are the browsers chat apps
/// open links in; only the invite's own page is kept from programs.
#[test]
fn a_browser_is_not_taken_for_a_program() {
    let old_safari = request(&[
        (
            "User-Agent",
            "Mozilla/5.0 (iPad; CPU OS 12_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like \
             Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1",
        ),
        ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
    ]);
    assert!(!automated(&old_safari));
    for agent in [
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/130.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, \
         like Gecko) Mobile/15E148 Instagram 350.0.0.0",
    ] {
        assert!(
            !automated(&with_header(browser("/"), "User-Agent", agent)),
            "{agent}"
        );
    }

    let dir = crate::test_dir();
    let page = Mutex::new(Page::new(dir.path().to_owned()));
    let mut health = request(&[]);
    health.target = "/healthz".to_owned();
    assert_eq!(handle(&health, &page, NOW).status, 200);
    let mut download = request(&[("User-Agent", "AndroidDownloadManager/14")]);
    download.target = "/d/nothing/anna-phone.p12".to_owned();
    assert_eq!(
        handle(&download, &page, NOW).status,
        404,
        "a download manager is answered as any client"
    );
}

/// A client that reaches the port from the internet, past nginx, cannot choose the address a
/// receipt names.
#[test]
fn a_far_client_cannot_name_its_own_address() {
    let mut far = request(&[("X-Real-IP", "192.0.2.1")]);
    for (peer, believed) in [
        ("198.51.100.9:4000", false),
        ("[2001:db8::9]:4000", false),
        ("127.0.0.1:4000", true),
        ("10.0.0.2:4000", true),
        ("[::ffff:172.18.0.5]:4000", true),
        ("[fd00::5]:4000", true),
    ] {
        far.peer = peer.parse().unwrap();
        assert_eq!(
            client_address(&far).to_string() == "192.0.2.1",
            believed,
            "{peer}"
        );
    }
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
    let body = collect(&mut page, &format!("/i/{token}/"), "x");
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

/// The download for the device that opened the page comes first: the profile for an iPhone, iPad
/// or a Mac (which an iPad says it is), the `.p12` for everything else.
#[test]
fn the_device_s_own_download_comes_first() {
    for (client, profile_first) in [
        ("203.0.113.7, iPhone", true),
        ("203.0.113.7, iPad", true),
        ("203.0.113.7, Mac", true),
        ("203.0.113.7, Android", false),
        ("203.0.113.7, Windows", false),
        ("203.0.113.7, an unknown device", false),
    ] {
        let dir = crate::test_dir();
        let (_ca, mut page, token) = page_with_invite(dir.path());
        let body = collect(&mut page, &format!("/i/{token}"), client);
        let profile = body.find(".mobileconfig").unwrap();
        let p12 = body.find(".p12").unwrap();
        assert_eq!(profile < p12, profile_first, "{client}:\n{body}");
    }
}

/// An invite that names a site to check against ends with that site, to open once the
/// certificate is installed; one that names none says nothing about checking.
#[test]
fn the_page_ends_with_a_site_to_check_the_certificate_on() {
    let dir = crate::test_dir();
    let (ca, mut page, token) = page_with_invite(dir.path());
    let body = collect(&mut page, &format!("/i/{token}"), "x");
    assert!(!body.contains("Check that it works"), "{body}");

    let options = invite::Options {
        check: Some("https://cloud.example.org/"),
        ..Default::default()
    };
    let (_, token) = invite_for_the_laptop(&ca, dir.path(), options);
    let body = collect(&mut page, &format!("/i/{token}"), "x");
    assert!(body.contains("Check that it works"), "{body}");
    assert!(
        body.contains(
            r#"<a class="button" href="https://cloud.example.org/" target="_blank" rel="noopener noreferrer">Open cloud.example.org</a>"#
        ),
        "the site opens beside the page, which stays: {body}"
    );
    assert!(
        body.contains("choose the one from <b>Test &amp; family</b>"),
        "{body}"
    );
}
