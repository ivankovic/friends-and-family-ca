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
//! `ffca serve`: the enrollment page, where an invite's link leads.
//!
//! It is given the invites folder and nothing else: no key, no ledger. Behind nginx, on the
//! enrollment site, which never asks for a client certificate.
//!
//! * `GET /i/<token>` shows whose certificate it is and a button. Opening the link does not use
//!   it up: chat apps fetch links to preview them, and that must not spend an invite. A request
//!   that is not a person opening the link in a browser ([`automated`]) - such a preview - is
//!   shown nothing of the invite, not even whether it exists: it gets a page that says the link
//!   is for a person, with a way on (`GET /i/<token>/open`) for a person it took for a program.
//! * `POST /i/<token>` - the button - collects the invite (`crate::invite::collect`) and sends
//!   the browser on to the installation page, at a random address of its own.
//! * `GET /d/<id>` is that page: a profile for iPhone and iPad, a `.p12` for everything else,
//!   and the password both ask for while installing - or, when the administrator sends the
//!   password another way, a line that says so. The files are kept in memory for
//!   [`DOWNLOAD_WINDOW`], so that the person can reload the page, try both files, or come back
//!   from the installer, without a second invite.
//! * `GET /d/<id>/<file>` serves them.
//!
//! Every answer forbids caching and referrers - the token is in the address - and the page has no
//! scripts. Requests are logged without their tokens.
//!
//! The HTTP underneath is [`http`]'s, made for nginx in front and wary of whoever is not.

pub mod http;

use std::collections::HashMap;
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::{Duration, OffsetDateTime};

use crate::invite::{self, Payload, Unavailable};

/// How long the files of a collected invite can be downloaded.
pub const DOWNLOAD_WINDOW: Duration = Duration::minutes(10);

/// An answer, before it is HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Set for a file to save: its name.
    pub attachment: Option<String>,
    /// Set for a redirect: where the browser goes next.
    pub location: Option<String>,
}

/// The page's state: the files of invites collected in the last [`DOWNLOAD_WINDOW`].
pub struct Page {
    folder: PathBuf,
    downloads: HashMap<String, Download>,
}

/// A collected invite, while its files can be downloaded.
struct Download {
    payload: Payload,
    until: OffsetDateTime,
    /// The invite it was: its file's name (`crate::invite::id`), so that its link, opened again,
    /// can say what happened to it.
    invite: String,
}

impl Drop for Download {
    /// Overwrites the key before the memory is given back. The copies made on the way - the
    /// answers sent, the sealed file read - are not reached: this shortens how long the key is
    /// in the page's memory, and does not promise it is gone.
    fn drop(&mut self) {
        let mut password = std::mem::take(&mut self.payload.password)
            .unwrap_or_default()
            .into_bytes();
        for bytes in [
            &mut self.payload.p12,
            &mut self.payload.mobileconfig,
            &mut password,
        ] {
            bytes.fill(0);
            std::hint::black_box(&bytes);
        }
    }
}

impl Page {
    pub fn new(folder: PathBuf) -> Page {
        Page {
            folder,
            downloads: HashMap::new(),
        }
    }

    /// Answers `method` on `path`, for a client described as `client` (its address and device).
    pub fn answer(&mut self, method: &str, path: &str, client: &str, now: OffsetDateTime) -> Reply {
        self.downloads.retain(|_, download| download.until > now);
        let segments = route(path);
        let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
        match (method, parts.as_slice()) {
            ("GET", ["healthz"]) => Reply {
                status: 200,
                content_type: "text/plain",
                body: b"ok\n".to_vec(),
                attachment: None,
                location: None,
            },
            ("GET", []) => html(
                200,
                "Friends and Family CA",
                "<h1>Friends and Family CA</h1><p>Invites are collected here, by their own links.</p>",
            ),
            ("GET", ["i", token] | ["i", token, "open"]) => {
                match invite::open(&self.folder, token, now) {
                    Ok(payload) => html(200, &payload.holder, &invitation(token, &payload)),
                    Err(unavailable) => self.unavailable(token, unavailable),
                }
            }
            ("POST", ["i", token]) => {
                // Made before the invite is collected: without it, the files could not be offered.
                let Some(id) = random_id() else {
                    return html(
                        503,
                        "Try again",
                        "<h1>Something went wrong</h1><p>The invite is still unused. Try again in a minute.</p>",
                    );
                };
                match invite::collect(&self.folder, token, now, client) {
                    Ok(payload) => {
                        let until = now.checked_add(DOWNLOAD_WINDOW).unwrap_or(now);
                        let invite = invite::id(token).unwrap_or_default();
                        let download = Download {
                            payload,
                            until,
                            invite,
                        };
                        // The browser is sent on to a page it can load again: the answer to a
                        // POST cannot be reloaded, or come back to, without asking for the
                        // invite a second time.
                        let location = format!("/d/{id}");
                        self.downloads.insert(id, download);
                        Reply {
                            location: Some(location),
                            ..html(
                                303,
                                "Collected",
                                "<h1>Collected</h1><p>The certificate is on the next page.</p>",
                            )
                        }
                    }
                    Err(unavailable) => self.unavailable(token, unavailable),
                }
            }
            ("GET", ["d", id]) => match self.downloads.get(*id) {
                Some(download) => html(
                    200,
                    &download.payload.holder,
                    &installation(id, &download.payload, is_apple(client)),
                ),
                None => download_over(),
            },
            ("GET", ["d", id, file]) => match self.downloads.get(*id).map(|d| &d.payload) {
                Some(payload) if *file == format!("{}.mobileconfig", payload.stem) => Reply {
                    status: 200,
                    content_type: "application/x-apple-aspen-config",
                    body: payload.mobileconfig.clone(),
                    attachment: Some(file.to_string()),
                    location: None,
                },
                Some(payload) if *file == format!("{}.p12", payload.stem) => Reply {
                    status: 200,
                    content_type: "application/x-pkcs12",
                    body: payload.p12.clone(),
                    attachment: Some(file.to_string()),
                    location: None,
                },
                _ => download_over(),
            },
            _ => html(404, "Not found", "<h1>Nothing here</h1>"),
        }
    }

    /// The page for an invite that cannot be opened. One collected through this page a moment
    /// ago says so: the person who pressed the button and came back to the link is told where
    /// their files are, not that someone else may have taken them.
    fn unavailable(&self, token: &str, unavailable: Unavailable) -> Reply {
        let collected_here = unavailable == Unavailable::Gone
            && invite::id(token).is_some_and(|id| self.downloads.values().any(|d| d.invite == id));
        if collected_here {
            return html(
                410,
                "Collected",
                "<h1>This invite was collected a few minutes ago</h1><p>If that was you, go back to the page with the password and the downloads: it is still open in this browser, one step back. Each invite works once.</p><p class=\"small\">If it was not you, tell whoever sent you the link.</p>",
            );
        }
        unavailable_page(unavailable)
    }
}

fn download_over() -> Reply {
    html(
        404,
        "Gone",
        "<h1>This download is over</h1><p>Its files are kept for ten minutes after the button is pressed. Ask for a new invite.</p>",
    )
}

/// What a request that is no person's browser gets for an invite's link: nothing of the invite -
/// not whose it is, not whether it exists - and a way on for a person taken for a program.
fn not_for_programs(path: &str) -> Option<Reply> {
    let segments = route(path);
    let [i, token] = segments.as_slice() else {
        return None;
    };
    if i != "i" {
        return None;
    }
    // Only a token goes into the page: its letters need no escaping.
    invite::id(token)?;
    Some(html(
        403,
        "An invite",
        &format!(
            r#"<h1>An invite</h1>
<p>This link is for one person: it hands a certificate to the device that opens it. Open it in that device's browser.</p>
<p><a class="button" href="/i/{token}/open">Open the invite</a></p>"#
        ),
    ))
}

/// Whether `request` comes from a program rather than a person opening a link in a browser: a
/// chat app or a mail scanner fetching the link to preview it, a crawler, a script, a browser
/// loading the page ahead of time.
///
/// A browser that follows a link says so (`Sec-Fetch-Mode: navigate`, an `Accept` that asks for
/// HTML); a previewer names itself, or sends none of it. Whoever wants in can claim to be a
/// browser: this keeps an invite's name out of previews and its page away from scanners, and
/// the secret in the link is what guards the certificate.
pub fn automated(request: &http::Request) -> bool {
    const MARKERS: [&str; 26] = [
        "bot",
        "crawl",
        "spider",
        "preview",
        "facebookexternalhit",
        "whatsapp",
        "embedly",
        "iframely",
        "headless",
        "scrapy",
        "curl/",
        "wget/",
        "python",
        "go-http-client",
        "okhttp",
        "java/",
        "libwww",
        "httpclient",
        "axios",
        "node-fetch",
        "undici",
        "google-",
        "feedfetcher",
        "mediapartners",
        "validator",
        "monitor",
    ];
    let agent = request
        .header("User-Agent")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if agent.trim().is_empty() || MARKERS.iter().any(|marker| agent.contains(marker)) {
        return true;
    }
    let ahead_of_time = ["Sec-Purpose", "Purpose", "X-Purpose", "X-Moz"]
        .iter()
        .filter_map(|name| request.header(name))
        .any(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("prefetch") || value.contains("preview") || value.contains("prerender")
        });
    let asks_for_html = request
        .header("Accept")
        .is_some_and(|accept| accept.to_ascii_lowercase().contains("text/html"));
    let follows_a_link = request
        .header("Sec-Fetch-Mode")
        .is_none_or(|mode| mode.eq_ignore_ascii_case("navigate"))
        && request
            .header("Sec-Fetch-Dest")
            .is_none_or(|dest| dest.eq_ignore_ascii_case("document"));
    ahead_of_time || !asks_for_html || !follows_a_link
}

/// Serves the page on `listen` until the process ends.
pub fn run(listen: &str, folder: PathBuf) -> Result<()> {
    let listener =
        TcpListener::bind(listen).with_context(|| format!("cannot listen on {listen}"))?;
    // In a container the page is the first process, which gets no default handling of SIGTERM:
    // without this, `docker stop` waits and then kills it. Nothing is lost by exiting at once - a
    // collected invite's files are only ever in memory, for ten minutes.
    ctrlc::set_handler(|| std::process::exit(0))
        .map_err(|e| anyhow!("cannot handle SIGTERM: {e}"))?;
    eprintln!(
        "ffca serve: listening on {listen}, invites in {}",
        folder.display()
    );
    let page = Mutex::new(Page::new(folder));
    http::serve(
        listener,
        http::Limits::default(),
        Arc::new(move |request: &http::Request| handle(request, &page, OffsetDateTime::now_utc())),
    )
}

/// Answers one request, made at `now`, and logs it.
fn handle(request: &http::Request, page: &Mutex<Page>, now: OffsetDateTime) -> http::Response {
    let address = client_address(request);
    let device = device(request.header("User-Agent").unwrap_or_default());
    let refused = (request.method == "GET" && automated(request))
        .then(|| not_for_programs(&request.target))
        .flatten();
    let reply = refused.unwrap_or_else(|| {
        page.lock().unwrap_or_else(|p| p.into_inner()).answer(
            &request.method,
            &request.target,
            &format!("{address}, {device}"),
            now,
        )
    });
    eprintln!(
        "{}",
        log_line(
            &request.method,
            &request.target,
            reply.status,
            address,
            device
        )
    );
    let mut headers = vec![
            ("Content-Type", reply.content_type.to_owned()),
            ("Cache-Control", "no-store".to_owned()),
            ("Referrer-Policy", "no-referrer".to_owned()),
            ("X-Content-Type-Options", "nosniff".to_owned()),
            (
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".to_owned(),
            ),
        ];
    if let Some(name) = reply.attachment {
        headers.push(("Content-Disposition", disposition(&name)));
    }
    if let Some(location) = reply.location {
        headers.push(("Location", location));
    }
    http::Response {
        status: reply.status,
        headers,
        body: reply.body,
    }
}

/// Where a request comes from: the address nginx gives in `X-Real-IP`, or, without one that is an
/// address, the connection's own. The header is believed only on a connection that can be
/// nginx's - from this machine or a private network, where a container's neighbours are: a
/// client that reaches the port from the internet cannot choose the address a receipt names.
fn client_address(request: &http::Request) -> IpAddr {
    let peer = request.peer.ip();
    let peer = match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(peer, IpAddr::V4),
        v4 => v4,
    };
    let near = match peer {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    };
    request
        .header("X-Real-IP")
        .filter(|_| near)
        .and_then(|a| a.parse().ok())
        .unwrap_or(peer)
}

/// The log's line for a request: its path without secrets, and nothing that could forge a line.
fn log_line(method: &str, path: &str, status: u16, address: IpAddr, device: &str) -> String {
    format!("{method} {} {status} ({address}, {device})", redact(path))
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// A path as the page reads it: without its query, in segments, each percent-decoded - a browser
/// sends "Čedo" as "%C4%8Cedo" - and empty segments dropped, so `/i/<token>/` is `/i/<token>`.
fn route(path: &str) -> Vec<String> {
    path.split('?')
        .next()
        .unwrap_or("")
        .split('/')
        .filter(|s| !s.is_empty())
        .map(percent_decode)
        .collect()
}

fn percent_decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (
            bytes[i],
            bytes.get(i + 1).copied().and_then(hex),
            bytes.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(high), Some(low)) => {
                out.push((high * 16 + low) as u8);
                i += 3;
            }
            (byte, _, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A path as the log shows it: from the same segments the page answers by, with tokens and
/// download addresses left out, and nothing that could forge a log line.
///
/// A path that is not the page's own is shown only if it is too short to hold a secret: a token
/// is 43 characters and a download address 32, however a client spells the rest of the path.
fn redact(path: &str) -> String {
    const LONGEST_SHOWN: usize = 31;
    let parts = route(path);
    let shown = match parts.as_slice() {
        [i, _] if i == "i" => "/i/…".to_owned(),
        [i, _, open] if i == "i" && open == "open" => "/i/…/open".to_owned(),
        [d, _] if d == "d" => "/d/…".to_owned(),
        [d, _, file] if d == "d" => format!("/d/…/{file}"),
        _ => {
            let whole = format!("/{}", parts.join("/"));
            if whole.chars().count() <= LONGEST_SHOWN {
                whole
            } else {
                format!("/… ({} characters)", whole.chars().count())
            }
        }
    };
    shown
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

/// A `Content-Disposition` for `name`: a plain-ASCII `filename` for old browsers, and the exact
/// name as `filename*` (RFC 6266).
fn disposition(name: &str) -> String {
    let plain: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let exact: String = name
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    format!("attachment; filename=\"{plain}\"; filename*=UTF-8''{exact}")
}

/// The kind of device a browser says it runs on.
fn device(user_agent: &str) -> &'static str {
    for (marker, name) in [
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android"),
        ("Macintosh", "Mac"),
        ("Windows", "Windows"),
        ("CrOS", "ChromeOS"),
        ("Linux", "Linux"),
    ] {
        if user_agent.contains(marker) {
            return name;
        }
    }
    "an unknown device"
}

/// A download's address, or `None` if the system has no randomness to give.
fn random_id() -> Option<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

fn unavailable_page(unavailable: Unavailable) -> Reply {
    match unavailable {
        Unavailable::Expired => html(
            410,
            "Expired",
            "<h1>This invite has expired</h1><p>Invites work for a day. Ask whoever sent it for a new one.</p>",
        ),
        Unavailable::Gone => html(
            404,
            "Used or cancelled",
            "<h1>This invite has been used or cancelled</h1><p>Each invite works once. If you did not use it yourself, check that the link was copied whole; if it was, tell whoever sent it to you: someone else may have used it.</p>",
        ),
        Unavailable::Malformed => html(
            404,
            "Incomplete link",
            "<h1>This link is incomplete</h1><p>Part of it was lost on the way. Copy the whole link, or scan the code again.</p>",
        ),
    }
}

fn invitation(token: &str, payload: &Payload) -> String {
    format!(
        r#"<h1>A certificate for {holder}</h1>
<p>From <b>{ca}</b>. It lets this device into the sites that ask for one.</p>
<p>Open this page on the device that should have it. The button uses the invite up: it works once.</p>
<p class="small">On an iPhone or iPad, open this page in Safari first: a page opened inside a chat app cannot install the certificate.</p>
<form method="post" action="/i/{token}"><button type="submit">Get the certificate</button></form>"#,
        holder = escape(&payload.holder),
        ca = escape(&payload.ca),
    )
}

/// Whether `client`, as [`handle`] writes it ("203.0.113.7, iPhone"), is an Apple device, which
/// installs the profile; anything else installs the `.p12`. iPadOS calls itself a Mac.
fn is_apple(client: &str) -> bool {
    matches!(client.rsplit(", ").next(), Some("iPhone" | "iPad" | "Mac"))
}

/// The installation page: the password, then both downloads, the one for the device that
/// opened the page first.
fn installation(id: &str, payload: &Payload, apple: bool) -> String {
    let (copy, type_it) = match payload.password {
        Some(_) => (
            "<li>Copy the password above.</li>\n",
            "paste the password when it asks",
        ),
        None => ("", "type the password you were sent when it asks"),
    };
    let profile = format!(
        r#"<h2>iPhone or iPad</h2>
<p><a class="button" href="/d/{id}/{stem}.mobileconfig">Download the profile</a></p>
<ol>
{copy}<li>Allow the download.</li>
<li>Open <b>Settings</b>, tap <b>Profile Downloaded</b> near the top, then <b>Install</b>, and {type_it}.</li>
</ol>
<p class="small">On a Mac, use the certificate file instead.</p>
"#,
        stem = escape(&payload.stem),
    );
    let p12 = format!(
        r#"<h2>Android or a computer</h2>
<p><a class="button" href="/d/{id}/{stem}.p12">Download the certificate</a></p>
<ol>
<li>Android: open the file, or go to <b>Settings › Security › Encryption &amp; credentials › Install a certificate › VPN &amp; app user certificate</b>, and type the password.</li>
<li>Firefox: <b>Settings › Privacy &amp; Security › View Certificates › Your Certificates › Import</b>.</li>
<li>Chrome, Edge: <b>Settings › Privacy and security › Security › Manage certificates</b>, then import the file into <b>Your certificates</b> (on Windows and macOS, opening the file does the same).</li>
<li>Windows, macOS: open the file and type the password.</li>
</ol>
"#,
        stem = escape(&payload.stem),
    );
    let (first, second) = if apple {
        (profile, p12)
    } else {
        (p12, profile)
    };
    let check = match &payload.check {
        Some(site) => format!(
            r#"<h2>Check that it works</h2>
<p>Once it is installed, open the site. When the browser asks which certificate to use, choose the one from <b>{ca}</b>.</p>
<p><a class="button" href="{site}" target="_blank" rel="noopener noreferrer">Open {shown}</a></p>
<p class="small">If the site opens, the certificate works. If you see an error page instead - “400 Bad Request”, or “No required SSL certificate was sent” - it is not installed yet.</p>
"#,
            ca = escape(&payload.ca),
            site = escape(site),
            shown = escape(site.trim_start_matches("https://").trim_end_matches('/')),
        ),
        None => String::new(),
    };
    let password = match &payload.password {
        Some(password) => format!(
            r#"<p>The certificate's password:</p>
<p class="password"><code>{}</code></p>
<p class="small">Installing it asks for this password. Tap it to select all of it, to copy.</p>"#,
            escape(password)
        ),
        None => r#"<p>Installing it asks for a <b>password</b>, which is not on this page: whoever sent you the link sends it to you another way. Ask them if you do not have it yet.</p>"#
            .to_owned(),
    };
    format!(
        r#"<h1>{holder}</h1>
{password}
{first}{second}{check}<p class="small">These links work for ten minutes; this page can be opened again until then.</p>"#,
        holder = escape(&payload.holder),
    )
}

fn html(status: u16, title: &str, body: &str) -> Reply {
    let page = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 17px/1.5 system-ui, sans-serif; max-width: 34em; margin: 2em auto; padding: 0 1em; color: #222; background: #fff; }}
h1 {{ font-size: 1.4em; }} h2 {{ font-size: 1.1em; margin-top: 2em; }}
button, a.button {{ display: inline-block; font: inherit; padding: .7em 1.4em; border-radius: .5em; border: 0; background: #1f5fbf; color: #fff; text-decoration: none; }}
code {{ font-size: 1.2em; background: #eee; padding: .2em .4em; border-radius: .3em; }}
.small {{ color: #666; font-size: .9em; }}
.password code {{ font-size: 1.6em; letter-spacing: .08em; user-select: all; -webkit-user-select: all; word-break: break-all; }}
@media (prefers-color-scheme: dark) {{ body {{ background: #161616; color: #ddd; }} code {{ background: #333; }} .small {{ color: #999; }} }}
</style></head>
<body>
{body}
</body></html>
"#,
        title = escape(title)
    );
    Reply {
        status,
        content_type: "text/html; charset=utf-8",
        body: page.into_bytes(),
        attachment: None,
        location: None,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests;
