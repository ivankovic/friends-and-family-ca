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
//! `ffca serve`: the enrollment page, where an invite's link leads.
//!
//! It is given the invites folder and nothing else: no key, no ledger. Behind nginx, on the
//! enrollment site, which never asks for a client certificate.
//!
//! * `GET /i/<token>` shows whose certificate it is and a button. Opening the link does not use
//!   it up: chat apps fetch links to preview them, and that must not spend an invite.
//! * `POST /i/<token>` - the button - collects the invite (`crate::invite::collect`) and shows how
//!   to install it: a profile for iPhone and iPad, a `.p12` for everything else, and the password
//!   both ask for while installing.
//!   The two files are kept in memory for [`DOWNLOAD_WINDOW`], under a random address of their
//!   own, so that the person can try both, or again, without a second invite.
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
}

/// The page's state: the files of invites collected in the last [`DOWNLOAD_WINDOW`].
pub struct Page {
    folder: PathBuf,
    downloads: HashMap<String, (Payload, OffsetDateTime)>,
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
        self.downloads.retain(|_, (_, until)| *until > now);
        let segments = route(path);
        let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
        match (method, parts.as_slice()) {
            ("GET", ["healthz"]) => Reply {
                status: 200,
                content_type: "text/plain",
                body: b"ok\n".to_vec(),
                attachment: None,
            },
            ("GET", []) => html(
                200,
                "Friends and Family CA",
                "<h1>Friends and Family CA</h1><p>Invites are collected here, by their own links.</p>",
            ),
            ("GET", ["i", token]) => match invite::open(&self.folder, token, now) {
                Ok(payload) => html(200, &payload.holder, &invitation(token, &payload)),
                Err(unavailable) => unavailable_page(unavailable),
            },
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
                        let body = installation(&id, &payload);
                        let title = payload.holder.clone();
                        let until = now.checked_add(DOWNLOAD_WINDOW).unwrap_or(now);
                        self.downloads.insert(id, (payload, until));
                        html(200, &title, &body)
                    }
                    Err(unavailable) => unavailable_page(unavailable),
                }
            }
            ("GET", ["d", id, file]) => match self.downloads.get(*id) {
                Some((payload, _)) if *file == format!("{}.mobileconfig", payload.stem) => Reply {
                    status: 200,
                    content_type: "application/x-apple-aspen-config",
                    body: payload.mobileconfig.clone(),
                    attachment: Some(file.to_string()),
                },
                Some((payload, _)) if *file == format!("{}.p12", payload.stem) => Reply {
                    status: 200,
                    content_type: "application/x-pkcs12",
                    body: payload.p12.clone(),
                    attachment: Some(file.to_string()),
                },
                _ => html(
                    404,
                    "Gone",
                    "<h1>This download is over</h1><p>Its files are kept for ten minutes after the button is pressed. Ask for a new invite.</p>",
                ),
            },
            _ => html(404, "Not found", "<h1>Nothing here</h1>"),
        }
    }
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
    let reply = page.lock().unwrap_or_else(|p| p.into_inner()).answer(
        &request.method,
        &request.target,
        &format!("{address}, {device}"),
        now,
    );
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
    http::Response {
        status: reply.status,
        headers,
        body: reply.body,
    }
}

/// Where a request comes from: the address nginx gives in `X-Real-IP`, or, without one that is an
/// address, the connection's own.
fn client_address(request: &http::Request) -> IpAddr {
    request
        .header("X-Real-IP")
        .and_then(|a| a.parse().ok())
        .unwrap_or(request.peer.ip())
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
            "<h1>This invite has been used or cancelled</h1><p>Each invite works once. If you did not use it yourself, tell whoever sent it to you: someone else may have.</p>",
        ),
    }
}

fn invitation(token: &str, payload: &Payload) -> String {
    format!(
        r#"<h1>A certificate for {holder}</h1>
<p>From <b>{ca}</b>. It lets this device into the sites that ask for one.</p>
<p>Open this page on the device that should have it. The button uses the invite up: it works once.</p>
<form method="post" action="/i/{token}"><button type="submit">Get the certificate</button></form>"#,
        holder = escape(&payload.holder),
        ca = escape(&payload.ca),
    )
}

fn installation(id: &str, payload: &Payload) -> String {
    format!(
        r#"<h1>{holder}</h1>
<p>The certificate's password: <code>{password}</code></p>
<p class="small">Installing it asks for this password.</p>
<h2>iPhone or iPad</h2>
<p><a class="button" href="/d/{id}/{stem}.mobileconfig">Download the profile</a></p>
<ol>
<li>Allow the download.</li>
<li>Open <b>Settings</b>, tap <b>Profile Downloaded</b> near the top, then <b>Install</b>, and type the password when it asks.</li>
</ol>
<h2>Android, Boox, a computer</h2>
<p><a class="button" href="/d/{id}/{stem}.p12">Download the certificate</a></p>
<ol>
<li>Android: open the file, or go to <b>Settings › Security › Encryption &amp; credentials › Install a certificate › VPN &amp; app user certificate</b>, and type the password.</li>
<li>Firefox: <b>Settings › Privacy &amp; Security › View Certificates › Your Certificates › Import</b>.</li>
<li>Windows, macOS: open the file and type the password.</li>
</ol>
<p class="small">These links work for ten minutes. Keep this page open until the certificate is installed.</p>"#,
        holder = escape(&payload.holder),
        stem = escape(&payload.stem),
        password = escape(&payload.password),
    )
}

fn html(status: u16, title: &str, body: &str) -> Reply {
    let page = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{ font: 17px/1.5 system-ui, sans-serif; max-width: 34em; margin: 2em auto; padding: 0 1em; color: #222; background: #fff; }}
h1 {{ font-size: 1.4em; }} h2 {{ font-size: 1.1em; margin-top: 2em; }}
button, a.button {{ display: inline-block; font: inherit; padding: .7em 1.4em; border-radius: .5em; border: 0; background: #1f5fbf; color: #fff; text-decoration: none; }}
code {{ font-size: 1.2em; background: #eee; padding: .2em .4em; border-radius: .3em; }}
.small {{ color: #666; font-size: .9em; }}
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
