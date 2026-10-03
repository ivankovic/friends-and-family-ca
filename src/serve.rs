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
//!   to install it: a profile for iPhone and iPad, a `.p12` and its password for everything else.
//!   The two files are kept in memory for [`DOWNLOAD_WINDOW`], under a random address of their
//!   own, so that the person can try both, or again, without a second invite.
//! * `GET /d/<id>/<file>` serves them.
//!
//! Every answer forbids caching and referrers - the token is in the address - and the page has no
//! scripts. Requests are logged without their tokens.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
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
        let parts: Vec<&str> = path
            .split('?')
            .next()
            .unwrap_or("")
            .trim_matches('/')
            .split('/')
            .collect();
        match (method, parts.as_slice()) {
            ("GET", ["healthz"]) => Reply {
                status: 200,
                content_type: "text/plain",
                body: b"ok\n".to_vec(),
                attachment: None,
            },
            ("GET", [""]) => html(
                200,
                "Friends and Family CA",
                "<h1>Friends and Family CA</h1><p>Invites are collected here, by their own links.</p>",
            ),
            ("GET", ["i", token]) => match invite::open(&self.folder, token, now) {
                Ok(payload) => html(200, &payload.holder, &invitation(token, &payload)),
                Err(unavailable) => unavailable_page(unavailable),
            },
            ("POST", ["i", token]) => match invite::collect(&self.folder, token, now, client) {
                Ok(payload) => {
                    let id = random_id();
                    let body = installation(&id, &payload);
                    let title = payload.holder.clone();
                    self.downloads.insert(id, (payload, now + DOWNLOAD_WINDOW));
                    html(200, &title, &body)
                }
                Err(unavailable) => unavailable_page(unavailable),
            },
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
    let server =
        tiny_http::Server::http(listen).map_err(|e| anyhow!("cannot listen on {listen}: {e}"))?;
    eprintln!(
        "ffca serve: listening on {listen}, invites in {}",
        folder.display()
    );
    let mut page = Page::new(folder);
    for mut request in server.incoming_requests() {
        let method = request.method().as_str().to_owned();
        let path = request.url().to_owned();
        let header = |name: &str| {
            request
                .headers()
                .iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_owned())
        };
        let address = header("X-Real-IP")
            .or_else(|| request.remote_addr().map(|a| a.ip().to_string()))
            .unwrap_or_default();
        let device = device(&header("User-Agent").unwrap_or_default());
        // The button's form has no fields; whatever came is read and dropped.
        let _ = std::io::copy(
            &mut request.as_reader().take(64 * 1024),
            &mut std::io::sink(),
        );
        let reply = page.answer(
            &method,
            &path,
            &format!("{address}, {device}"),
            OffsetDateTime::now_utc(),
        );
        eprintln!(
            "{method} {} {} ({address}, {device})",
            redact(&path),
            reply.status
        );
        let mut response =
            tiny_http::Response::from_data(reply.body).with_status_code(reply.status);
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
            headers.push((
                "Content-Disposition",
                format!("attachment; filename=\"{name}\""),
            ));
        }
        for (name, value) in headers {
            if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                response = response.with_header(header);
            }
        }
        if let Err(error) = request.respond(response) {
            eprintln!("ffca serve: cannot answer: {error}");
        }
    }
    Ok(())
}

/// A path as the log shows it: tokens and download addresses left out.
fn redact(path: &str) -> String {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["i", _] => "/i/…".to_owned(),
        ["d", _, file] => format!("/d/…/{file}"),
        _ => path.to_owned(),
    }
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

fn random_id() -> String {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("randomness");
    URL_SAFE_NO_PAD.encode(bytes)
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
<h2>iPhone or iPad</h2>
<p><a class="button" href="/d/{id}/{stem}.mobileconfig">Download the profile</a></p>
<ol>
<li>Allow the download.</li>
<li>Open <b>Settings</b>, tap <b>Profile Downloaded</b> near the top, then <b>Install</b>.</li>
</ol>
<h2>Android, Boox, a computer</h2>
<p><a class="button" href="/d/{id}/{stem}.p12">Download the certificate</a></p>
<p>Its password: <code>{password}</code></p>
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
