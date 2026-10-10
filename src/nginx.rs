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
//! nginx: which sites ask for a client certificate, and changing that safely.
//!
//! A site is a `server` block that listens with `ssl`, in a `*.conf` file of the folder the
//! settings name. Its mode is its `ssl_verify_client`: `on` is required; `optional` lets a visitor
//! without a certificate in but still refuses a bad one - revoked, expired, another CA's - so a
//! lost phone stays out even there. ffca never writes `optional_no_ca`, which also lets in a
//! certificate from any issuer; a site written that way by hand reads as optional, and is marked.
//! So is a site whose name another block on the same address also claims: nginx serves one of the
//! two and ignores the other, whatever either says.
//!
//! ffca writes its three lines in a block of its own, inside the `server` block, after its
//! `server_name`:
//!
//! ```nginx
//!     # BEGIN ffca - client certificates, managed by Friends and Family CA
//!     ssl_client_certificate /etc/nginx/certs/ffca-ca.crt;
//!     ssl_crl /etc/nginx/certs/ffca.crl;
//!     ssl_verify_client on;
//!     # END ffca
//! ```
//!
//! Any other `ssl_client_certificate`, `ssl_crl` or `ssl_verify_client` directly in that block
//! would clash with these, so ffca comments it out, marked `# ffca: `; turning a site off comments
//! out only a `ssl_verify_client` of its own, the line that makes nginx ask. It changes nothing
//! else, and it refuses - rather than guesses - when a line it would comment out holds another
//! directive too, when its block holds anything but its own lines, or when the `server` block is
//! written on one line. Before anything is written, the changed file is read back and compared
//! with the original: every statement but ffca's three must be as it was, and the site must ask
//! as it was told to.
//!
//! The configuration is read with a parser that follows nginx's own rules for words, quoted
//! strings, escapes, comments and `${variable}`, not with patterns over lines: the stop-bots
//! blocks at the top of every site are `if` blocks full of quoted regular expressions and closing
//! braces, and a parser that reads a line differently from nginx would report a site as asking
//! for a certificate while nginx does not.
//!
//! Every change is checked with the settings' test command (`nginx -t`) before nginx reloads; if
//! the test fails, the file is put back as it was and nothing reloads. nginx reads the CA's
//! certificate and CRL from copies ffca keeps in a folder nginx can see, refreshed before every
//! test and reload: the state folder holds the CA's key and stays its owner's only.
//!
//! ffca runs as root, so it writes only into folders that nobody but root (or the CA's owner, where
//! that is not root) can change: a folder another user could write is one where they could swap a
//! site for a link to any file, and have root write into that, or put their own CA where nginx
//! reads this one's.

use std::fmt;
use std::fs;
use std::io::Read;
use std::ops::RangeInclusive;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::ca::{self, Ca};
use crate::config;
use crate::store::{PUBLIC, Store};

/// The CA's certificate, as nginx reads it.
pub const CA_FILE: &str = "ffca-ca.crt";
/// The CA's revocation list, as nginx reads it.
pub const CRL_FILE: &str = "ffca.crl";
const BEGIN: &str = "# BEGIN ffca";
const END: &str = "# END ffca";
const DISABLED: &str = "# ffca: ";
const MANAGED: [&str; 3] = ["ssl_client_certificate", "ssl_crl", "ssl_verify_client"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No client certificate asked for.
    Off,
    /// Asked for; a visitor without one gets in, a bad one is refused.
    Optional,
    /// Required: without a valid certificate from this CA, nobody gets in.
    Required,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Off, Mode::Optional, Mode::Required];

    fn value(self) -> Option<&'static str> {
        match self {
            Mode::Off => None,
            Mode::Optional => Some("optional"),
            Mode::Required => Some("on"),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Off => "off",
            Mode::Optional => "optional",
            Mode::Required => "required",
        })
    }
}

/// One HTTPS `server` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub file: PathBuf,
    /// Which `server` block of the file, counting every one, in order.
    pub index: usize,
    pub names: Vec<String>,
    pub mode: Mode,
    /// Whether its `ssl_client_certificate` is this CA's.
    pub uses_ca: bool,
    /// Whether it says `optional_no_ca`: any issuer's certificate gets in.
    pub any_issuer: bool,
    /// The addresses it listens on, as nginx groups servers: `443` is `*:443`.
    pub listens: Vec<String>,
    /// Whether another site in the folder has one of its names on one of its addresses. nginx
    /// serves the one it reads first and ignores the other, so what the other says does not count.
    pub duplicate: bool,
}

impl Site {
    pub fn name(&self) -> &str {
        self.names.first().map_or("_", String::as_str)
    }

    pub fn file_name(&self) -> String {
        self.file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }

    pub fn serves(&self, host: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(host))
    }

    /// The (name, address) pairs nginx chooses this server by.
    fn keys(&self) -> impl Iterator<Item = (String, &str)> {
        self.names
            .iter()
            .filter(|n| !n.is_empty() && *n != "_")
            .flat_map(|n| {
                self.listens
                    .iter()
                    .map(move |l| (n.to_ascii_lowercase(), l.as_str()))
            })
    }
}

/// The sites in the folder, and the files that could not be read as nginx configuration.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Survey {
    pub sites: Vec<Site>,
    pub problems: Vec<String>,
}

/// Every site in `nginx.sites`, in file-name order.
pub fn survey(nginx: &config::Nginx) -> Result<Survey> {
    let mut files: Vec<PathBuf> = fs::read_dir(&nginx.sites)
        .with_context(|| format!("cannot read {}", nginx.sites.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "conf") && path.is_file())
        .collect();
    files.sort();
    let mut survey = Survey::default();
    for file in files {
        match fs::read_to_string(&file)
            .map_err(anyhow::Error::from)
            .and_then(|text| sites_in(&file, &text, nginx))
        {
            Ok(sites) => survey.sites.extend(sites),
            Err(error) => survey
                .problems
                .push(format!("{}: {error:#}", file.display())),
        }
    }
    let duplicates: Vec<bool> = survey
        .sites
        .iter()
        .enumerate()
        .map(|(i, site)| {
            site.keys().any(|key| {
                survey
                    .sites
                    .iter()
                    .enumerate()
                    .any(|(j, other)| j != i && other.keys().any(|k| k == key))
            })
        })
        .collect();
    for (site, duplicate) in survey.sites.iter_mut().zip(duplicates) {
        site.duplicate = duplicate;
    }
    Ok(survey)
}

fn sites_in(file: &Path, text: &str, nginx: &config::Nginx) -> Result<Vec<Site>> {
    let config = Parsed::new(text)?;
    let ca_path = nginx.ca_files_in_nginx.join(CA_FILE).display().to_string();
    let mut sites = Vec::new();
    for (index, server) in config.servers().into_iter().enumerate() {
        let children = server.block.as_deref().unwrap_or_default();
        let directive = |name: &'static str| directives(children, name);
        let tls = directive("listen").any(|l| l.args.iter().any(|a| a == "ssl"));
        if !tls {
            continue;
        }
        let mode = match directive("ssl_verify_client")
            .last()
            .and_then(|d| d.args.first())
        {
            Some(value) if value == "on" => Mode::Required,
            Some(value) if value.starts_with("optional") => Mode::Optional,
            _ => Mode::Off,
        };
        sites.push(Site {
            file: file.to_owned(),
            index,
            names: directive("server_name")
                .flat_map(|d| d.args.clone())
                .collect(),
            mode,
            uses_ca: directive("ssl_client_certificate")
                .last()
                .is_some_and(|d| d.args.first() == Some(&ca_path)),
            any_issuer: directive("ssl_verify_client")
                .last()
                .is_some_and(|d| d.args.first().is_some_and(|v| v == "optional_no_ca")),
            listens: directive("listen")
                .filter_map(|d| d.args.first())
                .map(|a| listen_address(a))
                .collect(),
            duplicate: false,
        });
    }
    Ok(sites)
}

/// A `listen` address as nginx groups servers by it: `443`, `*:443` and `0.0.0.0:443` are one.
fn listen_address(address: &str) -> String {
    if address.starts_with("unix:") {
        return address.to_owned();
    }
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (host, port),
        _ if address.bytes().all(|b| b.is_ascii_digit()) => ("*", address),
        _ => (address, "80"),
    };
    let host = if host == "0.0.0.0" { "*" } else { host };
    format!("{}:{port}", host.to_ascii_lowercase())
}

/// `text` with site `index` set to `mode`: see the module documentation for what changes.
pub fn plan(text: &str, index: usize, mode: Mode, nginx: &config::Nginx) -> Result<String> {
    let parsed = Parsed::new(text)?;
    let servers = parsed.servers();
    let server = *servers
        .get(index)
        .with_context(|| format!("there is no server block number {}", index + 1))?;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let regions = parsed.regions(server, &lines)?;
    let in_region = |line: usize| regions.iter().any(|r| r.contains(&line));

    let children = server.block.as_deref().unwrap_or_default();
    // Asking for a certificate, ffca's lines would clash with any others; turning it off, only a
    // `ssl_verify_client` still asks, and the rest can stay as they are.
    let clashing: &[&str] = match mode {
        Mode::Off => &["ssl_verify_client"],
        Mode::Optional | Mode::Required => &MANAGED,
    };
    let mut disable = Vec::new();
    for child in children {
        if child.block.is_some()
            || !clashing.contains(&child.name.as_str())
            || in_region(child.first_line)
        {
            continue;
        }
        ensure!(
            parsed.alone(child),
            "line {} holds more than `{}`; change it by hand",
            child.first_line + 1,
            child.name
        );
        disable.extend(child.first_line..=child.last_line);
    }

    // The block goes on lines of its own: after the last `server_name` that ends its line, else
    // after the `{` that opens the server, else before the `}` that closes it. Anywhere else it
    // could land outside the server, and ask every site at once.
    let open = server.tokens.end - 1;
    let anchor = children
        .iter()
        .filter(|c| {
            c.block.is_none()
                && c.name == "server_name"
                && !in_region(c.first_line)
                && parsed.ends_its_line(c.tokens.end - 1)
        })
        .map(|c| c.last_line)
        .next_back();
    let (at, indent) = match anchor {
        Some(line) => (line + 1, indentation(lines[line]).to_owned()),
        None if parsed.ends_its_line(open) => (
            server.last_line + 1,
            format!("{}    ", indentation(lines[server.first_line])),
        ),
        None if parsed.starts_its_line(server.close_token) => (
            server.close_line,
            format!("{}    ", indentation(lines[server.close_line])),
        ),
        None => bail!(
            "the server block on line {} is written on one line; put its server_name on a line \
             of its own, then try again",
            server.first_line + 1
        ),
    };
    let wanted: Vec<(String, Vec<String>)> = match mode.value() {
        None => Vec::new(),
        Some(value) => {
            let folder = config::checked_folder_in_nginx(&nginx.ca_files_in_nginx)?;
            vec![
                (
                    "ssl_client_certificate".to_owned(),
                    vec![folder.join(CA_FILE).display().to_string()],
                ),
                (
                    "ssl_crl".to_owned(),
                    vec![folder.join(CRL_FILE).display().to_string()],
                ),
                ("ssl_verify_client".to_owned(), vec![value.to_owned()]),
            ]
        }
    };
    let mut block = Vec::new();
    if !wanted.is_empty() {
        block.push("\n".to_owned());
        block.push(format!(
            "{indent}{BEGIN} - client certificates, managed by Friends and Family CA\n"
        ));
        for (name, args) in &wanted {
            block.push(format!("{indent}{name} {};\n", args.join(" ")));
        }
        block.push(format!("{indent}{END}\n"));
    }

    let mut out = String::with_capacity(text.len() + 300);
    for (i, line) in lines.iter().enumerate() {
        if i == at {
            block.iter().for_each(|l| out.push_str(l));
        }
        if in_region(i) {
            continue;
        }
        if disable.contains(&i) {
            let indent = indentation(line);
            out.push_str(indent);
            out.push_str(DISABLED);
            out.push_str(&line[indent.len()..]);
        } else {
            out.push_str(line);
        }
    }
    if at >= lines.len() && !block.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        block.iter().for_each(|l| out.push_str(l));
    }
    check_plan(&parsed, &out, index, &wanted).with_context(|| {
        format!(
            "ffca's change to the server block on line {} would not do only what it should; \
             change it by hand",
            server.first_line + 1
        )
    })?;
    Ok(out)
}

/// Reads `out` back and compares it with `before`: every statement but the target server's own
/// `ssl_client_certificate`, `ssl_crl` and `ssl_verify_client` is as it was, and those are
/// exactly `wanted` - or, turning it off, no `ssl_verify_client` and nothing that was not there.
fn check_plan(
    before: &Parsed,
    out: &str,
    index: usize,
    wanted: &[(String, Vec<String>)],
) -> Result<()> {
    let after = Parsed::new(out).context("it would not read as nginx configuration")?;
    let (mut managed_before, mut managed_after) = (Vec::new(), Vec::new());
    let shape_before = shape(&before.statements, index, &mut 0, &mut managed_before);
    let shape_after = shape(&after.statements, index, &mut 0, &mut managed_after);
    ensure!(
        shape_before == shape_after,
        "it would change more than the client-certificate lines"
    );
    if wanted.is_empty() {
        ensure!(
            managed_after
                .iter()
                .all(|(name, _)| name != "ssl_verify_client"),
            "the server would still ask for a certificate"
        );
        ensure!(
            managed_after.iter().all(|m| managed_before.contains(m)),
            "it would add client-certificate lines"
        );
    } else {
        managed_after.sort();
        let mut wanted = wanted.to_vec();
        wanted.sort();
        ensure!(
            managed_after == wanted,
            "the server would end up with {managed_after:?}"
        );
    }
    let lines: Vec<&str> = out.split_inclusive('\n').collect();
    let server = *after
        .servers()
        .get(index)
        .context("the server block would be gone")?;
    let regions = after.regions(server, &lines)?;
    ensure!(
        regions.len() == usize::from(!wanted.is_empty()),
        "it would leave {} blocks of ffca's",
        regions.len()
    );
    Ok(())
}

/// A statement as nginx acts on it: no lines, no comments.
#[derive(Debug, PartialEq, Eq)]
struct Node {
    name: String,
    args: Vec<String>,
    block: Option<Vec<Node>>,
}

/// `statements` as [`Node`]s, with server block `target`'s own client-certificate directives
/// taken out into `managed`. `seen` counts server blocks, in the order of [`Parsed::servers`].
fn shape(
    statements: &[Statement],
    target: usize,
    seen: &mut usize,
    managed: &mut Vec<(String, Vec<String>)>,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    for statement in statements {
        let block = statement.block.as_ref().map(|block| {
            let this = (statement.name == "server").then(|| {
                *seen += 1;
                *seen - 1
            });
            let mut children = shape(block, target, seen, managed);
            if this == Some(target) {
                children.retain(|child| {
                    let ours = child.block.is_none() && MANAGED.contains(&child.name.as_str());
                    if ours {
                        managed.push((child.name.clone(), child.args.clone()));
                    }
                    !ours
                });
            }
            children
        });
        nodes.push(Node {
            name: statement.name.clone(),
            args: statement.args.clone(),
            block,
        });
    }
    nodes
}

/// The directives called `name` among `statements`, not counting blocks.
fn directives<'a>(
    statements: &'a [Statement],
    name: &'a str,
) -> impl Iterator<Item = &'a Statement> {
    statements
        .iter()
        .filter(move |s| s.block.is_none() && s.name == name)
}

fn indentation(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// Sets `site` to `mode`: writes the file, tests nginx's configuration, reloads. A refused test or
/// reload puts the file back as it was. Returns whether anything changed.
///
/// A site linked into the folder (`sites-enabled/x -> ../sites-available/x`) is changed where the
/// link points, and stays linked. Where that is is settled once, before the file is read: the
/// file read, the one written and the one put back are the same, and if anything else changes it
/// meanwhile, ffca leaves it alone.
pub fn set_mode(nginx: &config::Nginx, ca: &Ca, site: &Site, mode: Mode) -> Result<bool> {
    publish(nginx, ca)?;
    let real = fs::canonicalize(&site.file)
        .with_context(|| format!("cannot find {}", site.file.display()))?;
    check_folder(real.parent().unwrap_or(Path::new("/")), ca)?;
    let (original, id) = read_file(&real)?;
    let now = sites_in(&site.file, &original, nginx)?;
    ensure!(
        now.iter()
            .any(|s| s.index == site.index && s.names == site.names),
        "{} changed since it was read; look again",
        site.file.display()
    );
    let planned = plan(&original, site.index, mode, nginx)?;
    if planned == original {
        return Ok(false);
    }
    let written = replace(&real, id, &original, &planned)?;
    let restore = |what: &str, error: anyhow::Error| -> anyhow::Error {
        match replace(&real, written, &planned, &original) {
            Ok(_) => anyhow!(
                "{what}, so {} is back as it was:\n{error:#}",
                site.file.display()
            ),
            Err(also) => anyhow!(
                "{what}, and putting {} back failed too ({also:#}):\n{error:#}",
                site.file.display()
            ),
        }
    };
    let tested = match run(&nginx.test) {
        Ok(printed) => printed,
        Err(error) => return Err(restore("nginx refused the change", error)),
    };
    if mode != Mode::Off
        && let Some(name) = conflicting(&tested, &site.names)
    {
        return Err(restore(
            &format!("nginx has two server blocks for {name} and ignores one of them"),
            anyhow!(
                "remove or rename the other, then try again; nginx said:\n{}",
                tested.trim_end()
            ),
        ));
    }
    if let Err(error) = run(&nginx.reload) {
        let error = restore("nginx did not reload", error);
        let _ = run(&nginx.reload);
        return Err(error);
    }
    Ok(true)
}

/// The first of `names` that nginx's test output says another server block also claims.
fn conflicting<'a>(printed: &str, names: &'a [String]) -> Option<&'a str> {
    printed
        .lines()
        .filter_map(|line| line.split_once("conflicting server name \""))
        .filter_map(|(_, rest)| rest.split_once('"').map(|(name, _)| name))
        .find_map(|claimed| {
            names
                .iter()
                .find(|n| n.eq_ignore_ascii_case(claimed))
                .map(String::as_str)
        })
}

/// The enrollment site's file, in the sites folder.
pub const ENROLLMENT_FILE: &str = "ffca-enrollment.conf";
const ENROLLMENT_MARK: &str = "# Written by Friends and Family CA: the enrollment page";

/// The enrollment site's configuration: a `server` for `enrollment.host` that forwards to
/// `enrollment.upstream` and never asks for a client certificate. Its `listen`, TLS certificate
/// and `include`s are copied from a site on the same domain - `k.example.org` takes them from
/// `cloud.example.org` - which also says which certificate covers the name. Returns the file and
/// its text.
///
/// Nothing on the site is in the access log. Invite links (`/i/<token>`, `/d/<id>/...`) carry
/// their secret in the path, and a shared access log is read by more than the administrator (bot
/// detectors, log shippers). Turning the log off for those paths alone is not enough: a request
/// turned away before nginx picks a location - by a bot filter's `return` at the top of the
/// server, which turns away chat apps fetching a link to preview it - is logged by the server's
/// own settings. Errors are logged as the includes say, except under the invite paths.
///
/// Blocks another tool marked in the file it rewrites - `# BEGIN stop-bots ... # END stop-bots` -
/// are kept, at the top of the `server` block, where stop-bots puts its own.
pub fn enrollment_site(
    nginx: &config::Nginx,
    enrollment: &config::Enrollment,
) -> Result<(PathBuf, String)> {
    let host = config::checked_host(&enrollment.host)?;
    let domain = host.split_once('.').map_or(host.as_str(), |(_, d)| d);
    let survey = survey(nginx)?;
    let template = survey
        .sites
        .iter()
        .find(|site| {
            site.file_name() != ENROLLMENT_FILE
                && site
                    .names
                    .iter()
                    .any(|n| n == domain || n.ends_with(&format!(".{domain}")))
        })
        .with_context(|| {
            format!(
                "no site in {} is on {domain}, to copy its TLS certificate from",
                nginx.sites.display()
            )
        })?;
    let text = fs::read_to_string(&template.file)?;
    let parsed = Parsed::new(&text)?;
    let server = parsed.servers()[template.index];
    let children = server.block.as_deref().unwrap_or_default();
    let mut copied = Vec::new();
    for child in children.iter().filter(|c| c.block.is_none()) {
        let args: Vec<String> = match child.name.as_str() {
            // One `default_server` and one `reuseport` per address: they stay with their site.
            "listen" => child
                .args
                .iter()
                .filter(|a| !matches!(a.as_str(), "default_server" | "default" | "reuseport"))
                .cloned()
                .collect(),
            "http2" | "ssl_certificate" | "ssl_certificate_key" | "include" => child.args.clone(),
            _ => continue,
        };
        copied.push(format!(
            "    {} {};",
            child.name,
            args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
        ));
    }
    ensure!(
        copied
            .iter()
            .any(|l| l.trim_start().starts_with("ssl_certificate ")),
        "{} has no ssl_certificate of its own to copy",
        template.file.display()
    );
    let upstream = config::checked_upstream(&enrollment.upstream)?;
    let address = upstream.trim_start_matches("http://");
    let host_part = address
        .rsplit_once(':')
        .map_or(address, |(h, _)| h)
        .trim_matches(['[', ']']);
    let literal = host_part == "localhost" || host_part.parse::<std::net::IpAddr>().is_ok();
    let file = nginx.sites.join(ENROLLMENT_FILE);
    // Blocks other tools wrote into the site - stop-bots' bot filter - stay when ffca rewrites it.
    let kept = match fs::read_to_string(&file) {
        Ok(existing) if existing.starts_with(ENROLLMENT_MARK) => foreign_blocks(&existing),
        _ => Vec::new(),
    };
    let proxy = |lines: &mut Vec<String>| {
        lines.push(format!(
            "        proxy_pass {};",
            if literal {
                upstream.as_str()
            } else {
                "$ffca_enrollment"
            }
        ));
        lines.push("        proxy_set_header Host $host;".to_owned());
        lines.push("        proxy_set_header X-Real-IP $remote_addr;".to_owned());
    };
    // A file name is the one thing here no check has seen; it goes into a comment, on one line.
    let template_name: String = template
        .file_name()
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let mut lines = vec![
        format!("{ENROLLMENT_MARK}, where invites are collected."),
        "# It never asks for a client certificate: whoever opens an invite has none yet. Its listen,".to_owned(),
        format!("# TLS certificate and includes are copied from {template_name}."),
        "server {".to_owned(),
    ];
    for block in &kept {
        lines.extend(block.iter().cloned());
        lines.push(String::new());
    }
    lines.extend(copied);
    lines.push(format!("    server_name {host};"));
    lines.push("    ssl_verify_client off;".to_owned());
    lines.push(String::new());
    lines.push(
        "    # An invite's link carries its secret, and a request turned away before it reaches a"
            .to_owned(),
    );
    lines.push(
        "    # location - by a bot filter, say - is logged here: nothing on this site is."
            .to_owned(),
    );
    lines.push("    access_log off;".to_owned());
    lines.push(String::new());
    if !literal {
        lines.push("    # Looked up when a request comes (Docker's DNS), so that nginx starts while the page is down.".to_owned());
        lines.push("    resolver 127.0.0.11 valid=30s ipv6=off;".to_owned());
        lines.push(format!("    set $ffca_enrollment {upstream};"));
        lines.push(String::new());
    }
    lines.push("    location / {".to_owned());
    proxy(&mut lines);
    lines.push("    }".to_owned());
    lines.push(String::new());
    lines.push(
        "    # nginx names the request in an error too - the page being down, say.".to_owned(),
    );
    lines.push("    location ~ ^/(i|d)/ {".to_owned());
    lines.push("        error_log /dev/null crit;".to_owned());
    proxy(&mut lines);
    lines.push("    }".to_owned());
    lines.push("}".to_owned());
    let site = lines.join("\n") + "\n";
    Ok((file, site))
}

/// The blocks of `text` that another tool marked as its own - `# BEGIN <tool> ...` to
/// `# END <tool>`, stop-bots' among them - with their lines as they are. A block without its end
/// is not kept, and the lines after its start are still looked through.
fn foreign_blocks(text: &str) -> Vec<Vec<String>> {
    let lines: Vec<&str> = text.lines().collect();
    let marker = |line: &str, kind: &str| -> Option<String> {
        let rest = line.trim_start().strip_prefix(kind)?;
        rest.split_whitespace().next().map(str::to_owned)
    };
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        i += 1;
        let Some(tool) = marker(lines[start], "# BEGIN ") else {
            continue;
        };
        if tool == "ffca" {
            continue;
        }
        if let Some(end) =
            (i..lines.len()).find(|&j| marker(lines[j], "# END ").as_ref() == Some(&tool))
        {
            blocks.push(lines[start..=end].iter().map(|l| (*l).to_owned()).collect());
            i = end + 1;
        }
    }
    blocks
}

/// Writes the enrollment site, tests nginx's configuration and reloads; a refusal leaves the
/// sites folder as it was. Only ever writes over a file that ffca wrote.
pub fn write_enrollment_site(
    nginx: &config::Nginx,
    ca: &Ca,
    file: &Path,
    text: &str,
) -> Result<()> {
    publish(nginx, ca)?;
    let folder = file.parent().unwrap_or(Path::new("."));
    check_folder(folder, ca)?;
    let before = match read_file(file) {
        Ok((existing, _)) if existing.starts_with(ENROLLMENT_MARK) => Some(existing),
        Ok(_) => bail!(
            "{} exists and is not ffca's; move it away first",
            file.display()
        ),
        Err(error) if not_found(&error) => None,
        Err(error) => {
            return Err(error.context(format!(
                "{} exists and ffca cannot read it as its own; move it away first",
                file.display()
            )));
        }
    };
    Store::new(folder).write(
        &file.file_name().unwrap_or_default().to_string_lossy(),
        text.as_bytes(),
        PUBLIC,
    )?;
    let restore = || -> Result<()> {
        let (now, id) = read_file(file)?;
        ensure!(
            now == text,
            "{} changed meanwhile; it is left as it is",
            file.display()
        );
        match &before {
            Some(existing) => replace(file, id, text, existing).map(|_| ()),
            None => fs::remove_file(file).map_err(anyhow::Error::from),
        }
    };
    if let Err(error) = run(&nginx.test) {
        let _ = restore();
        bail!("nginx refused the enrollment site, so it is not written:\n{error:#}");
    }
    if let Err(error) = run(&nginx.reload) {
        let _ = restore();
        let _ = run(&nginx.reload);
        bail!("nginx did not reload, so the enrollment site is not written:\n{error:#}");
    }
    Ok(())
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// An argument as nginx reads it back: quoted, and escaped, if it holds anything nginx would read
/// as more than its text.
fn quote(argument: &str) -> String {
    if argument.is_empty()
        || argument
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "{};#'\"\\".contains(c))
    {
        let mut quoted = String::from("\"");
        for c in argument.chars() {
            match c {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                '\n' => quoted.push_str("\\n"),
                '\r' => quoted.push_str("\\r"),
                '\t' => quoted.push_str("\\t"),
                c => quoted.push(c),
            }
        }
        quoted.push('"');
        quoted
    } else {
        argument.to_owned()
    }
}

/// Copies the CA's certificate and CRL to where nginx reads them. Each is replaced by a rename -
/// a new file, never one written over - because nginx 1.27.4 and later keep a CRL across a reload
/// when its file looks unchanged (same inode, size and modification time): an empty CRL re-signed
/// within the same second would be all three, and nginx would go on refusing every client with the
/// expired one. The folder must be mounted into nginx's container as a folder, not file by file,
/// for a rename to reach it.
///
/// Whoever could write that folder could put their own CA in it, and every site would let their
/// certificates in: it is made readable by all and writable by its owner only, and a folder
/// anyone but root or the CA's owner could change is refused.
pub fn publish(nginx: &config::Nginx, ca: &Ca) -> Result<()> {
    if !nginx.ca_files.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&nginx.ca_files)
            .with_context(|| format!("cannot create {}", nginx.ca_files.display()))?;
        // The mode above went through the umask.
        fs::set_permissions(&nginx.ca_files, fs::Permissions::from_mode(0o755))?;
    }
    check_folder(&nginx.ca_files, ca)?;
    let target = Store::new(&nginx.ca_files);
    let source = ca.store();
    target.write(
        CA_FILE,
        source.read(ca::CERTIFICATE_FILE)?.as_bytes(),
        PUBLIC,
    )?;
    target.write(CRL_FILE, source.read(ca::CRL_FILE)?.as_bytes(), PUBLIC)
}

/// Refuses a folder that someone other than root and the CA's owner could change: its owner, or
/// anyone at all if its group or everyone may write it.
fn check_folder(folder: &Path, ca: &Ca) -> Result<()> {
    let metadata =
        fs::metadata(folder).with_context(|| format!("cannot read {}", folder.display()))?;
    let owner = fs::metadata(ca.store().dir())?.uid();
    ensure!(metadata.is_dir(), "{} is not a folder", folder.display());
    ensure!(
        metadata.uid() == 0 || metadata.uid() == owner,
        "{} belongs to user {}, who could change what nginx reads in it; give it to root",
        folder.display(),
        metadata.uid()
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "{} can be changed by others than its owner (mode {:o}), who could change what nginx \
         reads in it; `chmod go-w` it",
        folder.display(),
        metadata.mode() & 0o7777
    );
    Ok(())
}

/// Publishes the CA's files and reloads nginx, after testing its configuration: what a new CRL
/// needs before nginx refuses what it revokes.
pub fn publish_and_reload(nginx: &config::Nginx, ca: &Ca) -> Result<()> {
    publish(nginx, ca)?;
    run(&nginx.test)?;
    run(&nginx.reload).map(|_| ())
}

/// Runs a settings command - a program and its arguments, split at spaces - and returns what it
/// printed; an error carries that too.
pub fn run(command: &str) -> Result<String> {
    let mut words = command.split_whitespace();
    let program = words.next().context("the command is empty")?;
    let output = Command::new(program)
        .args(words)
        .output()
        .with_context(|| format!("cannot run `{command}`"))?;
    let printed = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(printed)
    } else {
        bail!(
            "`{command}` failed ({}):\n{}",
            output.status,
            printed.trim_end()
        )
    }
}

/// A file's identity: its device and inode.
type FileId = (u64, u64);

/// The text of the file at `path`, which must be a file and not a link, and its identity.
fn read_file(path: &Path) -> Result<(String, FileId)> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "{} is not a file", path.display());
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok((text, (metadata.dev(), metadata.ino())))
}

/// Writes `text` over the file at `path` - a file, not a link - keeping its owner and
/// permissions, through a temporary file and a rename; but only while it is still the file `id`,
/// holding `expected`. Returns the new file's identity.
fn replace(path: &Path, id: FileId, expected: &str, text: &str) -> Result<FileId> {
    let (now, now_id) = read_file(path)?;
    ensure!(
        now_id == id && now == expected,
        "{} changed while ffca was changing it; it is left as it is now",
        path.display()
    );
    let metadata = fs::symlink_metadata(path)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    Store::new(dir).write_owned(
        &name,
        text.as_bytes(),
        metadata.permissions().mode() & 0o7777,
        Some((metadata.uid(), metadata.gid())),
    )?;
    let written = fs::symlink_metadata(path)?;
    Ok((written.dev(), written.ino()))
}

/// nginx's configuration as statements: a directive ends with `;`, a block is `{ ... }`.
#[derive(Debug, Clone)]
struct Statement {
    name: String,
    args: Vec<String>,
    /// Lines, from 0: where its first word is, and its `;` or `{`.
    first_line: usize,
    last_line: usize,
    /// Its tokens, by index, up to its `;` or `{`.
    tokens: std::ops::Range<usize>,
    block: Option<Vec<Statement>>,
    /// The line and the token of its block's `}`; of its `;`, for a directive.
    close_line: usize,
    close_token: usize,
    /// How many blocks it is in.
    depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Word,
    Open,
    Close,
    End,
}

#[derive(Debug, Clone)]
struct Token {
    kind: Kind,
    /// A word as nginx reads it: without its quotes, its escapes undone.
    text: String,
    /// The line it starts on, from 0.
    line: usize,
}

/// A `#` comment, which runs to the end of its line.
#[derive(Debug, Clone)]
struct Comment {
    line: usize,
    text: String,
    /// How many blocks it is in.
    depth: usize,
    /// How many tokens come before it.
    after: usize,
    /// Whether it is the first thing on its line.
    alone: bool,
}

struct Parsed {
    tokens: Vec<Token>,
    comments: Vec<Comment>,
    statements: Vec<Statement>,
}

impl Parsed {
    fn new(text: &str) -> Result<Parsed> {
        let (tokens, comments) = tokenize(text)?;
        let mut at = 0;
        let statements = parse_block(&tokens, &mut at, 0)?;
        Ok(Parsed {
            tokens,
            comments,
            statements,
        })
    }

    /// Every `server` block, in order, however deep.
    fn servers(&self) -> Vec<&Statement> {
        fn walk<'a>(statements: &'a [Statement], out: &mut Vec<&'a Statement>) {
            for statement in statements {
                if let Some(block) = &statement.block {
                    if statement.name == "server" {
                        out.push(statement);
                    }
                    walk(block, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.statements, &mut out);
        out
    }

    /// Whether `statement` has its lines to itself: no other token on them.
    fn alone(&self, statement: &Statement) -> bool {
        self.tokens.iter().enumerate().all(|(i, token)| {
            let on_its_lines = (statement.first_line..=statement.last_line).contains(&token.line);
            !on_its_lines || statement.tokens.contains(&i)
        })
    }

    /// Whether nothing but a comment follows token `index` on its line.
    fn ends_its_line(&self, index: usize) -> bool {
        self.tokens
            .get(index + 1)
            .is_none_or(|next| next.line > self.tokens[index].line)
    }

    /// Whether nothing comes before token `index` on its line.
    fn starts_its_line(&self, index: usize) -> bool {
        index == 0 || self.tokens[index - 1].line < self.tokens[index].line
    }

    /// The lines of ffca's blocks in `server`, each with the blank line before it: from a comment
    /// that is exactly `# BEGIN ffca` (or `# BEGIN ffca - ...`) to one that is exactly
    /// `# END ffca`, each on a line of its own, directly in the server block. Anything in one but
    /// ffca's three directives, each on lines of its own, is refused: turning the site off would
    /// delete it.
    fn regions(&self, server: &Statement, lines: &[&str]) -> Result<Vec<RangeInclusive<usize>>> {
        let open = server.tokens.end - 1;
        let inside = |c: &&Comment| {
            c.after > open && c.after <= server.close_token && c.depth == server.depth + 1
        };
        let is_begin = |text: &str| text == BEGIN || text.starts_with(&format!("{BEGIN} - "));
        let mut regions = Vec::new();
        let mut begin = None;
        for comment in self.comments.iter().filter(inside).filter(|c| c.alone) {
            let text = comment.text.trim_end();
            if is_begin(text) {
                ensure!(
                    begin.is_none(),
                    "line {}: an ffca block inside another",
                    comment.line + 1
                );
                begin = Some(comment.line);
            } else if text == END {
                let start = begin.take().with_context(|| {
                    format!("line {}: {END} without its {BEGIN}", comment.line + 1)
                })?;
                regions.push(start..=comment.line);
            }
        }
        if let Some(start) = begin {
            bail!("line {}: an ffca block without its {END}", start + 1);
        }
        let children = server.block.as_deref().unwrap_or_default();
        for region in &regions {
            let ours = |index: usize| {
                children.iter().any(|c| {
                    c.block.is_none()
                        && MANAGED.contains(&c.name.as_str())
                        && c.tokens.contains(&index)
                        && region.contains(&c.first_line)
                        && region.contains(&c.last_line)
                })
            };
            let foreign_token =
                (0..self.tokens.len()).any(|i| region.contains(&self.tokens[i].line) && !ours(i));
            let foreign_comment = self.comments.iter().any(|c| {
                region.contains(&c.line) && c.line != *region.start() && c.line != *region.end()
            });
            ensure!(
                !foreign_token && !foreign_comment,
                "lines {}-{}: ffca's block holds more than its own lines; change it by hand",
                region.start() + 1,
                region.end() + 1
            );
        }
        // The blank line ffca puts before its block goes with it.
        Ok(regions
            .into_iter()
            .map(|r| {
                let (start, end) = r.into_inner();
                if start > 0 && lines[start - 1].trim().is_empty() {
                    start - 1..=end
                } else {
                    start..=end
                }
            })
            .collect())
    }
}

fn parse_block(tokens: &[Token], at: &mut usize, depth: usize) -> Result<Vec<Statement>> {
    let mut statements = Vec::new();
    loop {
        let Some(first) = tokens.get(*at) else {
            ensure!(depth == 0, "a block is not closed: a `}}` is missing");
            return Ok(statements);
        };
        match first.kind {
            Kind::Close if depth > 0 => {
                *at += 1;
                return Ok(statements);
            }
            Kind::Close => bail!("line {}: a `}}` closes nothing", first.line + 1),
            Kind::End | Kind::Open => bail!("line {}: unexpected `{}`", first.line + 1, first.text),
            Kind::Word => {}
        }
        let start = *at;
        let mut words = Vec::new();
        while let Some(token) = tokens.get(*at).filter(|t| t.kind == Kind::Word) {
            words.push(token.text.clone());
            *at += 1;
        }
        let end = tokens.get(*at).with_context(|| {
            format!(
                "line {}: `{}` is not ended with `;`",
                first.line + 1,
                words[0]
            )
        })?;
        let name = words.remove(0);
        let mut statement = Statement {
            name,
            args: words,
            first_line: first.line,
            last_line: end.line,
            tokens: start..*at + 1,
            block: None,
            close_line: end.line,
            close_token: *at,
            depth,
        };
        *at += 1;
        match end.kind {
            Kind::End => {}
            Kind::Open => {
                statement.block = Some(parse_block(tokens, at, depth + 1)?);
                statement.close_token = *at - 1;
                statement.close_line = tokens[*at - 1].line;
            }
            _ => bail!("line {}: unexpected `{}`", end.line + 1, end.text),
        }
        statements.push(statement);
    }
}

/// nginx's whitespace: nothing else separates words, a no-break space among them.
fn space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Splits `text` into tokens and comments by nginx's rules (`ngx_conf_read_token`):
///
/// * a word ends at whitespace, `;` or `{` - not at `}`, a quote or `#`, which are part of it;
/// * a quote starts a quoted string only at the start of a word, and a quoted string must be
///   followed by whitespace, `;`, `{` or `)`;
/// * `#` starts a comment only at the start of a word;
/// * `\` takes the next character as it is, and `$` followed by `{` keeps the `{` in the word;
/// * in what a word holds, `\"`, `\'` and `\\` are that character, `\t`, `\r` and `\n` the control
///   characters, and any other `\` stays.
fn tokenize(text: &str) -> Result<(Vec<Token>, Vec<Comment>)> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut comments = Vec::new();
    let mut line = 0;
    let mut depth = 0usize;
    let mut words = 0;
    let mut line_has_token = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if space(c) {
            if c == '\n' {
                line += 1;
                line_has_token = false;
            }
            i += 1;
            continue;
        }
        match c {
            '#' => {
                let start = i;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                comments.push(Comment {
                    line,
                    text: chars[start..i].iter().collect(),
                    depth,
                    after: tokens.len(),
                    alone: !line_has_token,
                });
                continue;
            }
            ';' | '{' => {
                ensure!(words > 0, "line {}: unexpected `{c}`", line + 1);
                let kind = if c == '{' {
                    depth += 1;
                    Kind::Open
                } else {
                    Kind::End
                };
                tokens.push(Token {
                    kind,
                    text: c.to_string(),
                    line,
                });
                words = 0;
                i += 1;
            }
            '}' => {
                ensure!(words == 0, "line {}: unexpected `}}`", line + 1);
                depth = depth.saturating_sub(1);
                tokens.push(Token {
                    kind: Kind::Close,
                    text: c.to_string(),
                    line,
                });
                i += 1;
            }
            _ => {
                let start_line = line;
                let quote = matches!(c, '"' | '\'').then_some(c);
                if quote.is_some() {
                    i += 1;
                }
                let mut raw = String::new();
                let (mut escaped, mut variable) = (false, false);
                loop {
                    let Some(&ch) = chars.get(i) else {
                        ensure!(
                            quote.is_none(),
                            "line {}: a quoted string is not closed",
                            start_line + 1
                        );
                        break;
                    };
                    if !escaped && quote.is_none() {
                        let keeps_brace = ch == '{' && variable;
                        if !keeps_brace && (space(ch) || ch == ';' || ch == '{') {
                            break;
                        }
                    }
                    i += 1;
                    if ch == '\n' {
                        line += 1;
                    }
                    if escaped {
                        escaped = false;
                        raw.push(ch);
                        continue;
                    }
                    if ch == '{' && variable {
                        raw.push(ch);
                        continue;
                    }
                    if Some(ch) == quote {
                        let next = chars.get(i).copied();
                        ensure!(
                            next.is_none_or(|n| space(n) || matches!(n, ';' | '{' | ')')),
                            "line {}: unexpected `{}` after a quoted string",
                            line + 1,
                            next.unwrap_or_default()
                        );
                        break;
                    }
                    escaped = ch == '\\';
                    variable = ch == '$';
                    raw.push(ch);
                }
                tokens.push(Token {
                    kind: Kind::Word,
                    text: unescape(&raw),
                    line: start_line,
                });
                words += 1;
            }
        }
        line_has_token = true;
    }
    Ok((tokens, comments))
}

/// What nginx makes of the escapes in a word.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let replacement = match chars.peek() {
                Some(&next @ ('"' | '\'' | '\\')) => Some(next),
                Some('t') => Some('\t'),
                Some('r') => Some('\r'),
                Some('n') => Some('\n'),
                _ => None,
            };
            if let Some(replacement) = replacement {
                chars.next();
                out.push(replacement);
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests;
