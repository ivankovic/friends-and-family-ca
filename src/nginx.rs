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
//! nginx: which sites ask for a client certificate, and changing that safely.
//!
//! A site is a `server` block that listens with `ssl`, in a `*.conf` file of the folder the
//! settings name. Its mode is its `ssl_verify_client`: `on` is required; `optional` (and
//! `optional_no_ca`) let a visitor without a certificate in but still refuse a bad one - revoked,
//! expired, another CA's - so a lost phone stays out even there.
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
//! directive too.
//!
//! The configuration is read with a small parser of nginx's syntax (words, quoted strings,
//! comments, `{` `}` `;`, `${variable}`), not with patterns over lines: the stop-bots blocks at the
//! top of every site are `if` blocks full of quoted regular expressions and closing braces.
//!
//! Every change is checked with the settings' test command (`nginx -t`) before nginx reloads; if
//! the test fails, the file is put back as it was and nothing reloads. nginx reads the CA's
//! certificate and CRL from copies ffca keeps in a folder nginx can see, refreshed before every
//! test and reload: the state folder holds the CA's key and stays its owner's only.

use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
        });
    }
    Ok(sites)
}

/// `text` with site `index` set to `mode`: see the module documentation for what changes.
pub fn plan(text: &str, index: usize, mode: Mode, nginx: &config::Nginx) -> Result<String> {
    let parsed = Parsed::new(text)?;
    let servers = parsed.servers();
    let server = servers
        .get(index)
        .with_context(|| format!("there is no server block number {}", index + 1))?;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let inside = server.first_line + 1..server.close_line;

    let begin = inside
        .clone()
        .find(|&i| lines[i].trim_start().starts_with(BEGIN));
    let region = match begin {
        Some(begin) => {
            let end = (begin..server.close_line)
                .find(|&i| lines[i].trim_start().starts_with(END))
                .with_context(|| format!("line {}: an ffca block without its {END}", begin + 1))?;
            // The blank line ffca puts before its block goes with it.
            let start = if begin > 0 && lines[begin - 1].trim().is_empty() {
                begin - 1
            } else {
                begin
            };
            Some(start..=end)
        }
        None => None,
    };
    let in_region = |line: usize| region.as_ref().is_some_and(|r| r.contains(&line));

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

    let anchor = children
        .iter()
        .filter(|c| c.block.is_none() && c.name == "server_name" && !in_region(c.first_line))
        .map(|c| c.last_line)
        .next_back();
    let (anchor, indent) = match anchor {
        Some(line) => (line, indentation(lines[line]).to_owned()),
        None => (
            server.first_line,
            format!("{}    ", indentation(lines[server.first_line])),
        ),
    };
    let block: Vec<String> = match mode.value() {
        None => Vec::new(),
        Some(value) => {
            let folder = &nginx.ca_files_in_nginx;
            vec![
                "\n".to_owned(),
                format!(
                    "{indent}{BEGIN} - client certificates, managed by Friends and Family CA\n"
                ),
                format!(
                    "{indent}ssl_client_certificate {};\n",
                    folder.join(CA_FILE).display()
                ),
                format!("{indent}ssl_crl {};\n", folder.join(CRL_FILE).display()),
                format!("{indent}ssl_verify_client {value};\n"),
                format!("{indent}{END}\n"),
            ]
        }
    };

    let mut out = String::with_capacity(text.len() + 300);
    for (i, line) in lines.iter().enumerate() {
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
        if i == anchor {
            if !line.ends_with('\n') {
                out.push('\n');
            }
            block.iter().for_each(|l| out.push_str(l));
        }
    }
    Ok(out)
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
pub fn set_mode(nginx: &config::Nginx, ca: &Ca, site: &Site, mode: Mode) -> Result<bool> {
    publish(nginx, ca)?;
    let original = fs::read_to_string(&site.file)
        .with_context(|| format!("cannot read {}", site.file.display()))?;
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
    replace(&site.file, &planned)?;
    let restore = |what: &str, error: anyhow::Error| -> anyhow::Error {
        match replace(&site.file, &original) {
            Ok(()) => anyhow!(
                "{what}, so {} is back as it was:\n{error:#}",
                site.file.display()
            ),
            Err(also) => anyhow!(
                "{what}, and putting {} back failed too ({also:#}):\n{error:#}",
                site.file.display()
            ),
        }
    };
    if let Err(error) = run(&nginx.test) {
        return Err(restore("nginx refused the change", error));
    }
    if let Err(error) = run(&nginx.reload) {
        let error = restore("nginx did not reload", error);
        let _ = run(&nginx.reload);
        return Err(error);
    }
    Ok(true)
}

/// The enrollment site's file, in the sites folder.
pub const ENROLLMENT_FILE: &str = "ffca-enrollment.conf";
const ENROLLMENT_MARK: &str = "# Written by Friends and Family CA: the enrollment page";

/// The enrollment site's configuration: a `server` for `enrollment.host` that forwards to
/// `enrollment.upstream` and never asks for a client certificate. Its `listen`, TLS certificate
/// and `include`s are copied from a site on the same domain - `k.example.org` takes them from
/// `cloud.example.org` - which also says which certificate covers the name. Returns the file and
/// its text.
pub fn enrollment_site(
    nginx: &config::Nginx,
    enrollment: &config::Enrollment,
) -> Result<(PathBuf, String)> {
    let host = &enrollment.host;
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
    let forward = if literal {
        format!(
            "        proxy_pass {upstream};
"
        )
    } else {
        format!(
            "        # Looked up when a request comes (Docker's DNS), so that nginx starts while the page is down.
                     resolver 127.0.0.11 valid=30s ipv6=off;
                     set $ffca_enrollment {upstream};
                     proxy_pass $ffca_enrollment;
"
        )
    };
    let file = nginx.sites.join(ENROLLMENT_FILE);
    let site = format!(
        "{ENROLLMENT_MARK}, where invites are collected.
         # It never asks for a client certificate: whoever opens an invite has none yet. Its listen,
         # TLS certificate and includes are copied from {template}.
         server {{
         {copied}
             server_name {host};

             location / {{
         {forward}                 proxy_set_header Host $host;
                 proxy_set_header X-Real-IP $remote_addr;
             }}
         }}
",
        template = template.file_name(),
        copied = copied.join(
            "
"
        ),
    );
    Ok((file, site))
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
    let before = match fs::read_to_string(file) {
        Ok(existing) if existing.starts_with(ENROLLMENT_MARK) => Some(existing),
        Ok(_) => bail!(
            "{} exists and is not ffca's; move it away first",
            file.display()
        ),
        Err(_) => None,
    };
    Store::new(file.parent().unwrap_or(Path::new("."))).write(
        &file.file_name().unwrap_or_default().to_string_lossy(),
        text.as_bytes(),
        PUBLIC,
    )?;
    let restore = || match &before {
        Some(existing) => replace(file, existing),
        None => fs::remove_file(file).map_err(anyhow::Error::from),
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

/// An argument as nginx reads it back: quoted if it holds anything that would split it.
fn quote(argument: &str) -> String {
    if argument.is_empty()
        || argument
            .chars()
            .any(|c| c.is_whitespace() || "{};#'\"".contains(c))
    {
        format!(
            "\"{}\"",
            argument.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        argument.to_owned()
    }
}

/// Copies the CA's certificate and CRL to where nginx reads them.
pub fn publish(nginx: &config::Nginx, ca: &Ca) -> Result<()> {
    fs::create_dir_all(&nginx.ca_files)
        .with_context(|| format!("cannot create {}", nginx.ca_files.display()))?;
    let target = Store::new(&nginx.ca_files);
    let source = ca.store();
    target.write(
        CA_FILE,
        source.read(ca::CERTIFICATE_FILE)?.as_bytes(),
        PUBLIC,
    )?;
    target.write(CRL_FILE, source.read(ca::CRL_FILE)?.as_bytes(), PUBLIC)
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

/// Writes `text` over `path`, keeping its permissions, through a temporary file and a rename.
fn replace(path: &Path, text: &str) -> Result<()> {
    let mode = fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    Store::new(dir).write(&name, text.as_bytes(), mode)
}

/// nginx's configuration as statements: a directive ends with `;`, a block is `{ ... }`.
#[derive(Debug, Clone)]
struct Statement {
    name: String,
    args: Vec<String>,
    /// Lines, from 0: where its first word is, and its `;` or `{`.
    first_line: usize,
    last_line: usize,
    /// Its tokens, by index.
    tokens: std::ops::Range<usize>,
    block: Option<Vec<Statement>>,
    close_line: usize,
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
    text: String,
    line: usize,
}

struct Parsed {
    tokens: Vec<Token>,
    statements: Vec<Statement>,
}

impl Parsed {
    fn new(text: &str) -> Result<Parsed> {
        let tokens = tokenize(text)?;
        let mut at = 0;
        let statements = parse_block(&tokens, &mut at, false)?;
        Ok(Parsed { tokens, statements })
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
}

fn parse_block(tokens: &[Token], at: &mut usize, nested: bool) -> Result<Vec<Statement>> {
    let mut statements = Vec::new();
    loop {
        let Some(first) = tokens.get(*at) else {
            ensure!(!nested, "a block is not closed: a `}}` is missing");
            return Ok(statements);
        };
        match first.kind {
            Kind::Close if nested => {
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
        };
        *at += 1;
        match end.kind {
            Kind::End => {}
            Kind::Open => {
                statement.block = Some(parse_block(tokens, at, true)?);
                statement.close_line = tokens[*at - 1].line;
            }
            _ => bail!("line {}: unexpected `{}`", end.line + 1, end.text),
        }
        statements.push(statement);
    }
}

fn tokenize(text: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' | '}' | ';' => {
                let kind = match c {
                    '{' => Kind::Open,
                    '}' => Kind::Close,
                    _ => Kind::End,
                };
                tokens.push(Token {
                    kind,
                    text: c.to_string(),
                    line,
                });
                i += 1;
            }
            '"' | '\'' => {
                let (start_line, quote) = (line, c);
                let mut word = String::new();
                i += 1;
                loop {
                    let Some(&next) = chars.get(i) else {
                        bail!("line {}: a quoted string is not closed", start_line + 1);
                    };
                    i += 1;
                    match next {
                        '\\' if i < chars.len() => {
                            word.push(next);
                            word.push(chars[i]);
                            line += usize::from(chars[i] == '\n');
                            i += 1;
                        }
                        n if n == quote => break,
                        n => {
                            line += usize::from(n == '\n');
                            word.push(n);
                        }
                    }
                }
                tokens.push(Token {
                    kind: Kind::Word,
                    text: word,
                    line: start_line,
                });
            }
            _ => {
                let mut word = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c == '$' && chars.get(i + 1) == Some(&'{') {
                        while i < chars.len() && chars[i] != '}' {
                            word.push(chars[i]);
                            i += 1;
                        }
                        ensure!(i < chars.len(), "line {}: `${{` is not closed", line + 1);
                    } else if c == '\\' && i + 1 < chars.len() {
                        word.push(c);
                        i += 1;
                    } else if c.is_whitespace() || matches!(c, '{' | '}' | ';' | '"' | '\'') {
                        break;
                    }
                    word.push(chars[i]);
                    i += 1;
                }
                tokens.push(Token {
                    kind: Kind::Word,
                    text: word,
                    line,
                });
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests;
