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
use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use time::{Duration, OffsetDateTime};

use friends_and_family_ca::ca::{self, Ca, Key};
use friends_and_family_ca::config::Config;
use friends_and_family_ca::files::issue_to_files;
use friends_and_family_ca::invite;
use friends_and_family_ca::ledger::{
    Certificate, Holder, KeyHolder, Ledger, Reason, Status, Target,
};
use friends_and_family_ca::nginx;
use friends_and_family_ca::store::Store;

/// A small certificate authority for mutual-TLS client certificates.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The folder the CA keeps its key, certificates and ledger in.
    #[arg(
        long,
        global = true,
        env = "FFCA_STATE_DIR",
        default_value = "/var/lib/ffca"
    )]
    state_dir: PathBuf,

    /// Without one, `ffca` opens the terminal UI.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the CA in a terminal UI: set it up, issue, revoke, rename.
    Tui {
        /// The folder certificates issued from the UI are written to, with their keys.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Serve the enrollment page, where invites are collected. It needs the invites folder only.
    Serve {
        /// The address and port to listen on.
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,
        /// The invites folder; by default the one in the state folder.
        #[arg(long)]
        invites: Option<PathBuf>,
    },
    /// Checks that the enrollment page answers, for a container's healthcheck: the image has no
    /// curl or wget.
    #[command(hide = true)]
    Healthz {
        #[arg(long, default_value = "127.0.0.1:8080")]
        address: String,
    },
    /// Create the CA.
    Init {
        /// The CA's name, as devices show it when they list installed certificates.
        #[arg(long)]
        name: String,
        /// How many years the CA is valid. Every certificate it issues expires by then.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..=i64::from(ca::MAX_CA_YEARS)))]
        years: u16,
    },
    /// Issue a certificate to a person's device or to an agent, written as files.
    Issue {
        #[command(flatten)]
        who: Who,
        /// The agent's certificate signing request (PEM). Its key then never leaves the agent;
        /// without one, the CA generates the key and writes it beside the certificate.
        #[arg(long, requires = "agent")]
        csr: Option<PathBuf>,
        /// How many days the certificate is valid.
        #[arg(long, default_value_t = ca::DEFAULT_CLIENT_VALIDITY.whole_days() as u32)]
        days: u32,
        /// The folder to write the certificate, and the key, into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Revoke one certificate, a device's or agent's certificates, or every device of a person.
    Revoke {
        #[command(flatten)]
        who: Who,
        /// One certificate, by the first characters of its serial number (see `ffca list`).
        #[arg(long, conflicts_with_all = ["person", "agent"])]
        serial: Option<String>,
        /// Why: the device is lost (or its key leaked), the certificate is replaced, or the
        /// device, agent or person is gone for good - which also retires them.
        #[arg(long, value_enum)]
        reason: Reason,
    },
    /// Rename a person, a device or an agent.
    Rename {
        #[command(flatten)]
        who: Who,
        /// The new name.
        #[arg(long)]
        to: String,
    },
    /// List every person, device and agent, with their certificates.
    List,
    /// Daily, from a timer: re-sign the revocation list before it expires, record collected
    /// invites, and revoke the certificates of those that expired uncollected.
    CrlRefresh,
}

/// Who a command is about: a person (and one of their devices), or an agent.
#[derive(clap::Args)]
struct Who {
    /// A person.
    #[arg(long, conflicts_with = "agent")]
    person: Option<String>,
    /// One of the person's devices, in words they recognise: "phone", "work laptop".
    #[arg(long, requires = "person")]
    device: Option<String>,
    /// An agent: a program or machine that authenticates as itself, such as a backup job.
    #[arg(long)]
    agent: Option<String>,
}

impl Who {
    /// The person's device or the agent; a person alone is not enough.
    fn holder(&self) -> Result<Holder<'_>> {
        match self.target()? {
            Some(Target::Holder(holder)) => Ok(holder),
            Some(_) => bail!("which of their devices? Name it with --device"),
            None => bail!("whose? Name a --person and --device, or an --agent"),
        }
    }

    fn target(&self) -> Result<Option<Target<'_>>> {
        Ok(match (&self.person, &self.device, &self.agent) {
            (Some(person), Some(device), None) => {
                Some(Target::Holder(Holder::Device { person, device }))
            }
            (Some(person), None, None) => Some(Target::Person(person)),
            (None, None, Some(agent)) => Some(Target::Holder(Holder::Agent(agent))),
            (None, None, None) => None,
            _ => bail!("name a --person (and --device), or an --agent, not both"),
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let store = Store::new(&args.state_dir);
    let now = OffsetDateTime::now_utc();
    let command = args.command.unwrap_or(Command::Tui {
        out: PathBuf::from("."),
    });
    // As root, ffca runs the commands the state folder's config.toml names; the enrollment page
    // runs as nobody, and reads only its invites.
    let as_root = unsafe { libc::geteuid() } == 0;
    if as_root && !matches!(command, Command::Serve { .. } | Command::Healthz { .. }) {
        store.check_owner(0, &[friends_and_family_ca::config::FILE])?;
    }
    match command {
        Command::Tui { out } => friends_and_family_ca::tui::run(store, out)?,
        Command::Healthz { address } => {
            use std::io::{Read, Write};
            let address: std::net::SocketAddr = address
                .parse()
                .context("an address such as 127.0.0.1:8080")?;
            let mut stream =
                std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(3))?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
            stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
            let mut answer = String::new();
            stream.take(4096).read_to_string(&mut answer)?;
            if !answer.starts_with("HTTP/1.1 200") && !answer.starts_with("HTTP/1.0 200") {
                bail!(
                    "the enrollment page answers: {}",
                    answer.lines().next().unwrap_or("nothing")
                );
            }
        }
        Command::Serve { listen, invites } => {
            let folder = invites.unwrap_or_else(|| invite::dir(&store));
            friends_and_family_ca::serve::run(&listen, folder)?;
        }
        Command::Init { name, years } => {
            let ca = Ca::create(&store, &name, now, ca::years(years))?;
            println!(
                "Created the CA \"{}\" in {}, valid until {}.",
                name.trim(),
                store.dir().display(),
                ca.not_after().date()
            );
            println!(
                "Point the web server at {}",
                store.path(ca::CERTIFICATE_FILE).display()
            );
            println!("and {}.", store.path(ca::CRL_FILE).display());
        }
        Command::Issue {
            who,
            csr,
            days,
            out,
        } => {
            // clap's `requires = "agent"` is skipped when --person is given, which conflicts with
            // --agent, so a person's device with a CSR would otherwise get through.
            if csr.is_some() && who.agent.is_none() {
                bail!("--csr is for agents: a person's device gets a key from the CA");
            }
            let ca = Ca::open(&store)?;
            let request = csr
                .map(|path| {
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("cannot read {}", path.display()))
                })
                .transpose()?;
            let key = match &request {
                Some(pem) => Key::Request(pem),
                None => Key::Generate,
            };
            let validity = Duration::days(days.into());
            let (issued, files) = issue_to_files(&ca, who.holder()?, key, &out, now, validity)?;
            println!(
                "Issued {} to {}, valid until {}.",
                issued.certificate.serial,
                issued.holder,
                issued.certificate.not_after.date()
            );
            println!("Certificate: {}", files[0].display());
            if let Some(key) = files.get(1) {
                println!(
                    "Key:         {} - hand it over and delete it",
                    key.display()
                );
            }
        }
        Command::Revoke {
            who,
            serial,
            reason,
        } => {
            let ca = Ca::open(&store)?;
            let ledger = ca.ledger()?;
            let target = match &serial {
                Some(prefix) => Target::Certificate(ledger.find(prefix)?.1.serial),
                None => who
                    .target()?
                    .context("what? Name a --serial, a --person or an --agent")?,
            };
            for revoked in ca.revoke(target, reason, now)? {
                println!("Revoked {} ({}).", revoked.holder, revoked.serial);
            }
            if reason == Reason::Retired && serial.is_none() {
                println!("Retired; nothing more will be issued to it under this name.");
            }
            println!("The new CRL is {}.", store.path(ca::CRL_FILE).display());
            reach_nginx(&store, &ca)?;
        }
        Command::Rename { who, to } => {
            let ca = Ca::open(&store)?;
            let target = who
                .target()?
                .context("what? Name a --person (and --device), or an --agent")?;
            ca.rename(target, &to)?;
            println!("Renamed. Certificates already issued keep the old name.");
        }
        Command::List => {
            let ledger = Ca::open(&store)?.ledger()?;
            print!("{}", list(&ledger, now));
        }
        Command::CrlRefresh => {
            let ca = Ca::open(&store)?;
            // The CRL comes first in importance: whatever is wrong with the invites folder, which
            // the enrollment page can write, the CRL is still signed and handed to nginx, and only
            // then is the trouble reported.
            let tended = invite::tend(&ca, &invite::dir(&store), now);
            if let Ok(tended) = &tended {
                for holder in &tended.collected {
                    println!("Recorded the invite collected for {holder}.");
                }
                for holder in &tended.closed {
                    println!("Closed the invite for {holder}.");
                }
            }
            ca.refresh_crl(now)?;
            println!(
                "Signed a new CRL, valid until {}.",
                (now + ca::CRL_VALIDITY).date()
            );
            reach_nginx(&store, &ca)?;
            match tended {
                Ok(tended) if tended.problems.is_empty() => {}
                Ok(tended) => bail!("in the invites folder:\n{}", tended.problems.join("\n")),
                Err(error) => return Err(error.context("the invites were not tidied")),
            }
        }
    }
    Ok(())
}

/// Hands a new CRL to nginx, if ffca knows how to reach it: until nginx reloads, it keeps
/// accepting what the CRL revokes. A failure fails the command, so that a timer reports it.
fn reach_nginx(store: &Store, ca: &Ca) -> Result<()> {
    let Some(settings) = Config::load(store)?.nginx else {
        return Ok(());
    };
    nginx::publish_and_reload(&settings, ca)
        .context("the CRL is signed, but nginx still has the previous one")?;
    println!("nginx reloaded with it.");
    Ok(())
}

/// Every person with their devices, then every agent, each with its certificates newest first.
fn list(ledger: &Ledger, now: OffsetDateTime) -> String {
    let mut out = String::new();
    if ledger.people.is_empty() && ledger.agents.is_empty() {
        out.push_str("No certificates yet. Issue one with `ffca issue`.\n");
    }
    for person in &ledger.people {
        let _ = writeln!(out, "{}", person.name);
        person
            .devices
            .iter()
            .for_each(|device| list_holder(&mut out, device, now));
    }
    if !ledger.agents.is_empty() {
        out.push_str("Agents\n");
        ledger
            .agents
            .iter()
            .for_each(|agent| list_holder(&mut out, agent, now));
    }
    out
}

fn list_holder(out: &mut String, holder: &KeyHolder, now: OffsetDateTime) {
    match holder.retired {
        Some(when) => _ = writeln!(out, "  {}, retired {}", holder.name, when.date()),
        None => _ = writeln!(out, "  {}", holder.name),
    }
    let mut certificates: Vec<&Certificate> = holder.certificates.iter().collect();
    certificates.sort_by_key(|c| std::cmp::Reverse(c.not_before));
    for certificate in certificates {
        let status = match certificate.status(now) {
            Status::Valid => format!("valid until {}", certificate.not_after.date()),
            Status::Expired => format!("expired {}", certificate.not_after.date()),
            Status::Revoked => {
                let when = certificate
                    .revoked
                    .map(|r| r.date().to_string())
                    .unwrap_or_default();
                match certificate.reason {
                    Some(reason) => {
                        format!("revoked {when} ({})", format!("{reason:?}").to_lowercase())
                    }
                    None => format!("revoked {when}"),
                }
            }
        };
        let _ = writeln!(
            out,
            "    {}  {status}",
            &certificate.serial.to_string()[..8]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use friends_and_family_ca::ca::Issued;

    /// clap's own consistency checks on the definition above (duplicate names, conflicting
    /// arguments), which otherwise only fire when a user happens to reach the broken part.
    #[test]
    fn cli_definition_is_valid() {
        Args::command().debug_assert();
    }

    fn parse(line: &str) -> Result<Args, clap::Error> {
        Args::try_parse_from(line.split(' '))
    }

    #[test]
    fn who_names_a_device_a_person_or_an_agent() {
        let who = |line| match parse(line).unwrap().command {
            Some(Command::Rename { who, .. }) => who,
            _ => unreachable!(),
        };
        let device = who("ffca rename --person Anna --device phone --to x");
        assert_eq!(
            device.target().unwrap(),
            Some(Target::Holder(Holder::Device {
                person: "Anna",
                device: "phone"
            }))
        );
        assert_eq!(
            who("ffca rename --person Anna --to x").target().unwrap(),
            Some(Target::Person("Anna"))
        );
        let agent = who("ffca rename --agent backup --to x");
        assert_eq!(agent.holder().unwrap(), Holder::Agent("backup"));
        let person = who("ffca rename --person Anna --to x");
        assert!(
            person
                .holder()
                .unwrap_err()
                .to_string()
                .contains("--device")
        );
    }

    #[test]
    fn contradictory_names_are_refused_by_the_parser() {
        assert!(parse("ffca issue --person Anna --agent backup").is_err());
        assert!(
            parse("ffca issue --device phone").is_err(),
            "a device needs its person"
        );
        assert!(parse("ffca revoke --serial ab --person Anna --reason lost").is_err());
    }

    /// As the library's `test_dir`: in memory where possible, since the store syncs every write.
    fn test_dir() -> tempfile::TempDir {
        match std::path::Path::new("/dev/shm").is_dir() {
            true => tempfile::tempdir_in("/dev/shm").unwrap(),
            false => tempfile::tempdir().unwrap(),
        }
    }

    fn ca(dir: &std::path::Path) -> Ca {
        let state = Store::new(dir.join("state"));
        Ca::create(
            &state,
            "Test",
            OffsetDateTime::now_utc(),
            ca::DEFAULT_CA_VALIDITY,
        )
        .unwrap()
    }

    const ANNA_PHONE: Holder = Holder::Device {
        person: "Anna",
        device: "phone",
    };

    #[test]
    fn list_groups_by_person_then_agents_newest_first() {
        let dir = test_dir();
        let ca = ca(dir.path());
        let now = OffsetDateTime::now_utc();
        let old = ca
            .issue(
                ANNA_PHONE,
                Key::Generate,
                now - Duration::days(1),
                ca::DEFAULT_CLIENT_VALIDITY,
            )
            .unwrap();
        let new = ca
            .issue(ANNA_PHONE, Key::Generate, now, ca::DEFAULT_CLIENT_VALIDITY)
            .unwrap();
        ca.revoke(
            Target::Certificate(old.certificate.serial),
            Reason::Replaced,
            now,
        )
        .unwrap();
        let tablet = Holder::Device {
            person: "Anna",
            device: "tablet",
        };
        ca.issue(tablet, Key::Generate, now, ca::DEFAULT_CLIENT_VALIDITY)
            .unwrap();
        ca.revoke(Target::Holder(tablet), Reason::Retired, now)
            .unwrap();
        ca.issue(
            Holder::Agent("backup"),
            Key::Generate,
            now,
            ca::DEFAULT_CLIENT_VALIDITY,
        )
        .unwrap();

        let text = list(&ca.ledger().unwrap(), now);
        let lines: Vec<&str> = text.lines().collect();
        let today = now.date();
        let short = |issued: &Issued| issued.certificate.serial.to_string()[..8].to_owned();
        assert_eq!(lines[0], "Anna");
        assert_eq!(lines[1], "  phone");
        assert!(
            lines[2].starts_with(&format!("    {}  valid until", short(&new))),
            "{text}"
        );
        assert_eq!(
            lines[3],
            format!("    {}  revoked {today} (replaced)", short(&old))
        );
        assert_eq!(lines[4], format!("  tablet, retired {today}"));
        assert!(lines[5].ends_with("(retired)"), "{text}");
        assert_eq!(lines[6], "Agents");
        assert_eq!(lines[7], "  backup");
    }

    #[test]
    fn an_empty_list_says_how_to_start() {
        assert!(list(&Ledger::default(), OffsetDateTime::now_utc()).contains("ffca issue"));
    }
}
