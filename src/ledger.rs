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
//! The ledger: who holds certificates, every certificate the CA has issued, which are revoked,
//! and the number of the last CRL. It is the CA's memory; the certificates themselves are kept
//! beside it only so they can be exported again.
//!
//! Two kinds of principal sit at the top: **people**, who have devices, and **agents** - programs
//! and machines that authenticate as themselves, such as a backup job. A person's device and an
//! agent are both a [`KeyHolder`]: something that holds one key at a time, and so has a current
//! certificate and the history of the ones before it (replaced, lost, expired). Nothing is ever
//! deleted, because the CRL must keep listing a revoked certificate for as long as it is valid; a
//! device or agent that is gone for good is *retired* instead, and is issued nothing more.
//!
//! People and agents share one namespace, and device names are unique within their person, all
//! ignoring case: "anna" finds Anna, and `ffca revoke --agent backup` can never mean a person.
//!
//! It is TOML, nested the way it is owned, so that an administrator can read and repair it
//! without ffca. The CRL is rebuilt from it every time, never edited in place, so the two cannot
//! disagree.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use crate::store::{PRIVATE, Store};

pub const FILE: &str = "ledger.toml";
const MAX_NAME_LENGTH: usize = 64;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// The number of the last CRL signed; the next one gets this plus one. RFC 5280 requires it
    /// to increase monotonically, and some verifiers reject a CRL older than one they have seen.
    pub crl_number: u64,
    #[serde(default, rename = "person", skip_serializing_if = "Vec::is_empty")]
    pub people: Vec<Person>,
    #[serde(default, rename = "agent", skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<KeyHolder>,
    #[serde(default, rename = "invite", skip_serializing_if = "Vec::is_empty")]
    pub invites: Vec<Invite>,
}

/// A link that hands a certificate over: see `crate::invite`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// The link's secret. Only here, in the CA's own folder: the enrollment page keeps its hash.
    pub token: String,
    pub serial: Serial,
    /// Who it is for, as `Holder` writes it: "Anna (phone)".
    pub holder: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
    pub state: InviteState,
    /// When it stopped being open: collected, expired or cancelled.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub closed: Option<OffsetDateTime>,
    /// Where it was collected from, as the enrollment page saw it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteState {
    Open,
    Collected,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    pub name: String,
    #[serde(default, rename = "device", skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<KeyHolder>,
}

/// A person's device, or an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyHolder {
    pub name: String,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub retired: Option<OffsetDateTime>,
    #[serde(default, rename = "certificate", skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub serial: Serial,
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Valid,
    Expired,
    Revoked,
}

impl Certificate {
    pub fn status(&self, now: OffsetDateTime) -> Status {
        if self.revoked.is_some() {
            Status::Revoked
        } else if now > self.not_after {
            Status::Expired
        } else {
            Status::Valid
        }
    }

    /// The file the certificate is kept in, inside the state folder.
    pub fn file(&self) -> String {
        format!("issued/{}.crt", self.serial)
    }
}

impl KeyHolder {
    fn new(name: &str) -> KeyHolder {
        KeyHolder {
            name: name.to_owned(),
            retired: None,
            certificates: Vec::new(),
        }
    }

    /// The certificate the holder is using now: the newest one that is valid. Usually the only
    /// valid one; two overlap while a replacement is being installed.
    pub fn current(&self, now: OffsetDateTime) -> Option<&Certificate> {
        self.certificates
            .iter()
            .filter(|c| c.status(now) == Status::Valid)
            .max_by_key(|c| c.not_before)
    }
}

/// Who a certificate is for, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder<'a> {
    Device { person: &'a str, device: &'a str },
    Agent(&'a str),
}

impl fmt::Display for Holder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Holder::Device { person, device } => write!(f, "{person} ({device})"),
            Holder::Agent(agent) => write!(f, "{agent} (agent)"),
        }
    }
}

/// What a revocation or a rename applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// One certificate.
    Certificate(Serial),
    /// A device's or an agent's valid certificates.
    Holder(Holder<'a>),
    /// Every device of a person.
    Person(&'a str),
}

/// Where a key holder sits in the ledger: indices, so that it can be found again after the
/// ledger has been borrowed for something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Device(usize, usize),
    Agent(usize),
}

/// One certificate a revocation reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    pub holder: String,
    pub serial: Serial,
}

impl Ledger {
    /// The ledger on disk, or an empty one if the CA has none yet.
    pub fn load(store: &Store) -> Result<Ledger> {
        if !store.exists(FILE) {
            return Ok(Ledger::default());
        }
        let text = store.read(FILE)?;
        toml::from_str(&text).map_err(|e| anyhow!("{} is damaged: {e}", store.path(FILE).display()))
    }

    pub fn save(&self, store: &Store) -> Result<()> {
        let text = toml::to_string(self)?;
        store.write(FILE, text.as_bytes(), PRIVATE)
    }

    pub fn person(&self, name: &str) -> Option<&Person> {
        self.people.iter().find(|p| same_name(&p.name, name))
    }

    pub fn agent(&self, name: &str) -> Option<&KeyHolder> {
        self.agents.iter().find(|a| same_name(&a.name, name))
    }

    /// Where `holder` is, if it exists.
    pub fn place(&self, holder: Holder) -> Option<Place> {
        match holder {
            Holder::Device { person, device } => {
                let p = self
                    .people
                    .iter()
                    .position(|p| same_name(&p.name, person))?;
                let d = self.people[p]
                    .devices
                    .iter()
                    .position(|d| same_name(&d.name, device))?;
                Some(Place::Device(p, d))
            }
            Holder::Agent(agent) => self
                .agents
                .iter()
                .position(|a| same_name(&a.name, agent))
                .map(Place::Agent),
        }
    }

    pub fn at(&self, place: Place) -> &KeyHolder {
        match place {
            Place::Device(p, d) => &self.people[p].devices[d],
            Place::Agent(a) => &self.agents[a],
        }
    }

    pub fn at_mut(&mut self, place: Place) -> &mut KeyHolder {
        match place {
            Place::Device(p, d) => &mut self.people[p].devices[d],
            Place::Agent(a) => &mut self.agents[a],
        }
    }

    /// `holder` as the ledger spells it.
    pub fn holder_at(&self, place: Place) -> Holder<'_> {
        match place {
            Place::Device(p, d) => Holder::Device {
                person: &self.people[p].name,
                device: &self.people[p].devices[d].name,
            },
            Place::Agent(a) => Holder::Agent(&self.agents[a].name),
        }
    }

    /// The holder a new certificate goes to, created if it is new. Refuses a retired holder, and
    /// a new person or agent whose name the other kind already uses.
    pub fn place_for_issue(&mut self, holder: Holder) -> Result<Place> {
        let place = match self.place(holder) {
            Some(place) => place,
            None => match holder {
                Holder::Device { person, device } => {
                    let person = checked_name("person", person)?;
                    let device = checked_name("device", device)?;
                    let p = match self.people.iter().position(|p| same_name(&p.name, person)) {
                        Some(p) => p,
                        None => {
                            ensure!(
                                self.agent(person).is_none(),
                                "{person} is an agent's name; a person needs another"
                            );
                            self.people.push(Person {
                                name: person.to_owned(),
                                devices: Vec::new(),
                            });
                            self.people.len() - 1
                        }
                    };
                    self.people[p].devices.push(KeyHolder::new(device));
                    Place::Device(p, self.people[p].devices.len() - 1)
                }
                Holder::Agent(agent) => {
                    let agent = checked_name("agent", agent)?;
                    ensure!(
                        self.person(agent).is_none(),
                        "{agent} is a person's name; an agent needs another"
                    );
                    self.agents.push(KeyHolder::new(agent));
                    Place::Agent(self.agents.len() - 1)
                }
            },
        };
        if let Some(when) = self.at(place).retired {
            bail!(
                "{} was retired on {}; give the new one a name of its own",
                self.holder_at(place),
                when.date()
            );
        }
        Ok(place)
    }

    /// Every certificate, with who holds it.
    pub fn certificates(&self) -> impl Iterator<Item = (Holder<'_>, &Certificate)> {
        let devices = self.people.iter().flat_map(|p| {
            p.devices.iter().flat_map(move |d| {
                let holder = Holder::Device {
                    person: &p.name,
                    device: &d.name,
                };
                d.certificates.iter().map(move |c| (holder, c))
            })
        });
        let agents = self.agents.iter().flat_map(|a| {
            a.certificates
                .iter()
                .map(move |c| (Holder::Agent(&a.name), c))
        });
        devices.chain(agents)
    }

    /// The one certificate whose serial starts with `prefix` (in hex, any case), so the
    /// administrator can type the first few characters the list shows.
    pub fn find(&self, prefix: &str) -> Result<(Holder<'_>, &Certificate)> {
        let prefix = prefix.trim().to_ascii_lowercase();
        ensure!(!prefix.is_empty(), "no serial number given");
        let mut matches = self
            .certificates()
            .filter(|(_, c)| c.serial.to_string().starts_with(&prefix));
        match (matches.next(), matches.next()) {
            (Some(found), None) => Ok(found),
            (None, _) => bail!("no certificate has a serial number starting with {prefix}"),
            (Some(_), Some(_)) => {
                bail!("more than one certificate has a serial number starting with {prefix}")
            }
        }
    }

    /// Revokes what `target` names: one certificate, a holder's valid certificates, or those of
    /// every device of a person. Expired certificates are left alone: no verifier accepts them
    /// anyway.
    ///
    /// On a holder or person, `Reason::Replaced` spares each holder's newest certificate, the one
    /// that replaces the rest, and `Reason::Retired` also retires the holders, so nothing more is
    /// issued to them.
    pub fn revoke(
        &mut self,
        target: Target,
        reason: Reason,
        now: OffsetDateTime,
    ) -> Result<Vec<Revoked>> {
        let places = match target {
            Target::Certificate(serial) => {
                let (place, index) = self
                    .locate(serial)
                    .ok_or_else(|| anyhow!("no certificate has the serial number {serial}"))?;
                let holder = self.holder_at(place).to_string();
                let certificate = &mut self.at_mut(place).certificates[index];
                if let Some(when) = certificate.revoked {
                    bail!("{serial} ({holder}) was already revoked on {}", when.date());
                }
                certificate.revoked = Some(now);
                certificate.reason = Some(reason);
                return Ok(vec![Revoked { holder, serial }]);
            }
            Target::Holder(holder) => {
                vec![
                    self.place(holder)
                        .ok_or_else(|| anyhow!("there is no {holder}"))?,
                ]
            }
            Target::Person(name) => {
                let p = self
                    .people
                    .iter()
                    .position(|p| same_name(&p.name, name))
                    .ok_or_else(|| anyhow!("there is no person called {name}"))?;
                (0..self.people[p].devices.len())
                    .map(|d| Place::Device(p, d))
                    .collect()
            }
        };
        let mut revoked = Vec::new();
        let mut retired = false;
        for place in places {
            let holder = self.holder_at(place).to_string();
            let key_holder = self.at_mut(place);
            let spared = match reason {
                Reason::Replaced => key_holder.current(now).map(|c| c.serial),
                _ => None,
            };
            for certificate in &mut key_holder.certificates {
                if certificate.status(now) == Status::Valid && Some(certificate.serial) != spared {
                    certificate.revoked = Some(now);
                    certificate.reason = Some(reason);
                    revoked.push(Revoked {
                        holder: holder.clone(),
                        serial: certificate.serial,
                    });
                }
            }
            if reason == Reason::Retired && key_holder.retired.is_none() {
                key_holder.retired = Some(now);
                retired = true;
            }
        }
        if revoked.is_empty() && !retired {
            if reason == Reason::Replaced {
                bail!("{} has no older certificate to replace", describe(target));
            }
            bail!("{} has no valid certificate to revoke", describe(target));
        }
        Ok(revoked)
    }

    /// Renames a person, a device or an agent. Certificates already issued keep the name they
    /// were issued with: it is what the device shows and what the web server logs.
    pub fn rename(&mut self, target: Target, new_name: &str) -> Result<()> {
        match target {
            Target::Certificate(_) => bail!("a certificate cannot be renamed; rename its holder"),
            Target::Person(name) => {
                let new_name = checked_name("person", new_name)?;
                let p = self
                    .people
                    .iter()
                    .position(|p| same_name(&p.name, name))
                    .ok_or_else(|| anyhow!("there is no person called {name}"))?;
                let taken = self
                    .people
                    .iter()
                    .enumerate()
                    .any(|(i, q)| i != p && same_name(&q.name, new_name))
                    || self.agent(new_name).is_some();
                ensure!(!taken, "the name {new_name} is taken");
                self.people[p].name = new_name.to_owned();
            }
            Target::Holder(holder) => {
                let place = self
                    .place(holder)
                    .ok_or_else(|| anyhow!("there is no {holder}"))?;
                let new_name = match place {
                    Place::Device(p, d) => {
                        let new_name = checked_name("device", new_name)?;
                        let devices = &self.people[p].devices;
                        let taken = devices
                            .iter()
                            .enumerate()
                            .any(|(i, e)| i != d && same_name(&e.name, new_name));
                        ensure!(
                            !taken,
                            "{} already has a device called {new_name}",
                            self.people[p].name
                        );
                        new_name
                    }
                    Place::Agent(a) => {
                        let new_name = checked_name("agent", new_name)?;
                        let taken = self
                            .agents
                            .iter()
                            .enumerate()
                            .any(|(i, e)| i != a && same_name(&e.name, new_name))
                            || self.person(new_name).is_some();
                        ensure!(!taken, "the name {new_name} is taken");
                        new_name
                    }
                };
                self.at_mut(place).name = new_name.to_owned();
            }
        }
        Ok(())
    }

    fn locate(&self, serial: Serial) -> Option<(Place, usize)> {
        let devices =
            self.people.iter().enumerate().flat_map(|(p, person)| {
                (0..person.devices.len()).map(move |d| Place::Device(p, d))
            });
        let agents = (0..self.agents.len()).map(Place::Agent);
        devices.chain(agents).find_map(|place| {
            let index = self
                .at(place)
                .certificates
                .iter()
                .position(|c| c.serial == serial)?;
            Some((place, index))
        })
    }
}

fn describe(target: Target) -> String {
    match target {
        Target::Certificate(serial) => serial.to_string(),
        Target::Holder(holder) => holder.to_string(),
        Target::Person(name) => name.to_owned(),
    }
}

/// Names compare without case, as people type them.
fn same_name(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// A person's, device's, agent's or CA's name, as it will appear in a certificate and in the web
/// server's logs: trimmed, not empty, short, and free of control characters, which could forge
/// log lines.
pub fn checked_name<'a>(what: &str, name: &'a str) -> Result<&'a str> {
    let name = name.trim();
    ensure!(!name.is_empty(), "the {what} cannot be empty");
    ensure!(
        name.chars().count() <= MAX_NAME_LENGTH,
        "the {what} is longer than {MAX_NAME_LENGTH} characters"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "the {what} contains a control character"
    );
    Ok(name)
}

/// A certificate serial number: 16 random bytes, the top bit clear so the DER integer is positive.
/// RFC 5280 allows up to 20 octets and asks for at least 64 bits of randomness from public CAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Serial(pub [u8; 16]);

impl Serial {
    pub fn random() -> Result<Serial> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness available: {e}"))?;
        bytes[0] &= 0x7f;
        // A leading zero byte would be dropped by DER, and the serial in the certificate would no
        // longer match this one byte for byte.
        bytes[0] |= 0x01;
        Ok(Serial(bytes))
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl FromStr for Serial {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Serial> {
        let digits = s.as_bytes();
        if digits.len() != 32 {
            bail!("a serial number is 32 hex digits, not {:?}", s);
        }
        let mut bytes = [0u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| anyhow!("{s:?} is not hex"))?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| anyhow!("{s:?} is not hex"))?;
        }
        Ok(Serial(bytes))
    }
}

impl Serialize for Serial {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Serial {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Serial, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Why a certificate was revoked, in the administrator's words. Each maps to an RFC 5280 reason
/// code in the CRL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    /// The device was lost or stolen, or its key may have leaked.
    Lost,
    /// A new certificate replaces this one.
    Replaced,
    /// The device, agent or person no longer needs access. Also retires them.
    Retired,
}

impl Reason {
    pub fn crl_reason(self) -> rcgen::RevocationReason {
        match self {
            Reason::Lost => rcgen::RevocationReason::KeyCompromise,
            Reason::Replaced => rcgen::RevocationReason::Superseded,
            Reason::Retired => rcgen::RevocationReason::CessationOfOperation,
        }
    }
}

#[cfg(test)]
mod tests;
