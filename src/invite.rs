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
//! Invites: one-time links that hand a device its certificate.
//!
//! Making an invite issues the certificate at once, packs it for the device (`crate::bundle`) and
//! seals the pack in a file of the invites folder - the one folder the enrollment page
//! (`ffca serve`) is given. The page never holds the CA's key, so it cannot issue anything; all it
//! can do with an invite is hand it over once, or refuse it.
//!
//! * The link carries a random 256-bit token. The file is named after the token's SHA-256, and
//!   sealed (ChaCha20-Poly1305) with a key derived from the token (HKDF-SHA256): the folder alone
//!   reveals nothing, and nothing in it can be read without the link. The token itself is kept in
//!   the ledger, in the CA's own folder, so the UI can show the link again.
//! * The expiry is sealed into the file as associated data: write access to the folder cannot
//!   extend an invite without breaking it.
//! * Collecting is a rename of the file, which only one request can win; the page then writes a
//!   receipt - when, from where, on what - and deletes the file. A second click finds nothing.
//!
//! Whatever needs the key happens on the CA's side, in [`tend`], which the UI and `crl-refresh`
//! run: receipts go into the ledger, and an invite that expired, was cancelled or whose holder was
//! revoked gets its file deleted and, if never collected, its certificate revoked - the key that
//! certificate was issued for existed only in the sealed file.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::{digest, hkdf};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::bundle::{self, Bundle};
use crate::ca::{self, Ca, Key};
use crate::ledger::{Holder, Invite, InviteState, Reason, Status, Target};
use crate::store::{PRIVATE, Store};

/// The invites folder, inside the state folder.
pub const DIR: &str = "invites";
/// How long an invite can be collected.
pub const VALIDITY: Duration = Duration::hours(24);
const SALT: &[u8] = b"Friends and Family CA invite";

/// What a collected invite hands over, as the enrollment page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub ca: String,
    pub holder: String,
    pub stem: String,
    pub password: String,
    #[serde(with = "base64_bytes")]
    pub p12: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub mobileconfig: Vec<u8>,
}

/// An invite file: only its expiry is in the clear.
#[derive(Debug, Serialize, Deserialize)]
struct Sealed {
    version: u32,
    expires: i64,
    nonce: String,
    sealed: String,
}

/// What the enrollment page writes when an invite is collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The address and the browser it came from.
    pub by: String,
}

/// Why an invite cannot be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Collected, cancelled, or never made.
    Gone,
    Expired,
}

/// A new invite: the link to send, and what the ledger now records.
pub struct Made {
    pub link: String,
    pub invite: Invite,
}

/// The invites folder of the CA in `store`.
pub fn dir(store: &Store) -> PathBuf {
    store.path(DIR)
}

/// The link for `token` on the enrollment site `host`.
pub fn link(host: &str, token: &str) -> String {
    format!("https://{host}/i/{token}")
}

/// Issues a certificate to the device `holder`, and makes the invite that hands it over.
pub fn make(
    ca: &Ca,
    folder: &Path,
    holder: Holder,
    host: &str,
    now: OffsetDateTime,
) -> Result<Made> {
    prepare_folder(folder)?;
    let issued = ca.issue(holder, Key::Generate, now, ca::DEFAULT_CLIENT_VALIDITY)?;
    let serial = issued.certificate.serial;
    let made = (|| -> Result<Made> {
        let stem = match holder {
            Holder::Device { person, device } => {
                crate::files::file_stem(&format!("{person} {device}"))
            }
            Holder::Agent(agent) => crate::files::file_stem(agent),
        };
        let Bundle {
            holder,
            stem,
            password,
            p12,
            mobileconfig,
        } = bundle::make(ca, &issued, &stem)?;
        let payload = Payload {
            ca: ca.name().to_owned(),
            holder,
            stem,
            password,
            p12,
            mobileconfig,
        };
        let token = random_token()?;
        let now = issued.certificate.not_before + crate::ca::BACKDATE;
        let expires = now + VALIDITY;
        seal(folder, &token, &payload, expires)?;
        let invite = Invite {
            token: token.clone(),
            serial,
            holder: payload.holder.clone(),
            created: now,
            expires,
            state: InviteState::Open,
            closed: None,
            collected_by: None,
        };
        ca.change(|ledger| {
            ledger.invites.push(invite.clone());
            Ok(())
        })?;
        Ok(Made {
            link: link(host, &token),
            invite,
        })
    })();
    if made.is_err() {
        // A certificate whose key was never handed over: nobody holds it, and it goes.
        let _ = ca.revoke(Target::Certificate(serial), Reason::Retired, now);
    }
    made
}

/// Reads the invite for `token` without collecting it: what the page shows before the button.
pub fn open(folder: &Path, token: &str, now: OffsetDateTime) -> Result<Payload, Unavailable> {
    let id = id(token).ok_or(Unavailable::Gone)?;
    let text =
        fs::read_to_string(folder.join(format!("{id}.invite"))).map_err(|_| Unavailable::Gone)?;
    unseal(&text, token, &id, now)
}

/// Collects the invite for `token`: hands its payload over once, and leaves a receipt.
pub fn collect(
    folder: &Path,
    token: &str,
    now: OffsetDateTime,
    by: &str,
) -> Result<Payload, Unavailable> {
    let id = id(token).ok_or(Unavailable::Gone)?;
    let file = folder.join(format!("{id}.invite"));
    let claimed = folder.join(format!("{id}.claimed"));
    let text = fs::read_to_string(&file).map_err(|_| Unavailable::Gone)?;
    // Checked before the claim, so that an expired invite is left for `tend`.
    unseal(&text, token, &id, now)?;
    fs::rename(&file, &claimed).map_err(|_| Unavailable::Gone)?;
    let payload = unseal(&text, token, &id, now);
    let receipt = Receipt {
        at: now,
        by: by.chars().filter(|c| !c.is_control()).take(300).collect(),
    };
    let written = serde_json::to_string(&receipt)
        .map_err(anyhow::Error::from)
        .and_then(|json| {
            Store::new(folder).write(&format!("{id}.collected"), json.as_bytes(), PRIVATE)
        });
    let _ = fs::remove_file(&claimed);
    if written.is_err() {
        // Without a receipt, `tend` would revoke a certificate that was handed over.
        return Err(Unavailable::Gone);
    }
    payload
}

/// What [`tend`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tended {
    pub collected: Vec<String>,
    pub closed: Vec<String>,
    /// Whether it revoked anything, and so signed a new CRL.
    pub revoked: bool,
    /// What it could not make sense of in the folder, one line each; the rest was still tended.
    pub problems: Vec<String>,
}

/// How long a claim - an invite the page is handing over - may take before it counts as
/// abandoned.
const CLAIM_GRACE: Duration = Duration::minutes(10);
/// The most a receipt can be: a time and a line naming an address and a device.
const RECEIPT_LIMIT: u64 = 4096;

/// Brings the ledger's open invites up to date with the folder; see the module documentation.
///
/// The folder is written by the enrollment page, which faces the internet, and this runs as
/// root, holding the CA's lock: nothing in the folder is followed through a link, read without
/// a size limit, or allowed to stop the rest. An invite is looked at in the order the page
/// changes it - the invite file, then the claim, then the receipt - so a collection in progress
/// is never mistaken for one that never happened.
pub fn tend(ca: &Ca, folder: &Path, now: OffsetDateTime) -> Result<Tended> {
    let ledger = ca.ledger()?;
    let present = |path: PathBuf| fs::symlink_metadata(path).is_ok();
    let due = |invite: &Invite| {
        let Some(id) = id(&invite.token) else {
            return true;
        };
        let valid = ledger
            .find(&invite.serial.to_string())
            .is_ok_and(|(_, c)| c.status(now) == Status::Valid);
        !valid || now >= invite.expires || !present(folder.join(format!("{id}.invite")))
    };
    if !ledger
        .invites
        .iter()
        .any(|i| i.state == InviteState::Open && due(i))
    {
        return Ok(Tended::default());
    }
    let mut to_revoke = Vec::new();
    let mut tended = ca.change(|ledger| {
        let mut tended = Tended::default();
        let valid: Vec<bool> = ledger
            .invites
            .iter()
            .map(|i| {
                ledger
                    .find(&i.serial.to_string())
                    .is_ok_and(|(_, c)| c.status(now) == Status::Valid)
            })
            .collect();
        for (invite, valid) in ledger.invites.iter_mut().zip(valid) {
            if invite.state != InviteState::Open {
                continue;
            }
            let Some(id) = id(&invite.token) else {
                tended.problems.push(format!(
                    "the invite for {} has a damaged token",
                    invite.holder
                ));
                continue;
            };
            let file = folder.join(format!("{id}.invite"));
            let mut close = |invite: &mut Invite, state| {
                invite.state = state;
                invite.closed = Some(now);
                tended.closed.push(invite.holder.clone());
            };
            if !valid {
                close(invite, InviteState::Cancelled);
            } else if present(file.clone()) {
                if now < invite.expires {
                    continue;
                }
                close(invite, InviteState::Expired);
                to_revoke.push(invite.serial);
            } else if claim_age(&folder.join(format!("{id}.claimed")), now)
                .is_some_and(|age| age < CLAIM_GRACE)
            {
                // The page is handing it over this moment; its receipt follows.
                continue;
            } else {
                let receipt_file = folder.join(format!("{id}.collected"));
                match read_receipt(&receipt_file) {
                    Ok(Some(receipt)) => {
                        invite.state = InviteState::Collected;
                        invite.closed = Some(receipt.at);
                        invite.collected_by = Some(receipt.by);
                        tended.collected.push(invite.holder.clone());
                    }
                    Ok(None) => {
                        close(invite, InviteState::Cancelled);
                        to_revoke.push(invite.serial);
                    }
                    Err(problem) => {
                        tended.problems.push(format!(
                            "the invite for {}: {problem}; its certificate is revoked",
                            invite.holder
                        ));
                        close(invite, InviteState::Cancelled);
                        to_revoke.push(invite.serial);
                    }
                }
                if let Err(error) = remove_if_there(&receipt_file) {
                    tended.problems.push(format!("{error:#}"));
                }
            }
            for leftover in [file, folder.join(format!("{id}.claimed"))] {
                if invite.state != InviteState::Open
                    && let Err(error) = remove_if_there(&leftover)
                {
                    tended.problems.push(format!("{error:#}"));
                }
            }
        }
        Ok(tended)
    })?;
    for serial in to_revoke {
        match ca.revoke(Target::Certificate(serial), Reason::Retired, now) {
            Ok(_) => tended.revoked = true,
            Err(error) => tended.problems.push(format!("{error:#}")),
        }
    }
    Ok(tended)
}

/// How long ago `claim` was made, if there is one.
fn claim_age(claim: &Path, now: OffsetDateTime) -> Option<Duration> {
    let modified = fs::symlink_metadata(claim).ok()?.modified().ok()?;
    Some(now - OffsetDateTime::from(modified))
}

/// The receipt at `path`, if there is one. Only a small, ordinary file counts: the page could
/// leave a link, a pipe or a huge file there, and this runs as root, under the CA's lock.
fn read_receipt(path: &Path) -> std::result::Result<Option<Receipt>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("its receipt is not an ordinary file".to_owned()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("its receipt is not an ordinary file".to_owned());
    }
    if metadata.len() > RECEIPT_LIMIT {
        return Err("its receipt is too large".to_owned());
    }
    let mut text = String::new();
    file.take(RECEIPT_LIMIT)
        .read_to_string(&mut text)
        .map_err(|_| "its receipt is not text".to_owned())?;
    let receipt: Receipt =
        serde_json::from_str(&text).map_err(|_| "its receipt is damaged".to_owned())?;
    Ok(Some(Receipt {
        at: receipt.at,
        by: printable(&receipt.by),
    }))
}

/// `text` with control characters dropped and its length capped: what the page sends is shown in
/// the UI and kept in the ledger.
fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(300).collect()
}

/// Cancels the open invite for `serial`: its file goes and its certificate is revoked. If the
/// invite has been collected meanwhile, nothing is revoked, and that is the error: whoever
/// collected it holds a valid certificate, which only revoking the device stops.
pub fn cancel(
    ca: &Ca,
    folder: &Path,
    serial: crate::ledger::Serial,
    now: OffsetDateTime,
) -> Result<()> {
    let invite = ca
        .ledger()?
        .invites
        .into_iter()
        .find(|i| i.serial == serial && i.state == InviteState::Open)
        .context("that invite is no longer open")?;
    let id = id(&invite.token).context("the invite's token is damaged")?;
    remove_if_there(&folder.join(format!("{id}.invite")))?;
    // A claim in progress would leave the invite open: let it finish, then look again.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        tend(ca, folder, now)?;
        let after = ca
            .ledger()?
            .invites
            .into_iter()
            .find(|i| i.serial == serial);
        match after.map(|i| (i.state, i.collected_by)) {
            Some((InviteState::Collected, by)) => bail!(
                "{} collected the invite already, from {}: if that was not them, revoke the device",
                invite.holder,
                by.unwrap_or_else(|| "an unknown place".to_owned())
            ),
            Some((InviteState::Open, _)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Some((InviteState::Open, _)) => {
                bail!("the invite is being collected right now; look again in a moment")
            }
            _ => return Ok(()),
        }
    }
}

/// Gives the invites folder, and the ordinary files in it, to the user the enrollment page runs
/// as, creating it if needed. Run by the UI when the enrollment settings are saved. Each file is
/// opened without following links and given away through that open file: a link the page left
/// in its folder hands over nothing.
pub fn hand_over_folder(folder: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    prepare_folder(folder)?;
    let give = |file: &fs::File, path: &Path| {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid)).with_context(|| {
            format!(
                "cannot give {} to {uid}:{gid}, who the enrollment page runs as; run ffca as root",
                path.display()
            )
        })
    };
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(folder)
        .with_context(|| format!("{} is not a folder", folder.display()))?;
    give(&directory, folder)?;
    for entry in fs::read_dir(folder)?.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(file) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        else {
            continue;
        };
        if file.metadata().is_ok_and(|m| m.file_type().is_file()) {
            give(&file, &path)?;
        }
    }
    Ok(())
}

/// Creates the invites folder if needed, owner-only. Whoever owns it - the user the enrollment
/// page runs as - owns the invites written into it.
fn prepare_folder(folder: &Path) -> Result<()> {
    if !folder.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(folder)
            .with_context(|| format!("cannot create {}", folder.display()))?;
    }
    Ok(())
}

fn seal(folder: &Path, token: &str, payload: &Payload, expires: OffsetDateTime) -> Result<()> {
    let id = id(token).context("a token of the wrong shape")?;
    let key = key(token)?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("no randomness available: {e}"))?;
    let mut data = serde_json::to_vec(payload)?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad(&id, expires.unix_timestamp())),
        &mut data,
    )
    .map_err(|_| anyhow!("cannot seal the invite"))?;
    let sealed = Sealed {
        version: 1,
        expires: expires.unix_timestamp(),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(data),
    };
    let name = format!("{id}.invite");
    // The folder's owner - the user the page runs as - owns what is written into it.
    let owner = fs::symlink_metadata(folder)?;
    Store::new(folder).write_owned(
        &name,
        serde_json::to_string(&sealed)?.as_bytes(),
        PRIVATE,
        Some((owner.uid(), owner.gid())),
    )
}

fn unseal(text: &str, token: &str, id: &str, now: OffsetDateTime) -> Result<Payload, Unavailable> {
    let sealed: Sealed = serde_json::from_str(text).map_err(|_| Unavailable::Gone)?;
    if sealed.version != 1 {
        return Err(Unavailable::Gone);
    }
    if now.unix_timestamp() >= sealed.expires {
        return Err(Unavailable::Expired);
    }
    let nonce: [u8; 12] = STANDARD
        .decode(&sealed.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or(Unavailable::Gone)?;
    let mut data = STANDARD
        .decode(&sealed.sealed)
        .map_err(|_| Unavailable::Gone)?;
    let key = key(token).map_err(|_| Unavailable::Gone)?;
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(id, sealed.expires)),
            &mut data,
        )
        .map_err(|_| Unavailable::Gone)?;
    serde_json::from_slice(plain).map_err(|_| Unavailable::Gone)
}

fn aad(id: &str, expires: i64) -> Vec<u8> {
    format!("ffca invite v1 {id} {expires}").into_bytes()
}

fn key(token: &str) -> Result<LessSafeKey> {
    let secret = URL_SAFE_NO_PAD
        .decode(token)
        .context("a token of the wrong shape")?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(&secret);
    let okm = prk
        .expand(&[b"key"], &CHACHA20_POLY1305)
        .map_err(|_| anyhow!("cannot derive the invite's key"))?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// The file name for `token`: its SHA-256 in hex, or nothing for something that is not a token.
pub fn id(token: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .ok()
        .filter(|b| b.len() == 32)?;
    Some(
        digest::digest(&digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness available: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn remove_if_there(file: &Path) -> Result<()> {
    match fs::remove_file(file) {
        Err(e) if e.kind() != ErrorKind::NotFound => {
            Err(e).with_context(|| format!("cannot delete {}", file.display()))
        }
        _ => Ok(()),
    }
}

mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
