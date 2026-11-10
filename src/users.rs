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
//! HTTP logins: the users nginx checks itself, on a site whose HTTP auth is on.
//!
//! A user is a name and a password hash, kept in `users.toml` in the CA's folder, its owner's
//! only. nginx never reads that file: for each site whose HTTP auth is on, ffca writes the users
//! that site lets in to a password file of its own next to the CA's certificate (see
//! [`crate::nginx`]), and rewrites those files when a password changes or a user goes.
//!
//! Hashes are SHA-512 crypt (`$6$`, 5000 rounds), which nginx checks with the system's `crypt()`:
//! glibc's and musl's both have it, and nothing weaker is written. nginx checks the password on
//! every request, and the rounds are what each costs; a password ffca generates is 24 characters
//! from 56 letters and digits (139 bits), which no number of rounds needs to protect. nginx's
//! workers read the password files: they are their group's only when the settings name it
//! (`users_group`), and readable by every user of the machine otherwise - then a password a
//! person chooses should be one that is not used anywhere else.
//!
//! A name is what a browser and nginx's log show, and what goes into the password file as it is:
//! letters, digits and `.`, `_`, `@`, `-`, at most 64, so it can be neither a separator of the
//! file nor a pattern in nginx's configuration.

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::store::{PRIVATE, Store};

/// The users file, in the CA's folder.
pub const FILE: &str = "users.toml";
/// How long a password ffca makes up is.
pub const GENERATED_LENGTH: usize = 24;
const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ROUNDS: usize = 5000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    /// SHA-512 crypt of the password: `$6$<salt>$<hash>`.
    pub hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub changed: OffsetDateTime,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Users {
    #[serde(default, rename = "user")]
    pub users: Vec<User>,
}

impl Users {
    /// The users in `store`; none if there is no users file yet.
    pub fn load(store: &Store) -> Result<Users> {
        if !store.exists(FILE) {
            return Ok(Users::default());
        }
        let text = store.read(FILE)?;
        let users: Users = toml::from_str(&text).with_context(|| format!("cannot read {FILE}"))?;
        for user in &users.users {
            checked_name(&user.name).with_context(|| format!("{FILE} holds a bad name"))?;
            ensure!(
                user.hash.starts_with("$6$") && !user.hash.contains([':', '\n']),
                "{FILE}: {} has no SHA-512 crypt hash",
                user.name
            );
        }
        Ok(users)
    }

    pub fn save(&self, store: &Store) -> Result<()> {
        store.write(FILE, toml::to_string(self)?.as_bytes(), PRIVATE)
    }

    pub fn get(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.users.iter().map(|u| u.name.as_str())
    }

    /// Adds `name` with `password`, or with a password made up here when there is none; returns
    /// the password, the only time it is shown.
    pub fn add(&mut self, name: &str, password: Option<&str>) -> Result<String> {
        let name = checked_name(name)?;
        ensure!(self.get(&name).is_none(), "{name} is taken");
        let password = match password {
            Some(p) => checked_password(p)?.to_owned(),
            None => generate()?,
        };
        self.users.push(User {
            name,
            hash: hash(&password)?,
            changed: OffsetDateTime::now_utc(),
        });
        self.users.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(password)
    }

    /// Gives `name` a new password, `password` or a made-up one; returns it.
    pub fn set_password(&mut self, name: &str, password: Option<&str>) -> Result<String> {
        let password = match password {
            Some(p) => checked_password(p)?.to_owned(),
            None => generate()?,
        };
        let hash = hash(&password)?;
        let user = self
            .users
            .iter_mut()
            .find(|u| u.name == name)
            .with_context(|| format!("there is no user {name}"))?;
        user.hash = hash;
        user.changed = OffsetDateTime::now_utc();
        Ok(password)
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let before = self.users.len();
        self.users.retain(|u| u.name != name);
        ensure!(self.users.len() < before, "there is no user {name}");
        Ok(())
    }

    /// The lines of a password file that lets in `names`, in that order: `name:hash`. A name
    /// without a user is an error: a file that silently left someone out would lock them out.
    pub fn password_file(&self, names: &[String]) -> Result<String> {
        let mut out = String::new();
        for name in names {
            let user = self
                .get(name)
                .with_context(|| format!("there is no user {name}"))?;
            out.push_str(&format!("{}:{}\n", user.name, user.hash));
        }
        Ok(out)
    }
}

/// A user name as it may stand in a password file and in nginx's configuration.
pub fn checked_name(name: &str) -> Result<String> {
    let name = name.trim();
    ensure!(!name.is_empty(), "a user needs a name");
    ensure!(name.len() <= 64, "a user name is at most 64 characters");
    ensure!(
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-')),
        "a user name is letters, digits and . _ @ - only: {name:?}"
    );
    Ok(name.to_owned())
}

fn checked_password(password: &str) -> Result<&str> {
    ensure!(
        password.chars().count() >= 12,
        "a password is at least 12 characters"
    );
    ensure!(
        !password.contains(['\n', '\r', '\0']),
        "a password is one line"
    );
    Ok(password)
}

/// A password of [`GENERATED_LENGTH`] letters and digits, none that look alike (`0`, `O`, `o`,
/// `1`, `l`, `I`): 56 characters, easy to type on a phone.
pub fn generate() -> Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut out = String::with_capacity(GENERATED_LENGTH);
    while out.len() < GENERATED_LENGTH {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).map_err(|e| anyhow!("no randomness available: {e}"))?;
        // Rejection sampling: no letter more likely than another.
        let limit = 256 - 256 % ALPHABET.len();
        if usize::from(byte[0]) < limit {
            out.push(ALPHABET[usize::from(byte[0]) % ALPHABET.len()] as char);
        }
    }
    Ok(out)
}

/// SHA-512 crypt of `password` with a new 16-character salt.
pub fn hash(password: &str) -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness available: {e}"))?;
    let salt: String = bytes
        .iter()
        .map(|b| CRYPT_ALPHABET[usize::from(b % 64)] as char)
        .collect();
    Ok(sha512_crypt(password.as_bytes(), salt.as_bytes(), ROUNDS))
}

/// SHA-512 crypt, as Ulrich Drepper specified it ("Unix crypt using SHA-256 and SHA-512"): what
/// glibc's and musl's `crypt()` compute for `$6$`. `rounds` other than 5000 are written into the
/// result as `rounds=N$`.
pub fn sha512_crypt(password: &[u8], salt: &[u8], rounds: usize) -> String {
    use ring::digest::{Context, SHA512};
    let salt = &salt[..salt.len().min(16)];
    let digest = |parts: &[&[u8]]| -> [u8; 64] {
        let mut context = Context::new(&SHA512);
        for part in parts {
            context.update(part);
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(context.finish().as_ref());
        out
    };
    // Step 4-8: digest B.
    let b = digest(&[password, salt, password]);
    // Step 1-3, 9-12: digest A.
    let mut context = Context::new(&SHA512);
    context.update(password);
    context.update(salt);
    let mut n = password.len();
    while n > 64 {
        context.update(&b);
        n -= 64;
    }
    context.update(&b[..n]);
    let mut n = password.len();
    while n > 0 {
        if n & 1 == 1 {
            context.update(&b);
        } else {
            context.update(password);
        }
        n >>= 1;
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(context.finish().as_ref());
    // Step 13-16: P, from DP.
    let mut context = Context::new(&SHA512);
    for _ in 0..password.len() {
        context.update(password);
    }
    let dp = context.finish();
    let p: Vec<u8> = dp
        .as_ref()
        .iter()
        .cycle()
        .take(password.len())
        .copied()
        .collect();
    // Step 17-20: S, from DS.
    let mut context = Context::new(&SHA512);
    for _ in 0..16 + usize::from(a[0]) {
        context.update(salt);
    }
    let ds = context.finish();
    let s: Vec<u8> = ds
        .as_ref()
        .iter()
        .cycle()
        .take(salt.len())
        .copied()
        .collect();
    // Step 21: the rounds.
    let mut c = a;
    for i in 0..rounds {
        let mut context = Context::new(&SHA512);
        if i % 2 == 1 {
            context.update(&p);
        } else {
            context.update(&c);
        }
        if i % 3 != 0 {
            context.update(&s);
        }
        if i % 7 != 0 {
            context.update(&p);
        }
        if i % 2 == 1 {
            context.update(&c);
        } else {
            context.update(&p);
        }
        c.copy_from_slice(context.finish().as_ref());
    }
    // Step 22: the result, in the crypt alphabet, bytes in Drepper's order.
    const ORDER: [(usize, usize, usize); 21] = [
        (0, 21, 42),
        (22, 43, 1),
        (44, 2, 23),
        (3, 24, 45),
        (25, 46, 4),
        (47, 5, 26),
        (6, 27, 48),
        (28, 49, 7),
        (50, 8, 29),
        (9, 30, 51),
        (31, 52, 10),
        (53, 11, 32),
        (12, 33, 54),
        (34, 55, 13),
        (56, 14, 35),
        (15, 36, 57),
        (37, 58, 16),
        (59, 17, 38),
        (18, 39, 60),
        (40, 61, 19),
        (62, 20, 41),
    ];
    let mut encoded = String::with_capacity(86);
    let mut push = |value: u32, chars: usize| {
        let mut v = value;
        for _ in 0..chars {
            encoded.push(CRYPT_ALPHABET[(v & 0x3f) as usize] as char);
            v >>= 6;
        }
    };
    for (x, y, z) in ORDER {
        push(
            (u32::from(c[x]) << 16) | (u32::from(c[y]) << 8) | u32::from(c[z]),
            4,
        );
    }
    push(u32::from(c[63]), 2);
    let salt = String::from_utf8_lossy(salt);
    if rounds == ROUNDS {
        format!("$6${salt}${encoded}")
    } else {
        format!("$6$rounds={rounds}${salt}${encoded}")
    }
}

/// The salt and rounds of a `$6$` hash, to check a password against it.
#[cfg(test)]
fn parts(hash: &str) -> Result<(String, usize)> {
    let rest = hash.strip_prefix("$6$").context("not a $6$ hash")?;
    let (rounds, rest) = match rest.strip_prefix("rounds=") {
        Some(r) => {
            let (n, rest) = r.split_once('$').context("no salt")?;
            (n.parse()?, rest)
        }
        None => (ROUNDS, rest),
    };
    let (salt, _) = rest.split_once('$').context("no hash")?;
    Ok((salt.to_owned(), rounds))
}

/// Whether `password` matches `hash`, as nginx's `crypt()` would decide.
#[cfg(test)]
pub fn verify(password: &str, hash: &str) -> bool {
    match parts(hash) {
        Ok((salt, rounds)) => sha512_crypt(password.as_bytes(), salt.as_bytes(), rounds) == hash,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests;
