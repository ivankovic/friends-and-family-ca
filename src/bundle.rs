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
//! What a device installs: a certificate and its key, packed the way its system takes them.
//!
//! * A PKCS#12 file (`.p12`), protected by a password the person types once, for Android (the
//!   Boox included), Windows, macOS and the browsers. It is made by the `openssl` command with
//!   3DES and a SHA-1 MAC: every importer still accepts those, while OpenSSL 3's default (AES and
//!   SHA-256) is refused by older Android and macOS keychains. It holds the client certificate and
//!   its key only: a CA certificate in the file would be installed as a trusted authority on
//!   Android, which this CA has no business being.
//! * An Apple configuration profile (`.mobileconfig`) for iPhone and iPad, which carries the same
//!   file and its password, so installing it asks for nothing but a confirmation. Its identifier
//!   is the CA's and the device's, so a renewed profile replaces the one before it. It is not
//!   signed: iOS shows it as "unverified", which is accurate.

use std::fmt::Write as _;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::ca::{Ca, Issued};

/// A device's certificate, ready to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Who holds it: "Anna (phone)".
    pub holder: String,
    /// A file name without extension: "anna-phone".
    pub stem: String,
    /// The PKCS#12 file's password.
    pub password: String,
    pub p12: Vec<u8>,
    pub mobileconfig: Vec<u8>,
}

/// Packs `issued`, which must carry the key the CA generated, for `stem`'s device.
pub fn make(ca: &Ca, issued: &Issued, stem: &str) -> Result<Bundle> {
    let key = issued
        .key_pem
        .as_deref()
        .context("this certificate's key was never the CA's to hand over")?;
    let password = password()?;
    let p12 = pkcs12(&issued.certificate_pem, key, &issued.holder, &password)?;
    let identifier = format!(
        "ffca.{}.{}",
        identifier_part(ca.name()),
        identifier_part(stem)
    );
    let mobileconfig = mobileconfig(
        ca.name(),
        &issued.holder,
        stem,
        &identifier,
        &password,
        &p12,
    )?;
    Ok(Bundle {
        holder: issued.holder.clone(),
        stem: stem.to_owned(),
        password,
        p12,
        mobileconfig,
    })
}

/// A password to type on a phone: four groups of four letters and digits, none that look alike
/// (no 0/o, 1/l/i). About 79 bits.
fn password() -> Result<String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness available: {e}"))?;
    let mut password = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            password.push('-');
        }
        // 256 % 31 leaves a bias of under 3% on a few characters; harmless at 79 bits.
        password.push(char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]));
    }
    Ok(password)
}

fn pkcs12(certificate: &str, key: &str, name: &str, password: &str) -> Result<Vec<u8>> {
    let dir = tempfile::tempdir().context("cannot make a temporary folder")?;
    let key_file = dir.path().join("key.pem");
    let certificate_file = dir.path().join("certificate.pem");
    let out = dir.path().join("bundle.p12");
    std::fs::write(&key_file, key)?;
    std::fs::write(&certificate_file, certificate)?;
    let output = Command::new("openssl")
        .args(["pkcs12", "-export"])
        .arg("-inkey")
        .arg(&key_file)
        .arg("-in")
        .arg(&certificate_file)
        .args(["-name", name])
        .args([
            "-certpbe",
            "PBE-SHA1-3DES",
            "-keypbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
        ])
        // The password reaches openssl through its environment, not its command line, which
        // other users can read in the process list.
        .args(["-passout", "env:FFCA_P12_PASSWORD"])
        .env("FFCA_P12_PASSWORD", password)
        .arg("-out")
        .arg(&out)
        .output()
        .context("cannot run `openssl`, which makes the .p12 files")?;
    if !output.status.success() {
        bail!(
            "openssl pkcs12 failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(std::fs::read(&out)?)
}

fn mobileconfig(
    ca: &str,
    holder: &str,
    stem: &str,
    identifier: &str,
    password: &str,
    p12: &[u8],
) -> Result<Vec<u8>> {
    let data = STANDARD.encode(p12);
    let mut wrapped = String::new();
    for line in data.as_bytes().chunks(64) {
        let _ = writeln!(wrapped, "        {}", std::str::from_utf8(line)?);
    }
    let x = xml_escape;
    let profile = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>{identifier}.certificate</string>
            <key>PayloadUUID</key>
            <string>{certificate_uuid}</string>
            <key>PayloadDisplayName</key>
            <string>{holder}</string>
            <key>PayloadCertificateFileName</key>
            <string>{stem}.p12</string>
            <key>Password</key>
            <string>{password}</string>
            <key>PayloadContent</key>
            <data>
{wrapped}            </data>
        </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>{identifier}</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadDisplayName</key>
    <string>{ca}: {holder}</string>
    <key>PayloadDescription</key>
    <string>A client certificate for {holder}, from {ca}. It lets this device into the sites that ask for one.</string>
    <key>PayloadOrganization</key>
    <string>{ca}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
</dict>
</plist>
"#,
        identifier = x(identifier),
        certificate_uuid = uuid()?,
        profile_uuid = uuid()?,
        holder = x(holder),
        stem = x(stem),
        password = x(password),
        ca = x(ca),
    );
    Ok(profile.into_bytes())
}

/// A random (version 4) UUID, as profiles name their payloads.
fn uuid() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow!("no randomness available: {e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|byte| format!("{byte:02X}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// A piece of a reverse-DNS identifier: lowercase letters, digits and hyphens.
fn identifier_part(text: &str) -> String {
    let mut part = String::new();
    for c in text.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            part.push(c);
        } else if !part.is_empty() && !part.ends_with('-') {
            part.push('-');
        }
    }
    let part = part.trim_end_matches('-');
    if part.is_empty() {
        "x".to_owned()
    } else {
        part.to_owned()
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests;
