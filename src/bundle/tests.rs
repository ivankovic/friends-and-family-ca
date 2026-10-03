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
//! The bundles are opened by the programs devices use, or the nearest stand-ins: `openssl pkcs12`
//! for the `.p12`, Python's `plistlib` for the profile.

use std::process::Command;

use time::OffsetDateTime;

use super::*;
use crate::ca::{self, Key};
use crate::ledger::Holder;
use crate::store::Store;

fn issued(dir: &std::path::Path, person: &str, device: &str) -> (Ca, Issued) {
    let ca = Ca::create(
        &Store::new(dir.join("state")),
        "Test family",
        OffsetDateTime::now_utc(),
        ca::DEFAULT_CA_VALIDITY,
    )
    .unwrap();
    let issued = ca
        .issue(
            Holder::Device { person, device },
            Key::Generate,
            OffsetDateTime::now_utc(),
            ca::DEFAULT_CLIENT_VALIDITY,
        )
        .unwrap();
    (ca, issued)
}

/// `openssl pkcs12` on `p12` with `password` and extra arguments: what it printed, if it worked.
fn openssl_pkcs12(
    dir: &std::path::Path,
    p12: &[u8],
    password: &str,
    args: &[&str],
) -> Result<String, String> {
    let file = dir.join("bundle.p12");
    std::fs::write(&file, p12).unwrap();
    let output = Command::new("openssl")
        .arg("pkcs12")
        .arg("-in")
        .arg(&file)
        .args(["-passin", &format!("pass:{password}")])
        .args(args)
        .output()
        .expect("these tests need the `openssl` command");
    let printed = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(printed)
    } else {
        Err(printed)
    }
}

#[test]
fn the_p12_holds_the_certificate_and_its_key_in_the_encryption_every_device_takes() {
    let dir = crate::test_dir();
    let (ca, issued) = issued(dir.path(), "Anna", "phone");
    let bundle = make(&ca, &issued, "anna-phone").unwrap();
    let info = openssl_pkcs12(
        dir.path(),
        &bundle.p12,
        &bundle.password,
        &["-info", "-noout"],
    )
    .unwrap();
    assert!(info.contains("MAC: sha1"), "{info}");
    assert_eq!(
        info.matches("pbeWithSHA1And3-KeyTripleDES-CBC").count(),
        2,
        "{info}"
    );
    let contents = openssl_pkcs12(dir.path(), &bundle.p12, &bundle.password, &["-nodes"]).unwrap();
    assert_eq!(
        contents.matches("BEGIN CERTIFICATE").count(),
        1,
        "the client certificate only, no CA:\n{contents}"
    );
    let certificate = &issued.certificate_pem;
    let body = certificate.lines().nth(1).unwrap();
    assert!(contents.contains(body), "the issued certificate");
    assert!(
        contents.contains("friendlyName: Anna (phone)"),
        "{contents}"
    );
    assert!(contents.contains("BEGIN PRIVATE KEY"), "{contents}");
}

#[test]
fn the_p12_needs_its_password() {
    let dir = crate::test_dir();
    let (ca, issued) = issued(dir.path(), "Anna", "phone");
    let bundle = make(&ca, &issued, "anna-phone").unwrap();
    assert!(openssl_pkcs12(dir.path(), &bundle.p12, "wrong", &["-nodes"]).is_err());
}

#[test]
fn passwords_are_easy_to_type_and_never_repeat() {
    let first = password().unwrap();
    assert_eq!(first.len(), 19);
    assert!(first.split('-').all(|g| g.len() == 4), "{first}");
    assert!(!first.contains(['0', 'o', '1', 'l', 'i']), "{first}");
    assert_ne!(first, password().unwrap());
}

/// The profile, read by a real property-list parser.
fn plist(dir: &std::path::Path, profile: &[u8], expression: &str) -> String {
    let file = dir.join("profile.mobileconfig");
    std::fs::write(&file, profile).unwrap();
    let script = format!(
        "import plistlib,sys,base64\np = plistlib.load(open(sys.argv[1], 'rb'))\nprint({expression})"
    );
    let output = Command::new("python3")
        .args(["-c", &script])
        .arg(&file)
        .output()
        .expect("python3");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}

#[test]
fn the_profile_carries_the_p12_and_its_password_for_ios() {
    let dir = crate::test_dir();
    let (ca, issued) = issued(dir.path(), "Anna", "phone");
    let bundle = make(&ca, &issued, "anna-phone").unwrap();
    let payload = "p['PayloadContent'][0]";
    assert_eq!(
        plist(
            dir.path(),
            &bundle.mobileconfig,
            &format!("{payload}['PayloadType']")
        ),
        "com.apple.security.pkcs12"
    );
    assert_eq!(
        plist(
            dir.path(),
            &bundle.mobileconfig,
            &format!("{payload}['Password']")
        ),
        bundle.password
    );
    assert_eq!(
        plist(
            dir.path(),
            &bundle.mobileconfig,
            &format!("base64.b64encode({payload}['PayloadContent']).decode()")
        ),
        STANDARD.encode(&bundle.p12)
    );
    assert_eq!(
        plist(dir.path(), &bundle.mobileconfig, "p['PayloadIdentifier']"),
        "ffca.test-family.anna-phone"
    );
    assert_eq!(
        plist(dir.path(), &bundle.mobileconfig, "p['PayloadDisplayName']"),
        "Test family: Anna (phone)"
    );
    assert_eq!(
        plist(dir.path(), &bundle.mobileconfig, "len(p['PayloadContent'])"),
        "1",
        "no CA payload"
    );
}

#[test]
fn names_are_escaped_in_the_profile() {
    let dir = crate::test_dir();
    let (ca, issued) = issued(dir.path(), "Anna & <Ben>", "\"phone\"");
    let bundle = make(&ca, &issued, "anna-ben-phone").unwrap();
    assert_eq!(
        plist(
            dir.path(),
            &bundle.mobileconfig,
            "p['PayloadContent'][0]['PayloadDisplayName']"
        ),
        "Anna & <Ben> (\"phone\")"
    );
}

#[test]
fn a_renewed_profile_replaces_the_one_before() {
    let dir = crate::test_dir();
    let (ca, issued) = issued(dir.path(), "Anna", "phone");
    let renewed = ca
        .issue(
            Holder::Device {
                person: "Anna",
                device: "phone",
            },
            Key::Generate,
            OffsetDateTime::now_utc(),
            ca::DEFAULT_CLIENT_VALIDITY,
        )
        .unwrap();
    let first = make(&ca, &issued, "anna-phone").unwrap();
    let second = make(&ca, &renewed, "anna-phone").unwrap();
    let id = |b: &Bundle| {
        plist(
            dir.path(),
            &b.mobileconfig,
            "p['PayloadIdentifier'], p['PayloadUUID']",
        )
    };
    let (first, second) = (id(&first), id(&second));
    assert_eq!(
        first.split_whitespace().next(),
        second.split_whitespace().next(),
        "same identifier"
    );
    assert_ne!(first, second, "different UUIDs");
}

#[test]
fn an_agents_own_key_cannot_be_bundled() {
    let dir = crate::test_dir();
    let (ca, mut issued) = issued(dir.path(), "Anna", "phone");
    issued.key_pem = None;
    assert!(
        make(&ca, &issued, "x")
            .unwrap_err()
            .to_string()
            .contains("never the CA's")
    );
}
