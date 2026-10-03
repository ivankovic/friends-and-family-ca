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
use time::macros::datetime;

use super::*;
use crate::ledger::Ledger;

const NOW: OffsetDateTime = datetime!(2026-10-03 12:00 UTC);
const ANNA_PHONE: Holder = Holder::Device {
    person: "Anna",
    device: "phone",
};

fn ca(dir: &Path) -> Ca {
    Ca::create(
        &Store::new(dir.join("state")),
        "Test family",
        NOW,
        ca::DEFAULT_CA_VALIDITY,
    )
    .unwrap()
}

fn token(made: &Made) -> String {
    made.link.rsplit('/').next().unwrap().to_owned()
}

fn files(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn status(ca: &Ca, serial: crate::ledger::Serial, now: OffsetDateTime) -> Status {
    ca.ledger()
        .unwrap()
        .find(&serial.to_string())
        .unwrap()
        .1
        .status(now)
}

fn invite_state(ledger: &Ledger) -> InviteState {
    ledger.invites[0].state
}

#[test]
fn an_invite_hands_over_its_bundle_once() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    assert!(
        made.link.starts_with("https://k.example.org/i/"),
        "{}",
        made.link
    );
    let token = token(&made);
    assert_eq!(token.len(), 43);

    let opened = open(&folder, &token, NOW).unwrap();
    assert_eq!(
        (
            opened.ca.as_str(),
            opened.holder.as_str(),
            opened.stem.as_str()
        ),
        ("Test family", "Anna (phone)", "anna-phone")
    );
    assert_eq!(
        open(&folder, &token, NOW).unwrap(),
        opened,
        "opening does not use it up"
    );

    let collected = collect(&folder, &token, NOW, "203.0.113.7 iPhone").unwrap();
    assert_eq!(collected, opened);
    assert_eq!(
        collect(&folder, &token, NOW, "again"),
        Err(Unavailable::Gone)
    );
    assert_eq!(open(&folder, &token, NOW), Err(Unavailable::Gone));
    let id = id(&token).unwrap();
    assert_eq!(files(&folder), [format!("{id}.collected")]);
}

#[test]
fn the_folder_alone_reveals_nothing() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    let token = token(&made);
    let id = id(&token).unwrap();
    let text = fs::read_to_string(folder.join(format!("{id}.invite"))).unwrap();
    assert!(
        !text.contains(&token) && !text.contains("Anna") && !text.contains("PRIVATE"),
        "{text}"
    );
    assert!(!files(&folder).iter().any(|f| f.contains(&token)));
    let other = random_token().unwrap();
    assert_eq!(
        open(&folder, &other, NOW),
        Err(Unavailable::Gone),
        "another token opens nothing"
    );
    assert_eq!(open(&folder, "not a token", NOW), Err(Unavailable::Gone));
}

#[test]
fn an_expired_invite_cannot_be_collected_or_extended() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let token = token(&make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap());
    let later = NOW + VALIDITY + Duration::seconds(1);
    assert_eq!(open(&folder, &token, later), Err(Unavailable::Expired));
    assert_eq!(
        collect(&folder, &token, later, "x"),
        Err(Unavailable::Expired)
    );

    // Someone who can write to the folder pushes the expiry out: the seal no longer opens.
    let file = folder.join(format!("{}.invite", id(&token).unwrap()));
    let mut sealed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    sealed["expires"] = serde_json::json!(later.unix_timestamp() + 86_400);
    fs::write(&file, sealed.to_string()).unwrap();
    assert_eq!(open(&folder, &token, later), Err(Unavailable::Gone));
}

#[test]
fn tend_records_a_collected_invite_and_keeps_its_certificate() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    collect(&folder, &token(&made), NOW, "203.0.113.7 iPhone").unwrap();
    let tended = tend(&ca, &folder, NOW + Duration::hours(1)).unwrap();
    assert_eq!(
        tended,
        Tended {
            collected: vec!["Anna (phone)".into()],
            closed: vec![],
            revoked: false
        }
    );
    let ledger = ca.ledger().unwrap();
    assert_eq!(invite_state(&ledger), InviteState::Collected);
    assert_eq!(
        ledger.invites[0].collected_by.as_deref(),
        Some("203.0.113.7 iPhone")
    );
    assert_eq!(ledger.invites[0].closed, Some(NOW));
    assert_eq!(status(&ca, made.invite.serial, NOW), Status::Valid);
    assert!(
        files(&folder).is_empty(),
        "the receipt is moved into the ledger"
    );
    assert_eq!(
        tend(&ca, &folder, NOW + VALIDITY * 2).unwrap(),
        Tended::default(),
        "nothing more to do"
    );
}

#[test]
fn tend_revokes_what_was_never_collected() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    assert_eq!(
        tend(&ca, &folder, NOW + Duration::hours(23)).unwrap(),
        Tended::default(),
        "still open"
    );
    let later = NOW + VALIDITY;
    let tended = tend(&ca, &folder, later).unwrap();
    assert_eq!(tended.closed, ["Anna (phone)"]);
    assert!(tended.revoked);
    assert_eq!(invite_state(&ca.ledger().unwrap()), InviteState::Expired);
    assert_eq!(status(&ca, made.invite.serial, later), Status::Revoked);
    assert!(files(&folder).is_empty());
}

#[test]
fn cancelling_deletes_the_invite_and_revokes_its_certificate() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    cancel(&ca, &folder, made.invite.serial, NOW).unwrap();
    assert_eq!(invite_state(&ca.ledger().unwrap()), InviteState::Cancelled);
    assert_eq!(status(&ca, made.invite.serial, NOW), Status::Revoked);
    assert_eq!(open(&folder, &token(&made), NOW), Err(Unavailable::Gone));
    assert!(
        cancel(&ca, &folder, made.invite.serial, NOW).is_err(),
        "no longer open"
    );
}

#[test]
fn revoking_the_device_closes_its_invite() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    ca.revoke(Target::Holder(ANNA_PHONE), Reason::Retired, NOW)
        .unwrap();
    let tended = tend(&ca, &folder, NOW).unwrap();
    assert_eq!(tended.closed, ["Anna (phone)"]);
    assert!(!tended.revoked, "it was revoked already");
    assert_eq!(invite_state(&ca.ledger().unwrap()), InviteState::Cancelled);
    assert_eq!(open(&folder, &token(&made), NOW), Err(Unavailable::Gone));
}

#[test]
fn an_invite_is_only_made_for_a_holder_the_ca_would_issue_to() {
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    ca.issue(ANNA_PHONE, Key::Generate, NOW, ca::DEFAULT_CLIENT_VALIDITY)
        .unwrap();
    ca.revoke(Target::Holder(ANNA_PHONE), Reason::Retired, NOW)
        .unwrap();
    let folder = dir.path().join("invites");
    assert!(
        make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW)
            .err()
            .unwrap()
            .to_string()
            .contains("retired")
    );
    assert!(ca.ledger().unwrap().invites.is_empty());
}

#[test]
fn the_folder_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::test_dir();
    let ca = ca(dir.path());
    let folder = dir.path().join("invites");
    let made = make(&ca, &folder, ANNA_PHONE, "k.example.org", NOW).unwrap();
    assert_eq!(
        fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let file = folder.join(format!("{}.invite", id(&token(&made)).unwrap()));
    assert_eq!(
        fs::metadata(file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
