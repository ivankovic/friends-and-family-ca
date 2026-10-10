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
use time::Duration;
use time::macros::datetime;

use super::*;

const NOW: OffsetDateTime = datetime!(2026-10-03 12:00 UTC);

fn anna(device: &'static str) -> Holder<'static> {
    Holder::Device {
        person: "Anna",
        device,
    }
}

/// Records a certificate for `holder` the way the CA does, valid for a year from [`NOW`].
fn issue(ledger: &mut Ledger, holder: Holder) -> Serial {
    let place = ledger.place_for_issue(holder).unwrap();
    let serial = Serial::random().unwrap();
    ledger.at_mut(place).certificates.push(Certificate {
        serial,
        not_before: NOW,
        not_after: NOW + Duration::days(365),
        revoked: None,
        reason: None,
    });
    serial
}

fn status(ledger: &Ledger, serial: Serial) -> Status {
    let (_, certificate) = ledger.find(&serial.to_string()).unwrap();
    certificate.status(NOW)
}

#[test]
fn serial_round_trips_through_hex() {
    let serial = Serial::random().unwrap();
    assert_eq!(serial.to_string().parse::<Serial>().unwrap(), serial);
}

#[test]
fn random_serials_are_positive_and_full_length() {
    for _ in 0..1000 {
        let serial = Serial::random().unwrap();
        assert!(serial.0[0] & 0x80 == 0, "negative: {serial}");
        assert!(
            serial.0[0] != 0,
            "a leading zero byte would shorten it: {serial}"
        );
    }
}

#[test]
fn serial_rejects_wrong_length_and_non_hex() {
    assert!("abc".parse::<Serial>().is_err());
    assert!("zz".repeat(16).parse::<Serial>().is_err());
}

#[test]
fn a_person_has_many_devices_and_a_device_many_certificates() {
    let mut ledger = Ledger::default();
    issue(&mut ledger, anna("phone"));
    issue(&mut ledger, anna("laptop"));
    issue(
        &mut ledger,
        Holder::Device {
            person: "anna",
            device: "PHONE",
        },
    );
    assert_eq!(ledger.people.len(), 1, "names match without case");
    let anna = &ledger.people[0];
    assert_eq!(anna.name, "Anna", "the first spelling stays");
    assert_eq!(anna.devices.len(), 2);
    assert_eq!(anna.devices[0].certificates.len(), 2);
}

#[test]
fn the_ledger_round_trips_through_nested_toml() {
    let dir = crate::test_dir();
    let store = Store::new(dir.path());
    let mut ledger = Ledger {
        crl_number: 7,
        ..Ledger::default()
    };
    let lost = issue(&mut ledger, anna("phone"));
    issue(&mut ledger, anna("phone"));
    issue(&mut ledger, Holder::Agent("backup"));
    ledger
        .revoke(Target::Certificate(lost), Reason::Lost, NOW)
        .unwrap();
    ledger.save(&store).unwrap();
    assert_eq!(Ledger::load(&store).unwrap(), ledger);
    let text = store.read(FILE).unwrap();
    for expected in [
        "[[person]]\nname = \"Anna\"",
        "[[person.device]]\nname = \"phone\"",
        "[[person.device.certificate]]",
        "reason = \"lost\"",
        "[[agent]]\nname = \"backup\"",
        "[[agent.certificate]]",
    ] {
        assert!(text.contains(expected), "no {expected:?} in\n{text}");
    }
}

#[test]
fn a_missing_ledger_is_empty() {
    let dir = crate::test_dir();
    assert_eq!(
        Ledger::load(&Store::new(dir.path())).unwrap(),
        Ledger::default()
    );
}

#[test]
fn a_damaged_ledger_is_an_error_naming_the_file() {
    let dir = crate::test_dir();
    let store = Store::new(dir.path());
    store
        .write(FILE, b"crl_number = \"seven\"", PRIVATE)
        .unwrap();
    let error = Ledger::load(&store).unwrap_err().to_string();
    assert!(error.contains("ledger.toml is damaged"), "{error}");
}

#[test]
fn people_and_agents_share_one_namespace() {
    let mut ledger = Ledger::default();
    issue(&mut ledger, anna("phone"));
    issue(&mut ledger, Holder::Agent("backup"));
    let error = ledger.place_for_issue(Holder::Agent("ANNA")).unwrap_err();
    assert!(error.to_string().contains("is a person's name"), "{error}");
    let error = ledger
        .place_for_issue(Holder::Device {
            person: "Backup",
            device: "phone",
        })
        .unwrap_err();
    assert!(error.to_string().contains("is an agent's name"), "{error}");
}

#[test]
fn names_must_be_printable_and_short() {
    let mut ledger = Ledger::default();
    let mut try_person = |person: &str| {
        ledger
            .place_for_issue(Holder::Device {
                person,
                device: "phone",
            })
            .err()
    };
    assert!(
        try_person(" ")
            .unwrap()
            .to_string()
            .contains("cannot be empty")
    );
    assert!(
        try_person("Anna\nCN=admin")
            .unwrap()
            .to_string()
            .contains("control character")
    );
    assert!(
        try_person(&"a".repeat(65))
            .unwrap()
            .to_string()
            .contains("longer than")
    );
    assert!(
        try_person("Ana Marija Čolić").is_none(),
        "non-ASCII names are fine"
    );
}

#[test]
fn find_takes_a_unique_prefix_in_any_case() {
    let mut ledger = Ledger::default();
    let first = issue(&mut ledger, anna("phone"));
    let mut second = Serial::random().unwrap();
    second.0[..2].copy_from_slice(&first.0[..2]);
    second.0[2] = first.0[2] ^ 0xff;
    let place = ledger.place(anna("phone")).unwrap();
    let mut copy = ledger.at(place).certificates[0].clone();
    copy.serial = second;
    ledger.at_mut(place).certificates.push(copy);

    let (holder, found) = ledger.find(&first.to_string()[..6].to_uppercase()).unwrap();
    assert_eq!((holder, found.serial), (anna("phone"), first));
    let ambiguous = ledger.find(&first.to_string()[..4]).unwrap_err();
    assert!(
        ambiguous.to_string().contains("more than one"),
        "{ambiguous}"
    );
    assert!(ledger.find(" ").is_err());
}

#[test]
fn revoking_a_device_leaves_the_persons_other_devices_alone() {
    let mut ledger = Ledger::default();
    let phone = issue(&mut ledger, anna("phone"));
    let laptop = issue(&mut ledger, anna("laptop"));
    let revoked = ledger
        .revoke(Target::Holder(anna("Phone")), Reason::Lost, NOW)
        .unwrap();
    assert_eq!(
        revoked,
        [Revoked {
            holder: "Anna (phone)".into(),
            serial: phone
        }]
    );
    assert_eq!(status(&ledger, phone), Status::Revoked);
    assert_eq!(status(&ledger, laptop), Status::Valid);
    assert!(
        ledger
            .at(ledger.place(anna("phone")).unwrap())
            .retired
            .is_none(),
        "lost is not retired"
    );
}

#[test]
fn revoking_a_person_revokes_every_device() {
    let mut ledger = Ledger::default();
    let phone = issue(&mut ledger, anna("phone"));
    let laptop = issue(&mut ledger, anna("laptop"));
    let agent = issue(&mut ledger, Holder::Agent("backup"));
    let revoked = ledger
        .revoke(Target::Person("anna"), Reason::Retired, NOW)
        .unwrap();
    assert_eq!(revoked.len(), 2);
    assert_eq!(status(&ledger, phone), Status::Revoked);
    assert_eq!(status(&ledger, laptop), Status::Revoked);
    assert_eq!(status(&ledger, agent), Status::Valid);
    assert!(
        ledger.people[0]
            .devices
            .iter()
            .all(|d| d.retired == Some(NOW))
    );
}

#[test]
fn a_retired_holder_is_issued_nothing() {
    let mut ledger = Ledger::default();
    issue(&mut ledger, Holder::Agent("backup"));
    ledger
        .revoke(
            Target::Holder(Holder::Agent("backup")),
            Reason::Retired,
            NOW,
        )
        .unwrap();
    let error = ledger.place_for_issue(Holder::Agent("backup")).unwrap_err();
    assert!(error.to_string().contains("was retired"), "{error}");
}

#[test]
fn replacing_revokes_only_what_is_named() {
    let mut ledger = Ledger::default();
    let old = issue(&mut ledger, anna("phone"));
    let new = issue(&mut ledger, anna("phone"));
    ledger
        .revoke(Target::Certificate(old), Reason::Replaced, NOW)
        .unwrap();
    assert_eq!(status(&ledger, new), Status::Valid);
    let place = ledger.place(anna("phone")).unwrap();
    assert_eq!(ledger.at(place).current(NOW).unwrap().serial, new);
}

#[test]
fn revoking_twice_or_nothing_is_refused() {
    let mut ledger = Ledger::default();
    let phone = issue(&mut ledger, anna("phone"));
    ledger
        .revoke(Target::Certificate(phone), Reason::Lost, NOW)
        .unwrap();
    let again = ledger
        .revoke(Target::Certificate(phone), Reason::Lost, NOW)
        .unwrap_err();
    assert!(again.to_string().contains("already revoked"), "{again}");
    let nothing = ledger
        .revoke(Target::Holder(anna("phone")), Reason::Lost, NOW)
        .unwrap_err();
    assert!(
        nothing.to_string().contains("no valid certificate"),
        "{nothing}"
    );
    let nobody = ledger
        .revoke(Target::Person("Ben"), Reason::Lost, NOW)
        .unwrap_err();
    assert!(
        nobody.to_string().contains("no person called Ben"),
        "{nobody}"
    );
    let unknown = ledger
        .revoke(Target::Certificate(Serial([1; 16])), Reason::Lost, NOW)
        .unwrap_err();
    assert!(
        unknown.to_string().contains("no certificate has"),
        "{unknown}"
    );
}

#[test]
fn expired_certificates_are_not_revoked() {
    let mut ledger = Ledger::default();
    let phone = issue(&mut ledger, anna("phone"));
    let later = NOW + Duration::days(400);
    let error = ledger
        .revoke(Target::Holder(anna("phone")), Reason::Lost, later)
        .unwrap_err();
    assert!(
        error.to_string().contains("no valid certificate"),
        "{error}"
    );
    assert_eq!(ledger.find(&phone.to_string()).unwrap().1.revoked, None);
}

#[test]
fn renaming_keeps_the_certificates_and_checks_the_namespace() {
    let mut ledger = Ledger::default();
    let phone = issue(&mut ledger, anna("phone"));
    issue(&mut ledger, anna("laptop"));
    issue(&mut ledger, Holder::Agent("backup"));
    ledger.rename(Target::Person("anna"), "Ana").unwrap();
    ledger
        .rename(
            Target::Holder(Holder::Device {
                person: "Ana",
                device: "phone",
            }),
            "old phone",
        )
        .unwrap();
    let (holder, _) = ledger.find(&phone.to_string()).unwrap();
    assert_eq!(
        holder,
        Holder::Device {
            person: "Ana",
            device: "old phone"
        }
    );

    let taken =
        |ledger: &mut Ledger, target, name| ledger.rename(target, name).unwrap_err().to_string();
    assert!(taken(&mut ledger, Target::Person("Ana"), "BACKUP").contains("is taken"));
    assert!(
        taken(&mut ledger, Target::Holder(Holder::Agent("backup")), "ana").contains("is taken")
    );
    let device = Target::Holder(Holder::Device {
        person: "Ana",
        device: "laptop",
    });
    assert!(taken(&mut ledger, device, "Old Phone").contains("already has a device"));
    ledger.rename(device, "Laptop").unwrap();
}

#[test]
fn every_certificate_is_listed_with_its_holder() {
    let mut ledger = Ledger::default();
    let phone = issue(&mut ledger, anna("phone"));
    let agent = issue(&mut ledger, Holder::Agent("backup"));
    let all: Vec<_> = ledger.certificates().map(|(h, c)| (h, c.serial)).collect();
    assert_eq!(
        all,
        [(anna("phone"), phone), (Holder::Agent("backup"), agent)]
    );
}

/// Two certificates overlap while a replacement is installed; "replaced" retires the old one only.
#[test]
fn replacing_a_holder_spares_its_newest_certificate() {
    let mut ledger = Ledger::default();
    let place = ledger.place_for_issue(anna("phone")).unwrap();
    let mut certificate = |days: i64| {
        let serial = Serial::random().unwrap();
        ledger.at_mut(place).certificates.push(Certificate {
            serial,
            not_before: NOW + Duration::days(days),
            not_after: NOW + Duration::days(days + 365),
            revoked: None,
            reason: None,
        });
        serial
    };
    let oldest = certificate(-20);
    let older = certificate(-10);
    let newest = certificate(0);
    let revoked = ledger
        .revoke(Target::Holder(anna("phone")), Reason::Replaced, NOW)
        .unwrap();
    let serials: Vec<Serial> = revoked.iter().map(|r| r.serial).collect();
    assert_eq!(serials, [oldest, older]);
    assert_eq!(status(&ledger, newest), Status::Valid);
    let again = ledger
        .revoke(Target::Holder(anna("phone")), Reason::Replaced, NOW)
        .unwrap_err();
    assert!(
        again.to_string().contains("no older certificate"),
        "{again}"
    );
}

/// Person "A" with device "B (C" and person "A (B" with device "C" would both be `CN=A (B (C)`.
#[test]
fn a_person_or_device_name_cannot_hold_parentheses() {
    let mut ledger = Ledger::default();
    for (person, device) in [("A", "B (C"), ("A (B", "C"), ("Anna", "phone)")] {
        let error = ledger
            .place_for_issue(Holder::Device { person, device })
            .unwrap_err();
        assert!(error.to_string().contains("parentheses"), "{error}");
    }
    issue(&mut ledger, anna("phone"));
    let error = ledger
        .rename(Target::Person("Anna"), "Anna (mum)")
        .unwrap_err();
    assert!(error.to_string().contains("parentheses"), "{error}");
    ledger
        .place_for_issue(Holder::Agent("backup (nas)"))
        .unwrap();
}
