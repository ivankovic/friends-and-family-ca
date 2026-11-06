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

use super::*;

#[test]
fn sha512_crypt_matches_the_specifications_test_vectors() {
    // From Drepper's "Unix crypt using SHA-256 and SHA-512", the SHA-512 tests.
    assert_eq!(
        sha512_crypt(b"Hello world!", b"saltstring", 5000),
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    );
    assert_eq!(
        sha512_crypt(b"Hello world!", b"saltstringsaltstring", 10000),
        "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
    );
    // The specification writes `rounds=5000$` when it was asked for; the hash is the same.
    assert_eq!(
        sha512_crypt(b"This is just a test", b"toolongsaltstring", 5000),
        "$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
    );
}

#[test]
fn sha512_crypt_agrees_with_openssl() {
    // `openssl passwd -6` is a second implementation of the same function; skipped without it.
    // Not for an empty password, for which it prints `<NULL>` instead of a hash.
    for (password, salt) in [
        ("correct horse", "AbCdEfGh12345678"),
        ("ü€ long password with spaces and 33 chars", "./09azAZ"),
    ] {
        let Ok(output) = std::process::Command::new("openssl")
            .args(["passwd", "-6", "-salt", salt, password])
            .output()
        else {
            return;
        };
        if !output.status.success() {
            return;
        }
        let expected = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            sha512_crypt(password.as_bytes(), salt.as_bytes(), 5000),
            expected.trim()
        );
    }
}

#[test]
fn a_hash_checks_its_password_and_no_other() {
    let hash = hash("correct horse battery").unwrap();
    assert!(hash.starts_with("$6$"));
    assert!(verify("correct horse battery", &hash));
    assert!(!verify("correct horse batterY", &hash));
    // A new salt every time: the same password never hashes the same twice.
    assert_ne!(hash, super::hash("correct horse battery").unwrap());
}

#[test]
fn a_generated_password_is_long_and_easy_to_type() {
    let a = generate().unwrap();
    assert_eq!(a.len(), GENERATED_LENGTH);
    assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(!a.contains(['0', 'O', 'o', '1', 'l', 'I']));
    assert_ne!(a, generate().unwrap());
}

#[test]
fn names_that_could_break_a_password_file_or_a_pattern_are_refused() {
    for bad in [
        "",
        "  ",
        "a:b",
        "a b",
        "a\nb",
        "ä",
        "a|b",
        "a)b",
        "a$b",
        "a\"b",
        &"x".repeat(65),
    ] {
        assert!(checked_name(bad).is_err(), "{bad:?}");
    }
    for good in ["boox", "Anna.K", "scan_1", "marko@home", "a-b"] {
        assert_eq!(checked_name(good).unwrap(), good);
    }
    assert_eq!(checked_name("  boox ").unwrap(), "boox");
}

#[test]
fn users_are_added_once_and_their_passwords_shown_once() {
    let mut users = Users::default();
    let generated = users.add("boox", None).unwrap();
    assert!(verify(&generated, &users.get("boox").unwrap().hash));
    let chosen = users.add("anna", Some("a long enough one")).unwrap();
    assert_eq!(chosen, "a long enough one");
    assert!(
        users
            .add("boox", None)
            .unwrap_err()
            .to_string()
            .contains("taken")
    );
    assert!(users.add("ben", Some("short")).is_err());
    assert_eq!(users.names().collect::<Vec<_>>(), ["anna", "boox"]);
}

#[test]
fn a_new_password_replaces_the_old() {
    let mut users = Users::default();
    let old = users.add("boox", None).unwrap();
    let new = users.set_password("boox", None).unwrap();
    let hash = &users.get("boox").unwrap().hash;
    assert!(verify(&new, hash));
    assert!(!verify(&old, hash));
    assert!(users.set_password("nobody", None).is_err());
}

#[test]
fn a_password_file_lists_the_names_asked_for_and_refuses_unknown_ones() {
    let mut users = Users::default();
    users.add("anna", None).unwrap();
    users.add("boox", None).unwrap();
    let file = users.password_file(&["boox".to_owned()]).unwrap();
    assert_eq!(file.lines().count(), 1);
    let (name, hash) = file.trim_end().split_once(':').unwrap();
    assert_eq!(name, "boox");
    assert_eq!(hash, users.get("boox").unwrap().hash);
    assert!(users.password_file(&["nobody".to_owned()]).is_err());
    assert_eq!(users.password_file(&[]).unwrap(), "");
}

#[test]
fn users_are_kept_in_the_cas_folder_its_owners_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::test_dir();
    let store = Store::new(dir.path());
    assert_eq!(Users::load(&store).unwrap(), Users::default());
    let mut users = Users::default();
    users.add("boox", None).unwrap();
    users.save(&store).unwrap();
    assert_eq!(Users::load(&store).unwrap(), users);
    let mode = std::fs::metadata(store.path(FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_users_file_with_a_bad_name_or_hash_is_refused() {
    let dir = crate::test_dir();
    let store = Store::new(dir.path());
    let changed = "2026-11-06T12:00:00Z";
    store
        .write(
            FILE,
            format!("[[user]]\nname = \"a:b\"\nhash = \"$6$x$y\"\nchanged = {changed}\n")
                .as_bytes(),
            PRIVATE,
        )
        .unwrap();
    assert!(Users::load(&store).is_err());
    store
        .write(
            FILE,
            format!("[[user]]\nname = \"ab\"\nhash = \"plain\"\nchanged = {changed}\n").as_bytes(),
            PRIVATE,
        )
        .unwrap();
    assert!(Users::load(&store).is_err());
}
