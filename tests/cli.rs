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
//! The `ffca` command line, end to end: the real binary, its exit codes, what it prints, the
//! files it writes, and whether OpenSSL accepts the result.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Ffca, openssl_request, openssl_verify};

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_creates_the_ca_and_says_where_to_point_the_web_server() {
    let ffca = Ffca::new();
    let printed = ffca.ok(&["init", "--name", "Test family", "--years", "5"]);
    assert!(
        printed.contains("Created the CA \"Test family\""),
        "{printed}"
    );
    assert!(
        printed.contains(&ffca.ca_certificate().display().to_string()),
        "{printed}"
    );
    assert!(
        printed.contains(&ffca.crl().display().to_string()),
        "{printed}"
    );
    assert_eq!(mode(&ffca.state), 0o700);
    assert_eq!(mode(&ffca.state.join("ca.key")), 0o600);
    let (code, error) = ffca.fails(&["init", "--name", "Again"]);
    assert_eq!(code, 1);
    assert!(error.contains("already holds a CA"), "{error}");
}

#[test]
fn every_command_but_init_needs_a_ca_and_says_how_to_make_one() {
    let ffca = Ffca::new();
    for args in [
        &["list"][..],
        &["issue", "--person", "Anna", "--device", "phone"],
        &["revoke", "--person", "Anna", "--reason", "lost"],
        &["rename", "--person", "Anna", "--to", "Ana"],
        &["crl-refresh"],
    ] {
        let (code, error) = ffca.fails(args);
        assert_eq!(code, 1, "{args:?}");
        assert!(error.contains("ffca init"), "{args:?}: {error}");
    }
}

#[test]
fn the_state_dir_flag_wins_over_the_environment() {
    let ffca = Ffca::initialised();
    let elsewhere = common::test_dir();
    let state = elsewhere.path().join("other");
    let printed = ffca.ok(&[
        "--state-dir",
        state.to_str().unwrap(),
        "init",
        "--name",
        "Other",
    ]);
    assert!(printed.contains(&state.display().to_string()), "{printed}");
    assert!(state.join("ca.crt").exists());
}

#[test]
fn issuing_writes_a_certificate_openssl_accepts_and_a_private_key() {
    let ffca = Ffca::initialised();
    let printed = ffca.ok(&["issue", "--person", "Anna", "--device", "work laptop"]);
    assert!(
        printed.contains("to Anna (work laptop), valid until"),
        "{printed}"
    );
    let certificate = ffca.out.join("anna-work-laptop.crt");
    let key = ffca.out.join("anna-work-laptop.key");
    assert_eq!(mode(&key), 0o600);
    assert!(
        std::fs::read_to_string(&key)
            .unwrap()
            .contains("PRIVATE KEY")
    );
    openssl_verify(&ffca, &certificate).unwrap();
}

#[test]
fn an_agent_with_a_signing_request_gets_a_certificate_for_its_own_key() {
    let ffca = Ffca::initialised();
    let (key, request) = openssl_request(ffca.dir.path(), "backup");
    let printed = ffca.ok(&[
        "issue",
        "--agent",
        "backup",
        "--csr",
        request.to_str().unwrap(),
    ]);
    assert!(printed.contains("to backup (agent)"), "{printed}");
    assert!(!printed.contains("Key:"), "no key for a request: {printed}");
    assert!(!ffca.out.join("backup.key").exists());
    let certificate = ffca.out.join("backup.crt");
    openssl_verify(&ffca, &certificate).unwrap();
    let public = |args: &[&str]| {
        let output = std::process::Command::new("openssl")
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(
        public(&[
            "x509",
            "-in",
            certificate.to_str().unwrap(),
            "-noout",
            "-pubkey"
        ]),
        public(&["pkey", "-in", key.to_str().unwrap(), "-pubout"]),
        "the certificate carries the agent's own key"
    );
}

#[test]
fn issuing_refuses_without_writing_or_recording_anything() {
    let ffca = Ffca::initialised();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    let cases: [(&[&str], &str); 4] = [
        (&["issue", "--person", "Anna"], "--device"),
        (&["issue", "--agent", "anna"], "is a person's name"),
        (
            &[
                "issue", "--person", "Ben", "--device", "phone", "--csr", "x.csr",
            ],
            "--csr is for agents",
        ),
        (
            &["issue", "--person", "Anna", "--device", "phone"],
            "File exists",
        ),
    ];
    for (args, expected) in cases {
        let (code, error) = ffca.fails(args);
        assert_eq!(code, 1, "{args:?}");
        assert!(error.contains(expected), "{args:?}: {error}");
    }
    let list = ffca.ok(&["list"]);
    assert_eq!(list.matches("valid until").count(), 1, "{list}");
    assert!(!list.contains("Ben"), "{list}");
}

#[test]
fn the_parser_refuses_contradictions_with_usage() {
    let ffca = Ffca::initialised();
    for args in [
        &["issue", "--person", "Anna", "--agent", "backup"][..],
        &["issue", "--device", "phone"],
        &["revoke", "--person", "Anna"],
        &[
            "revoke", "--serial", "ab", "--agent", "backup", "--reason", "lost",
        ],
    ] {
        let (code, error) = ffca.fails(args);
        assert_eq!(code, 2, "{args:?}: {error}");
        assert!(error.contains("Usage:"), "{args:?}: {error}");
    }
}

#[test]
fn revoking_at_each_level_reaches_exactly_what_it_names() {
    let ffca = Ffca::initialised();
    let old_phone = Ffca::serial(&ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]));
    std::fs::rename(
        ffca.out.join("anna-phone.crt"),
        ffca.out.join("old-phone.crt"),
    )
    .unwrap();
    std::fs::remove_file(ffca.out.join("anna-phone.key")).unwrap();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    ffca.ok(&["issue", "--person", "Anna", "--device", "laptop"]);
    ffca.ok(&["issue", "--person", "Ben", "--device", "tablet"]);
    ffca.ok(&["issue", "--agent", "backup"]);

    let printed = ffca.ok(&[
        "revoke",
        "--serial",
        &old_phone[..6],
        "--reason",
        "replaced",
    ]);
    assert!(
        printed.contains(&format!("Revoked Anna (phone) ({old_phone})")),
        "{printed}"
    );
    let printed = ffca.ok(&[
        "revoke", "--person", "anna", "--device", "LAPTOP", "--reason", "lost",
    ]);
    assert!(printed.contains("Revoked Anna (laptop)"), "{printed}");
    let printed = ffca.ok(&["revoke", "--person", "Ben", "--reason", "retired"]);
    assert!(
        printed.contains("Revoked Ben (tablet)") && printed.contains("Retired"),
        "{printed}"
    );

    let verdict = |file: &str| openssl_verify(&ffca, &ffca.out.join(file));
    assert!(
        verdict("old-phone.crt")
            .unwrap_err()
            .contains("certificate revoked")
    );
    assert!(
        verdict("anna-laptop.crt")
            .unwrap_err()
            .contains("certificate revoked")
    );
    assert!(
        verdict("ben-tablet.crt")
            .unwrap_err()
            .contains("certificate revoked")
    );
    verdict("anna-phone.crt").unwrap();
    verdict("backup.crt").unwrap();

    let (code, error) = ffca.fails(&["revoke", "--serial", &old_phone, "--reason", "lost"]);
    assert_eq!(code, 1);
    assert!(error.contains("already revoked"), "{error}");
    let (_, error) = ffca.fails(&["issue", "--person", "Ben", "--device", "tablet"]);
    assert!(error.contains("was retired"), "{error}");
}

#[test]
fn list_shows_people_then_agents_with_their_history() {
    let ffca = Ffca::initialised();
    assert!(ffca.ok(&["list"]).contains("No certificates yet"));
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    ffca.ok(&["issue", "--agent", "backup"]);
    ffca.ok(&["revoke", "--agent", "backup", "--reason", "retired"]);
    let list = ffca.ok(&["list"]);
    let lines: Vec<&str> = list.lines().collect();
    assert_eq!(lines[0], "Anna");
    assert_eq!(lines[1], "  phone");
    assert!(lines[2].contains("valid until"), "{list}");
    assert_eq!(lines[3], "Agents");
    assert!(lines[4].starts_with("  backup, retired "), "{list}");
    assert!(lines[5].ends_with("(retired)"), "{list}");
}

#[test]
fn renaming_reaches_the_ledger_and_the_next_certificate() {
    let ffca = Ffca::initialised();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    ffca.ok(&["issue", "--agent", "backup"]);
    ffca.ok(&["rename", "--person", "anna", "--to", "Ana"]);
    ffca.ok(&[
        "rename",
        "--person",
        "Ana",
        "--device",
        "phone",
        "--to",
        "old phone",
    ]);
    let (code, error) = ffca.fails(&["rename", "--agent", "backup", "--to", "ana"]);
    assert_eq!(code, 1);
    assert!(error.contains("is taken"), "{error}");
    ffca.ok(&["issue", "--person", "Ana", "--device", "old phone"]);
    let subject = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-subject", "-in"])
        .arg(ffca.out.join("ana-old-phone.crt"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(subject.stdout).unwrap().trim(),
        "subject=OU = people, CN = Ana (old phone)"
    );
}

#[test]
fn crl_refresh_signs_a_newer_crl() {
    let ffca = Ffca::initialised();
    let number = || {
        let output = std::process::Command::new("openssl")
            .args(["crl", "-noout", "-crlnumber", "-in"])
            .arg(ffca.crl())
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    assert_eq!(number(), "crlNumber=0x01");
    let printed = ffca.ok(&["crl-refresh"]);
    assert!(
        printed.contains("Signed a new CRL, valid until"),
        "{printed}"
    );
    assert_eq!(number(), "crlNumber=0x02");
}

#[test]
fn a_damaged_ledger_is_reported_and_left_alone() {
    let ffca = Ffca::initialised();
    let ledger = ffca.state.join("ledger.toml");
    std::fs::write(&ledger, "crl_number = \"seven\"").unwrap();
    for args in [
        &["list"][..],
        &["issue", "--agent", "backup"],
        &["crl-refresh"],
    ] {
        let (code, error) = ffca.fails(args);
        assert_eq!(code, 1, "{args:?}");
        assert!(
            error.contains("ledger.toml is damaged"),
            "{args:?}: {error}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(&ledger).unwrap(),
        "crl_number = \"seven\""
    );
}

/// With nginx set up, a new CRL reaches it: copied where nginx reads it, then a test and a reload.
#[test]
fn revoke_and_crl_refresh_hand_the_new_crl_to_nginx() {
    let ffca = Ffca::initialised();
    let nginx = ffca.dir.path().join("nginx");
    let (tested, reloaded) = (
        ffca.dir.path().join("tested"),
        ffca.dir.path().join("reloaded"),
    );
    std::fs::write(
        ffca.state.join("config.toml"),
        format!(
            "[nginx]\nsites = \"{0}/conf.d\"\nca_files = \"{0}/certs\"\nca_files_in_nginx = \"/etc/nginx/certs\"\ntest = \"touch {1}\"\nreload = \"touch {2}\"\n",
            nginx.display(),
            tested.display(),
            reloaded.display()
        ),
    )
    .unwrap();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    let printed = ffca.ok(&[
        "revoke", "--person", "Anna", "--device", "phone", "--reason", "lost",
    ]);
    assert!(printed.contains("nginx reloaded with it."), "{printed}");
    assert!(tested.exists() && reloaded.exists());
    let published = std::fs::read_to_string(nginx.join("certs/ffca.crl")).unwrap();
    assert_eq!(published, std::fs::read_to_string(ffca.crl()).unwrap());
    let printed = ffca.ok(&["crl-refresh"]);
    assert!(printed.contains("nginx reloaded with it."), "{printed}");
    assert_ne!(
        std::fs::read_to_string(nginx.join("certs/ffca.crl")).unwrap(),
        published
    );
}

#[test]
fn a_crl_that_cannot_reach_nginx_fails_the_command() {
    let ffca = Ffca::initialised();
    let nginx = ffca.dir.path().join("nginx");
    std::fs::write(
        ffca.state.join("config.toml"),
        format!(
            "[nginx]\nsites = \"{0}/conf.d\"\nca_files = \"{0}/certs\"\nca_files_in_nginx = \"/etc/nginx/certs\"\ntest = \"false\"\nreload = \"true\"\n",
            nginx.display()
        ),
    )
    .unwrap();
    let (code, error) = ffca.fails(&["crl-refresh"]);
    assert_eq!(code, 1);
    assert!(
        error.contains("the CRL is signed, but nginx still has the previous one"),
        "{error}"
    );
}

#[test]
fn healthz_says_whether_the_enrollment_page_answers() {
    let ffca = Ffca::initialised();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = format!("127.0.0.1:{port}");
    let (code, _) = ffca.fails(&["healthz", "--address", &address]);
    assert_eq!(code, 1, "nothing listens yet");
    let mut serve = ffca
        .command(&["serve", "--listen", &address])
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ffca
        .run(&["healthz", "--address", &address])
        .status
        .success()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "ffca serve never answered"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    serve.kill().unwrap();
    serve.wait().unwrap();
}

/// As a container's first process, the page gets no default handling of SIGTERM; it handles it.
#[test]
fn the_enrollment_page_stops_on_sigterm() {
    let ffca = Ffca::initialised();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = format!("127.0.0.1:{port}");
    let mut serve = ffca
        .command(&["serve", "--listen", &address])
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    while !ffca
        .run(&["healthz", "--address", &address])
        .status
        .success()
    {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let status = std::process::Command::new("kill")
        .args(["-TERM", &serve.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = serve.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "still running after SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
