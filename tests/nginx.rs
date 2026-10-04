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
//! The CA against a real nginx: the web server this project exists to protect.
//!
//! Each test starts `nginx:alpine` in a container (podman, or docker if that is what there is)
//! with a site that requires a client certificate over the CA's certificate and CRL, and asks it
//! with `curl`. nginx answers a refused certificate with a bare 400 whatever the reason - also
//! with `ssl_verify_client optional` or `optional_no_ca`, which forgive only a missing
//! certificate and an unknown CA - and writes the reason to its error log, so that is where the
//! tests read OpenSSL's verdict.
//!
//! Set `FFCA_CONTAINER_ENGINE` to choose the engine and `FFCA_NGINX_IMAGE` to choose the image.
//! The first run pulls the image.

#![cfg(target_os = "linux")]

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::{Ffca, openssl_request};
use friends_and_family_ca::ca::Ca;
use friends_and_family_ca::config::{self, Config};
use friends_and_family_ca::ledger::Holder;
use friends_and_family_ca::store::Store;
use friends_and_family_ca::{invite, nginx};
use time::OffsetDateTime;

const IMAGE: &str = "docker.io/library/nginx:alpine";
/// Long enough for a first run to pull the image.
const START_TIMEOUT: Duration = Duration::from_secs(180);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(20);

/// A running nginx container serving the CA in `ffca`; stopped when dropped.
struct Nginx {
    engine: String,
    container: String,
    /// What the container reads: the server's own certificate and key, the configuration, and
    /// copies of the CA's certificate and CRL (the state folder is its owner's only).
    config: tempfile::TempDir,
    /// The site, which requires a client certificate.
    port: u16,
}

impl Nginx {
    fn start(ffca: &Ffca) -> Nginx {
        let body = r#"
    ssl_client_certificate /etc/ffca/ca.crt;
    ssl_crl /etc/ffca/crl.pem;
    server {
        listen 127.0.0.1:PORT ssl;
        ssl_verify_client on;
        location / { return 200 "$ssl_client_s_dn\n"; }
    }"#;
        Nginx::start_with(ffca, body, &[])
    }

    /// nginx with `body` inside its `http` block and `sites` in `/etc/ffca/sites/`; `PORT` in either
    /// is the port it listens on.
    fn start_with(ffca: &Ffca, body: &str, sites: &[(&str, &str)]) -> Nginx {
        let engine = engine();
        let config = common::test_dir();
        let port = free_port();
        let server_key = rcgen::KeyPair::generate().unwrap();
        // One certificate for every name the tests use, as a wildcard would be.
        let names = ["localhost", "books.example.test", "k.example.test"]
            .map(str::to_owned)
            .to_vec();
        let server = rcgen::CertificateParams::new(names)
            .unwrap()
            .self_signed(&server_key)
            .unwrap();
        std::fs::write(config.path().join("server.crt"), server.pem()).unwrap();
        std::fs::write(config.path().join("server.key"), server_key.serialize_pem()).unwrap();
        let config_text = format!(
            "pid /tmp/nginx.pid;\n\
             # info: where nginx says why it refused a client certificate.\n\
             error_log stderr info;\n\
             events {{}}\n\
             http {{\n    access_log off;\n    \
             ssl_certificate /etc/ffca/server.crt;\n    \
             ssl_certificate_key /etc/ffca/server.key;\n{body}\n}}\n"
        );
        std::fs::write(
            config.path().join("nginx.conf"),
            config_text.replace("PORT", &port.to_string()),
        )
        .unwrap();
        std::fs::create_dir(config.path().join("sites")).unwrap();
        for (name, text) in sites {
            std::fs::write(
                config.path().join("sites").join(name),
                text.replace("PORT", &port.to_string()),
            )
            .unwrap();
        }
        let mut nginx = Nginx {
            engine,
            container: String::new(),
            config,
            port,
        };
        nginx.publish(ffca);
        let image = std::env::var("FFCA_NGINX_IMAGE").unwrap_or_else(|_| IMAGE.to_owned());
        let mount = format!("{}:/etc/ffca:ro,z", nginx.config.path().display());
        // Rootless podman's database can be busy with another test's container: try again.
        let mut attempts = 0;
        let output = loop {
            let output = Command::new(&nginx.engine)
                .args([
                    "run",
                    "--detach",
                    "--rm",
                    "--network",
                    "host",
                    "--volume",
                    &mount,
                    &image,
                ])
                .args(["nginx", "-c", "/etc/ffca/nginx.conf", "-g", "daemon off;"])
                .output()
                .expect("the container engine runs");
            attempts += 1;
            let busy = String::from_utf8_lossy(&output.stderr).contains("database is locked");
            if output.status.success() || !busy || attempts == 5 {
                break output;
            }
            std::thread::sleep(Duration::from_secs(2));
        };
        assert!(
            output.status.success(),
            "{} run failed:\n{}",
            nginx.engine,
            String::from_utf8_lossy(&output.stderr)
        );
        nginx.container = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        let deadline = Instant::now() + START_TIMEOUT;
        while TcpStream::connect(("127.0.0.1", nginx.port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "nginx did not start:\n{}",
                nginx.logs()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        nginx
    }

    /// Copies the CA's certificate and CRL to where nginx reads them, as a deployment does.
    ///
    /// Each file is replaced by a rename, as ffca publishes them, not copied over: nginx 1.27.4 and
    /// later keep a CRL across a reload when its file looks unchanged (same inode, size and
    /// modification time), and an empty CRL re-signed within the same second is all three.
    fn publish(&self, ffca: &Ffca) {
        for (from, to) in [(ffca.ca_certificate(), "ca.crt"), (ffca.crl(), "crl.pem")] {
            let staged = self.config.path().join(format!(".{to}.new"));
            std::fs::copy(from, &staged).unwrap();
            std::fs::rename(&staged, self.config.path().join(to)).unwrap();
        }
    }

    /// Publishes the CA's files and reloads nginx, then waits until `client` gets `verdict`: a
    /// reload replaces the workers gracefully, not at once.
    fn reload_until(&self, ffca: &Ffca, client: Client, verdict: &str) {
        self.publish(ffca);
        let output = Command::new(&self.engine)
            .args([
                "exec",
                &self.container,
                "nginx",
                "-c",
                "/etc/ffca/nginx.conf",
                "-s",
                "reload",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let deadline = Instant::now() + RELOAD_TIMEOUT;
        loop {
            let seen = self.verdict(client);
            if seen == verdict {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "still {seen:?} after the reload, not {verdict:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The status and body the site gives `client`.
    fn get(&self, client: Client) -> (u16, String) {
        curl(self.port, client, &self.config.path().join("server.crt"))
    }

    /// nginx's verdict on `client`, in the words of `$ssl_client_verify`: `SUCCESS`, `NONE`, or
    /// `FAILED:` and OpenSSL's reason, which nginx only writes to its error log.
    fn verdict(&self, client: Client) -> String {
        let before = self.verify_errors().len();
        let (status, body) = self.get(client);
        match status {
            200 => return "SUCCESS".to_owned(),
            400 if body.contains("No required SSL certificate was sent") => {
                return "NONE".to_owned();
            }
            400 => {}
            _ => panic!("nginx answered {status}: {body}"),
        }
        // The engine relays the log a moment after nginx writes it.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(reason) = self.verify_errors().get(before) {
                return format!("FAILED:{reason}");
            }
            assert!(
                Instant::now() < deadline,
                "a 400 without a reason in the log:\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The reasons nginx gave for refusing client certificates, oldest first:
    /// "client SSL certificate verify error: (23:certificate revoked) while ...".
    fn verify_errors(&self) -> Vec<String> {
        let marker = "client SSL certificate verify error: (";
        self.logs()
            .lines()
            .filter_map(|line| {
                let rest = &line[line.find(marker)? + marker.len()..];
                let (_code, rest) = rest.split_once(':')?;
                Some(rest[..rest.find(')')?].to_owned())
            })
            .collect()
    }

    fn logs(&self) -> String {
        Command::new(&self.engine)
            .args(["logs", &self.container])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr)
            })
            .unwrap_or_default()
    }
}

impl Drop for Nginx {
    fn drop(&mut self) {
        if !self.container.is_empty() {
            let _ = Command::new(&self.engine)
                .args(["rm", "--force", &self.container])
                .output();
        }
    }
}

/// A client: no certificate, or a certificate and its key.
#[derive(Clone, Copy)]
enum Client<'a> {
    Anonymous,
    With(&'a Path, &'a Path),
}

fn curl(port: u16, client: Client, server_certificate: &Path) -> (u16, String) {
    let mut command = Command::new("curl");
    command
        .args(["--silent", "--show-error", "--max-time", "10"])
        .arg("--cacert")
        .arg(server_certificate)
        .args(["--write-out", "\n%{http_code}"]);
    if let Client::With(certificate, key) = client {
        command.arg("--cert").arg(certificate).arg("--key").arg(key);
    }
    let output = command
        .arg(format!("https://localhost:{port}/"))
        .output()
        .expect("these tests need the `curl` command");
    let text = String::from_utf8(output.stdout).unwrap();
    let (body, status) = text.rsplit_once('\n').unwrap_or(("", &text));
    let status = status.parse().unwrap_or_else(|_| {
        panic!(
            "curl got no answer: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (status, body.to_owned())
}

/// The container engine: `FFCA_CONTAINER_ENGINE`, else podman, else docker - whichever runs.
fn engine() -> String {
    if let Ok(engine) = std::env::var("FFCA_CONTAINER_ENGINE") {
        return engine;
    }
    for engine in ["podman", "docker"] {
        let works = Command::new(engine)
            .arg("info")
            .output()
            .is_ok_and(|o| o.status.success());
        if works {
            return engine.to_owned();
        }
    }
    panic!(
        "these tests run nginx in a container: install podman or docker, or name one in FFCA_CONTAINER_ENGINE"
    );
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn files(ffca: &Ffca, stem: &str) -> (PathBuf, PathBuf) {
    (
        ffca.out.join(format!("{stem}.crt")),
        ffca.out.join(format!("{stem}.key")),
    )
}

#[test]
fn nginx_lets_in_people_and_agents_and_sees_who_they_are() {
    let ffca = Ffca::initialised();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    let (agent_key, request) = openssl_request(ffca.dir.path(), "backup");
    ffca.ok(&[
        "issue",
        "--agent",
        "backup",
        "--csr",
        request.to_str().unwrap(),
    ]);
    let nginx = Nginx::start(&ffca);

    let (certificate, key) = files(&ffca, "anna-phone");
    let anna = Client::With(&certificate, &key);
    assert_eq!(
        nginx.get(anna),
        (200, "CN=Anna (phone),OU=people\n".to_owned())
    );
    assert_eq!(nginx.verdict(anna), "SUCCESS");
    let agent_certificate = ffca.out.join("backup.crt");
    let agent = Client::With(&agent_certificate, &agent_key);
    assert_eq!(nginx.get(agent), (200, "CN=backup,OU=agents\n".to_owned()));
}

#[test]
fn nginx_refuses_no_certificate_and_another_cas() {
    let ffca = Ffca::initialised();
    let stranger = Ffca::initialised();
    stranger.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    let nginx = Nginx::start(&ffca);

    let (status, body) = nginx.get(Client::Anonymous);
    assert_eq!(status, 400);
    assert!(
        body.contains("No required SSL certificate was sent"),
        "{body}"
    );
    assert_eq!(nginx.verdict(Client::Anonymous), "NONE");

    let (certificate, key) = files(&stranger, "anna-phone");
    let foreign = Client::With(&certificate, &key);
    let (status, body) = nginx.get(foreign);
    assert_eq!(status, 400);
    assert!(body.contains("The SSL certificate error"), "{body}");
    assert!(
        nginx.verdict(foreign).starts_with("FAILED:"),
        "{}",
        nginx.verdict(foreign)
    );
}

#[test]
fn a_revoked_device_is_refused_once_nginx_reloads_and_the_others_stay_in() {
    let ffca = Ffca::initialised();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    ffca.ok(&["issue", "--person", "Anna", "--device", "laptop"]);
    let nginx = Nginx::start(&ffca);
    let (phone_certificate, phone_key) = files(&ffca, "anna-phone");
    let (laptop_certificate, laptop_key) = files(&ffca, "anna-laptop");
    let phone = Client::With(&phone_certificate, &phone_key);
    let laptop = Client::With(&laptop_certificate, &laptop_key);
    assert_eq!(nginx.verdict(phone), "SUCCESS");

    ffca.ok(&[
        "revoke", "--person", "Anna", "--device", "phone", "--reason", "lost",
    ]);
    nginx.reload_until(&ffca, phone, "FAILED:certificate revoked");
    until(
        || nginx.get(phone).0 == 400,
        "the revoked phone is refused by every worker",
    );
    assert_eq!(nginx.get(laptop).0, 200);
}

#[test]
fn an_expired_crl_locks_everyone_out_until_it_is_refreshed() {
    let ffca = Ffca::initialised();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    let (certificate, key) = files(&ffca, "anna-phone");
    let anna = Client::With(&certificate, &key);
    // What a month without `crl-refresh` leaves behind.
    let ca = Ca::open(&Store::new(&ffca.state)).unwrap();
    ca.refresh_crl(OffsetDateTime::now_utc() - time::Duration::days(31))
        .unwrap();
    let nginx = Nginx::start(&ffca);
    assert_eq!(nginx.verdict(anna), "FAILED:CRL has expired");
    assert_eq!(nginx.get(anna).0, 400);

    ffca.ok(&["crl-refresh"]);
    nginx.reload_until(&ffca, anna, "SUCCESS");
    until(
        || nginx.get(anna).0 == 200,
        "Anna gets in once the CRL is fresh",
    );
}

#[test]
fn an_expired_certificate_is_refused() {
    let ffca = Ffca::initialised();
    let ca = Ca::open(&Store::new(&ffca.state)).unwrap();
    let issued = ca
        .issue(
            friends_and_family_ca::ledger::Holder::Agent("old"),
            friends_and_family_ca::ca::Key::Generate,
            OffsetDateTime::now_utc() - time::Duration::days(10),
            time::Duration::days(5),
        )
        .unwrap();
    let certificate = ffca.out.join("old.crt");
    let key = ffca.out.join("old.key");
    std::fs::write(&certificate, &issued.certificate_pem).unwrap();
    std::fs::write(&key, issued.key_pem.unwrap()).unwrap();
    let nginx = Nginx::start(&ffca);
    let old = Client::With(&certificate, &key);
    assert_eq!(nginx.verdict(old), "FAILED:certificate has expired");
    assert_eq!(nginx.get(old).0, 400);
}

/// How ffca reaches the nginx in `nginx`: its sites folder, a folder for the CA's files, and
/// commands run inside the container.
fn settings(nginx: &Nginx, ca_files_in_nginx: &str) -> config::Nginx {
    let exec = format!(
        "{} exec {} nginx -c /etc/ffca/nginx.conf",
        nginx.engine, nginx.container
    );
    config::Nginx {
        sites: nginx.config.path().join("sites"),
        ca_files: nginx.config.path().join("certs"),
        ca_files_in_nginx: ca_files_in_nginx.into(),
        test: format!("{exec} -t"),
        reload: format!("{exec} -s reload"),
    }
}

const BOOKS: &str = r#"server {
    listen 127.0.0.1:PORT ssl;
    server_name localhost;

    location / { return 200 "$ssl_client_s_dn\n"; }
}
"#;

impl Nginx {
    /// Waits until nginx's verdict on `client` is `verdict`. After a reload, a worker of the old
    /// configuration can still answer for a moment: one answer of the new kind does not mean every
    /// next one is.
    fn until_verdict(&self, client: Client, verdict: &str) {
        let deadline = Instant::now() + RELOAD_TIMEOUT;
        loop {
            let seen = self.verdict(client);
            if seen == verdict {
                return;
            }
            assert!(Instant::now() < deadline, "still {seen:?}, not {verdict:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits until the site answers `client` with `status`: a reload replaces workers gracefully.
    fn until_status(&self, client: Client, status: u16) {
        let deadline = Instant::now() + RELOAD_TIMEOUT;
        loop {
            let (seen, body) = self.get(client);
            if seen == status {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "still {seen} ({body}), not {status}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[test]
fn ffca_requires_certificates_on_a_site_and_its_revocations_reach_nginx() {
    let ffca = Ffca::initialised();
    ffca.ok(&["issue", "--person", "Anna", "--device", "phone"]);
    let nginx = Nginx::start_with(
        &ffca,
        "    include /etc/ffca/sites/*.conf;",
        &[("books.conf", BOOKS)],
    );
    let settings = settings(&nginx, "/etc/ffca/certs");
    let store = Store::new(&ffca.state);
    Config {
        nginx: Some(settings.clone()),
        enrollment: None,
    }
    .save(&store)
    .unwrap();
    let ca = Ca::open(&store).unwrap();
    let (certificate, key) = files(&ffca, "anna-phone");
    let anna = Client::With(&certificate, &key);
    assert_eq!(
        nginx.get(Client::Anonymous),
        (200, "\n".to_owned()),
        "open to everyone at first"
    );

    let site = nginx::survey(&settings).unwrap().sites.remove(0);
    assert!(nginx::set_mode(&settings, &ca, &site, nginx::Mode::Required).unwrap());
    nginx.until_status(Client::Anonymous, 400);
    until(
        || nginx.get(anna) == (200, "CN=Anna (phone),OU=people\n".to_owned()),
        "nginx asks Anna's phone for its certificate and sees who it is",
    );

    let printed = ffca.ok(&[
        "revoke", "--person", "Anna", "--device", "phone", "--reason", "lost",
    ]);
    assert!(printed.contains("nginx reloaded with it."), "{printed}");
    nginx.until_verdict(anna, "FAILED:certificate revoked");

    let site = nginx::survey(&settings).unwrap().sites.remove(0);
    assert!(nginx::set_mode(&settings, &ca, &site, nginx::Mode::Off).unwrap());
    nginx.until_status(Client::Anonymous, 200);
    assert_eq!(
        std::fs::read_to_string(settings.sites.join("books.conf")).unwrap(),
        BOOKS.replace("PORT", &nginx.port.to_string())
    );
}

#[test]
fn a_change_nginx_refuses_leaves_the_site_as_it_was() {
    let ffca = Ffca::initialised();
    let nginx = Nginx::start_with(
        &ffca,
        "    include /etc/ffca/sites/*.conf;",
        &[("books.conf", BOOKS)],
    );
    // nginx cannot load a CA certificate from a folder it does not have.
    let settings = settings(&nginx, "/etc/ffca/missing");
    let ca = Ca::open(&Store::new(&ffca.state)).unwrap();
    let file = settings.sites.join("books.conf");
    let before = std::fs::read_to_string(&file).unwrap();
    let site = nginx::survey(&settings).unwrap().sites.remove(0);
    let error = nginx::set_mode(&settings, &ca, &site, nginx::Mode::Required).unwrap_err();
    assert!(
        error.to_string().contains("nginx refused the change"),
        "{error:#}"
    );
    assert!(
        format!("{error:#}").contains("/etc/ffca/missing/ffca-ca.crt"),
        "nginx's own words: {error:#}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    assert_eq!(nginx.get(Client::Anonymous).0, 200, "still serving");
}

/// `ffca serve` on this machine, stopped when dropped.
struct Serve {
    child: std::process::Child,
    port: u16,
}

impl Serve {
    fn start(ffca: &Ffca) -> Serve {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_ffca"))
            .args(["serve", "--listen", &format!("127.0.0.1:{port}")])
            .env("FFCA_STATE_DIR", &ffca.state)
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "ffca serve did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        Serve { child, port }
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `curl` on `url` through nginx at `port`, its host name resolved to this machine: the status
/// and the body. `extra` adds arguments, such as `-X POST` or a client certificate.
fn fetch(nginx: &Nginx, url: &str, extra: &[&str]) -> (u16, Vec<u8>) {
    let host = url
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let url = url.replacen(&host, &format!("{host}:{}", nginx.port), 1);
    let output = Command::new("curl")
        .args(["--silent", "--show-error", "--max-time", "10"])
        .arg("--cacert")
        .arg(nginx.config.path().join("server.crt"))
        .args(["--resolve", &format!("{host}:{}:127.0.0.1", nginx.port)])
        .args(["--write-out", "\n%{http_code}"])
        .args(extra)
        .arg(&url)
        .output()
        .expect("these tests need the `curl` command");
    let text = output.stdout;
    let split = text
        .iter()
        .rposition(|b| *b == b'\n')
        .expect("a status line");
    let status = String::from_utf8_lossy(&text[split + 1..])
        .parse()
        .unwrap_or_else(|_| panic!("curl: {}", String::from_utf8_lossy(&output.stderr)));
    (status, text[..split].to_vec())
}

const CLOUD: &str = r#"server {
    listen 127.0.0.1:PORT ssl;
    server_name books.example.test;
    ssl_certificate /etc/ffca/server.crt;
    ssl_certificate_key /etc/ffca/server.key;
    include /etc/ffca/sites/logging.inc;

    location / { return 200 "$ssl_client_s_dn\n"; }
}
"#;

/// The access log the sites include, as a server's shared logging snippet does.
const LOGGING: &str = "access_log /tmp/access.log;\n";

/// The whole way, as a family member takes it: an invite made, its link opened through nginx
/// without a certificate, the button pressed, the .p12 downloaded and opened with the password the
/// page shows - and with it, into a site that requires a certificate.
#[test]
fn an_invite_through_nginx_gets_a_device_into_a_protected_site() {
    let ffca = Ffca::initialised();
    let nginx = Nginx::start_with(
        &ffca,
        "    include /etc/ffca/sites/*.conf;",
        &[("books.conf", CLOUD), ("logging.inc", LOGGING)],
    );
    let serve = Serve::start(&ffca);
    let store = Store::new(&ffca.state);
    let settings = settings(&nginx, "/etc/ffca/certs");
    let enrollment = config::Enrollment {
        host: "k.example.test".into(),
        upstream: format!("http://127.0.0.1:{}", serve.port),
        user: config::default_page_user(),
    };
    Config {
        nginx: Some(settings.clone()),
        enrollment: Some(enrollment.clone()),
    }
    .save(&store)
    .unwrap();
    let ca = Ca::open(&store).unwrap();
    let books = nginx::survey(&settings).unwrap().sites.remove(0);
    nginx::set_mode(&settings, &ca, &books, nginx::Mode::Required).unwrap();
    let (file, text) = nginx::enrollment_site(&settings, &enrollment).unwrap();
    nginx::write_enrollment_site(&settings, &ca, &file, &text).unwrap();

    let made = invite::make(
        &ca,
        &invite::dir(&store),
        Holder::Device {
            person: "Anna",
            device: "phone",
        },
        "k.example.test",
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    // Opening the link: the enrollment site asks for no certificate.
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    let page = loop {
        let (status, body) = fetch(&nginx, &made.link, &[]);
        if status == 200 {
            break String::from_utf8(body).unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "the enrollment site answers {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(page.contains("A certificate for Anna (phone)"), "{page}");
    until(
        || fetch(&nginx, "https://books.example.test/", &[]).0 == 400,
        "the protected site wants a certificate",
    );

    // The button. A refusal by nginx itself (a worker from before the enrollment site existed)
    // never reached the page, so it used nothing up: ask again.
    let (status, body) = fetch_through(&nginx, &made.link, &["-X", "POST"]);
    assert_eq!(status, 200);
    let page = String::from_utf8(body).unwrap();
    let password = page
        .split("<code>")
        .nth(1)
        .unwrap()
        .split("</code>")
        .next()
        .unwrap();
    let p12_path = page
        .split("href=\"")
        .find(|p| p.contains(".p12\""))
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (status, p12) = fetch_through(&nginx, &format!("https://k.example.test{p12_path}"), &[]);
    assert_eq!(status, 200);

    // What a device does with the file and its password.
    let dir = ffca.dir.path();
    std::fs::write(dir.join("anna.p12"), &p12).unwrap();
    for (args, out) in [
        (&["-clcerts", "-nokeys"][..], "anna.crt"),
        (&["-nocerts", "-nodes"][..], "anna.key"),
    ] {
        let output = Command::new("openssl")
            .args(["pkcs12", "-in"])
            .arg(dir.join("anna.p12"))
            .args(["-passin", &format!("pass:{password}")])
            .args(args)
            .arg("-out")
            .arg(dir.join(out))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let (certificate, key) = (dir.join("anna.crt"), dir.join("anna.key"));
    let with_certificate = [
        "--cert",
        certificate.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
    ];
    until(
        || {
            fetch(&nginx, "https://books.example.test/", &with_certificate)
                == (200, b"CN=Anna (phone),OU=people\n".to_vec())
        },
        "Anna gets in with the certificate the invite handed over",
    );

    // Used up; and the CA learns who collected it.
    let (status, body) = fetch_through(&nginx, &made.link, &["-X", "POST"]);
    assert_eq!(status, 404, "{}", String::from_utf8_lossy(&body));
    let printed = ffca.ok(&["crl-refresh"]);
    assert!(
        printed.contains("Recorded the invite collected for Anna (phone)."),
        "{printed}"
    );
    let invite = Ca::open(&store)
        .unwrap()
        .ledger()
        .unwrap()
        .invites
        .remove(0);
    assert_eq!(
        invite.collected_by.as_deref(),
        Some("127.0.0.1, an unknown device")
    );

    // The invite's secret is nowhere in nginx's access log; other requests to the site are.
    let (status, _) = fetch_through(&nginx, "https://k.example.test/", &[]);
    assert_eq!(status, 200);
    let token = made.link.rsplit('/').next().unwrap();
    let log = || {
        let output = Command::new(&nginx.engine)
            .args(["exec", &nginx.container, "cat", "/tmp/access.log"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    until(
        || log().contains("\"GET / HTTP"),
        "the enrollment site's own requests are logged",
    );
    let log = log();
    assert!(!log.contains(token), "a token in the access log:\n{log}");
    assert!(
        !log.contains("/d/"),
        "a download address in the access log:\n{log}"
    );

    // stop-bots' filter, written into the site as stop-bots does, survives ffca rewriting it.
    let written = std::fs::read_to_string(&file).unwrap();
    let filter = "    # BEGIN stop-bots (DO NOT EDIT)\n    if ($http_user_agent ~* \"BadBot\") {\n        return 403;\n    }\n    # END stop-bots\n";
    std::fs::write(
        &file,
        written.replacen("server {\n", &format!("server {{\n{filter}\n"), 1),
    )
    .unwrap();
    let (file, text) = nginx::enrollment_site(&settings, &enrollment).unwrap();
    nginx::write_enrollment_site(&settings, &ca, &file, &text).unwrap();
    assert!(std::fs::read_to_string(&file).unwrap().contains(filter));
    until(
        || fetch(&nginx, "https://k.example.test/", &["-A", "BadBot"]).0 == 403,
        "the bot filter still turns bots away",
    );
    assert_eq!(fetch(&nginx, "https://k.example.test/", &[]).0, 200);
}

/// `fetch`, asked again while nginx refuses it with 400 itself: after a reload, a worker of the
/// old configuration can still answer for a moment, without the site the request is for.
fn fetch_through(nginx: &Nginx, url: &str, extra: &[&str]) -> (u16, Vec<u8>) {
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    loop {
        let answer = fetch(nginx, url, extra);
        if answer.0 != 400 || Instant::now() >= deadline {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits until `condition` holds: after a reload, a worker of the old configuration can still
/// answer for a moment.
fn until(condition: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    while !condition() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
