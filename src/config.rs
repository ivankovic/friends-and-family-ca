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
//! The administrator's settings, kept beside the CA in `config.toml`: how to reach the web server,
//! and the site the enrollment page will live on. Written by the terminal UI, readable and
//! editable by hand.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::store::{PRIVATE, Store};

pub const FILE: &str = "config.toml";

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nginx: Option<Nginx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<Enrollment>,
}

/// How ffca reaches nginx. nginx often runs in a container, so a folder can have two names: the
/// one on this machine, where ffca writes, and the one inside nginx, which its configuration names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nginx {
    /// The folder of site configurations ffca may edit: every `*.conf` in it.
    pub sites: PathBuf,
    /// Where ffca copies the CA's certificate and CRL for nginx, on this machine. Never the key.
    pub ca_files: PathBuf,
    /// The same folder as nginx sees it.
    pub ca_files_in_nginx: PathBuf,
    /// Checks nginx's configuration, as a command and its arguments, split at spaces.
    pub test: String,
    /// Makes nginx load the configuration and the CA's files again.
    pub reload: String,
}

/// The site the enrollment page lives on. It never asks for a client certificate: whoever opens
/// an invite has none yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub host: String,
    /// Where nginx finds `ffca serve`, as a URL: its container's name on nginx's network, or an
    /// address on this machine.
    #[serde(default = "default_upstream")]
    pub upstream: String,
    /// Who `ffca serve` runs as, `uid:gid`: the invites folder is theirs, so that the page can
    /// read invites and delete them once collected.
    #[serde(default = "default_page_user")]
    pub user: String,
}

pub fn default_upstream() -> String {
    "http://ffca:8080".to_owned()
}

/// `nobody`, which the container image runs as.
pub fn default_page_user() -> String {
    "65534:65534".to_owned()
}

/// A `uid:gid` pair, as numbers.
pub fn checked_user(user: &str) -> Result<(u32, u32)> {
    let user = user.trim();
    let (uid, gid) = user.split_once(':').unwrap_or((user, user));
    match (uid.parse(), gid.parse()) {
        (Ok(uid), Ok(gid)) => Ok((uid, gid)),
        _ => anyhow::bail!("{user} is not uid:gid, such as 65534:65534"),
    }
}

/// An upstream nginx can `proxy_pass` to: `http://` and a host, with an optional port.
pub fn checked_upstream(upstream: &str) -> Result<String> {
    let upstream = upstream.trim().trim_end_matches('/');
    let rest = upstream
        .strip_prefix("http://")
        .with_context(|| format!("{upstream} does not start with http://"))?;
    ensure!(
        !rest.is_empty()
            && !rest.contains('/')
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:[]_".contains(c)),
        "{upstream} is not an address such as http://ffca:8080"
    );
    Ok(upstream.to_owned())
}

/// The CA files' folder as nginx sees it: a full path that ffca can write into nginx's
/// configuration as it is, unquoted - nothing in it that nginx would read as the end of a word, a
/// comment, a quote, an escape or a variable.
pub fn checked_folder_in_nginx(folder: &Path) -> Result<PathBuf> {
    let text = folder
        .to_str()
        .with_context(|| format!("{} is not UTF-8", folder.display()))?
        .trim();
    ensure!(
        text.starts_with('/'),
        "{text} is not a full path, such as /etc/nginx/certs"
    );
    ensure!(
        !text
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || ";{}#\"'\\$".contains(c)),
        "{text} holds a character nginx would read as more than a letter: no spaces, ; {{ }} # \
         quotes, \\ or $"
    );
    Ok(PathBuf::from(text))
}

impl Default for Nginx {
    /// nginx installed on this machine the usual way.
    fn default() -> Nginx {
        Nginx {
            sites: "/etc/nginx/conf.d".into(),
            ca_files: "/etc/nginx/ffca".into(),
            ca_files_in_nginx: "/etc/nginx/ffca".into(),
            test: "nginx -t".into(),
            reload: "nginx -s reload".into(),
        }
    }
}

impl Config {
    /// The settings on disk, or none if there are none yet.
    pub fn load(store: &Store) -> Result<Config> {
        if !store.exists(FILE) {
            return Ok(Config::default());
        }
        let text = store.read(FILE)?;
        toml::from_str(&text).map_err(|e| anyhow!("{} is damaged: {e}", store.path(FILE).display()))
    }

    pub fn save(&self, store: &Store) -> Result<()> {
        store.write(FILE, toml::to_string(self)?.as_bytes(), PRIVATE)
    }
}

/// A host name for the enrollment site: letters, digits, hyphens and dots, as DNS allows.
pub fn checked_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    ensure!(
        !host.is_empty(),
        "the enrollment site needs a name, such as k.example.org"
    );
    ensure!(host.len() <= 253, "{host} is too long for a host name");
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    ensure!(
        host.contains('.') && host.split('.').all(label_ok),
        "{host} is not a host name, such as k.example.org"
    );
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_are_optional() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path());
        assert_eq!(Config::load(&store).unwrap(), Config::default());
        let config = Config {
            nginx: Some(Nginx {
                sites: "/srv/domaci/nginx/conf.d".into(),
                ca_files: "/srv/domaci/nginx/certs".into(),
                ca_files_in_nginx: "/etc/nginx/certs".into(),
                test: "docker exec nginx nginx -t".into(),
                reload: "docker exec nginx nginx -s reload".into(),
            }),
            enrollment: Some(Enrollment {
                host: "k.domaci.ivankovic.me".into(),
                upstream: default_upstream(),
                user: default_page_user(),
            }),
        };
        config.save(&store).unwrap();
        assert_eq!(Config::load(&store).unwrap(), config);
        assert!(store.read(FILE).unwrap().contains("[nginx]"));
    }

    #[test]
    fn a_damaged_file_is_named() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path());
        store.write(FILE, b"[nginx]\nsites = 3", PRIVATE).unwrap();
        assert!(
            Config::load(&store)
                .unwrap_err()
                .to_string()
                .contains("config.toml is damaged")
        );
    }

    #[test]
    fn an_older_file_without_the_upstream_gets_the_default() {
        let dir = crate::test_dir();
        let store = Store::new(dir.path());
        store
            .write(FILE, b"[enrollment]\nhost = \"k.example.org\"\n", PRIVATE)
            .unwrap();
        assert_eq!(
            Config::load(&store).unwrap().enrollment.unwrap().upstream,
            "http://ffca:8080"
        );
    }

    #[test]
    fn page_users_are_numbers() {
        assert_eq!(checked_user("65534:65534").unwrap(), (65534, 65534));
        assert_eq!(checked_user(" 1000 ").unwrap(), (1000, 1000));
        assert!(checked_user("nobody").is_err());
        assert!(checked_user("1000:staff").is_err());
    }

    #[test]
    fn upstreams_are_http_addresses() {
        assert_eq!(
            checked_upstream(" http://ffca:8080/ ").unwrap(),
            "http://ffca:8080"
        );
        assert_eq!(
            checked_upstream("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        for bad in [
            "ffca:8080",
            "https://ffca",
            "http://",
            "http://ffca/path",
            "http://ffca;rm",
        ] {
            assert!(checked_upstream(bad).is_err(), "{bad:?} passed");
        }
    }

    #[test]
    fn the_folder_in_nginx_is_a_plain_full_path() {
        assert_eq!(
            checked_folder_in_nginx(Path::new(" /etc/nginx/certs ")).unwrap(),
            PathBuf::from("/etc/nginx/certs")
        );
        for bad in [
            "etc/nginx/certs",
            "",
            "/etc/my certs",
            "/etc/x;#",
            "/etc/x}",
            "/etc/$x",
            "/etc/\\x",
            "/etc/'x'",
            "/etc/\"x",
            "/etc/x\ny",
        ] {
            assert!(
                checked_folder_in_nginx(Path::new(bad)).is_err(),
                "{bad:?} passed"
            );
        }
    }

    #[test]
    fn host_names_are_checked_and_normalised() {
        assert_eq!(
            checked_host(" K.Domaci.Ivankovic.me. ").unwrap(),
            "k.domaci.ivankovic.me"
        );
        for bad in [
            "",
            "localhost",
            "k..example.org",
            "-k.example.org",
            "k_1.example.org",
            "k example.org",
        ] {
            assert!(checked_host(bad).is_err(), "{bad:?} passed");
        }
    }
}
