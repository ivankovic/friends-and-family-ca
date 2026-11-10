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
//! The certificate authority: creating it, issuing client certificates, revoking them, and signing
//! the certificate revocation list (CRL).
//!
//! The CA's key and the keys it generates are ECDSA P-256. Every TLS stack a family's devices run
//! accepts it for client certificates (Android, iOS, macOS, Windows, the browsers), and its keys
//! and signatures are small. Ed25519 would be nicer, and is not accepted for client certificates
//! by enough of them. An agent that sends its own request may use P-256, P-384, RSA of 2048 bits
//! or more, or Ed25519: whatever runs the agent decides what it can present.
//!
//! The CA key is a plain PKCS#8 PEM file, readable by its owner only, because `crl-refresh` signs
//! with it unattended every hour. That makes every copy of the state folder, backups and
//! snapshots included, as good as the key: whoever has one can mint certificates the ledger never
//! saw, which only a new CA stops. All files are standard PEM, so `openssl` can carry on if ffca ever cannot.
//!
//! The administrator can instead have the key encrypted to the machine ([`Ca::encrypt_key`]),
//! by `systemd-creds`: `ca.key.cred` replaces `ca.key`, `crl-refresh` still signs unattended, and
//! a copy of the state folder is no longer the key - on a machine with a TPM, nothing on its
//! disk is; without one, the folder and systemd's own key (`/var/lib/systemd/credential.secret`)
//! together are. The price is that no other machine can read it: a restore elsewhere needs a
//! copy of the plain key, kept offline, or the key decrypted ([`Ca::decrypt_key`]) before the
//! move. It is a choice, off unless made, because a home server whose disk dies is the likelier
//! loss.
//!
//! The CA certificate itself is limited to client authentication too (extended key usage
//! `clientAuth`): should it ever end up among a system's trusted authorities, OpenSSL and the
//! browsers refuse a server certificate under it.
//!
//! A client certificate is for client authentication only (extended key usage `clientAuth`, key
//! usage `digitalSignature`, `CA:FALSE`), so a leaked one cannot be used to impersonate a server or
//! sign other certificates. Its subject says who holds it, and of which kind: a person's device is
//! `CN=<person> (<device>),OU=people` and an agent is `CN=<agent>,OU=agents`, as nginx's
//! `$ssl_client_s_dn` shows it. nginx can log it, and `map` it, for example to let an agent reach
//! only the paths it needs.
//!
//! The CA generates the key for a person's device, because the device's own installer takes a
//! finished key and certificate. An agent can instead send a certificate signing request (CSR):
//! then its key never leaves the machine it runs on. Only the CSR's public key is used; what it
//! asks for (names, usages, validity) is ignored, and the CA decides all of it as above. The
//! certificate is checked to carry exactly the request's key before it is kept.
//!
//! The CRL is rebuilt from the ledger on every change and on every refresh. A web server rejects
//! every client once the CRL is past its `nextUpdate`, so [`CRL_VALIDITY`] is a month and
//! `crl-refresh` runs hourly: a month of missed refreshes before anyone is locked out.

use std::fmt::Write as _;

use anyhow::{Context, Result, bail, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData,
    RevokedCertParams, SerialNumber,
};
use time::{Duration, OffsetDateTime};

use crate::ledger::{Certificate, Holder, Ledger, Reason, Revoked, Serial, Target, checked_name};
use crate::store::{PRIVATE, PUBLIC, Store};

pub const CERTIFICATE_FILE: &str = "ca.crt";
pub const KEY_FILE: &str = "ca.key";
/// The key encrypted to this machine, in place of [`KEY_FILE`]: see [`Ca::encrypt_key`].
pub const ENCRYPTED_KEY_FILE: &str = "ca.key.cred";
/// The command that encrypts the key to this machine and decrypts it: systemd's, which uses the
/// machine's TPM where it has one and a key of its own under `/var/lib/systemd` otherwise.
pub const KEY_ENCRYPTER: &str = "systemd-creds";
/// The name the encrypted key is bound to: `systemd-creds` decrypts it under no other.
const KEY_CREDENTIAL: &str = "ffca-ca-key";
pub const CRL_FILE: &str = "crl.pem";
const ISSUED_DIR: &str = "issued";

/// How long a CRL stays valid. See the module documentation for why a month.
pub const CRL_VALIDITY: Duration = Duration::days(30);
/// How long a client certificate is valid unless the administrator says otherwise: long enough
/// that nobody has to re-enrol every phone each year, short enough that a forgotten device ages out.
pub const DEFAULT_CLIENT_VALIDITY: Duration = Duration::days(730);
/// How long the CA itself is valid unless the administrator says otherwise.
pub const DEFAULT_CA_VALIDITY: Duration = Duration::days(3653);
/// The most years a CA can be made valid for: past that, nobody remembers how it was set up.
pub const MAX_CA_YEARS: u16 = 30;

/// `years` calendar years, leap days included.
pub fn years(years: u16) -> Duration {
    Duration::days(365 * i64::from(years) + i64::from(years / 4))
}
/// How far back a new certificate's validity starts, so a clock a little behind ours still
/// accepts it.
pub(crate) const BACKDATE: Duration = Duration::hours(1);

/// A CA on disk, with its key loaded.
pub struct Ca {
    store: Store,
    name: String,
    certificate_pem: String,
    key: KeyPair,
    not_after: OffsetDateTime,
}

/// What the CRL on disk says about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrlStatus {
    pub number: u64,
    pub next_update: OffsetDateTime,
}

/// Where the key of a new certificate comes from.
pub enum Key<'a> {
    /// The CA generates it, and hands it over with the certificate.
    Generate,
    /// The holder generated it and sent this certificate signing request, in PEM.
    Request(&'a str),
}

/// A freshly issued client certificate, and its private key if the CA generated it. The key
/// exists only here: the CA keeps the certificate, never the key.
pub struct Issued {
    /// Who holds it, as the ledger spells the names.
    pub holder: String,
    pub certificate: Certificate,
    pub certificate_pem: String,
    pub key_pem: Option<String>,
}

impl Ca {
    /// Creates a new CA named `name` in `store`, which must not hold one yet, and signs its first,
    /// empty CRL so that a web server can be pointed at both straight away.
    pub fn create(
        store: &Store,
        name: &str,
        now: OffsetDateTime,
        validity: Duration,
    ) -> Result<Ca> {
        let name = checked_name("CA name", name)?;
        let now = whole_seconds(now);
        ensure!(validity.is_positive(), "the CA's validity must be positive");
        store.create_dir()?;
        let _lock = store.lock()?;
        if store.exists(CERTIFICATE_FILE) || store.exists(KEY_FILE) {
            bail!(
                "{} already holds a CA; remove it first to start over",
                store.dir().display()
            );
        }
        store.create_subdir(ISSUED_DIR)?;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        params.serial_number = Some(serial_number(Serial::random()?));
        params.not_before = now - BACKDATE;
        params.not_after = now + validity;
        // Path length 0: this CA signs client certificates directly and never another CA.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_identifier_method = KeyIdMethod::Sha256;
        let certificate = params.self_signed(&key)?;

        // The key first: a certificate without its key is a CA that can never sign again.
        store.write(KEY_FILE, key.serialize_pem().as_bytes(), PRIVATE)?;
        store.write(CERTIFICATE_FILE, certificate.pem().as_bytes(), PUBLIC)?;
        let ca = Ca {
            store: store.clone(),
            name: name.to_owned(),
            certificate_pem: certificate.pem(),
            key,
            not_after: params.not_after,
        };
        let mut ledger = Ledger::default();
        ca.advance_crl_number(&mut ledger)?;
        ledger.save(store)?;
        ca.write_crl(&ledger, now)?;
        Ok(ca)
    }

    /// Loads the CA in `store`.
    pub fn open(store: &Store) -> Result<Ca> {
        Ca::open_with(store, KEY_ENCRYPTER)
    }

    /// As [`Ca::open`], with `encrypter` the command that decrypts an encrypted key (see
    /// [`Ca::encrypt_key`]): `systemd-creds`, or what stands in for it in a test.
    pub fn open_with(store: &Store, encrypter: &str) -> Result<Ca> {
        if !store.exists(CERTIFICATE_FILE) {
            bail!(
                "there is no CA in {} yet; create one with `ffca init`",
                store.dir().display()
            );
        }
        let certificate_pem = store.read(CERTIFICATE_FILE)?;
        let (key_file, key_pem) = if store.exists(KEY_FILE) || !store.exists(ENCRYPTED_KEY_FILE) {
            (KEY_FILE, store.read(KEY_FILE)?)
        } else {
            let pem = decrypt(encrypter, &store.read(ENCRYPTED_KEY_FILE)?).with_context(|| {
                format!(
                    "cannot decrypt {}, which only the machine it was encrypted on can: on \
                     another machine, restore the copy of the key you kept",
                    store.path(ENCRYPTED_KEY_FILE).display()
                )
            })?;
            (ENCRYPTED_KEY_FILE, pem)
        };
        let key = KeyPair::from_pem(&key_pem)
            .with_context(|| format!("{} is not a usable key", store.path(key_file).display()))?;
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).map_err(|e| {
                anyhow::anyhow!("{} is damaged: {e}", store.path(CERTIFICATE_FILE).display())
            })?;
        let certificate = pem.parse_x509()?;
        ensure!(
            certificate.public_key().raw == key.subject_public_key_info(),
            "{} does not belong to {}",
            store.path(key_file).display(),
            store.path(CERTIFICATE_FILE).display()
        );
        let not_after = certificate.validity().not_after.to_datetime();
        let name = certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or_default()
            .to_owned();
        Ok(Ca {
            store: store.clone(),
            name,
            certificate_pem,
            key,
            not_after,
        })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Whether the key on disk is encrypted to this machine: see [`Ca::encrypt_key`].
    pub fn key_encrypted(&self) -> bool {
        !self.store.exists(KEY_FILE) && self.store.exists(ENCRYPTED_KEY_FILE)
    }

    /// Encrypts the key on disk to this machine, with `encrypter` (`systemd-creds`): the plain
    /// `ca.key` is replaced by `ca.key.cred`, which only this machine can decrypt. The encrypted
    /// file is written and read back - decrypted, and compared with the key in use - before the
    /// plain one is deleted, so no failure on the way leaves the CA without a key.
    ///
    /// Deleting a file does not erase what a disk, a snapshot or an older backup still holds of
    /// it: those copies stay as good as the key.
    pub fn encrypt_key(&self, encrypter: &str) -> Result<()> {
        let _lock = self.store.lock()?;
        let pem = self.key.serialize_pem();
        let encrypted = run_with_input(
            &format!("{encrypter} encrypt --name={KEY_CREDENTIAL} - -"),
            pem.as_bytes(),
        )
        .context("cannot encrypt the CA's key to this machine; it is left as it was")?;
        ensure!(
            !encrypted.trim().is_empty() && !encrypted.contains("PRIVATE KEY"),
            "`{encrypter}` did not encrypt the key; it is left as it was"
        );
        self.store
            .write(ENCRYPTED_KEY_FILE, encrypted.as_bytes(), PRIVATE)?;
        let read_back = self
            .store
            .read(ENCRYPTED_KEY_FILE)
            .and_then(|text| decrypt(encrypter, &text))
            .and_then(|pem| Ok(KeyPair::from_pem(&pem)?));
        match read_back {
            Ok(key) if key.serialize_der() == self.key.serialize_der() => {}
            other => {
                let _ = std::fs::remove_file(self.store.path(ENCRYPTED_KEY_FILE));
                let why = other.err().map(|e| format!(": {e:#}")).unwrap_or_default();
                bail!(
                    "the encrypted key does not decrypt to the CA's key{why}; the key is left \
                     as it was"
                );
            }
        }
        if self.store.exists(KEY_FILE) {
            std::fs::remove_file(self.store.path(KEY_FILE)).with_context(|| {
                format!("cannot delete {}", self.store.path(KEY_FILE).display())
            })?;
        }
        Ok(())
    }

    /// Puts the key back on disk as a plain `ca.key`, its owner's only, and deletes the
    /// encrypted one: what a move to another machine starts with.
    pub fn decrypt_key(&self) -> Result<()> {
        let _lock = self.store.lock()?;
        self.store
            .write(KEY_FILE, self.key.serialize_pem().as_bytes(), PRIVATE)?;
        match std::fs::remove_file(self.store.path(ENCRYPTED_KEY_FILE)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).with_context(|| {
                format!(
                    "cannot delete {}",
                    self.store.path(ENCRYPTED_KEY_FILE).display()
                )
            }),
            _ => Ok(()),
        }
    }

    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// The CA's name: its certificate's common name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The number and expiry of the CRL on disk.
    pub fn crl_status(&self) -> Result<CrlStatus> {
        let pem = self.store.read(CRL_FILE)?;
        let damaged = || format!("{} is damaged", self.store.path(CRL_FILE).display());
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).with_context(damaged)?;
        let (_, crl) = x509_parser::parse_x509_crl(&pem.contents).with_context(damaged)?;
        let number = crl
            .crl_number()
            .and_then(|n| n.to_u64_digits().first().copied())
            .unwrap_or(0);
        let next_update = crl.next_update().with_context(damaged)?.to_datetime();
        Ok(CrlStatus {
            number,
            next_update,
        })
    }

    /// The subject of the certificate `serial` as issued, which a later rename does not change,
    /// written as nginx's `$ssl_client_s_dn` writes it (RFC 4514): most specific first, commas
    /// between, special characters escaped - "CN=Anna (phone),OU=people".
    pub fn subject(&self, serial: Serial) -> Result<String> {
        let file = format!("{ISSUED_DIR}/{serial}.crt");
        let pem = self.store.read(&file)?;
        let damaged = || format!("{} is damaged", self.store.path(&file).display());
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).with_context(damaged)?;
        let certificate = pem.parse_x509().with_context(damaged)?;
        let mut parts = Vec::new();
        for attribute in certificate.subject().iter_attributes() {
            let key = if *attribute.attr_type() == x509_parser::oid_registry::OID_X509_COMMON_NAME {
                "CN"
            } else if *attribute.attr_type()
                == x509_parser::oid_registry::OID_X509_ORGANIZATIONAL_UNIT
            {
                "OU"
            } else {
                continue;
            };
            let value = attribute.as_str().with_context(damaged)?;
            parts.push(format!("{key}={}", rfc4514_escape(value)));
        }
        parts.reverse();
        Ok(parts.join(","))
    }

    /// The ledger as it is on disk now.
    pub fn ledger(&self) -> Result<Ledger> {
        Ledger::load(&self.store)
    }

    /// Issues a client certificate to `holder`, which is created if it is new, valid for
    /// `validity` or until the CA itself expires, whichever comes first.
    pub fn issue(
        &self,
        holder: Holder,
        key: Key,
        now: OffsetDateTime,
        validity: Duration,
    ) -> Result<Issued> {
        let now = whole_seconds(now);
        ensure!(
            validity.is_positive(),
            "the certificate's validity must be positive"
        );
        ensure!(
            now < self.not_after,
            "the CA expired on {}; it cannot issue certificates any more",
            self.not_after.date()
        );
        let request = match key {
            Key::Generate => None,
            Key::Request(pem) => {
                let key = request_key(pem)?;
                let request = CertificateSigningRequestParams::from_pem(pem)
                    .context("the certificate signing request is not usable")?;
                Some((request, key))
            }
        };

        let _lock = self.store.lock()?;
        let mut ledger = self.ledger()?;
        let place = ledger.place_for_issue(holder)?;
        let holder = ledger.holder_at(place);
        let serial = Serial::random()?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let (common_name, unit) = match holder {
            Holder::Device { person, device } => (format!("{person} ({device})"), "people"),
            Holder::Agent(agent) => (agent.to_owned(), "agents"),
        };
        // Most general first, as X.509 names are written: RFC 2253 then prints it most specific
        // first, which is how nginx's `$ssl_client_s_dn` reads - "CN=Anna (phone),OU=people".
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, unit);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.serial_number = Some(serial_number(serial));
        params.not_before = now - BACKDATE;
        params.not_after = (now + validity).min(self.not_after);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        let (certificate, key_pem) = match &request {
            None => {
                let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
                (
                    params.signed_by(&key, &self.issuer()?)?,
                    Some(key.serialize_pem()),
                )
            }
            Some((request, key)) => {
                let certificate = params.signed_by(&request.public_key, &self.issuer()?)?;
                // rcgen names the key's algorithm after the request's signature: a P-256 key
                // signed with SHA-384 would come out as a P-384 key nobody can read.
                let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der())
                    .context("the CA made a certificate it cannot read")?;
                ensure!(
                    parsed.public_key().raw == key.as_slice(),
                    "the certificate signing request's signature does not match its key; sign \
                     a P-256 key's request with SHA-256 and a P-384 key's with SHA-384"
                );
                (certificate, None)
            }
        };

        let record = Certificate {
            serial,
            not_before: params.not_before,
            not_after: params.not_after,
            revoked: None,
            reason: None,
        };
        let holder = holder.to_string();
        self.store
            .write(&record.file(), certificate.pem().as_bytes(), PUBLIC)?;
        ledger.at_mut(place).certificates.push(record.clone());
        ledger.save(&self.store)?;
        Ok(Issued {
            holder,
            certificate: record,
            certificate_pem: certificate.pem(),
            key_pem,
        })
    }

    /// Revokes what `target` names (see [`Ledger::revoke`]) and signs a CRL that lists it.
    pub fn revoke(
        &self,
        target: Target,
        reason: Reason,
        now: OffsetDateTime,
    ) -> Result<Vec<Revoked>> {
        let now = whole_seconds(now);
        let _lock = self.store.lock()?;
        let mut ledger = self.ledger()?;
        let revoked = ledger.revoke(target, reason, now)?;
        self.advance_crl_number(&mut ledger)?;
        ledger.save(&self.store)?;
        self.write_crl(&ledger, now)?;
        Ok(revoked)
    }

    /// Changes the ledger under the lock, signing no CRL: for records that revoke nothing. The
    /// ledger is written only if `f` changed it.
    pub fn change<T>(&self, f: impl FnOnce(&mut Ledger) -> Result<T>) -> Result<T> {
        self.change_then(f, |_| Ok(()))
    }

    /// As [`Ca::change`], then runs `then` while the lock is still held: for a file that the
    /// ledger must record before it exists, and that no other process may find missing before it
    /// is written.
    pub fn change_then<T>(
        &self,
        f: impl FnOnce(&mut Ledger) -> Result<T>,
        then: impl FnOnce(&T) -> Result<()>,
    ) -> Result<T> {
        let _lock = self.store.lock()?;
        let mut ledger = self.ledger()?;
        let before = ledger.clone();
        let result = f(&mut ledger)?;
        if ledger != before {
            ledger.save(&self.store)?;
        }
        then(&result)?;
        Ok(result)
    }

    /// Changes the ledger under the lock and, if `f` revoked anything, signs a new CRL: the
    /// revocation is saved in the same write as the rest of the change, so the two never come
    /// apart. Says whether it signed. The ledger is written only if `f` changed it.
    pub fn change_and_sign<T>(
        &self,
        now: OffsetDateTime,
        f: impl FnOnce(&mut Ledger) -> Result<T>,
    ) -> Result<(T, bool)> {
        let now = whole_seconds(now);
        let _lock = self.store.lock()?;
        let mut ledger = self.ledger()?;
        let before = ledger.clone();
        let result = f(&mut ledger)?;
        if ledger == before {
            return Ok((result, false));
        }
        let revoked = |ledger: &Ledger| {
            ledger
                .certificates()
                .filter(|(_, certificate)| certificate.revoked.is_some())
                .count()
        };
        let sign = revoked(&ledger) != revoked(&before);
        if sign {
            self.advance_crl_number(&mut ledger)?;
        }
        ledger.save(&self.store)?;
        if sign {
            self.write_crl(&ledger, now)?;
        }
        Ok((result, sign))
    }

    /// Renames a person, a device or an agent (see [`Ledger::rename`]).
    pub fn rename(&self, target: Target, new_name: &str) -> Result<()> {
        let _lock = self.store.lock()?;
        let mut ledger = self.ledger()?;
        ledger.rename(target, new_name)?;
        ledger.save(&self.store)
    }

    /// Signs a new CRL from the ledger, valid for [`CRL_VALIDITY`] from `now`.
    pub fn refresh_crl(&self, now: OffsetDateTime) -> Result<()> {
        let now = whole_seconds(now);
        let _lock = self.store.lock()?;
        let mut ledger = self.ledger()?;
        self.advance_crl_number(&mut ledger)?;
        ledger.save(&self.store)?;
        self.write_crl(&ledger, now)
    }

    /// Gives `ledger` the next CRL number: past its own and past the CRL on disk's, so that no
    /// two different CRLs ever share one. The caller holds the lock, and saves the ledger -
    /// with whatever it revoked - before [`Ca::write_crl`] signs: a crash in between leaves a
    /// number unused, which RFC 5280 allows, and the next refresh lists the revocation. The other
    /// order would let a crash forget a revocation the CRL on disk already listed.
    fn advance_crl_number(&self, ledger: &mut Ledger) -> Result<()> {
        let on_disk = self.crl_status().map_or(0, |status| status.number);
        ledger.crl_number = ledger
            .crl_number
            .max(on_disk)
            .checked_add(1)
            .context("the CRL number has run out")?;
        Ok(())
    }

    /// Signs the CRL `ledger` describes, with its number, and writes it; the caller holds the lock.
    /// It is valid from a little before `now`, like a certificate, so a web server whose clock is
    /// a little behind ours does not take it for one from the future and refuse every client.
    fn write_crl(&self, ledger: &Ledger, now: OffsetDateTime) -> Result<()> {
        let params = CertificateRevocationListParams {
            this_update: now - BACKDATE,
            next_update: now + CRL_VALIDITY,
            crl_number: SerialNumber::from(ledger.crl_number),
            issuing_distribution_point: None,
            revoked_certs: ledger
                .certificates()
                .filter_map(|(_, certificate)| {
                    Some(RevokedCertParams {
                        serial_number: serial_number(certificate.serial),
                        revocation_time: certificate.revoked?,
                        reason_code: certificate.reason.map(Reason::crl_reason),
                        invalidity_date: None,
                    })
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&self.issuer()?)?;
        self.store.write(CRL_FILE, crl.pem()?.as_bytes(), PUBLIC)
    }

    fn issuer(&self) -> Result<Issuer<'_, &KeyPair>> {
        Ok(Issuer::from_ca_cert_pem(&self.certificate_pem, &self.key)?)
    }
}

/// The key in `encrypted`, as `encrypter` decrypts it.
fn decrypt(encrypter: &str, encrypted: &str) -> Result<String> {
    run_with_input(
        &format!("{encrypter} decrypt --name={KEY_CREDENTIAL} - -"),
        encrypted.as_bytes(),
    )
}

/// Runs `command` - a program and its arguments, split at spaces - with `input` on its standard
/// input, and returns what it printed. The key goes through pipes only: never an argument, which
/// every user of the machine can list, nor a temporary file.
fn run_with_input(command: &str, input: &[u8]) -> Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut words = command.split_whitespace();
    let program = words.next().context("the command is empty")?;
    let mut child = Command::new(program)
        .args(words)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run `{program}`"))?;
    let written = child
        .stdin
        .take()
        .context("the command's input")?
        .write_all(input);
    let output = child.wait_with_output()?;
    if !output.status.success() || written.is_err() {
        bail!(
            "`{program}` failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("`{program}` printed no text"))
}

/// Escapes a value for an RFC 4514 distinguished name as OpenSSL's RFC 2253 printing does, which
/// is what nginx's `$ssl_client_s_dn` holds: a backslash before each special character, and
/// before a leading `#` or space or a trailing space; every byte of a character beyond ASCII as
/// `\XX` - "Željko" is `\C5\BDeljko`.
fn rfc4514_escape(value: &str) -> String {
    let last = value.chars().count().saturating_sub(1);
    let mut escaped = String::new();
    for (i, c) in value.chars().enumerate() {
        if !c.is_ascii() {
            let mut bytes = [0; 4];
            for byte in c.encode_utf8(&mut bytes).bytes() {
                let _ = write!(escaped, "\\{byte:02X}");
            }
            continue;
        }
        let special = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (i == 0 && matches!(c, '#' | ' '))
            || (i == last && c == ' ');
        if special {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// The public key of the certificate signing request `pem`, as the DER of its
/// SubjectPublicKeyInfo, if it is of a kind the CA signs: P-256, P-384, RSA of 2048 bits or more,
/// or Ed25519. Anything else is too weak, or something nginx's OpenSSL may not take.
fn request_key(pem: &str) -> Result<Vec<u8>> {
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::prelude::FromDer;
    use x509_parser::public_key::PublicKey;
    const EC: &str = "1.2.840.10045.2.1";
    const P256: &str = "1.2.840.10045.3.1.7";
    const P384: &str = "1.3.132.0.34";
    const RSA: &str = "1.2.840.113549.1.1.1";
    const ED25519: &str = "1.3.101.112";
    let unusable = "the certificate signing request is not usable";
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).context(unusable)?;
    let (_, request) = X509CertificationRequest::from_der(&pem.contents).context(unusable)?;
    let key = &request.certification_request_info.subject_pki;
    let algorithm = key.algorithm.algorithm.to_id_string();
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());
    let accepted = match (algorithm.as_str(), curve.as_deref()) {
        (EC, Some(P256 | P384)) => true,
        (ED25519, _) => true,
        (RSA, _) => matches!(key.parsed(), Ok(PublicKey::RSA(rsa)) if rsa.key_size() >= 2048),
        _ => false,
    };
    ensure!(
        accepted,
        "the certificate signing request's key is not one the CA signs: use P-256, P-384, \
         RSA of 2048 bits or more, or Ed25519"
    );
    Ok(key.raw.to_vec())
}

/// Certificates and CRLs carry whole seconds; the ledger records the same instants they do.
pub(crate) fn whole_seconds(time: OffsetDateTime) -> OffsetDateTime {
    time.replace_nanosecond(0)
        .expect("zero is a valid nanosecond")
}

fn serial_number(serial: Serial) -> SerialNumber {
    SerialNumber::from_slice(&serial.0)
}

#[cfg(test)]
mod tests;
