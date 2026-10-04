# Changelog

All notable changes to Friends and Family CA. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the version numbers follow
[Semantic Versioning](https://semver.org/) as far as a 0.x release does: a minor bump may change
the on-disk CA layout or the command line, a patch bump does not.

## [Unreleased]

The first release.

### Added

- **The CA.** `sudo ffca` opens a terminal UI that sets the CA up on first run (ECDSA P-256, in
  `/var/lib/ffca`, its key readable by root only) and then manages it. The CA knows **people**,
  each with any number of **devices**, and **agents** - programs and machines that sign in as
  themselves. Certificates are for client authentication only, with subjects such as
  `CN=Anna (phone),OU=people` and `CN=backup,OU=agents`.
- **Issuing, renewing, revoking, renaming**, from the People & agents tab: a person's every
  device, one device, or one certificate; `replaced` keeps a device's newest certificate. A
  retired device or agent is issued nothing more under its name.
- **Invites.** A new or renewed device gets a one-time link, shown with its QR code, valid for a
  day. It holds the certificate packed for the device - a configuration profile for iPhone and
  iPad, a `.p12` for Android, Windows, macOS and the browsers, either locked with a password the
  page shows - sealed so that only the link opens it. The device's key is never written to disk. The Invites tab shows each one open, collected (when, and from where),
  expired or cancelled.
- **The enrollment page**, `ffca serve`: opening a link shows whose certificate it is, and only
  pressing the button uses the invite up. It runs as nobody with the invites folder and nothing
  else - an image is published on ghcr.io - and keeps invite secrets out of its log and nginx's.
  It is its own small HTTP server, with every request bounded in time and size.
- **nginx.** The Nginx tab says where nginx's sites and CA files are and how to test and reload it;
  lists every HTTPS site with its client-certificate mode - off, optional or required - and changes
  it with the lines shown first, `nginx -t`, and the file put back if nginx refuses; and writes the
  enrollment site, keeping blocks other tools such as stop-bots add to it.
- **Revocation that reaches nginx.** Every new revocation list is copied where nginx reads it, and
  nginx reloads. An hourly systemd timer, set up from the CA tab, re-signs the list (valid 30
  days), records collected invites, and revokes the certificates of invites that expired
  uncollected.
- **The command line**, for scripts: `ffca init`, `issue` (an agent may send its own certificate
  signing request, for a P-256, P-384, Ed25519 or RSA key), `revoke`, `rename`, `list`, `crl-refresh`, `serve`.
- **Deployment**: a guide, a Compose service for the enrollment page, and `make install`.
