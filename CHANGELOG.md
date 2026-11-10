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
  expired or cancelled. The QR code fits a plain 80 by 24 terminal; `c` puts the link on the
  clipboard of the terminal you sit at (OSC 52, over SSH too); cancelling one asks first. A link
  longer than the screen is wide is shown whole, over two rows, and the invite says so when it is
  collected while you look at it.
- **A password sent apart from the link**, if you choose: `P` on the Invites tab keeps the
  `.p12`'s password off the enrollment page. Each invite then shows it to you (`p` copies it), to
  send another way than the link, and the link alone hands over a file nobody can open.
- **The CA's key encrypted to the machine**, if you choose: `K` on the CA tab, or `ffca key
  encrypt`, has `systemd-creds` encrypt it - with the TPM where there is one - so that a copy of
  the state folder alone signs nothing; `K` again, or `ffca key decrypt`, puts the plain file
  back. Keep a copy of the plain key offline first: no other machine reads the encrypted one.
- **The terminal UI fits 80 by 24**: a dialog taller than the screen scrolls, the key hints keep
  `? help` and `q quit`, and long names are cut short rather than pushing columns out. A failure
  is shown whole, in a dialog; a long setting scrolls in its field; `1`-`5` go to a tab; Esc
  closes and never quits; renewing, and revoking a whole person, ask first. Without `sudo`, ffca
  says it cannot read the CA instead of offering to create one. Tab titles
  count open invites and certificates about to expire, and People marks a device whose invite is
  not collected yet. `/` filters People & agents. Forms take Ctrl-U, Ctrl-W, Ctrl-A, Ctrl-E, and
  Ctrl-S from any field. Requiring a client certificate on a site says how many devices and agents
  still get in, counting apart those whose invite is still open. A site's login under `on` is a
  checklist of ffca's users.
- **The enrollment page**, `ffca serve`: opening a link shows whose certificate it is, and only
  pressing the button uses the invite up. The download for the device that opened it comes first,
  and once a site requires certificates the page ends with a link to it, to check that it works.
  The page with the password and the downloads can be reloaded for ten minutes; a chat app's
  preview, a scanner or a script is shown nothing of an invite; and a link cut short on its way
  says so, rather than that someone used it. It runs as nobody with the invites folder and nothing
  else - an image is published on ghcr.io - and keeps invite secrets out of its log and nginx's.
  It is its own small HTTP server, with every request bounded in time and size.
- **nginx.** The Nginx tab says where nginx's sites and CA files are and how to test and reload it;
  lists every HTTPS site with its client-certificate mode - off, optional or required - and changes
  it with the lines shown first, `nginx -t`, and the file put back if nginx refuses; and writes the
  enrollment site, keeping blocks other tools such as stop-bots add to it. HTTP logins' password
  files can be given to nginx's group alone (`g` on the Users tab) instead of being readable by
  every user of the machine.
- **Revocation that reaches nginx.** Every new revocation list is copied where nginx reads it, and
  nginx reloads. An hourly systemd timer, set up from the CA tab, re-signs the list (valid 30
  days), records collected invites, and revokes the certificates of invites that expired
  uncollected.
- **The command line**, for scripts: `ffca init`, `issue` (an agent may send its own certificate
  signing request, for a P-256, P-384, Ed25519 or RSA key), `revoke`, `rename`, `list`, `crl-refresh`, `key`, `serve`.
- **Deployment**: a guide, a Compose service for the enrollment page, and `make install`.
