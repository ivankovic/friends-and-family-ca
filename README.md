# Friends and Family CA

[![CI](https://github.com/ivankovic/friends-and-family-ca/actions/workflows/ci.yml/badge.svg)](https://github.com/ivankovic/friends-and-family-ca/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](LICENSE)

A small certificate authority for mutual-TLS client certificates, for a home server and the people
who use it.

You self-host Nextcloud, Immich or Jellyfin, and you want only your own family's devices to reach
them: a client certificate on each device, checked by nginx before anything else runs. The tools
that issue those certificates are made for companies, and they expect every person to run
commands on their own device. Friends and Family CA is made for one administrator and a handful of
people who should never need to: you run a terminal UI over SSH, and they scan a QR code.

```
 Friends and Family CA · Domaci                                       CRL valid until 2 Nov 2026
 People & agents │ Invites │ Nginx │ CA
╭──────────────────────────────────╮╭──────────────────────────────────────────────────────────╮
│▾ Anna                            ││ Anna · phone                                             │
│  ● phone          until 2028     ││                                                          │
│  ● laptop         until 2028     ││ Current   439ce6f2   issued 3 Oct 2026, valid until 2028 │
│▾ Ben                             ││           CN=Anna (phone),OU=people                      │
│  ✕ tablet         retired        ││ Earlier   0330b08b   revoked 3 Oct 2026 · replaced       │
│▾ Agents                          ││                                                          │
│  ● backup         until 2028     ││                                                          │
│  ◐ monitoring     expires in 12 d││                                                          │
╰──────────────────────────────────╯╰──────────────────────────────────────────────────────────╯
 p new person  n new device  a new agent  u renew  r revoke  R rename  Tab switch  ? help  q quit
```

# What it does

* **A terminal UI** (`sudo ffca`) for everything an administrator does: create the CA; add people,
  their devices, and agents - programs that sign in as themselves, such as a backup job; renew,
  revoke and rename; see every certificate each has held.
* **Invites.** A new device gets a link, shown as a QR code, that works once for a day. It opens
  the enrollment page, which hands the device its certificate - a profile for iPhone and iPad, a
  `.p12` and its password for Android, Windows, macOS and the browsers - with how to install it.
* **nginx.** The Nginx tab lists your HTTPS sites and sets each to ask for no certificate, accept
  one, or require one. Every change is shown first, tested with `nginx -t`, and put back if nginx
  refuses it. It also writes the enrollment site.
* **Revocation that takes effect.** A revoked device is refused as soon as you press Enter: the
  new revocation list is copied where nginx reads it and nginx reloads. An hourly timer re-signs
  the list long before it expires, so nobody is locked out by a stale one, and tidies up invites.

Revoke a person, one of their devices, or a single certificate; agents may send their own
certificate signing request, so their key never leaves their machine.

# How it is built

* **The CA's key stays on the host**, readable by root only, with the ledger of every certificate
  issued. All files are standard PEM and TOML: `openssl` can take over, and a person can read them.
* **The enrollment page** (`ffca serve`), the only part that faces the internet, runs in a
  container next to nginx, as nobody, with the invites folder and nothing else. It cannot issue
  anything: it hands over an invite the administrator made, once.
* **An invite's link carries a 256-bit secret.** The invite is sealed with a key derived from it,
  and its file is named after the secret's hash, so the folder alone reveals nothing. Opening the
  link does not use it up - chat apps fetch links to preview them - only pressing the button does.
* **Certificates are ECDSA P-256**, for client authentication only, with subjects nginx can log and
  match: `CN=Anna (phone),OU=people`, `CN=backup,OU=agents`.

It is tested against what it drives: certificates checked by `rustls-webpki` and `openssl verify`,
a real nginx in a container asked by `curl` - an invite all the way to a site that requires a
certificate - and the terminal UI on a pseudo-terminal.

# Installing

It runs on Linux, beside nginx, and needs the `openssl` command, which makes the `.p12` files.

* **A release's binary** - static, for x86_64 and aarch64 - from the
  [releases page](https://github.com/ivankovic/friends-and-family-ca/releases), or
  `cargo binstall friends-and-family-ca`.
* **From crates.io:** `cargo install --locked friends-and-family-ca`.
* **From a checkout:** `make install` runs the tests, builds the release and installs it as
  `/usr/local/bin/ffca`.

The enrollment page's image is `ghcr.io/ivankovic/friends-and-family-ca`. The release's files and
the image are attested by the workflow that built them: `gh attestation verify <file> --repo
ivankovic/friends-and-family-ca` checks one.

Then follow **[the deployment guide](packaging/README.md)**: create the CA, tell it where nginx is,
start the enrollment page, invite your own devices, and turn sites on one at a time.

# License

Copyright (C) 2026 Marko Ivankovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3 of the License.

See the LICENSE file for the full text of the License.

## Cannot use AGPL software?

A commercial license is available as a monthly subscription through
[GitHub Sponsors](https://github.com/sponsors/ivankovic). It covers internal use of Friends and
Family CA by your organisation without the source-disclosure obligations of the AGPL. The terms
are in [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL). Pick the tier that names the commercial license
as a benefit. For invoicing or other arrangements, contact me at
[marko@ivankovic.me](mailto:marko@ivankovic.me).

# AI policy

This project uses substantial AI assistance, currently Claude Code. Most commits disclose this
with a `Co-Authored-By` trailer and a link to the session that produced them. This project does not
hide that fact. This project does not treat AI assistance as a lesser way to write software.

Contributions are not accepted at this time, to keep the development speed high (see
[CONTRIBUTING.md](CONTRIBUTING.md)). When that changes, AI-assisted contributions will be as
welcome as any other, disclosed the same way: whoever submits the work is responsible for
understanding it and standing behind it.

# For Developers, human or otherwise

See [CONTRIBUTING.md](CONTRIBUTING.md) for the technology overview, code-quality and testing
expectations, project structure, and what CI checks on every push and PR. `AGENTS.md` has
additional AI-agent-specific conventions.
