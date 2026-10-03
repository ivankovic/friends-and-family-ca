# Friends and Family CA

[![CI](https://github.com/ivankovic/friends-and-family-ca/actions/workflows/ci.yml/badge.svg)](https://github.com/ivankovic/friends-and-family-ca/actions/workflows/ci.yml)
[![License: AGPL v3+](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)

A small certificate authority for mutual-TLS client certificates, for a home server and the people
who use it.

You self-host Nextcloud, Immich or Jellyfin, and you want only your own family's devices to reach
them: a client certificate on each device, checked by the web server before anything else runs.
The tools that issue those certificates are made for companies, and they expect every person to
run commands on their own device. Friends and Family CA is made for one administrator and a
handful of people who should never need to.

> **Status: early development.** Nothing below works yet. The `ffca` binary has its commands, and
> each one says it is not implemented.

# What it does

* **A terminal UI for the administrator** (`ffca tui`), run over SSH. Every action is one key,
  with the keys always on screen, so there is nothing to remember between the few times a year
  you need it:
  * create the CA
  * issue a certificate for a person and a device, and revoke it when the phone is lost
  * choose, per site, whether the web server demands a certificate, accepts one, or ignores it
* **A web page for everyone else** (`ffca serve`). The administrator creates an invite in the
  terminal UI, and it shows a link and a QR code that work once and expire. The person opens it
  on their phone and installs the certificate: as a configuration profile on an iPhone or iPad,
  as a `.p12` file on Android.
* **A revocation list that never expires** (`ffca crl-refresh`), run from a timer. A web server
  that checks a revocation list refuses every client once the list is out of date.

The first web server it supports is nginx.

# License

Copyright (C) 2026 Marko Ivankovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

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
