# Changelog

All notable changes to Friends and Family CA. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the version numbers follow
[Semantic Versioning](https://semver.org/) as far as a 0.x release does: a minor bump may change
the on-disk CA layout or the command line, a patch bump does not.

## [Unreleased]

### Added

- `ffca init` creates a certificate authority (ECDSA P-256) in a state folder, `/var/lib/ffca` by
  default, and signs its first certificate revocation list.
- The CA knows **people**, each with any number of **devices**, and **agents**: programs and
  machines that authenticate as themselves. A certificate names its holder, as
  `CN=Anna (phone), OU=people` or `CN=backup, OU=agents`, so a web server can tell them apart.
- `ffca issue --person Anna --device phone` issues a certificate and writes it with its key.
  `ffca issue --agent backup --csr backup.csr` signs an agent's own request instead, so its key
  never leaves its machine.
- `ffca revoke` revokes one certificate (`--serial`), a device's or agent's certificates, or
  every device of a person, and signs a new revocation list straight away. `--reason retired`
  also retires them, so nothing more is issued under that name.
- `ffca rename` renames a person, a device or an agent; `ffca list` lists them all, with every
  certificate each has held.
- `ffca crl-refresh` re-signs the revocation list, which is valid for 30 days, for a daily timer.
- `ffca tui`: a terminal UI for the administrator. A tree of people with their devices, and
  agents, beside the selected one's certificates; one key each to issue to a new device or agent,
  renew, revoke (with what it will reach shown first), and rename - `p` adds a person, `n` a
  device to the selected one; a CA tab with the CA's files and
  its revocation list, which it can re-sign. A revocation list close to expiry is flagged on every
  screen.
- Revoking a device or agent as `replaced` keeps its newest certificate: renew, install the new
  certificate, then revoke the old ones in one step.
- `ffca tui` always opens. Without a CA it sets one up - its name and how many years it is valid -
  and then says which two files to point the web server's `ssl_client_certificate` and `ssl_crl`
  at. A folder it may not write, or a CA it cannot open, is explained on screen, with what to do.
  `ffca` with no command opens it too.
- An **Nginx** tab in `ffca tui`: where nginx's site configurations are, where it reads the CA's
  certificate and revocation list (ffca keeps copies there; never the key), how to test and reload
  it, and the enrollment site, with a DNS check. Every HTTPS site with its client-certificate
  mode - off, optional or required - which `s` changes: the lines are shown first, written in a
  `# BEGIN ffca` block, tested with `nginx -t`, put back if nginx refuses them, then reloaded. The
  enrollment site can never be set to ask for a certificate.
- A new revocation list reaches nginx: `ffca revoke`, `ffca crl-refresh` and the terminal UI copy
  it where nginx reads it and reload nginx, once nginx is set up. Until now nginx kept accepting
  revoked certificates until something else reloaded it.
- **Invites.** Once the enrollment site is set, a new device (`p`, `n`) or a renewal (`u`) gets an
  invite instead of files: a link, shown with its QR code, that works once for 24 hours. The
  certificate is packed for the device - a `.p12` with a password for Android, Boox, Windows,
  macOS and the browsers, a configuration profile for iPhone and iPad - and sealed in the invites
  folder, readable only with the link. An **Invites** tab lists them: open, collected (when and
  from where), expired, cancelled; `x` cancels one.
- `ffca serve`, the enrollment page: opening a link shows whose certificate it is (a link preview
  does not use it up); the button hands it over once, with how to install it. It runs in a
  container next to nginx, as nobody, with the invites folder and nothing else; its Dockerfile and
  a Compose service are in `packaging/`, with a deployment guide.
- On the Nginx tab: where nginx finds the page, who it runs as (it is given the invites folder),
  and `w`, which writes the enrollment site's `server` block - its TLS certificate copied from a
  site on the same domain - tests it and reloads nginx.
- On the CA tab, `T` sets up an hourly systemd timer running `ffca crl-refresh`, which now also
  records collected invites and revokes the certificates of invites that expired uncollected.
- The enrollment site leaves invite links out of nginx's access log: their path carries the
  invite's secret, and an access log is read by more than the CA's administrator. Other requests
  to the site are logged as before, so bot detectors still see them.
- Rewriting the enrollment site (`w`) keeps blocks other tools wrote into it, such as stop-bots'
  bot filter, as they were.
