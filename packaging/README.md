# Deploying Friends and Family CA

Three parts run on the server:

| Part | Runs as | Can reach |
|---|---|---|
| `ffca` - the terminal UI, and the command line | root, on the host (`sudo ffca`) | the CA's key, nginx's site configs and its CA files, `docker exec` |
| `ffca crl-refresh` - hourly, from a systemd timer | root, on the host | the same |
| `ffca serve` - the enrollment page | nobody (65534), in a container next to nginx | the invites folder, nothing else |

The enrollment page faces the internet, so it holds no key: it can hand over an invite that the
UI made, once, and that is all. Everything that signs runs on the host.

The steps below use a Docker Compose setup with nginx in a container, on a server whose sites are
`*.example.org`. The values for one such server are given as examples.

## 1. Install the binary on the host

```sh
cd friends-and-family-ca
git pull
make install
```

`make install` runs the whole test suite, builds the release, and installs it as
`/usr/local/bin/ffca`, asking for `sudo` for that last step. Nothing is installed if a test fails.
The tests need `cargo-nextest` (`cargo install cargo-nextest --locked`), and the end-to-end ones
`openssl`, `curl`, `script` and podman or docker; the host needs the `openssl` command anyway, to
make the `.p12` files.

## 2. Create the CA

```sh
sudo ffca
```

With no CA yet, it asks for a name - the one devices show among their installed certificates -
and how many years the CA is valid. The CA lives in `/var/lib/ffca`. **Put that folder in your
backups**: without the key, every certificate has to be issued again.

**Guard those backups like the key itself, because they hold it.** Whoever has a copy can make
certificates for any name - `CN=Anna (phone),OU=people` - that are in no ledger, so revoking by
serial cannot reach them, and the only cure is a new CA and every device enrolled again. Keep the
backups encrypted, and snapshots of the folder as private as the folder.

## 3. Tell it where nginx is

On the **Nginx** tab, press `e`:

| Field | What | Example |
|---|---|---|
| Site configs | the folder of nginx's `*.conf` site files, on the host | `/srv/domaci/nginx/conf.d` |
| CA files, here | a folder nginx can read, on the host: ffca copies the CA's certificate and revocation list there | `/srv/domaci/nginx/certs` |
| CA files, in nginx | the same folder, as nginx sees it | `/etc/nginx/certs` |
| Test command | | `docker exec nginx nginx -t` |
| Reload command | | `docker exec nginx nginx -s reload` |
| Enrollment site | the host name invites open; it needs DNS and a TLS certificate | `k.domaci.ivankovic.me` |
| Enrollment page at | where nginx finds `ffca serve` | `http://ffca:8080` |
| Page runs as | the page's `uid:gid`; it is given the invites folder | `65534:65534` |

Saving copies the CA's files where nginx reads them and hands `/var/lib/ffca/invites` to the
page's user. If nginx runs in a container, mount that folder into it as a folder, not file by
file: ffca replaces the files, and a file mounted on its own would keep showing the old one. The tab then lists every HTTPS site; nothing has changed in them yet.

A wildcard DNS record and a wildcard certificate cover the enrollment site already. Otherwise,
add a DNS record for it and get it a certificate before step 5.

## 4. Start the enrollment page

Add the service in [`compose/ffca.yml`](compose/ffca.yml) to your `docker-compose.yml`, under
`services:`. Adjust the build context (your checkout), the user (as on the Nginx tab), and the
network: one nginx is on, and nothing else - a container on the same network could reach the page
directly, past nginx and its limits. Then:

```sh
sudo docker compose up -d --build ffca
sudo docker compose ps ffca        # healthy, after a few seconds
```

The image is a static binary on an empty base, run as nobody, read-only, with every capability
dropped and a cap on its processes and memory (`pids_limit`, `mem_limit`). Its only volume is the
invites folder.

## 5. Write the enrollment site

On the **Nginx** tab, press `w`. ffca shows the `server` block it will write -
`ffca-enrollment.conf` in the site configs, with the listen, TLS certificate and includes of a
site on the same domain - then writes it, tests nginx's configuration and reloads. If nginx
refuses it, nothing is written.

The site forwards to the page by name through Docker's DNS, looked up when a request comes, so
nginx starts even while the page is down. It copies the other site's `include`s - a shared
logging snippet, say - but leaves invite links (`/i/…`, `/d/…`) out of the access log: their
path is the invite's secret. Check it in a browser: `https://<enrollment site>/` says "Friends
and Family CA".

A bot filter such as stop-bots finds the new site like any other: re-scan and apply it there.
Pressing `w` again later keeps whatever block another tool wrote into the file. Exempt the invite
paths, `/i/` and `/d/`, on the enrollment site from the filter, as you would `/.well-known/`: chat
apps fetch a link to preview it, and Android's download manager fetches the `.p12` without the
headers a browser sends, and a filter turns both away. A preview does not use the invite up - only
pressing the button does.

If no site on the enrollment site's `listen` address is marked `default_server`, nginx takes the
first one it reads as the default, and `ffca-enrollment.conf` sorts early: requests for an unknown
name, or for the bare IP address, then reach the enrollment page. That gives nothing away - the
page hands out nothing without an invite's secret - but mark another site `default_server` if you
would rather they went there.

## 6. Set up the refresh timer

On the **CA** tab, press `T`. It writes `ffca-crl-refresh.service` and `.timer` to
`/etc/systemd/system` and enables them, naming the `ffca` you are running - which must be the one
`make install` put in `/usr/local/bin`: the timer runs it as root, so ffca refuses a binary, or a
folder, that anyone but root could change. Every hour, the timer re-signs the revocation list (valid
for 30 days), records collected invites, revokes the certificates of invites that expired
uncollected, and reloads nginx with the result. The CA tab shows whether it runs; so does

```sh
systemctl list-timers ffca-crl-refresh.timer
```

## 7. Invite a device

On **People & agents**, press `p` for a new person (`n` adds a device to the selected one). The
invite's QR code and link appear: scan it with the device, or send it the link. The link works
once, for 24 hours.

* **iPhone, iPad**: open the link, press the button, download the profile, then in Settings tap
  *Profile Downloaded* and *Install*.
* **Android, Boox**: open the link, press the button, download the `.p12` and install it with
  the password the page shows.
* **Firefox, other computers**: the same `.p12`, imported in the browser's or the system's
  certificate settings.

The **Invites** tab shows each invite: open, collected (when, and from where), expired or
cancelled. If someone says they never collected an invite that shows as collected, revoke that
device.

## 8. Ask for certificates, a site at a time

On the **Nginx** tab, select a site and press `s`:

1. **Optional** first: devices with a certificate are checked - a revoked one is refused - while
   everyone else still gets in. Try the site from each device.
2. **Required** once they work: nobody gets in without a valid certificate from this CA.

Every change shows its lines first, is tested with `nginx -t`, and is put back if nginx refuses
it. Apps that cannot present a certificate (a TV's media player, some mobile apps) need their site
left off, or optional.

To see which certificate came in, log it: `$ssl_client_s_dn` names the person and device, and
`$ssl_client_serial` the certificate - `ffca list` shows its first characters, and `ffca revoke
--serial` takes it as nginx writes it. A serial that is in no ledger means someone has the CA's
key.

```nginx
log_format clients '$remote_addr [$time_local] "$request" $status "$ssl_client_s_dn" $ssl_client_serial';
```

## Revoking

On **People & agents**, select a device, an agent or a person and press `r`. The new revocation
list reaches nginx at once.

## Updating

```sh
cd friends-and-family-ca && git pull && make install
sudo docker compose up -d --build ffca
```

## Undoing it

1. On the **Nginx** tab, set every site back to **off** (`s`).
2. Delete `ffca-enrollment.conf` from the site configs and reload nginx.
3. Remove the `ffca` service: `sudo docker compose rm -sf ffca`, then its lines from
   `docker-compose.yml`.
4. `sudo systemctl disable --now ffca-crl-refresh.timer`, and delete the two units from
   `/etc/systemd/system`.

`/var/lib/ffca` keeps the CA, should you want it back.

## Releasing

For the maintainer. A release is cut from `main` by `make release`, and GitHub does the rest.

1. Deploy it on a real server and install certificates on real devices first: iPhone or iPad,
   Android, a desktop browser. The tests cannot say whether a device accepts what it is given.
2. In `CHANGELOG.md`, turn `## [Unreleased]` into `## [<version>] - <today>`, and make sure
   `Cargo.toml`, `packaging/nix/package.nix` and `packaging/compose/ffca.yml` name that version
   (`make check-versions`). Commit and push.
3. `cargo login` once, if this machine has not published to crates.io before.
4. `make release`. It refuses unless the tree is clean, on `main` and at `origin/main`, the version
   is untagged and named everywhere with its changelog section, and every test passes. Then it
   publishes the crate to crates.io - which cannot be undone, only yanked - and pushes the tag.
5. The tag starts `.github/workflows/release.yml`: static binaries for x86_64 and aarch64, the
   enrollment page's image on ghcr.io for amd64 and arm64, checksums, and the release, published
   with the changelog section as its notes. The tarballs and the image are attested. Watch it with
   `gh run watch`.

   The binaries are built with the Rust toolchain, zig and cargo-zigbuild that `release.yml`'s
   `env` names. Move them there, by hand, when a newer one is wanted.
6. The first time only: the image's package on ghcr.io is private when it is created. Make it
   public in the package's settings on GitHub.
7. Add `## [Unreleased]` back to the top of `CHANGELOG.md`.
