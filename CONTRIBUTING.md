# Contributing

**At this time, to keep the development speed high, contributions are not accepted.**

## Technology

The product is written in Rust. The developer scripts in `scripts/` are Python.

The administrator's UI is a terminal UI, written with the Ratatui and Crossterm libraries.

### UI design patterns

The UI uses the [Component architecture](https://ratatui.rs/concepts/application-patterns/component-architecture/).

Each component encapsulates its own state, event handlers, and rendering logic.

## Code quality

Format all code with `cargo fmt`, the standard Rust formatter. CI enforces this on every push and
pull request.

No Rust check errors are allowed. Run `cargo clippy` frequently. CI also enforces `cargo clippy`.

The Python under `scripts/` has the same two halves, as `ruff format` and `ruff check` - run both
with `make lint-python`. Install `ruff` once for every repository under your user with
`uv tool install ruff@0.16.4`, matching the version `.github/workflows/ci.yml` pins, or work inside
`nix develop`, whose devShell already has it. The rule set is pinned in the root `ruff.toml` rather
than left on ruff's defaults, for the reason that file gives.

### Comments describe how the code *is*

A comment explains what the code does and why it is that way. It does not narrate what the code
used to be, what was tried and reverted, or when either happened. "An earlier version kept the key
unencrypted" reads as a live fact to someone skimming, and cannot be checked against the code in
front of them.

Where the *reason* for a choice is that the alternative is worse, say so in the present tense:
**"a CRL past its next-update time makes nginx refuse every client, so the refresh runs daily"**,
not "we once locked everyone out".

Two things this does **not** mean:

* Runtime state is not history. "the previously issued certificate", "the old CRL" describe what
  the program is doing now.
* A test whose subject is a past bug keeps its subject - stated as the property it pins. "A revoked
  certificate stays revoked after the CRL is refreshed", not "refresh used to drop revocations".

`git log` and `git blame` hold the history.

## Testing

Run automated tests frequently during coding.

### Automated tests

Each file in `src/` ends with its own test module, as is typical in Rust. These tests must cover
both the happy path and corner cases. Certificates are security-critical: a test of one checks what
a TLS peer would check (the chain, the validity period, the key usage, the revocation list), not
only that a file was written.

**Per-file unit tests must run in under 1 second.**

### End-to-end tests

`tests/` runs the real `ffca` binary, the way it is used:

* `tests/cli.rs` - every command: exit codes, what it prints, the files it writes, and whether
  `openssl verify` accepts the certificates.
* `tests/nginx.rs` - the CA against a real nginx (`nginx:alpine` in a rootless container), with a
  site that requires a client certificate, asked by `curl`: people and agents get in and nginx sees
  who they are; no certificate, another CA's, an expired one and a revoked one (after a reload) are
  refused; an expired CRL locks everyone out until it is refreshed. And ffca driving it: setting a
  site to required and back (the file returns byte for byte), a CLI revocation reloading nginx by
  itself, and a change nginx refuses leaving the site as it was. nginx answers every refusal with
  a bare 400, even under `ssl_verify_client optional`, so the tests read OpenSSL's reason from its
  error log. Each test starts its own container; the first run pulls the image.
* `tests/tui_terminal.rs` - `ffca tui` under a pseudo-terminal (util-linux `script`), its output
  replayed on an emulated screen (the `vt100` crate): keys in, files out, the terminal restored on
  `q` and on Ctrl-C, and changes made elsewhere appearing without a key press.

They need `openssl`, `curl`, `script`, and podman or docker (`FFCA_CONTAINER_ENGINE` picks one;
`FFCA_NGINX_IMAGE` another image). GitHub's `ubuntu-latest` has all of them. The whole suite takes
about ten seconds, most of it the nginx containers starting.

### Test dependencies

**No mocks.** Mocks block testing through the interface, and mocks are brittle.

Use the real implementation where possible.

Where the real implementation is not possible, for example for filesystem or web-server access, use
a fake in-memory implementation.

The TUI is tested the way it is used: keys in, screen out. `src/tui/app/tests.rs` drives an
`App` against a real CA in a temporary folder and reads the rendered screen from Ratatui's
`TestBackend`. `cargo nextest run --run-ignored only print_screens --no-capture` prints the main
screens for a person to look at.

The CA's tests run `openssl verify`, because nginx checks client certificates with OpenSSL and its
verdict is the one that counts: install the `openssl` command to run them.

Tests that write state use `crate::test_dir()`, a temporary folder on `/dev/shm` where the system
has one. The store syncs every write to disk, and on a busy disk that makes the suite many times
slower for nothing a test checks.

## Code structure

Follow Rust's standard project structure.

```
<root of the repository>
    |- /src             <- The implementation
        |- main.rs      <- Entry point: parses CLI args and runs the chosen command
        |- lib.rs       <- The library the commands are built from
        |- store.rs     <- The state folder: the lock, and writes that land whole or not at all
        |- ledger.rs    <- People and their devices, agents, every certificate, the CRL number
        |- ledger/tests.rs
        |- ca.rs        <- Creating the CA, issuing, revoking, signing the CRL
        |- ca/tests.rs  <- Its tests: certificates checked by rustls-webpki and by `openssl verify`
        |- files.rs     <- Writing an issued certificate and its key to files
        |- config.rs    <- The administrator's settings (config.toml): nginx, the enrollment site
        |- bundle.rs    <- What a device installs: a .p12 (via openssl), an Apple profile
        |- invite.rs    <- Invites: sealed one-time bundles, collecting, tending, cancelling
        |- serve.rs     <- `ffca serve`, the enrollment page
        |- timer.rs     <- The hourly systemd timer for `ffca crl-refresh`
        |- nginx.rs     <- nginx's sites: a parser of its syntax, the client-certificate editor,
        |- nginx/          test-then-reload with rollback, and the CA's files where nginx reads them
        |- tui.rs       <- `ffca tui`: the event loop
        |- tui/         <- session.rs (setup, a CA that cannot open, or the app),
                           app.rs (carries out actions, draws the frame), action.rs,
                           components/ (people tree, Nginx tab, CA tab, form, revoke and
                           mode dialogs, message)
    |- /tests           <- End-to-end tests: the CLI, a real nginx, the TUI on a real terminal
    |- /scripts         <- Developer scripts (the local CI mirror)
    |- /packaging       <- Deployment: the guide (README.md), the enrollment page's Dockerfile and
                           Compose service; the Nix recipe; the third-party notices configuration
    |- README.md        <- High-level project summary. Must be readable to humans.
    |- CONTRIBUTING.md  <- This file
    |- AGENTS.md        <- AI-only instructions
    |- REVIEW.md        <- Open code-health items
```

`README.md` files can exist in any subdirectory: a high-level summary of it, readable by humans.
Why the code is the way it is lives next to the code, in module-level doc comments (`//!`), not in
separate design documents. Working notes (follow-ups, experiments, negative results) are kept out
of the repository; `AGENT_LOG.md` at the root is git-ignored for that. `REVIEW.md` stays root-only.

## Makefile targets

* `test` - `cargo nextest run --locked`: the unit tests and the end-to-end tests in `tests/` (see
  "End-to-end tests" for what those need). Requires `cargo-nextest` (`cargo install cargo-nextest
  --locked`, one-time).
* `build` - `cargo build --release --locked`. It does not run the tests.
* `install` - `test`, then `build`, then the binary installed as `/usr/local/bin/ffca` (`PREFIX`
  changes `/usr/local`), with `sudo` if that folder is not writable. A failing test installs
  nothing. This is how a server gets `ffca`: see `packaging/README.md`.
* `install-hooks` - one-time setup that points git at `.githooks/`. `pre-commit` formats the Rust
  and Python a commit stages (`cargo fmt`, `ruff format`). `pre-push` runs the fast subset of what
  CI checks (`cargo fmt --check`, `cargo clippy`, `ruff`) before a `git push` leaves your machine -
  see each file's own comment for exactly what it does and does not cover. `git push --no-verify`
  skips it for one push.
* `lint-python` - `ruff check` then `ruff format --check` over `scripts`, the directory CI's
  python job covers.
* `third-party-notices` - regenerates `THIRD-PARTY-NOTICES.md` from `Cargo.lock` with cargo-about
  (`cargo install cargo-about --features cli`). Run it after every dependency change and commit
  the result; `check-third-party-notices` fails CI otherwise.
* `ci` - the whole of CI, locally: every job in `.github/workflows/ci.yml`, in that file's own
  order. It reads the commands out of `ci.yml` itself rather than keeping a copy, so it cannot
  drift from CI; `python3 scripts/ci_local.py --list` shows the job ids and `--job <id>` runs one
  of them. Needs PyYAML.

## CI

Every push and pull request runs (see `.github/workflows/ci.yml`):

* `cargo fmt --check`
* `cargo clippy --tests -- -D warnings`
* `cargo build` + `cargo nextest run`, the end-to-end tests included
* `cargo audit` (checks Cargo.lock against the RustSec advisory database)
* `ruff check` and `ruff format --check` over `scripts/`, and `make check-third-party-notices`
* `cargo check --locked` on the toolchain `Cargo.toml`'s `rust-version` names
* `cargo package --locked` - the crate builds from its own tarball, as `cargo publish` will see it

`.github/workflows/nix.yml` builds the Nix recipe when one of its inputs changes, and weekly.

Every action is pinned by commit, with its version in a comment beside it, and dependabot moves
the pins; `dtolnay/rust-toolchain` has no releases, so its pin moves by hand. In
`.github/workflows/release.yml`, the job that compiles - and so runs every dependency's build
scripts - has a read-only token and no cache; only the jobs that run none of that code may write.
Keep it that way when adding a step.

All of these checks must pass before a PR is done. Two things run them locally, before GitHub
does - see "Makefile targets" above:

* `make install-hooks` puts the fast subset (fmt, clippy, ruff) on every `git push`, so the common
  mistakes never leave your machine.
* `make ci` runs *all* of the above, driven by parsing `ci.yml` itself so the two cannot drift.
  What it does not reproduce is the runner: it uses your toolchain and OS, where CI gets a clean
  pinned `ubuntu-latest`.
