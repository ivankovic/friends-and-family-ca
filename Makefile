# This file is part of Friends and Family CA.
#
# Copyright (C) 2026 Marko Ivankovic
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# Product-side targets: build, test, install, third-party notices, the local CI mirror.

.PHONY: test build install install-hooks lint-python ci third-party-notices \
	check-third-party-notices

test:
	cargo nextest run

build:
	cargo build --release

# Installs this working tree, uncommitted changes included, over whatever `ffca` is on PATH.
install:
	cargo install --path . --force

# One-time per clone: makes git use the checked-in .githooks/ (the fast subset of CI).
install-hooks:
	git config core.hooksPath .githooks
	@echo "hooks enabled (git config core.hooksPath .githooks):"
	@echo "  pre-commit - formats the Rust and Python a commit stages (cargo fmt / ruff format),"
	@echo "               re-staging only files with no further unstaged changes"
	@echo "  pre-push   - fmt + clippy + ruff, CI's fast subset (.githooks/pre-push)"

# Regenerates THIRD-PARTY-NOTICES.md, the licenses of every crate the product binary links, from
# Cargo.lock (cargo-about, `cargo install cargo-about --features cli`). Ships beside the binary in
# every distribution and is what LICENSE-COMMERCIAL's third-party clause points at, so
# `check-third-party-notices` fails CI when a dependency change is not reflected here.
NOTICES_CONFIG := packaging/notices/about.toml
NOTICES_TEMPLATE := packaging/notices/third-party-notices.hbs
third-party-notices:
	cargo about generate -c $(NOTICES_CONFIG) $(NOTICES_TEMPLATE) -o THIRD-PARTY-NOTICES.md

check-third-party-notices:
	@tmp=$$(mktemp) && trap 'rm -f "$$tmp"' EXIT; \
	cargo about generate -c $(NOTICES_CONFIG) $(NOTICES_TEMPLATE) -o "$$tmp" && \
	if ! diff -q "$$tmp" THIRD-PARTY-NOTICES.md >/dev/null; then \
		echo "THIRD-PARTY-NOTICES.md is stale against Cargo.lock: run \`make third-party-notices\` and commit it" >&2; \
		diff "$$tmp" THIRD-PARTY-NOTICES.md | head -20 >&2; \
		exit 1; \
	fi; \
	echo "THIRD-PARTY-NOTICES.md is up to date"

# Lints and format-checks all Python (scripts/) with the rules pinned in ruff.toml, the same set
# the hook and CI lint.
lint-python:
	@command -v ruff >/dev/null 2>&1 || { \
		echo "make lint-python needs \`ruff\` on PATH, which CI installs for itself." >&2; \
		echo "Install it for every repository under your user, at the version ci.yml pins:" >&2; \
		echo "    uv tool install ruff@$(RUFF_VERSION)" >&2; \
		echo "(or work inside \`nix develop\`, whose devShell already has it)" >&2; \
		exit 1; \
	}
	ruff check $(PYTHON_DIRS)
	ruff format --check $(PYTHON_DIRS)

# The version ci.yml pins ruff to, only for the message above: CI's copy decides a push.
RUFF_VERSION := 0.16.4

PYTHON_DIRS := scripts

# Runs every command .github/workflows/ci.yml runs, read from ci.yml so it cannot drift.
# `python3 scripts/ci_local.py --list` shows the jobs, `--job <id>` runs one.
ci:
	python3 scripts/ci_local.py
