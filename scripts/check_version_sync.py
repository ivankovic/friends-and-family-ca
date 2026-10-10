#!/usr/bin/env python3
# This file is part of Friends and Family CA.
#
# Copyright (C) 2026 Marko Ivankovic
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""Checks that every file repeating the version names the one Cargo.toml does.

Cargo.toml is the source of truth: the binary reports it, `make release` tags `v<it>`, and
release.yml builds whatever the tag names. These repeat it by hand:

* packaging/nix/package.nix - the `version ?` fallback
* packaging/compose/ffca.yml - the release image's tag

With `--release`, CHANGELOG.md must also have a dated section for it, `## [<version>] - YYYY-MM-DD`:
release.yml takes the release notes from there and refuses a tag without one.

Run by `make check-versions` (CI), and with `--release` by `make release`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def found(path: str, pattern: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        sys.exit(f"check_version_sync: no version found in {path}")
    return match.group(1)


def main() -> int:
    version = found("Cargo.toml", r'^version = "([^"]+)"')
    repeated = {
        "packaging/nix/package.nix": found(
            "packaging/nix/package.nix", r'^\s*version \? "([^"]+)"'
        ),
        "packaging/compose/ffca.yml": found(
            "packaging/compose/ffca.yml", r"ghcr\.io/ivankovic/friends-and-family-ca:([^\s]+)"
        ),
    }
    stale = {path: v for path, v in repeated.items() if v != version}
    for path, other in stale.items():
        print(
            f"check_version_sync: Cargo.toml says {version}, {path} says {other}", file=sys.stderr
        )
    if "--release" in sys.argv[1:]:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        heading = rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
        if not re.search(heading, changelog, re.MULTILINE):
            print(
                f"check_version_sync: CHANGELOG.md has no `## [{version}] - YYYY-MM-DD` section",
                file=sys.stderr,
            )
            return 1
    if stale:
        return 1
    print(f"check_version_sync: every file names {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
