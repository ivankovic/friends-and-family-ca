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

# The ffca derivation, kept separate from flake.nix so it can be imported directly by anyone not
# using flakes (`pkgs.callPackage ./packaging/nix/package.nix { }`) and so a nixpkgs submission has
# a single file to take.
#
# `src` is a parameter rather than a `fetchFromGitHub` call baked in here: the flake at the repo
# root passes the checkout itself, so `nix build` and `nix run` work on a working tree with no tag
# and no hash. A nixpkgs submission would instead pass a `fetchFromGitHub { ... hash = "sha256-..."; }`
# and swap `cargoLock.lockFile` for a `cargoHash`, since nixpkgs does not carry the lock file.
{
  lib,
  rustPlatform,
  makeWrapper,
  openssl,
  python3,
  src ? ../..,
  version ? "0.1.0",
}:

rustPlatform.buildRustPackage {
  pname = "friends-and-family-ca";
  inherit version src;

  # Avoids needing a vendor hash at all: the lock file is right here in the source tree.
  cargoLock.lockFile = "${src}/Cargo.lock";

  # cargo-nextest, as CI and the Makefile run the suite: one process per test.
  useNextest = true;

  # The library's tests only: they check certificates with the `openssl` command and the Apple
  # profile with Python's plistlib. The end-to-end tests in tests/ start nginx in a container and
  # the UI under a pseudo-terminal, which the build sandbox cannot.
  cargoTestFlags = [ "--lib" ];
  nativeCheckInputs = [
    openssl
    python3
  ];

  # ffca makes the .p12 files with the `openssl` command.
  nativeBuildInputs = [ makeWrapper ];
  postInstall = ''
    wrapProgram $out/bin/ffca --prefix PATH : ${lib.makeBinPath [ openssl ]}
  '';

  meta = {
    description = "A small certificate authority for mutual-TLS client certificates";
    longDescription = ''
      Friends and Family CA runs a certificate authority for a household or a small group: a
      terminal UI to issue and revoke client certificates and to choose which of a web server's
      sites demand one, and a web page where family and friends collect their certificates
      through a one-time invite link.
    '';
    homepage = "https://github.com/ivankovic/friends-and-family-ca";
    changelog = "https://github.com/ivankovic/friends-and-family-ca/releases";
    license = lib.licenses.agpl3Only;
    mainProgram = "ffca";
    maintainers = [ ];
    platforms = lib.platforms.linux;
  };
}
