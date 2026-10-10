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

# The enrollment page, `ffca serve`, as a container: one static binary on an empty image, run as
# nobody. It is given the invites folder and nothing else - see packaging/README.md.
#
# Build from the repository root:
#     docker build -f packaging/docker/Dockerfile -t friends-and-family-ca .
#
# Run it with an init (Compose's `init: true`, `docker run --init`): as a container's first
# process, the page would not stop on SIGTERM by itself.

# The build image is pinned by digest, which dependabot moves; it has musl-dev already, so the
# build fetches nothing but the crates Cargo.lock names, checked against their hashes.
FROM docker.io/library/rust:1-alpine@sha256:a96ea6d18d4062e38f16cfbadd8b4541d622f2527dd0a5eca1fb36d301da4e88 AS build
WORKDIR /src
COPY . .
# musl links statically: the binary needs nothing from the image it runs in.
RUN cargo build --release --locked --bin ffca && strip target/release/ffca

FROM scratch
COPY --from=build /src/target/release/ffca /ffca
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/ffca", "healthz"]
ENTRYPOINT ["/ffca"]
CMD ["serve", "--listen", "0.0.0.0:8080", "--invites", "/invites"]
