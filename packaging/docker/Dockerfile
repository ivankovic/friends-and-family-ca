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

# The enrollment page, `ffca serve`, as a container: one static binary on an empty image, run as
# nobody. It is given the invites folder and nothing else - see packaging/README.md.
#
# Build from the repository root:
#     docker build -f packaging/docker/Dockerfile -t friends-and-family-ca .
#
# Run it with an init (Compose's `init: true`, `docker run --init`): as a container's first
# process, the page would not stop on SIGTERM by itself.

FROM docker.io/library/rust:1-alpine AS build
RUN apk add --no-cache musl-dev
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
