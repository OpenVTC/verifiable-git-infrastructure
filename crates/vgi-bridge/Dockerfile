# The VGI bridge, as the container a community runs next to its VTC.
#
# Build from the repository root:
#   docker build -f crates/vgi-bridge/Dockerfile -t vgi-bridge .
#
# Runtime needs: the config at /etc/vgi-bridge/bridge.toml, the master key
# (a mounted secret, owner-only), a writable /var/lib/vgi-bridge for the state
# store, and `git` (the bridge-posted check fetches commit objects with it and
# never runs anything from them). See docs/BRIDGE.md.
#
# Both base images are pinned by digest, as every action is pinned by commit
# SHA; Dependabot keeps the pins current and CI refuses a FROM without one.

FROM rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
# The TDK's keyring store links libdbus on Linux (dbus-secret-service), so the
# build needs its headers and the runtime its shared library.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY . .
# One rustc at a time while the graph compiles trust-tasks-rs twice (0.36,
# and 0.34 with every family for trql-client 0.28): each is 10 GB or more,
# and two at once run the runner out of memory. Back to the default once a
# trql-client on the workspace's trust-tasks line removes the second copy.
RUN cargo build --release --locked -j 1 -p vgi-bridge

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git libdbus-1-3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/vgi-bridge --create-home vgi
COPY --from=build /src/target/release/vgi-bridge /usr/local/bin/vgi-bridge
USER vgi
ENV VGI_BRIDGE_CONFIG=/etc/vgi-bridge/bridge.toml
VOLUME ["/var/lib/vgi-bridge"]
EXPOSE 8080
# `/healthz` via the binary itself: the image carries no curl.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/vgi-bridge", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/vgi-bridge"]
CMD ["run"]
