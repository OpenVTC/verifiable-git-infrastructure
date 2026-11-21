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

FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
# The TDK's keyring store links libdbus on Linux (dbus-secret-service), so the
# build needs its headers and the runtime its shared library.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --locked -p vgi-bridge

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
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
