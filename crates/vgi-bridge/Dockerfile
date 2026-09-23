# The VGI bridge, as the container a community runs next to its VTC.
#
# Build from the repository root:
#   docker build -f crates/vgi-bridge/Dockerfile -t vgi-bridge .
#
# Runtime needs: the config at /etc/vgi-bridge/bridge.toml, the master key
# (a mounted secret, owner-only), a writable /var/lib/vgi-bridge for the state
# store, and `git` (the bridge-posted check fetches commit objects with it and
# never runs anything from them). See docs/BRIDGE.md.

FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p vgi-bridge

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/vgi-bridge --create-home vgi
COPY --from=build /src/target/release/vgi-bridge /usr/local/bin/vgi-bridge
USER vgi
ENV VGI_BRIDGE_CONFIG=/etc/vgi-bridge/bridge.toml
VOLUME ["/var/lib/vgi-bridge"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vgi-bridge"]
CMD ["run"]
