# deadhop lnaddr: two images from one build, each a single static binary on
# an empty base. Build context: this repository's root. Cargo fetches the
# shared crates from deadhop/server at the commit Cargo.lock pins.
#
#   docker build --target node    -t deadhop-lnaddr-node .
#   docker build --target gateway -t deadhop-lnaddr-gateway .
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY assets assets
RUN cargo build --release --locked --bins \
 && install -d -o 10001 -g 10001 -m 0700 /out/data \
 && cp target/release/lnaddr-node target/release/lnaddr-gateway /out/

# Next to the Lightning node: no listening port, only outbound relay connections.
FROM scratch AS node
COPY --from=build /out/lnaddr-node /lnaddr-node
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
ENV LNADDR_NODE_DATA_DIR=/data
VOLUME ["/data"]
ENTRYPOINT ["/lnaddr-node"]

# On the public host, behind any reverse proxy. /data keeps its keys, and
# network.json and audit.jsonl when its admins manage its relays.
FROM scratch AS gateway
COPY --from=build /out/lnaddr-gateway /lnaddr-gateway
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
ENV LNADDR_GATEWAY_DATA_DIR=/data LNADDR_GATEWAY_LISTEN=0.0.0.0:8080
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/lnaddr-gateway"]
