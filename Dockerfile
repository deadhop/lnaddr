# deadhop lnaddr: two images from one build, each a single static binary on
# an empty base. Build context: the repository root (the admin interface
# embeds the brand's fonts and mark).
#
#   docker build -f lnaddr/Dockerfile --target node    -t deadhop-lnaddr-node .
#   docker build -f lnaddr/Dockerfile --target gateway -t deadhop-lnaddr-gateway .
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY brand/logo/mark-currentcolor.svg brand/logo/
COPY brand/icons/favicon.svg brand/icons/
COPY brand/fonts/*.woff2 brand/fonts/
COPY server/crates server/crates
COPY lnaddr/Cargo.toml lnaddr/Cargo.lock lnaddr/
COPY lnaddr/src lnaddr/src
COPY lnaddr/assets lnaddr/assets
RUN cd lnaddr \
 && cargo build --release --locked --bins \
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

# On the public host, behind any reverse proxy.
FROM scratch AS gateway
COPY --from=build /out/lnaddr-gateway /lnaddr-gateway
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
ENV LNADDR_GATEWAY_DATA_DIR=/data LNADDR_GATEWAY_LISTEN=0.0.0.0:8080
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/lnaddr-gateway"]
