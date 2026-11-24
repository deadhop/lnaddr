# deadhop lnaddr

A Lightning address (LUD-16) for a node with no public address. Two static binaries:

- **`lnaddr-node`** runs next to your Lightning node (LND, Core Lightning, phoenixd or LNbits). It opens no port. It answers invoice requests over [ContextVM](https://contextvm.org) (MCP over Nostr), end-to-end encrypted, only from the keys you list, with an invoice-only credential.
- **`lnaddr-gateway`** runs on any public host behind any reverse proxy. It serves `/.well-known/lnurlp/<name>` from a cache, asks your node for each invoice over Nostr, and checks every invoice before a wallet sees it. It has an optional admin web interface and a CLI.

```text
wallet ──https──▶ reverse proxy ──▶ lnaddr-gateway ──Nostr relays──▶ lnaddr-node ──▶ your Lightning backend
```

Documentation: `site/docs/lnaddr/` (published at `/docs/lnaddr/`): architecture, performance, hardening, security, configuration, reverse proxies, backends, admin.

## Build

```sh
cargo build --release                       # target/release/lnaddr-node, lnaddr-gateway
docker build -f lnaddr/Dockerfile --target node    -t deadhop-lnaddr-node .     # from the repo root
docker build -f lnaddr/Dockerfile --target gateway -t deadhop-lnaddr-gateway .
```

Both images are a single static (musl) binary on `scratch`, about 8 MB each. No openssl or system TLS: rustls with ring and compiled-in web roots.

## Minimal run

```sh
# public host
lnaddr-gateway pubkey                                 # npub for the node's gateways
LNADDR_GATEWAY_DOMAIN=yourdomain.com LNADDR_GATEWAY_NODE=npub1node… lnaddr-gateway

# next to the Lightning node
lnaddr-node pubkey                                    # npub for the gateway's node
LNADDR_NODE_BACKEND=lnd LNADDR_NODE_BACKEND_SECRET_FILE=invoice.macaroon \
LNADDR_NODE_BACKEND_TLS_CERT_FILE=tls.cert LNADDR_NODE_GATEWAYS=npub1gw… \
LNADDR_NODE_ADDRESSES=you lnaddr-node
```

Configuration comes from built-in values (`LNADDR_NODE_BUILTIN` / `LNADDR_GATEWAY_BUILTIN` at build time), a TOML file (`--config`), environment variables, and (node, opt-in) address and limit changes from an admin key over ContextVM. Any layer can lock later ones out.

## Try it without a Lightning node

`demo/` is a local stage: a Nostr relay on `ws://127.0.0.1:7788` and a fake LND on `http://127.0.0.1:18080` (macaroon `demo`) that signs real regtest invoices. Run it, then the two real binaries against it with `network = "regtest"`, `LNADDR_NODE_BACKEND_URL=http://127.0.0.1:18080`, `LNADDR_NODE_BACKEND_SECRET=demo` and the relay above.

```sh
(cd demo && cargo run --release)
```

## Verify

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo llvm-cov --all-targets --fail-under-lines 100 --fail-under-functions 100
```

## Layout

| Path | What |
| --- | --- |
| `src/node/` | node service: config layers, backends, the MCP tools, the request loop and CLI |
| `src/gateway/` | gateway: config, node directory and cache, public HTTP, admin web, CLI |
| `src/lnurl.rs`, `src/bolt11.rs` | LUD-06/12/16 and invoice checks shared by both |
| `src/pool.rs`, `src/cvm.rs`, `src/handshake.rs` | relay pool (first OK wins), stateless ContextVM client, local MCP handshake |
| `src/files.rs`, `src/tls.rs`, `src/settings.rs`, `src/ratelimit.rs` | private files, pinned TLS, config parsing, rate limits |
