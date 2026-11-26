---
name: deadhop-lnaddr-setup
description: "Set up a Lightning address (you@yourdomain.com) for a Lightning node with no public address, using deadhop lnaddr: lnaddr-node next to LND, Core Lightning, phoenixd or LNbits with an invoice-only credential, and lnaddr-gateway on a public host behind a reverse proxy, paired by their Nostr keys. Use it whenever someone wants a Lightning address or LNURL-pay for a home node, asks how to run lnaddr-node or lnaddr-gateway, pair them, put the gateway behind Caddy, nginx or Traefik, try lnaddr without a node (the demo stage), check that /.well-known/lnurlp/<name> answers, or reach the gateway's admin interface."
license: MIT
metadata:
  repository: https://github.com/deadhop/lnaddr
---

# Set up a Lightning address with deadhop lnaddr

lnaddr has two binaries from one repository (https://github.com/deadhop/lnaddr):

- **`lnaddr-node`** runs next to the Lightning node. It opens no port: it connects out to Nostr
  relays and answers invoice requests over ContextVM, only from the keys it lists.
- **`lnaddr-gateway`** runs on a public host behind a reverse proxy. It serves
  `/.well-known/lnurlp/<name>`, asks the node for each invoice over Nostr, and checks every
  invoice (amount, description hash, network, expiry) before a wallet sees it.

Details live in the docs. Every page has a Markdown twin; fetch the one you need:

| Topic | Page |
| --- | --- |
| Walk-through with Docker | https://deadhop.run/docs/lnaddr/quickstart.md |
| Each backend and its invoice-only credential | https://deadhop.run/docs/lnaddr/backends.md |
| Caddy, nginx, Traefik, HAProxy, Apache, Tor | https://deadhop.run/docs/lnaddr/reverse-proxies.md |
| Every node setting, file and layer | https://deadhop.run/docs/lnaddr/node.md |
| Every gateway setting, domains, health | https://deadhop.run/docs/lnaddr/gateway.md |
| Admin web interface and CLI | https://deadhop.run/docs/lnaddr/admin.md |
| What each part can do if compromised | https://deadhop.run/docs/lnaddr/security.md |

## Safety rules

- **Invoice-only credential, always.** The node only makes invoices. Give it a credential that
  can do nothing else (table below). If the user offers an admin macaroon, an unrestricted rune,
  phoenixd's full password or an LNbits admin key, stop and help them make the limited one: if
  the node's host is ever taken, this is what limits the damage to "can make invoices".
- **Keep secrets out of the chat.** Never ask for the credential's contents, `node.key`,
  `gateway.key`, `admin.key` or `admin.token`. Point at files instead
  (`LNADDR_NODE_BACKEND_SECRET_FILE`, `LNADDR_NODE_BACKEND_TLS_CERT_FILE`); only public keys
  (`npub1…`) are exchanged.
- **Never put secrets in a built-in configuration** (`LNADDR_NODE_BUILTIN`,
  `LNADDR_GATEWAY_BUILTIN`): it is compiled into the binary. Point at secret files from it.
- **The admin web interface stays private.** It listens on loopback by default; reach it over
  SSH or a VPN. Never publish it.
- **Remote settings are off by default** (`LNADDR_NODE_REMOTE`). Leave them off unless the user
  wants to change addresses from the gateway; with them on, an admin key can also change the
  node's relays and proxies (see security.md for what that allows, and `LNADDR_NODE_PROXY_LOCKED`).

## Decide with the user first

1. **Backend:** LND, Core Lightning (clnrest), phoenixd or LNbits, and how the node service
   will reach it (same host, a Docker network, a LAN address).
2. **Docker or binaries.** There are no published images; both are built from the repository.
3. **Domain and public host,** with DNS pointing at it and ports 80 and 443 open for the proxy.
4. **Reverse proxy** already in use (it terminates TLS; the gateway speaks plain HTTP).
5. **Names to serve** (`you` for `you@yourdomain.com`). `LNADDR_NODE_ADDRESSES` gives each name
   1 to 1,000,000 sat and no comments; custom ranges, descriptions and per-domain names need a
   TOML file (node.md has an example).

## Steps

### 1. Build

```sh
git clone https://github.com/deadhop/lnaddr && cd lnaddr
docker build --target node    -t deadhop-lnaddr-node .
docker build --target gateway -t deadhop-lnaddr-gateway .
# or: cargo build --release   -> target/release/lnaddr-node, target/release/lnaddr-gateway
```

### 2. Exchange keys

Each side makes its Nostr key on first use, in its data directory (`/data` in the images).

```sh
lnaddr-gateway pubkey     # on the public host: give this npub to the node (LNADDR_NODE_GATEWAYS)
lnaddr-node pubkey        # next to the Lightning node: give this npub to the gateway (LNADDR_GATEWAY_NODE)
```

With Docker: `docker run --rm -v gateway-data:/data deadhop-lnaddr-gateway pubkey`, and the same
with `node-data` and `deadhop-lnaddr-node`. Reuse those volumes when running the services, or
the keys change.

### 3. Configure and check the node

| `LNADDR_NODE_BACKEND` | Credential (`LNADDR_NODE_BACKEND_SECRET_FILE`) | Pin |
| --- | --- | --- |
| `lnd` | `invoice.macaroon` (binary is fine, read as hex) | `LNADDR_NODE_BACKEND_TLS_CERT_FILE=tls.cert` |
| `cln` | a rune from `lightning-cli createrune restrictions='[["method=invoice"],["rate=60"]]'` | clnrest's `server.pem`, or `LNADDR_NODE_BACKEND_TLS_CERT_SHA256` |
| `phoenixd` | `http-password-limited-access` from `phoenix.conf` | none (plain http on loopback) |
| `lnbits` | the wallet's invoice/read key, not the admin key | web roots, or a pin |

Set `LNADDR_NODE_BACKEND_URL` when the backend is not at its usual local address (LND
`https://127.0.0.1:8080`, CLN `https://127.0.0.1:3010`, phoenixd `http://127.0.0.1:9740`). Inside
a container, `127.0.0.1` is the container itself: use the backend's address on a shared Docker
network. Plain `http://` is accepted only for loopback, private addresses, container names,
`.local`, `.internal`, `.onion` and `.i2p`.

```sh
LNADDR_NODE_BACKEND=lnd \
LNADDR_NODE_BACKEND_URL=https://lnd:8080 \
LNADDR_NODE_BACKEND_SECRET_FILE=/secrets/invoice.macaroon \
LNADDR_NODE_BACKEND_TLS_CERT_FILE=/secrets/tls.cert \
LNADDR_NODE_GATEWAYS=npub1gw… \
LNADDR_NODE_ADDRESSES=you \
lnaddr-node check
```

`check` prints the configuration (the credential as `(set)`) and makes a 1 sat test invoice:
`backend    ok: made a 1 sat test invoice for you (lnbc10n1…)`. Fix any error here before going
on. phoenixd and LNbits take whole satoshis, so every address must allow at least one whole
sat. Then run the same command without `check` (or `serve`) under Docker
(`--restart unless-stopped`, no `-p`) or systemd.

### 4. Run the gateway

```sh
LNADDR_GATEWAY_DOMAIN=yourdomain.com \
LNADDR_GATEWAY_NODE=npub1node… \
LNADDR_GATEWAY_TRUSTED_PROXIES=127.0.0.1 \
lnaddr-gateway
```

It listens on `127.0.0.1:8080` (`0.0.0.0:8080` in the image: publish it as
`-p 127.0.0.1:8080:8080`). `LNADDR_GATEWAY_TRUSTED_PROXIES` is the proxy's address as the gateway
sees it, so rate limits see real clients; from inside a container a proxy on the host appears
from Docker's networks (`172.16.0.0/12` by default). Both sides default to the relays
`wss://relay.contextvm.org` and `wss://relay2.contextvm.org`; if you change them
(`LNADDR_NODE_RELAYS`, `LNADDR_GATEWAY_RELAYS`), keep at least one in common.

### 5. Reverse proxy

Forward only `/.well-known/lnurlp/` (and `/healthz` if wanted) to the gateway. Caddy:

```text
yourdomain.com {
    handle /.well-known/lnurlp/* {
        reverse_proxy 127.0.0.1:8080
    }
}
```

The proxy must append the client to `X-Forwarded-For` (Caddy and Traefik do by default; nginx
needs `$proxy_add_x_forwarded_for`). Other proxies: reverse-proxies.md.

## Verify

```sh
lnaddr-gateway test you 21        # on the gateway host (docker exec lnaddr-gateway /lnaddr-gateway test you 21)
lnaddr-gateway status             # every node: reachable, latency, addresses
curl -s https://yourdomain.com/.well-known/lnurlp/you
curl -s "https://yourdomain.com/.well-known/lnurlp/you/callback?amount=21000"
curl -s https://yourdomain.com/healthz        # only if the proxy forwards it
```

`test` fetches and checks a real invoice over ContextVM without going through the proxy; the
`curl` lines check the public path. The first should return `"tag":"payRequest"` with a
`callback` on `https://yourdomain.com`, the second a `"pr":"lnbc…"` invoice (amounts are in
millisatoshis). `/healthz` answers `{"status":"ok"}` while at least one node answers. Then pay
`you@yourdomain.com` from a wallet; the node needs inbound liquidity to receive.

Common failures: a `503` on the callback means the gateway cannot reach the node (keys not
paired both ways, no relay in common, node down); a `404` means the name is not served (or,
with several domains, the proxy's `Host` names none of them); a `502` means the node's invoice
failed the gateway's checks. The node's log has the backend's error.

## Configuration layers and locking

Each binary reads, later layers winning: values built in at compile time
(`LNADDR_NODE_BUILTIN` / `LNADDR_GATEWAY_BUILTIN`, TOML text), a TOML file (`--config FILE` or
`LNADDR_NODE_CONFIG` / `LNADDR_GATEWAY_CONFIG`), then `LNADDR_NODE_*` / `LNADDR_GATEWAY_*`
variables. On the node, remote settings from an admin key come last, when switched on. Any
layer can switch later ones off with `sources = { file = false, env = false, remote = false }`,
and a source switched off stays off: use that for appliances that must run only on built-in
values. Setting tables: node.md and gateway.md.

## Try it without a Lightning node

`demo/` starts a Nostr relay on `ws://127.0.0.1:7788` and a fake LND on
`http://127.0.0.1:18080` (macaroon `demo`) that signs real regtest invoices nothing can pay:

```sh
(cd demo && cargo run --release)
```

Then run the real binaries against it, each with its own data directory:

```sh
LNADDR_NODE_NETWORK=regtest LNADDR_NODE_RELAYS=ws://127.0.0.1:7788 \
LNADDR_NODE_BACKEND=lnd LNADDR_NODE_BACKEND_URL=http://127.0.0.1:18080 LNADDR_NODE_BACKEND_SECRET=demo \
LNADDR_NODE_GATEWAYS=npub1gw… LNADDR_NODE_ADDRESSES=alice lnaddr-node

LNADDR_GATEWAY_DOMAIN=lnaddr.example LNADDR_GATEWAY_SCHEME=http LNADDR_GATEWAY_LISTEN=127.0.0.1:8090 \
LNADDR_GATEWAY_RELAYS=ws://127.0.0.1:7788 LNADDR_GATEWAY_NODE=npub1node… lnaddr-gateway

curl -s http://127.0.0.1:8090/.well-known/lnurlp/alice
```

`LNADDR_NODE_BACKEND_SECRET` (the credential inline) is fine for the demo; use the `_FILE`
form for a real node.

## The gateway's admin interface (optional)

The gateway serves wallets without it. To turn it on, set `LNADDR_GATEWAY_ADMIN_LISTEN` to a
loopback address such as `127.0.0.1:8081` and sign in with the token from
`lnaddr-gateway admin-token`; reach it with `ssh -L 8081:127.0.0.1:8081 host`. Off loopback
(for example inside a container) the session cookie is `Secure` by default, so the interface
then needs HTTPS in front; the listener and `secure_cookie` settings are in gateway.md. Never
publish it on a public address.

To change the node's addresses and limits from the gateway (`lnaddr-gateway node set-address …`,
or the web forms), the node must list the gateway's admin key and allow remote settings:

```sh
lnaddr-gateway admin-pubkey       # on the gateway: prints npub1admin…
# on the node: LNADDR_NODE_ADMINS=npub1admin… LNADDR_NODE_REMOTE=on
```

Without that, the web interface is read only. Commands and pages: admin.md.
