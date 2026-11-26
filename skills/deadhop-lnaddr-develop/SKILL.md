---
name: deadhop-lnaddr-develop
description: "Contribute to deadhop lnaddr (lnaddr-node and lnaddr-gateway, Rust): run the gate (just check, with 100% line and function coverage), move the shared crates from deadhop/server (just update-server-crates), keep assets/brand in step with deadhop/brand, and use the demo stage. Use it whenever you change code, tests, Cargo.toml or Cargo.lock in the deadhop/lnaddr repository, a CI run of lnaddr fails, coverage drops below 100%, or someone asks how to build, test or contribute to lnaddr."
license: MIT
metadata:
  repository: https://github.com/deadhop/lnaddr
---

# Develop deadhop lnaddr

One Rust crate (`deadhop-lnaddr`) with two binaries, `lnaddr-node` and `lnaddr-gateway`; all logic
is in the library (`src/bin/*.rs` are one call each). Requirements: Rust 1.99 (CI's toolchain),
[`just`](https://github.com/casey/just) and
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov).

## The gate

```sh
just check
```

It runs `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and
`cargo llvm-cov --all-targets --locked --fail-under-lines 100 --fail-under-functions 100`. CI runs
the same on every pull request; run it before you push.

- **Coverage is 100% of lines and functions**, binaries included (the tests run them as
  processes and stop them with SIGINT and SIGTERM). Every new line needs a test that reaches it;
  do not lower the thresholds or exclude code to pass.
- **`--locked`** means `Cargo.lock` must already match `Cargo.toml`. Commit the lock file with
  any dependency change.
- Tests run the whole system in process: a Nostr relay, the node, fake LND, Core Lightning,
  phoenixd and LNbits backends that sign real BOLT11 invoices, and the gateway on real sockets.
  Add a fake-backend case when you touch a backend; nothing tests against a live node, so keep
  the fakes faithful to each API's documentation.
- Every configuration mistake should fail with a message that names the setting. Tests check
  those messages, so update them with the wording.

## Shared crates from deadhop/server

`deadhop-tlspin`, `deadhop-cvm`, `deadhop-net`, `deadhop-common` and `deadhop-netengine`, and a
patched `rmcp` (`[patch.crates-io]`), come from https://github.com/deadhop/server by git
(`branch = "main"`), pinned by `Cargo.lock`.

```sh
just update-server-crates   # cargo update -p deadhop-tlspin -p deadhop-cvm -p deadhop-net -p deadhop-common -p deadhop-netengine -p rmcp
just check
```

- A change those crates need goes to deadhop/server first. Once it is merged there, run
  `just update-server-crates` here, adapt, and open the lnaddr pull request.
- Keep the `[patch.crates-io] rmcp` entry: `[patch]` does not pass down from a dependency, so
  every crate that links rmcp repeats it.
- Never commit a `Cargo.lock` whose `deadhop-*` or `rmcp` entries lack a
  `source = "git+https://github.com/deadhop/server…"` line (for example after building against
  a local path override): CI's `--locked` build fails on it.
- The repository must build from its own clone: no path dependencies that reach outside it. To
  work on server and lnaddr together, get both from a https://github.com/deadhop/stack checkout
  (`just clone`) and point Cargo at the local server checkout only temporarily, in nothing you
  commit; restore `Cargo.lock` before committing.

## Brand copies

`assets/brand/` holds copies of the deadhop brand's fonts, mark and favicon, compiled into the
gateway's admin interface (`src/gateway/admin.rs`). The originals are in
https://github.com/deadhop/brand: change them there first, then copy the files here unchanged.
Do not edit the copies in place.

## Demo stage

`demo/` is its own crate: a Nostr relay on `ws://127.0.0.1:7788` and a fake LND on
`http://127.0.0.1:18080` (macaroon `demo`) that signs regtest invoices nothing can pay.

```sh
(cd demo && cargo run --release)
```

Run both binaries against it to try a change by hand (the operator skill
`deadhop-lnaddr-setup` has the exact variables), then
`curl http://127.0.0.1:8090/.well-known/lnurlp/alice`.

## Where things are

| Path | What |
| --- | --- |
| `src/node/` | config layers, backends, MCP tools, network engine glue, request loop, CLI |
| `src/gateway/` | config, node directory and cache, public HTTP, admin web, network, console server, CLI |
| `src/lnurl.rs`, `src/bolt11.rs` | LUD-06/12/16 and the invoice checks both sides share |
| `src/settings.rs` | config parsing and the `sources` locks |
| `tests/binaries.rs` | the binaries as processes |

## Docs and pull requests

- The user docs are in https://github.com/deadhop/site under `docs/lnaddr/`. A change to a
  setting, command or behaviour needs a matching pull request there; do not add docs to this
  repository beyond the README. Setting names must match the source exactly (`LNADDR_NODE_*`,
  `LNADDR_GATEWAY_*`).
- Open issues and pull requests in https://github.com/deadhop/lnaddr.
- Never commit keys, macaroons, runes or tokens, even test ones from a real node; tests make
  their own.
