//! Running the node: its Nostr identity, the ContextVM server, and the
//! `lnaddr-node` command line.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use contextvm_sdk::transport::server::{NostrServerTransport, NostrServerTransportConfig};
use contextvm_sdk::{EncryptionMode, GiftWrapMode, ServerInfo};
use nostr_sdk::prelude::{Keys, ToBech32};
use rmcp::transport::IntoTransport;
use rmcp::{RoleServer, ServiceExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::node::config::{self, Config, KEY_FILE};
use crate::node::mcp::NodeServer;
use crate::node::service::Service;
use crate::pool::Pool;

pub struct Running {
    pub keys: Keys,
    pub svc: Arc<Service>,
    pool: Arc<Pool>,
    cancel: CancellationToken,
    task: JoinHandle<Result<String, String>>,
}

/// Bring the node up: identity, relay connections and the request loop.
pub async fn start(cfg: Config) -> Result<Running, String> {
    crate::files::open_dir(&cfg.data_dir)?;
    let keys = crate::files::load_or_create_keys(&cfg.data_dir.join(KEY_FILE))?;
    let allowed: Vec<String> = cfg.gateways.iter().chain(&cfg.admins).map(|k| k.to_hex()).collect();
    let pool = Arc::new(Pool::new(keys.clone(), cfg.socks5.clone()));
    let transport_config = NostrServerTransportConfig::default()
        .with_relay_urls(cfg.relays.clone())
        .with_encryption_mode(EncryptionMode::Required)
        // Ephemeral gift wraps (kind 21059): relays forward them and keep
        // nothing, so no stored reply can ever be replayed to a client.
        .with_gift_wrap_mode(GiftWrapMode::Ephemeral)
        // Never announced and never listed: nothing public leads to the node.
        .with_announced_server(false)
        .with_publish_relay_list(false)
        .with_bootstrap_relay_urls(Vec::new())
        // Requests from keys not listed are dropped before they are parsed.
        .with_allowed_public_keys(allowed)
        .with_oversized_enabled(false)
        .with_server_info(ServerInfo::default().with_name("deadhop lnaddr node".to_string()));
    let transport = NostrServerTransport::with_relay_pool(transport_config, pool.clone())
        .await
        .map_err(crate::why)?;
    let transport = crate::handshake::local(IntoTransport::<RoleServer, _, _>::into_transport(transport));
    let svc = Arc::new(Service::new(cfg));
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let (server, cancel) = (NodeServer::new(svc.clone()), cancel.clone());
        async move {
            let running = server.serve_with_ct(transport, cancel).await.map_err(crate::why)?;
            Ok::<String, String>(format!("{:?}", running.waiting().await))
        }
    });
    Ok(Running {
        keys,
        svc,
        pool,
        cancel,
        task,
    })
}

impl Running {
    pub async fn relays_connected(&self) -> usize {
        crate::pool::connected(&self.pool).await
    }

    /// Serve until `shutdown`; an error if the request loop ended first.
    pub async fn until(mut self, shutdown: crate::Shutdown) -> Result<(), String> {
        let outcome = tokio::select! {
            _ = shutdown => Ok(()),
            why = &mut self.task => Err(format!("the request loop ended: {}", match why { Ok(Ok(s) | Err(s)) => s, Err(e) => e.to_string() })),
        };
        self.cancel.cancel();
        if !self.task.is_finished() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.task).await;
        }
        let _ = contextvm_sdk::relay::RelayPoolTrait::disconnect(&*self.pool).await;
        outcome
    }
}

pub const USAGE: &str = "usage:
  lnaddr-node [serve]        run the node service
  lnaddr-node pubkey         print the node's public key (npub), creating its key if needed
  lnaddr-node check          check the configuration and make a test invoice on the backend
  lnaddr-node version        print the version

options:
  --config FILE              read FILE (TOML) before the LNADDR_NODE_* environment variables";

/// Default log filter: quiet libraries, so junk traffic cannot fill the log.
pub const DEFAULT_LOG: &str = "warn,deadhop_lnaddr=info,contextvm_sdk=off,rmcp=off";

pub fn log_filter(value: Option<String>) -> String {
    log_filter_or(value, DEFAULT_LOG)
}

/// `value`, or `default` when it is unset or blank.
pub fn log_filter_or(value: Option<String>, default: &str) -> String {
    value.filter(|v| !v.trim().is_empty()).unwrap_or_else(|| default.into())
}

/// Split `--config FILE` out of the arguments.
pub fn split_config(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut rest = Vec::new();
    let mut file = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--config" {
            file = Some(it.next().ok_or("--config needs a file")?.clone());
        } else if let Some(f) = a.strip_prefix("--config=") {
            file = Some(f.to_string());
        } else {
            rest.push(a.clone());
        }
    }
    Ok((rest, file))
}

fn print_check(cfg: &Config, out: &mut dyn Write) {
    let b = &cfg.backend;
    let _ = writeln!(out, "configuration");
    let _ = writeln!(
        out,
        "  sources    file={} env={} remote={}",
        cfg.sources.file, cfg.sources.env, cfg.sources.remote
    );
    let _ = writeln!(out, "  data dir   {}", cfg.data_dir.display());
    let _ = writeln!(out, "  relays     {}", cfg.relays.join(", "));
    let _ = writeln!(out, "  gateways   {}", cfg.gateways.len());
    let _ = writeln!(out, "  admins     {}", cfg.admins.len());
    let _ = writeln!(out, "  network    {:?}", cfg.network);
    let pin = b
        .pin
        .as_ref()
        .map(|p| format!(", pinned {}…", &hex::encode(p[0])[..16]))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "  backend    {} at {}{pin}, credential {}",
        b.kind.name(),
        b.url,
        crate::settings::redact(true)
    );
    for (name, a) in &cfg.addresses {
        let _ = writeln!(
            out,
            "  address    {name}: {}–{} sat, comments {}",
            a.min_sendable / 1000,
            a.max_sendable / 1000,
            a.comment_allowed
        );
    }
}

/// Check the configuration and that the backend makes a valid invoice.
pub async fn check(cfg: &Config, out: &mut dyn Write) -> ExitCode {
    print_check(cfg, out);
    let svc = Service::new(cfg.clone());
    let probe = match cfg.addresses.iter().next() {
        Some((name, a)) => (name.clone(), a.min_sendable.div_ceil(1000) * 1000),
        None => {
            let _ = writeln!(out, "no addresses configured: nothing to serve yet");
            return ExitCode::FAILURE;
        }
    };
    let p = crate::proto::MakeInvoiceParams {
        name: probe.0.clone(),
        domain: "check.invalid".into(),
        amount_msat: probe.1,
        comment: None,
    };
    match svc.invoice("local check", p).await {
        Ok(made) => {
            let _ = writeln!(
                out,
                "backend    ok: made a {} sat test invoice for {} ({}…)",
                probe.1 / 1000,
                probe.0,
                &made.pr[..24]
            );
            ExitCode::SUCCESS
        }
        Err(r) => {
            let detail = svc.last_error().unwrap_or(r.message);
            let _ = writeln!(out, "backend    FAILED: {detail}");
            ExitCode::FAILURE
        }
    }
}

/// Start with `cfg` and serve until `shutdown`.
pub async fn serve(cfg: Result<Config, String>, shutdown: crate::Shutdown) -> Result<(), String> {
    let running = start(cfg?).await?;
    let npub = running.keys.public_key().to_bech32().expect("keys encode");
    tracing::info!(%npub, "lnaddr node is serving");
    running.until(shutdown).await
}

/// What the binary runs.
pub async fn command(
    args: &[String],
    lookup: crate::Lookup,
    shutdown: crate::Shutdown,
    out: &mut dyn Write,
) -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_filter(lookup(
            "LNADDR_NODE_LOG",
        ))))
        .with_writer(std::io::stderr)
        .try_init();
    let (args, file) = match split_config(args) {
        Ok(v) => v,
        Err(e) => return fail(out, &e),
    };
    let lookup = move |k: &str| match (k, &file) {
        ("LNADDR_NODE_CONFIG", Some(f)) => Some(f.clone()),
        _ => lookup(k),
    };
    let cmd = args.first().map(String::as_str).unwrap_or("serve");
    if args.len() > 1 {
        return usage(out);
    }
    match cmd {
        "version" | "--version" => {
            let _ = writeln!(out, "lnaddr-node {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            let _ = writeln!(out, "{USAGE}");
            ExitCode::SUCCESS
        }
        "pubkey" => {
            let dir = config::data_dir_only(config::BUILTIN, &lookup);
            let made =
                crate::files::open_dir(&dir).and_then(|()| crate::files::load_or_create_keys(&dir.join(KEY_FILE)));
            match made {
                Ok(keys) => {
                    let _ = writeln!(out, "{}", keys.public_key().to_bech32().expect("keys encode"));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(out, &e),
            }
        }
        "check" => match config::load(config::BUILTIN, &lookup) {
            Ok(cfg) => check(&cfg, out).await,
            Err(e) => fail(out, &e),
        },
        "serve" => match serve(config::load(config::BUILTIN, &lookup), shutdown).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(out, &e),
        },
        _ => usage(out),
    }
}

fn usage(out: &mut dyn Write) -> ExitCode {
    let _ = writeln!(out, "{USAGE}");
    ExitCode::from(2)
}

fn fail(out: &mut dyn Write, e: &str) -> ExitCode {
    let _ = writeln!(out, "lnaddr-node: {e}");
    ExitCode::FAILURE
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::cvm::{CallError, NodeClient};
    use crate::node::backend::testutil::{serve, Fake};
    use crate::node::backend::Kind;
    use crate::node::service::tests::{admin_keys, gateway_keys, test_config};
    use crate::proto::{self, AddressList, ConfigView, MadeInvoice, Status};
    use nostr_relay_builder::MockRelay;
    use serde_json::json;
    use std::time::Duration;

    pub struct NodeRig {
        pub relay: MockRelay,
        pub relay_url: String,
        pub fake: Arc<Fake>,
        pub dir: tempfile::TempDir,
        pub cfg: Config,
    }

    pub async fn node_rig(kind: Kind) -> NodeRig {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(&url, kind, &dir.path().join("data"));
        cfg.relays = vec![relay_url.clone()];
        NodeRig {
            relay,
            relay_url,
            fake,
            dir,
            cfg,
        }
    }

    pub async fn client(r: &NodeRig, keys: Keys, node: &Keys, timeout: Duration) -> NodeClient {
        NodeClient::connect(
            keys,
            &node.public_key(),
            std::slice::from_ref(&r.relay_url),
            None,
            timeout,
        )
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gateways_and_admins_are_served_over_nostr_and_strangers_are_not() {
        let r = node_rig(Kind::Lnd).await;
        let node = start(r.cfg.clone()).await.unwrap();
        let key = node.keys.clone();
        let gw = client(&r, gateway_keys(), &key, Duration::from_secs(10)).await;
        let list: AddressList = gw.call(proto::LIST_ADDRESSES, json!({})).await.unwrap();
        assert_eq!(list.addresses.len(), 2);
        let made: MadeInvoice = gw
            .call(
                proto::MAKE_INVOICE,
                json!({ "name": "alice", "domain": "pay.example", "amount_msat": 5000 }),
            )
            .await
            .unwrap();
        assert!(made.pr.starts_with("lnbcrt"));
        let refused = gw.call::<Status>(proto::GET_STATUS, json!({})).await.unwrap_err();
        assert!(
            matches!(refused, CallError::Refused { ref code, .. } if code == "unauthorized"),
            "{refused:?}"
        );
        let bad = gw
            .call::<MadeInvoice>(proto::MAKE_INVOICE, json!({ "name": "alice" }))
            .await
            .unwrap_err();
        assert!(matches!(bad, CallError::Refused { .. }), "{bad:?}");
        // A tool answering with something else than promised is reported.
        let wrong = gw
            .call::<MadeInvoice>(proto::LIST_ADDRESSES, json!(null))
            .await
            .unwrap_err();
        assert!(matches!(wrong, CallError::Bad(_)), "{wrong:?}");
        assert!(gw.relays_connected().await >= 1);

        let admin = client(&r, admin_keys(), &key, Duration::from_secs(10)).await;
        let st: Status = admin.call(proto::GET_STATUS, json!({})).await.unwrap();
        assert_eq!(st.invoices_made, 1);
        let view: ConfigView = admin
            .call(
                proto::SET_ADDRESS,
                json!({ "name": "dave", "min_sendable": 1000, "max_sendable": 2000, "description": "Dave" }),
            )
            .await
            .unwrap();
        assert_eq!(view.addresses.len(), 3);
        let _: ConfigView = admin
            .call(proto::REMOVE_ADDRESS, json!({ "name": "dave" }))
            .await
            .unwrap();
        let _: ConfigView = admin
            .call(proto::SET_LIMITS, json!({ "invoices_per_minute": 50 }))
            .await
            .unwrap();
        let _: ConfigView = admin.call(proto::GET_CONFIG, json!({})).await.unwrap();

        // A key the node does not list gets no answer at all.
        let stranger = client(&r, Keys::generate(), &key, Duration::from_secs(2)).await;
        assert_eq!(
            stranger
                .call::<AddressList>(proto::LIST_ADDRESSES, json!({}))
                .await
                .unwrap_err(),
            CallError::Timeout
        );
        stranger.close().await;
        gw.close().await;
        admin.close().await;
        assert!(node.relays_connected().await >= 1);
        node.until(Box::pin(async {})).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restarted_node_answers_the_same_client_at_once() {
        let r = node_rig(Kind::Cln).await;
        let node = start(r.cfg.clone()).await.unwrap();
        let key = node.keys.clone();
        let gw = client(&r, gateway_keys(), &key, Duration::from_secs(10)).await;
        let _: AddressList = gw.call(proto::LIST_ADDRESSES, json!({})).await.unwrap();
        node.until(Box::pin(async {})).await.unwrap();
        // While it is down, calls time out instead of hanging.
        let short = client(&r, gateway_keys(), &key, Duration::from_secs(1)).await;
        assert_eq!(
            short
                .call::<AddressList>(proto::LIST_ADDRESSES, json!({}))
                .await
                .unwrap_err(),
            CallError::Timeout
        );
        let again = start(r.cfg.clone()).await.unwrap();
        assert_eq!(again.keys.public_key(), key.public_key());
        tokio::time::sleep(Duration::from_millis(500)).await;
        let list: AddressList = gw.call(proto::LIST_ADDRESSES, json!({})).await.unwrap();
        assert_eq!(list.addresses.len(), 2);
        again.until(Box::pin(async {})).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_command_line_runs_checks_and_serves() {
        let r = node_rig(Kind::Lnd).await;
        let data = r.dir.path().join("cli");
        let env: Vec<(String, String)> = vec![
            ("LNADDR_NODE_DATA_DIR".into(), data.display().to_string()),
            ("LNADDR_NODE_RELAYS".into(), r.relay_url.clone()),
            ("LNADDR_NODE_GATEWAYS".into(), gateway_keys().public_key().to_hex()),
            ("LNADDR_NODE_BACKEND".into(), "lnd".into()),
            ("LNADDR_NODE_BACKEND_URL".into(), r.cfg.backend.url.clone()),
            (
                "LNADDR_NODE_BACKEND_SECRET".into(),
                crate::node::backend::testutil::SECRET.into(),
            ),
            ("LNADDR_NODE_NETWORK".into(), "regtest".into()),
            ("LNADDR_NODE_ADDRESSES".into(), "alice".into()),
        ];
        let lookup = {
            let env = env.clone();
            move |k: &str| env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone())
        };
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let lookup = lookup.clone();
            async move {
                let mut out = Vec::new();
                let code = command(&args, Box::new(lookup), Box::pin(async {}), &mut out).await;
                (code, String::from_utf8(out).unwrap())
            }
        };
        let (code, out) = run(&["version"]).await;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.starts_with("lnaddr-node 0."));
        assert!(run(&["help"]).await.1.contains("usage:"));
        assert_eq!(run(&["nonsense"]).await.0, ExitCode::from(2));
        assert_eq!(run(&["check", "extra"]).await.0, ExitCode::from(2));
        assert!(run(&["--config"]).await.1.contains("needs a file"));
        let (code, out) = run(&["pubkey"]).await;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.starts_with("npub1"));
        assert_eq!(run(&["pubkey"]).await.1, out);
        let (code, out) = run(&["check"]).await;
        assert_eq!(code, ExitCode::SUCCESS, "{out}");
        assert!(
            out.contains("backend    ok: made a 1 sat test invoice for alice"),
            "{out}"
        );
        assert!(out.contains("credential (set)") && !out.contains(crate::node::backend::testutil::SECRET));
        *r.fake.fail.lock().unwrap() = Some((403, "denied".into()));
        let (code, out) = run(&["check"]).await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(out.contains("FAILED: the lnd backend answered 403: denied"), "{out}");
        let (code, out) = run(&["serve", "--config=/does/not/exist"]).await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(out.contains("/does/not/exist"));
        assert!(run(&["check", "--config", "/does/not/exist"])
            .await
            .1
            .contains("/does/not/exist"));
        // serve with an immediate shutdown.
        assert_eq!(run(&[]).await.0, ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn commands_fail_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        // A data directory under a file cannot be made.
        let bad_dir = file.join("data");
        let lookup = move |k: &str| (k == "LNADDR_NODE_DATA_DIR").then(|| bad_dir.display().to_string());
        let mut out = Vec::new();
        assert_eq!(
            command(
                &["pubkey".to_string()],
                Box::new(lookup.clone()),
                Box::pin(std::future::ready(())),
                &mut out
            )
            .await,
            ExitCode::FAILURE
        );
        let mut out = Vec::new();
        assert_eq!(
            command(&[], Box::new(lookup), Box::pin(std::future::ready(())), &mut out).await,
            ExitCode::FAILURE
        );
        assert!(String::from_utf8(out).unwrap().contains("lnaddr-node:"));
        // A valid configuration whose data directory cannot be made.
        let r = node_rig(Kind::Lnd).await;
        let mut cfg = r.cfg.clone();
        cfg.data_dir = file.join("data");
        assert!(start(cfg).await.is_err());
        // A pinned backend says so in the summary.
        let mut pinned = r.cfg.clone();
        pinned.backend.pin = Some(vec![[0xab; 32]]);
        let mut out = Vec::new();
        print_check(&pinned, &mut out);
        assert!(String::from_utf8(out).unwrap().contains("pinned abababababababab…"));
        // No addresses: check says so.
        let mut cfg = r.cfg.clone();
        cfg.addresses.clear();
        let mut out = Vec::new();
        assert_eq!(check(&cfg, &mut out).await, ExitCode::FAILURE);
        assert!(String::from_utf8(out).unwrap().contains("no addresses"));
        assert_eq!(log_filter(Some(" ".into())), DEFAULT_LOG);
        assert_eq!(log_filter(Some("debug".into())), "debug");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_loop_that_ends_stops_the_node() {
        let r = node_rig(Kind::Lnd).await;
        let node = start(r.cfg.clone()).await.unwrap();
        node.cancel.cancel();
        let e = node.until(Box::pin(std::future::pending())).await.unwrap_err();
        assert!(e.contains("request loop ended"), "{e}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_aborted_request_loop_is_reported() {
        let r = node_rig(Kind::Lnd).await;
        let node = start(r.cfg.clone()).await.unwrap();
        node.task.abort();
        let e = node.until(Box::pin(std::future::pending())).await.unwrap_err();
        assert!(e.contains("request loop ended"), "{e}");
    }
}
