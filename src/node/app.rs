//! Running the node: its Nostr identity, the ContextVM server, and the
//! `lnaddr-node` command line.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use contextvm_sdk::transport::server::{NostrServerTransport, NostrServerTransportConfig};
use contextvm_sdk::{EncryptionMode, GiftWrapMode, ServerInfo};
use deadhop_netengine::netruntime::{route_specs, same_relays, Routes};
use nostr_sdk::prelude::{Keys, ToBech32};
use rmcp::transport::IntoTransport;
use rmcp::{RoleServer, ServiceExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::node::config::{self, Config, KEY_FILE};
use crate::node::mcp::NodeServer;
use crate::node::network::{pool_states, LANE};
use crate::node::service::Service;
use crate::pool::Pool;

/// How long new relays get to connect before the previous ones come back.
#[cfg(not(test))]
const RELAY_CHECK: Duration = Duration::from_secs(30);
#[cfg(test)]
const RELAY_CHECK: Duration = Duration::from_secs(3);
/// How often the supervisor looks at the live relays.
#[cfg(not(test))]
const RELAY_WATCH_EVERY: Duration = Duration::from_secs(30);
#[cfg(test)]
const RELAY_WATCH_EVERY: Duration = Duration::from_millis(250);
/// How long no relay may be connected before the node goes back to the
/// relays (and with them the proxy) from its configuration.
#[cfg(not(test))]
const RELAY_DEAD_AFTER: Duration = Duration::from_secs(600);
#[cfg(test)]
const RELAY_DEAD_AFTER: Duration = Duration::from_secs(2);
/// Pause before connections are remade, so the reply to the request that
/// caused it is published on the old ones first.
#[cfg(not(test))]
const RESTART_GRACE: Duration = Duration::from_millis(1500);
#[cfg(test)]
const RESTART_GRACE: Duration = Duration::from_millis(200);
/// How often every live relay is checked end to end.
#[cfg(not(test))]
const RELAY_HEALTH_EVERY: Duration = Duration::from_secs(300);
#[cfg(test)]
const RELAY_HEALTH_EVERY: Duration = Duration::from_secs(1);
/// Audit-log reasons for going back to the configured relays.
const DEAD_RELAYS: &str = "no relay was connected for 10 minutes; back to the configured relays";
const DEAD_AT_START: &str = "no saved relay connected at startup; using the configured relays";

/// The node's identity and who may call it.
#[derive(Clone)]
struct Ident {
    keys: Keys,
    allowed: Vec<String>,
}

/// One generation of the node's relay connections and the request loop on
/// top of them.
struct Link {
    /// Each relay and the proxy it goes through ("" for straight).
    routes: Routes,
    pool: Arc<Pool>,
    cancel: CancellationToken,
    /// Cancelled by the request loop when it ends, for whatever reason.
    ended: CancellationToken,
    task: JoinHandle<()>,
}

impl Link {
    async fn up(id: &Ident, routes: Routes, svc: &Arc<Service>) -> Result<Link, String> {
        let sink: deadhop_net::relay::RelaySink = {
            let svc = svc.clone();
            Arc::new(move |relay, ok, ms| svc.net.runtime.record_relay_event(&*svc, relay, "send", ok, Some(ms)))
        };
        let specs = route_specs(&routes).map_err(crate::why)?;
        let pool = Arc::new(Pool::routed(id.keys.clone(), specs).with_sink(sink));
        let transport_config = NostrServerTransportConfig::default()
            .with_relay_urls(routes.iter().map(|(r, _)| r.clone()).collect())
            .with_encryption_mode(EncryptionMode::Required)
            // Ephemeral gift wraps (kind 21059): relays forward them and keep
            // nothing, so no stored reply can ever be replayed to a client.
            .with_gift_wrap_mode(GiftWrapMode::Ephemeral)
            // Never announced and never listed: nothing public leads to the node.
            .with_announced_server(false)
            .with_publish_relay_list(false)
            .with_bootstrap_relay_urls(Vec::new())
            // Requests from keys not listed are dropped before they are parsed.
            .with_allowed_public_keys(id.allowed.clone())
            .with_oversized_enabled(false)
            .with_server_info(ServerInfo::default().with_name("deadhop lnaddr node".to_string()));
        let transport = NostrServerTransport::with_relay_pool(transport_config, pool.clone())
            .await
            .map_err(crate::why)?;
        let transport = crate::handshake::local(IntoTransport::<RoleServer, _, _>::into_transport(transport));
        let cancel = CancellationToken::new();
        let ended = CancellationToken::new();
        let task = tokio::spawn({
            let (server, cancel, ended) = (NodeServer::new(svc.clone()), cancel.clone(), ended.clone());
            async move {
                let outcome: Result<String, String> = async {
                    let running = server.serve_with_ct(transport, cancel).await.map_err(crate::why)?;
                    Ok(format!("{:?}", running.waiting().await))
                }
                .await;
                tracing::info!(?outcome, "request loop ended");
                ended.cancel();
            }
        });
        svc.set_relay_pool(Some(pool.clone()));
        Ok(Link {
            routes,
            pool,
            cancel,
            ended,
            task,
        })
    }

    /// Move the relays whose route changed; the others keep their
    /// connections, and the request loop runs on.
    async fn reroute(&mut self, routes: Routes) -> Result<(), String> {
        let specs = route_specs(&routes).map_err(crate::why)?;
        self.pool.reroute(specs).await.map_err(crate::why)?;
        self.routes = routes;
        Ok(())
    }

    async fn close(self) {
        self.cancel.cancel();
        let _ = self.task.await;
        self.pool.client().disconnect().await;
    }

    /// Whether any relay is connected right now.
    async fn connected(&self) -> bool {
        pool_states(&self.pool).await.iter().any(|r| r.connected)
    }

    /// Whether any relay connects within `limit`.
    async fn connects_within(&self, limit: Duration) -> bool {
        let wait = async {
            while !self.connected().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(limit, wait).await.is_ok()
    }
}

/// Connect the node the way it is set to now: each relay through its route,
/// or (kill switch, every relay blocked) not at all.
async fn connect(id: &Ident, svc: &Arc<Service>) -> Result<Option<Link>, String> {
    match svc.net.runtime.lane_routes(&**svc, LANE) {
        Some(routes) => Ok(Some(Link::up(id, routes, svc).await?)),
        None => {
            tracing::warn!(
                "no relay has a route now (kill switch, blocked, or its proxy is down): the node is not connected"
            );
            svc.set_relay_pool(None);
            Ok(None)
        }
    }
}

type RelaySetup = (Vec<String>, BTreeMap<String, Vec<String>>);

/// The relays and which lanes use them, as the node is set to now.
fn relay_setup(svc: &Service) -> RelaySetup {
    let s = svc.net.settings();
    (s.relays, s.relay_keys)
}

async fn close(link: &mut Option<Link>) {
    if let Some(l) = link.take() {
        l.close().await;
    }
}

/// Whether the link (if there is one) has no relay connected within `limit`.
async fn dead(link: &Option<Link>, limit: Duration) -> bool {
    match link {
        Some(l) => !l.connects_within(limit).await,
        None => false,
    }
}

/// Connect again with the live relays. If a new relay setup cannot connect,
/// go back to the previous one so the node stays reachable.
async fn relink(id: &Ident, svc: &Arc<Service>, previous: RelaySetup) -> Result<Option<Link>, String> {
    if relay_setup(svc) == previous {
        return connect(id, svc).await;
    }
    // New connections that cannot even start count as connections that do
    // not connect.
    if let Ok(mut link) = connect(id, svc).await {
        if !dead(&link, RELAY_CHECK).await {
            return Ok(link);
        }
        close(&mut link).await;
    }
    tracing::warn!("no relay connected with the new settings; going back to the previous ones");
    svc.revert_connection(previous.0, previous.1, "no relay connected with the new relays")?;
    connect(id, svc).await
}

/// Drop the saved relays and connect with the configured ones: they are
/// under the host's control, so they are the way back in.
async fn fall_back(id: &Ident, svc: &Arc<Service>, why: &str) -> Result<Option<Link>, String> {
    svc.revert_connection(svc.config().relays.clone(), BTreeMap::new(), why)?;
    connect(id, svc).await
}

/// What the watchdog does about the relays, given what it sees.
#[derive(Debug, PartialEq, Eq)]
enum Watch {
    /// A relay is connected.
    Fine,
    /// None is, but not for long enough to act.
    Wait,
    /// None has been for long, and the configured relays are in use already.
    Retry,
    /// None has been for long: go back to the configured relays.
    FallBack,
}

fn watch_action(connected: bool, silent_for: Duration, on_configured_relays: bool) -> Watch {
    if connected {
        Watch::Fine
    } else if silent_for < RELAY_DEAD_AFTER {
        Watch::Wait
    } else if on_configured_relays {
        Watch::Retry
    } else {
        Watch::FallBack
    }
}

/// The value, or (after logging why) a signal that the node must stop.
fn or_fail<T>(result: Result<T, String>, what: &str, failed: &CancellationToken) -> Option<T> {
    if let Err(e) = &result {
        tracing::error!(error = %e, "{what}");
        failed.cancel();
    }
    result.ok()
}

/// Keep the request loop running: remake the connections when the relays
/// change, move relays to their new routes when the proxy pool decides
/// another way, and go back to the configured relays when saved ones have
/// had nothing connected for [`RELAY_DEAD_AFTER`].
async fn supervise(
    svc: Arc<Service>,
    id: Ident,
    mut link: Option<Link>,
    stop: CancellationToken,
    failed: CancellationToken,
    current: Arc<std::sync::Mutex<CancellationToken>>,
) {
    let mut watch = tokio::time::interval(RELAY_WATCH_EVERY);
    watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_connected = tokio::time::Instant::now();
    let mut live = relay_setup(&svc);
    loop {
        *current.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            link.as_ref().map_or_else(CancellationToken::new, |l| l.cancel.clone());
        let ended = link.as_ref().map(|l| l.ended.clone());
        let request_loop_ended = async {
            match &ended {
                Some(t) => t.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = stop.cancelled() => {
                close(&mut link).await;
                return;
            }
            _ = request_loop_ended => {
                tracing::warn!("request loop stopped unexpectedly");
                failed.cancel();
                return;
            }
            _ = svc.restart_requested() => {
                tokio::time::sleep(RESTART_GRACE).await;
                close(&mut link).await;
                let Some(next) = or_fail(relink(&id, &svc, live.clone()).await, "could not remake the relay connections", &failed) else { return };
                link = next;
                live = relay_setup(&svc);
                svc.restarted();
                last_connected = tokio::time::Instant::now();
                tracing::info!(connected = link.is_some(), "relay connections remade");
            }
            _ = svc.net.runtime.pool_changed() => {
                // The pool chose another proxy, or none. Move only the relays
                // whose route changed: a relay a rule keeps on its proxy stays
                // connected.
                let want = svc.net.runtime.lane_routes(&*svc, LANE);
                if want.as_ref() == link.as_ref().map(|l| &l.routes) {
                    continue;
                }
                tokio::time::sleep(RESTART_GRACE).await;
                match (&mut link, want) {
                    (Some(l), Some(routes)) if same_relays(&l.routes, &routes) => {
                        let Some(()) = or_fail(l.reroute(routes).await, "could not switch the relay connections", &failed) else { return };
                    }
                    _ => {
                        close(&mut link).await;
                        let Some(next) = or_fail(connect(&id, &svc).await, "could not switch the relay connections", &failed) else { return };
                        link = next;
                    }
                }
                live = relay_setup(&svc);
                svc.restarted();
                last_connected = tokio::time::Instant::now();
                tracing::info!(connected = link.is_some(), "relay connections moved");
            }
            _ = watch.tick() => {
                let Some(l) = &link else { continue };
                let on_configured = {
                    let s = svc.net.settings();
                    s.relays == svc.config().relays && s.relay_keys.is_empty()
                };
                match watch_action(l.connected().await, last_connected.elapsed(), on_configured) {
                    Watch::Fine => last_connected = tokio::time::Instant::now(),
                    Watch::Wait => {}
                    Watch::Retry => {
                        // Nothing better to go back to; the relay pool keeps retrying.
                        last_connected = tokio::time::Instant::now();
                        tracing::warn!("no relay has been connected for a while; still retrying them");
                    }
                    Watch::FallBack => {
                        last_connected = tokio::time::Instant::now();
                        tracing::warn!("no relay has been connected for a while; going back to the configured relays");
                        close(&mut link).await;
                        let Some(next) = or_fail(fall_back(&id, &svc, DEAD_RELAYS).await, "could not go back to the configured relays", &failed) else { return };
                        link = next;
                        live = relay_setup(&svc);
                        svc.restarted();
                    }
                }
            }
        }
    }
}

/// Check the live relays now and then, for `get_health` and the console.
async fn relay_health_loop(svc: Arc<Service>) {
    loop {
        svc.net.runtime.refresh_relay_health(&*svc).await;
        tokio::time::sleep(RELAY_HEALTH_EVERY).await;
    }
}

pub struct Running {
    pub keys: Keys,
    pub svc: Arc<Service>,
    stop: CancellationToken,
    /// Cancelled when the request loop fails and cannot be brought back.
    failed: CancellationToken,
    supervisor: JoinHandle<()>,
    probe: JoinHandle<()>,
    health: JoinHandle<()>,
    /// Cancels the current request loop (tests use it to simulate a crash).
    #[cfg_attr(not(test), allow(dead_code))]
    current: Arc<std::sync::Mutex<CancellationToken>>,
}

/// Bring the node up: identity, saved network settings, the proxies looked
/// at, relay connections and the request loop.
pub async fn start(cfg: Config) -> Result<Running, String> {
    crate::files::open_dir(&cfg.data_dir)?;
    let keys = crate::files::load_or_create_keys(&cfg.data_dir.join(KEY_FILE))?;
    let allowed: Vec<String> = cfg.gateways.iter().chain(&cfg.admins).map(|k| k.to_hex()).collect();
    let svc = Arc::new(Service::new(cfg.clone()));
    svc.load_network()?;
    svc.set_pubkey(&keys.public_key().to_hex());
    // Look at the proxies before connecting anything, so that no relay is
    // ever reached the wrong way round.
    svc.net.runtime.refresh_pool(&*svc).await;
    let id = Ident { keys, allowed };
    let saved = relay_setup(&svc) != (cfg.relays.clone(), BTreeMap::new());
    let mut link = connect(&id, &svc).await?;
    // Saved relays that cannot connect would leave the node unreachable, and
    // a restart would not help: go back to the configured ones.
    if saved && dead(&link, RELAY_CHECK).await {
        tracing::warn!("no saved relay connected; using the configured relays");
        close(&mut link).await;
        link = fall_back(&id, &svc, DEAD_AT_START).await?;
    }
    let stop = CancellationToken::new();
    let failed = CancellationToken::new();
    let current = Arc::new(std::sync::Mutex::new(CancellationToken::new()));
    let supervisor = tokio::spawn(supervise(
        svc.clone(),
        id.clone(),
        link,
        stop.clone(),
        failed.clone(),
        current.clone(),
    ));
    let probe = tokio::spawn({
        let (svc, stop) = (svc.clone(), stop.clone());
        async move { deadhop_netengine::proxypool::run_probe_loop(&svc.net.runtime, &*svc, stop).await }
    });
    let health = tokio::spawn(relay_health_loop(svc.clone()));
    Ok(Running {
        keys: id.keys,
        svc,
        stop,
        failed,
        supervisor,
        probe,
        health,
        current,
    })
}

impl Running {
    pub async fn relays_connected(&self) -> usize {
        deadhop_netengine::netruntime::NetworkHost::relay_states(&*self.svc)
            .await
            .iter()
            .filter(|r| r.connected)
            .count()
    }

    /// Serve until `shutdown`; an error if the request loop ended first.
    pub async fn until(self, shutdown: crate::Shutdown) -> Result<(), String> {
        let outcome = tokio::select! {
            _ = shutdown => Ok(()),
            _ = self.failed.cancelled() => Err("the request loop ended unexpectedly".to_string()),
        };
        self.health.abort();
        self.stop.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.supervisor).await;
        let _ = self.probe.await;
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        node.current.lock().unwrap().cancel();
        let e = node.until(Box::pin(std::future::pending())).await.unwrap_err();
        assert!(e.contains("request loop ended"), "{e}");
    }

    use crate::node::network::{read_network, write_network, NetworkFile, AUDIT_FILE};
    use crate::node::service::tests::caller;
    use deadhop_netengine::proxypool::{Applied, PoolState};

    /// Wait until `f` holds, polling.
    async fn eventually(what: &str, limit: Duration, f: impl Fn() -> bool) {
        let wait = async {
            while !f() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        assert!(
            tokio::time::timeout(limit, wait).await.is_ok(),
            "timed out waiting for {what}"
        );
    }

    fn last_audit(dir: &std::path::Path) -> (String, String) {
        let text = std::fs::read_to_string(dir.join(AUDIT_FILE)).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        (
            v["action"].as_str().unwrap().into(),
            v["detail"].as_str().unwrap().into(),
        )
    }

    fn update(svc: &Service, patch: serde_json::Value) {
        let p = serde_json::from_value(json!({ "patch": patch })).unwrap();
        svc.update_network(&caller(&admin_keys()), p).unwrap();
    }

    /// A node whose configured proxy (a live one) is its default route.
    async fn behind_a_proxy() -> (Running, NodeRig, tokio::task::JoinHandle<()>) {
        let (port, proxy) = deadhop_net::testing::socks5_proxy(None).await;
        let mut r = node_rig(Kind::Lnd).await;
        r.cfg.socks5 = Some(format!("socks5://127.0.0.1:{port}"));
        let node = start(r.cfg.clone()).await.unwrap();
        assert!(node.svc.net.runtime.lane_routes(&*node.svc, LANE).unwrap()[0]
            .1
            .contains(&port.to_string()));
        (node, r, proxy)
    }

    /// Make the plan route the node's relays through a proxy that cannot be used.
    fn unusable_route(node: &Running) {
        node.probe.abort();
        node.svc.net.runtime.pool.lock().unwrap().applied.insert(
            LANE.into(),
            Applied {
                active: Some("x".into()),
                active_url: Some("unusable".into()),
                state: PoolState::Active,
                next_switch_at: None,
                reachable: 1,
            },
        );
    }

    #[test]
    fn the_watchdog_waits_retries_or_falls_back() {
        let long = RELAY_DEAD_AFTER + Duration::from_secs(1);
        assert_eq!(watch_action(true, long, false), Watch::Fine);
        assert_eq!(watch_action(false, Duration::ZERO, false), Watch::Wait);
        assert_eq!(watch_action(false, long, true), Watch::Retry);
        assert_eq!(watch_action(false, long, false), Watch::FallBack);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_relays_that_do_not_connect_are_closed_and_reverted() {
        let r = node_rig(Kind::Lnd).await;
        let svc = Arc::new(Service::new(r.cfg.clone()));
        let id = Ident {
            keys: Keys::generate(),
            allowed: Vec::new(),
        };
        let previous = relay_setup(&svc);
        let mut moved = svc.net.settings();
        moved.relays = vec!["ws://127.0.0.1:9".into()];
        svc.net.set(moved);
        std::fs::create_dir_all(&r.cfg.data_dir).unwrap();
        let mut link = relink(&id, &svc, previous.clone()).await.unwrap();
        assert_eq!(link.as_ref().unwrap().routes[0].0, r.relay_url);
        assert_eq!(relay_setup(&svc), previous);
        close(&mut link).await;
    }

    #[tokio::test]
    async fn no_link_is_not_a_dead_link() {
        assert!(!dead(&None, Duration::ZERO).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_relays_take_over_and_ones_that_do_not_connect_are_reverted() {
        let r = node_rig(Kind::Lnd).await;
        let second = MockRelay::run().await.unwrap();
        let second_url = second.url().await.to_string();
        let node = start(r.cfg.clone()).await.unwrap();
        let svc = node.svc.clone();
        // Asked to restart with nothing changed: the same relays again.
        svc.schedule_restart();
        tokio::time::sleep(RESTART_GRACE + Duration::from_millis(500)).await;
        assert!(node.relays_connected().await >= 1);
        let both = vec![second_url.clone(), r.relay_url.clone()];
        update(&svc, json!({ "relays": both }));
        eventually("the new relay", Duration::from_secs(10), || {
            !svc.get_network(&caller(&admin_keys())).unwrap().restart_pending
        })
        .await;
        assert_eq!(svc.net.settings().relays, both);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(node.relays_connected().await, 2);
        let gw = client(&r, gateway_keys(), &node.keys, Duration::from_secs(10)).await;
        let gw2 = NodeClient::connect(
            gateway_keys(),
            &node.keys.public_key(),
            std::slice::from_ref(&second_url),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let list: AddressList = gw2.call(proto::LIST_ADDRESSES, json!({})).await.unwrap();
        assert_eq!(list.addresses.len(), 2);
        // A relay nothing answers on: back to the one that worked.
        update(&svc, json!({ "relays": ["ws://127.0.0.1:9"] }));
        eventually("the revert", Duration::from_secs(15), || {
            svc.net.settings().relays == both
        })
        .await;
        assert_eq!(last_audit(&r.cfg.data_dir).0, "revert_connection");
        assert_eq!(read_network(&r.cfg.data_dir).unwrap().relays, Some(both));
        gw.close().await;
        gw2.close().await;
        node.until(Box::pin(async {})).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relays_that_die_give_way_to_the_configured_ones() {
        let r = node_rig(Kind::Lnd).await;
        let second = MockRelay::run().await.unwrap();
        let node = start(r.cfg.clone()).await.unwrap();
        let svc = node.svc.clone();
        update(&svc, json!({ "relays": [second.url().await.to_string()] }));
        tokio::time::sleep(RESTART_GRACE + Duration::from_secs(1)).await;
        second.shutdown();
        eventually("the fallback", Duration::from_secs(20), || {
            svc.net.settings().relays == r.cfg.relays
        })
        .await;
        assert_eq!(
            last_audit(&r.cfg.data_dir),
            ("revert_connection".to_string(), DEAD_RELAYS.to_string())
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(node.relays_connected().await >= 1);
        node.until(Box::pin(async {})).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dead_configured_relays_are_only_retried() {
        let r = node_rig(Kind::Lnd).await;
        let node = start(r.cfg.clone()).await.unwrap();
        r.relay.shutdown();
        tokio::time::sleep(RELAY_DEAD_AFTER * 2 + Duration::from_secs(2)).await;
        assert!(!node.failed.is_cancelled());
        assert_eq!(node.svc.net.settings().relays, r.cfg.relays);
        node.until(Box::pin(async {})).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saved_relays_that_are_dead_at_startup_give_way_to_the_configured_ones() {
        let r = node_rig(Kind::Lnd).await;
        std::fs::create_dir_all(&r.cfg.data_dir).unwrap();
        let saved = NetworkFile {
            relays: Some(vec!["ws://127.0.0.1:9".into()]),
            ..Default::default()
        };
        write_network(&r.cfg.data_dir, &saved).unwrap();
        let node = start(r.cfg.clone()).await.unwrap();
        assert_eq!(node.svc.net.settings().relays, r.cfg.relays);
        assert_eq!(last_audit(&r.cfg.data_dir).1, DEAD_AT_START);
        node.until(Box::pin(async {})).await.unwrap();
        // Saved settings that do not fit stop the node at start.
        std::fs::write(r.cfg.data_dir.join(crate::node::network::NETWORK_FILE), "junk").unwrap();
        assert!(start(r.cfg.clone()).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_proxy_pool_moves_the_relays_and_the_kill_switch_cuts_them() {
        let r = node_rig(Kind::Lnd).await;
        let (port, proxy) = deadhop_net::testing::socks5_proxy(None).await;
        let node = start(r.cfg.clone()).await.unwrap();
        let svc = node.svc.clone();
        // Woken with nothing to change: nothing moves.
        svc.net.runtime.pool_switch.notify_one();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let url = format!("socks5://127.0.0.1:{port}");
        update(&svc, json!({ "proxies": { "list": [{ "id": "p", "url": url }] } }));
        update(&svc, json!({ "proxies": { "default": { "proxy": "p" } } }));
        let want = vec![(r.relay_url.clone(), url.clone())];
        eventually("the move to the proxy", Duration::from_secs(10), || {
            svc.net.runtime.lane_routes(&*svc, LANE) == Some(want.clone())
        })
        .await;
        tokio::time::sleep(RESTART_GRACE + Duration::from_millis(500)).await;
        // Still served, now through the proxy, on the same connections' loop.
        let gw = client(&r, gateway_keys(), &node.keys, Duration::from_secs(10)).await;
        let list: AddressList = gw.call(proto::LIST_ADDRESSES, json!({})).await.unwrap();
        assert_eq!(list.addresses.len(), 2);
        let admin = client(&r, admin_keys(), &node.keys, Duration::from_secs(10)).await;
        let health: serde_json::Value = admin.call("get_health", json!({})).await.unwrap();
        assert_eq!(health["proxy"], url.as_str());
        // The proxy goes away: the kill switch disconnects every relay.
        proxy.abort();
        eventually("the kill switch", Duration::from_secs(15), || {
            svc.net.runtime.lane_routes(&*svc, LANE).is_none()
        })
        .await;
        tokio::time::sleep(RESTART_GRACE + Duration::from_secs(1)).await;
        assert_eq!(node.relays_connected().await, 0);
        assert!(!node.failed.is_cancelled());
        gw.close().await;
        admin.close().await;
        node.until(Box::pin(async {})).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_switch_that_cannot_connect_stops_the_node() {
        let (node, _r, _proxy) = behind_a_proxy().await;
        unusable_route(&node);
        node.svc.net.runtime.pool_switch.notify_one();
        let e = node
            .until(Box::pin(tokio::time::sleep(Duration::from_secs(20))))
            .await
            .unwrap_err();
        assert!(e.contains("request loop ended"), "{e}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restart_that_cannot_reconnect_or_go_back_stops_the_node() {
        let (node, r, _proxy) = behind_a_proxy().await;
        // The new relays cannot even start, and going back cannot be saved.
        unusable_route(&node);
        let mut moved = node.svc.net.settings();
        moved.relays = vec!["ws://127.0.0.1:9".into()];
        node.svc.net.set(moved);
        std::fs::create_dir(r.cfg.data_dir.join("network.tmp")).unwrap();
        node.svc.schedule_restart();
        let e = node
            .until(Box::pin(tokio::time::sleep(Duration::from_secs(20))))
            .await
            .unwrap_err();
        assert!(e.contains("request loop ended"), "{e}");
    }
}
