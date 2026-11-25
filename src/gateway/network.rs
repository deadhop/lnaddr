//! The gateway's network on the shared network engine: its relays and
//! proxies, routing rules, proxy groups, relay health and the privacy audit,
//! for the keys in `admins` only.
//!
//! Two lanes, one per key the gateway connects with: `gateway`
//! (`gateway.key`, which asks the nodes for invoices) and `admin`
//! (`admin.key`, which manages the nodes from the admin page and the command
//! line, and is the identity the network console signs in to). Each node is
//! reached on the lane's relays that are also that node's relays in the
//! configuration (`nodes[].relays`), so a request never goes to a relay the
//! node does not read.
//!
//! The baseline is every node's relays (what the gateway always dialled) and
//! the configured `socks5` proxy. As on the node, what an admin changes is
//! saved in `network.json` in the data directory (only while remote settings
//! are on), every change is appended to `audit.jsonl`, and relay results are
//! kept in memory only.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use deadhop_netengine::error::Result as EngineResult;
use deadhop_netengine::netruntime::{
    route_specs, same_relays, AuditFacts, NetworkHost, NetworkRuntime, RelayEventRow, RelayState, Routes,
};
use deadhop_netengine::network::{same_relay, Lane, NetworkSettings, OfflinePolicy, ProxySettings, Topology};
use deadhop_netengine::privacy::ProxyCheck;
use deadhop_netengine::proxypool::PoolHealth;
use deadhop_netengine::relayhealth::RelayHealth;
use deadhop_netengine::view::{KeyInfo, NetworkView, UpdateNetworkParams};
use nostr_sdk::prelude::{Keys, PublicKey, ToBech32};
use nostr_sdk::RelayStatus;
use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;

use crate::cvm::NodeClient;
use crate::gateway::config::{Config, NodeConfig};
use crate::node::network::{
    append_audit, audit_detail, check_relays, copy, from_engine, read_network, to_engine, whole, write_network,
    AuditEntry, NetworkFile, AUDIT_FILE, AUDIT_MAX_BYTES, NETWORK_FILE, RELAY_EVENTS_KEPT,
};
use crate::node::service::{refuse, Caller, Refusal, MAX_CLOCK_SKEW_SECS};
use crate::pool::Pool;
use crate::proto::code;

/// The lane of `gateway.key`: invoices.
pub const GATEWAY_LANE: &str = "gateway";
/// The lane of `admin.key`: the nodes' admin tools and the network console.
pub const ADMIN_LANE: &str = "admin";
/// The host setting that keeps the proxies host-only.
pub const LOCK_SETTING: &str = "LNADDR_GATEWAY_PROXY_LOCKED";
/// How the lock is named while remote settings are off.
pub const REMOTE_OFF: &str = "remote settings off: LNADDR_GATEWAY_REMOTE";

/// The gateway's lanes: one per key.
pub fn lanes() -> Vec<Lane> {
    vec![
        Lane {
            id: GATEWAY_LANE.into(),
            label: "Gateway (invoices)".into(),
        },
        Lane {
            id: ADMIN_LANE.into(),
            label: "Admin (node admin and console)".into(),
        },
    ]
}

/// The network settings the configuration gives: every node's relays, once
/// each, and the one proxy (`socks5`) as the default route with the kill
/// switch, read as the node reads its own.
pub fn baseline(cfg: &Config) -> NetworkSettings {
    use deadhop_netengine::legacy;
    let mut relays: Vec<String> = Vec::new();
    for r in cfg.nodes.iter().flat_map(|n| &n.relays) {
        if !relays.iter().any(|x| same_relay(x, r)) {
            relays.push(r.clone());
        }
    }
    let mut old = legacy::ProxySettings::default();
    if let Some(url) = &cfg.socks5 {
        old.list.push(legacy::ProxyEntry {
            id: "socks5".into(),
            name: String::new(),
            url: url.clone(),
            keys: Vec::new(),
            pool: true,
            i2p: false,
        });
    }
    NetworkSettings {
        relays,
        relay_keys: BTreeMap::new(),
        relay_names: BTreeMap::new(),
        proxies: legacy::convert(&old, &lanes()),
    }
}

/// The relays of `routes` that `node` reads, with their routes.
fn for_node(routes: Routes, node: &NodeConfig) -> Option<Routes> {
    let mine: Routes = routes
        .into_iter()
        .filter(|(r, _)| node.relays.iter().any(|x| same_relay(x, r)))
        .collect();
    (!mine.is_empty()).then_some(mine)
}

/// What is wrong between the nodes and the relays each lane uses: a node the
/// gateway key shares no relay with cannot be asked for invoices; one the
/// admin key shares none with cannot be managed from the gateway.
pub fn shared_relay_warnings(cfg: &Config, t: &Topology) -> Vec<String> {
    let mut out = Vec::new();
    for (i, n) in cfg.nodes.iter().enumerate() {
        for (lane, what) in [
            (GATEWAY_LANE, "asked for invoices"),
            (ADMIN_LANE, "managed from the gateway"),
        ] {
            let mine = t.relays_for(lane);
            if !mine.iter().any(|r| n.relays.iter().any(|x| same_relay(x, r))) {
                out.push(format!(
                    "node {} shares no relay with the {lane} key, so it cannot be {what}; its relays: {}",
                    i + 1,
                    n.relays.join(", ")
                ));
            }
        }
    }
    out
}

/// One relay pool the gateway opened to a node.
pub struct Conn {
    lane: &'static str,
    node: NodeConfig,
    pool: Arc<Pool>,
    routes: Mutex<Routes>,
    stale: AtomicBool,
}

impl Conn {
    /// Moved off its relays or routes: make a new one before the next call.
    pub fn stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }

    async fn retire(&self) {
        self.stale.store(true, Ordering::Relaxed);
        self.pool.client().disconnect().await;
    }
}

/// The network part of the gateway's health: what the network views read.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct GatewayHealth {
    /// The gateway's keys, with their relays.
    pub keys: Vec<KeyInfo>,
    pub relays: Vec<RelayState>,
    /// Proxy the gateway key's relay connections go through now (password hidden), empty if direct.
    pub proxy: String,
    /// The last test of that proxy, if one ran.
    pub proxy_check: Option<ProxyCheck>,
    /// Every proxy, which one is in use and what happens when none works.
    pub proxy_pool: PoolHealth,
    /// The last health check of every live relay (empty until the first ran).
    pub relay_health: Vec<RelayHealth>,
    /// A relay change is waiting for the connections to be remade.
    pub restart_pending: bool,
    /// Nodes the gateway shares no relay with, per key.
    pub warnings: Vec<String>,
    /// How each node answered the gateway key lately.
    pub nodes: Vec<crate::gateway::nodes::Health>,
}

/// The gateway's network state (never saved, except through `network.json`).
pub struct Network {
    cfg: Config,
    pub runtime: NetworkRuntime,
    baseline: NetworkSettings,
    live: RwLock<NetworkSettings>,
    /// What `network.json` holds; its lock also keeps changes one at a time.
    stored: Mutex<NetworkFile>,
    events: Mutex<VecDeque<RelayEventRow>>,
    /// The relay pools open to nodes now.
    conns: Mutex<Vec<Weak<Conn>>>,
    /// The relay pool of the console's server, if it runs.
    server_pool: Mutex<Option<Arc<Pool>>>,
    restart: tokio::sync::Notify,
    restart_pending: AtomicBool,
    pubkeys: Mutex<BTreeMap<&'static str, String>>,
    now: fn() -> u64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Network {
    pub fn new(cfg: Config) -> Self {
        let baseline = baseline(&cfg);
        Network {
            cfg,
            runtime: NetworkRuntime::default(),
            live: RwLock::new(baseline.clone()),
            baseline,
            stored: Mutex::new(NetworkFile::default()),
            events: Mutex::new(VecDeque::new()),
            conns: Mutex::new(Vec::new()),
            server_pool: Mutex::new(None),
            restart: tokio::sync::Notify::new(),
            restart_pending: AtomicBool::new(false),
            pubkeys: Mutex::new(BTreeMap::new()),
            now: crate::unix_now,
        }
    }

    /// The network as the configuration and `network.json` set it, with
    /// the proxies looked at: what a one-off command connects with.
    pub async fn for_command(cfg: &Config) -> Result<Arc<Network>, String> {
        let net = Arc::new(Network::new(cfg.clone()));
        net.load_network()?;
        net.runtime.refresh_pool(&*net).await;
        Ok(net)
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn baseline(&self) -> &NetworkSettings {
        &self.baseline
    }

    pub fn clock(&self) -> u64 {
        (self.now)()
    }

    /// The live network settings.
    pub fn settings(&self) -> NetworkSettings {
        self.live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set(&self, next: NetworkSettings) {
        *self.live.write().unwrap_or_else(std::sync::PoisonError::into_inner) = next;
    }

    /// Tell the network views a key's public key.
    pub fn set_pubkey(&self, lane: &'static str, hex: &str) {
        lock(&self.pubkeys).insert(lane, hex.to_string());
    }

    /// How `lane` reaches `node` now: the lane's relays the node reads, each
    /// through its route; `None` when none may connect.
    pub fn node_routes(&self, lane: &str, node: &NodeConfig) -> Option<Routes> {
        self.runtime.lane_routes(self, lane).and_then(|r| for_node(r, node))
    }

    /// Open a client to `node` on `lane`'s routes, kept track of so a move
    /// of routes reaches it.
    pub async fn connect_node(
        self: &Arc<Self>,
        lane: &'static str,
        keys: Keys,
        node: &NodeConfig,
        timeout: std::time::Duration,
    ) -> Result<(NodeClient, Arc<Conn>), String> {
        let routes = self
            .node_routes(lane, node)
            .ok_or("no relay of this node has a route now (kill switch, blocked, or its proxy is down)".to_string())?;
        let sink: deadhop_net::relay::RelaySink = {
            let net = self.clone();
            Arc::new(move |relay, ok, ms| net.runtime.record_relay_event(&*net, relay, "send", ok, Some(ms)))
        };
        let specs = route_specs(&routes).map_err(crate::why)?;
        let pool = Arc::new(Pool::routed(keys, specs).with_sink(sink));
        let relays: Vec<String> = routes.iter().map(|(r, _)| r.clone()).collect();
        let client = NodeClient::on_pool(pool.clone(), &node.pubkey, &relays, timeout).await?;
        let conn = Arc::new(Conn {
            lane,
            node: node.clone(),
            pool,
            routes: Mutex::new(routes),
            stale: AtomicBool::new(false),
        });
        let mut conns = lock(&self.conns);
        conns.retain(|c| c.strong_count() > 0);
        conns.push(Arc::downgrade(&conn));
        Ok((client, conn))
    }

    fn live_conns(&self) -> Vec<Arc<Conn>> {
        lock(&self.conns).iter().filter_map(Weak::upgrade).collect()
    }

    /// Follow a move of routes: a pool whose relays stay the same moves the
    /// ones whose route changed and keeps the rest connected; any other is
    /// closed, and its link opens a new one on its next call.
    pub async fn move_conns(&self) {
        for c in self.live_conns() {
            let want = self.node_routes(c.lane, &c.node);
            let current = lock(&c.routes).clone();
            match want {
                Some(w) if same_relays(&current, &w) => {
                    if w == current {
                        continue;
                    }
                    let moved = match route_specs(&w) {
                        Ok(specs) => c.pool.reroute(specs).await.map_err(crate::why),
                        Err(e) => Err(e.to_string()),
                    };
                    match moved {
                        Ok(()) => *lock(&c.routes) = w,
                        Err(e) => {
                            tracing::warn!(error = %e, "could not move a node connection; it is remade");
                            c.retire().await;
                        }
                    }
                }
                _ => c.retire().await,
            }
        }
    }

    /// Close every node connection (their relays changed); each link opens
    /// a new one on its next call.
    pub async fn drop_conns(&self) {
        for c in self.live_conns() {
            c.retire().await;
        }
    }

    /// The relay pool of the console's server (`None`: not connected).
    pub fn set_server_pool(&self, pool: Option<Arc<Pool>>) {
        *lock(&self.server_pool) = pool;
    }

    /// Whether admins may not touch the proxies: locked on the host, or
    /// remote settings off. Then only the listed proxies can be tested and no
    /// I2P name looked up.
    pub fn proxies_locked(&self) -> bool {
        self.cfg.proxy_locked || !self.cfg.sources.remote
    }

    fn lock_setting(&self) -> &'static str {
        if self.cfg.proxy_locked || self.cfg.sources.remote {
            LOCK_SETTING
        } else {
            REMOTE_OFF
        }
    }

    /// The admin calling, by hex public key: one of `admins`, with a fresh
    /// signed request.
    pub fn admin(&self, c: &Caller) -> Result<String, Refusal> {
        let key = c.pubkey.as_deref().and_then(|k| PublicKey::from_hex(k).ok());
        let Some(key) = key.filter(|k| self.cfg.admins.contains(k)) else {
            return Err(refuse(code::UNAUTHORIZED, "this key may not manage this gateway"));
        };
        let e = c
            .event
            .as_ref()
            .ok_or_else(|| refuse(code::UNAUTHORIZED, "request event missing"))?;
        if e.created_at.as_secs().abs_diff(self.clock()) > MAX_CLOCK_SKEW_SECS {
            return Err(refuse(
                code::UNAUTHORIZED,
                "the request's timestamp is too far from the gateway's clock",
            ));
        }
        Ok(key.to_hex())
    }

    /// Append to the audit log. A log that cannot be written is an error:
    /// a change must not go unrecorded.
    pub(crate) fn record(&self, actor: &str, action: &str, detail: &str) -> Result<(), Refusal> {
        tracing::info!(actor, action, detail, "admin action");
        let entry = AuditEntry {
            at: self.clock(),
            actor: actor.into(),
            action: action.into(),
            detail: detail.into(),
        };
        append_audit(&self.cfg.data_dir.join(AUDIT_FILE), &entry, AUDIT_MAX_BYTES).map_err(|e| {
            tracing::error!(error = %e, "could not write the audit log");
            refuse(code::INTERNAL, "the gateway could not record the change")
        })
    }

    /// Read `network.json` (when remote settings are on) and run on it.
    /// Saved settings that do not fit stop the gateway with the reason;
    /// saved relays that leave a node out are only warned about.
    pub fn load_network(&self) -> Result<(), String> {
        if !self.cfg.sources.remote {
            return Ok(());
        }
        let mut stored = read_network(&self.cfg.data_dir)?;
        if self.cfg.proxy_locked && stored.proxies.take().is_some() {
            tracing::warn!(
                "{NETWORK_FILE}: the proxies are locked on the host ({LOCK_SETTING}); the saved ones are ignored"
            );
        }
        let next = stored.apply(&self.baseline);
        if let Some(r) = &stored.relays {
            check_relays(r).map_err(|e| format!("{NETWORK_FILE}: {}", e.message))?;
        }
        let t = Topology {
            settings: next.clone(),
            lanes: lanes(),
        };
        t.validate().map_err(|e| format!("{NETWORK_FILE}: {e}"))?;
        for w in shared_relay_warnings(&self.cfg, &t) {
            tracing::warn!("{NETWORK_FILE}: {w}");
        }
        *lock(&self.stored) = stored;
        self.set(next);
        Ok(())
    }

    /// Save `stored` changed by `f` and run on what it makes of the baseline.
    fn change_stored(&self, f: impl FnOnce(&mut NetworkFile, &NetworkSettings)) -> Result<(), Refusal> {
        let mut stored = lock(&self.stored);
        let mut next = stored.clone();
        f(&mut next, &self.baseline);
        self.save(&mut stored, next)
    }

    fn save(&self, stored: &mut NetworkFile, next: NetworkFile) -> Result<(), Refusal> {
        write_network(&self.cfg.data_dir, &next).map_err(|e| {
            tracing::error!(error = %e, "could not save the network settings");
            refuse(code::INTERNAL, "the gateway could not save the change")
        })?;
        self.set(next.apply(&self.baseline));
        *stored = next;
        Ok(())
    }

    /// The gateway's keys, with their relays.
    pub fn key_infos(&self) -> Vec<KeyInfo> {
        let t = self.topology();
        let keys = lock(&self.pubkeys);
        let serves = !self.cfg.admins.is_empty();
        lanes()
            .into_iter()
            .map(|l| {
                let admin = l.id == ADMIN_LANE;
                KeyInfo {
                    pubkey: keys.get(l.id.as_str()).cloned().unwrap_or_default(),
                    tools: if admin && serves { vec!["*".into()] } else { Vec::new() },
                    operators_only: admin,
                    relays: t.relays_for(&l.id),
                    id: l.id,
                    label: l.label,
                }
            })
            .collect()
    }

    /// The bitcoin network the nodes report, `bitcoin` until one has.
    fn chain(chain: Option<String>) -> String {
        chain.unwrap_or_else(|| "bitcoin".into())
    }

    fn view(&self, chain: Option<String>) -> NetworkView {
        let hide = |mut s: NetworkSettings| {
            s.proxies = s.proxies.redacted();
            s
        };
        NetworkView {
            settings: hide(self.settings()),
            defaults: hide(self.baseline.clone()),
            overridden: lock(&self.stored).names(),
            chain: Self::chain(chain),
            keys: self.key_infos(),
            proxy_locked: self.proxies_locked(),
            restart_pending: self.restart_pending(),
            warnings: shared_relay_warnings(&self.cfg, &self.topology()),
        }
    }

    /// The network settings (admins only).
    pub fn get_network(&self, c: &Caller, chain: Option<String>) -> Result<NetworkView, Refusal> {
        self.admin(c)?;
        Ok(self.view(chain))
    }

    /// Change the network settings (admins only, when remote settings are
    /// on). A relay list or relay assignment that leaves a node with no relay
    /// in common with the gateway key is refused.
    pub fn update_network(
        &self,
        c: &Caller,
        p: UpdateNetworkParams,
        chain: Option<String>,
    ) -> Result<NetworkView, Refusal> {
        let actor = self.admin(c)?;
        if !self.cfg.sources.remote {
            return Err(refuse(code::LOCKED, "remote settings are switched off on this gateway"));
        }
        let mut patch = p.patch;
        if self.cfg.proxy_locked && patch.proxies.is_some() {
            return Err(refuse(
                code::LOCKED,
                format!("the proxy settings are locked on the host ({LOCK_SETTING})"),
            ));
        }
        let mut stored = lock(&self.stored);
        let before = self.topology();
        if let Some(px) = &mut patch.proxies {
            px.resolve(&before.proxies.list).map_err(from_engine)?;
        }
        let mut next_file = stored.clone();
        next_file.merge(&patch);
        let next = Topology {
            settings: next_file.apply(&self.baseline),
            lanes: lanes(),
        };
        if let Some(r) = &patch.relays {
            check_relays(r)?;
        }
        next.validate().map_err(from_engine)?;
        if patch.relays.is_some() || patch.relay_keys.is_some() {
            // A node the gateway key shares no relay with gets no invoice
            // request, and nothing would undo it: the gateway's own relays
            // still connect.
            let gw = next.relays_for(GATEWAY_LANE);
            if let Some((i, n)) = self
                .cfg
                .nodes
                .iter()
                .enumerate()
                .find(|(_, n)| !gw.iter().any(|r| n.relays.iter().any(|x| same_relay(x, r))))
            {
                return Err(refuse(
                    code::INVALID,
                    format!(
                        "relays: node {} ({}) would share no relay with the gateway key; keep one of {}",
                        i + 1,
                        n.pubkey.to_bech32().expect("keys encode"),
                        n.relays.join(", ")
                    ),
                ));
            }
        }
        if let Some(url) = patch
            .relay_names
            .iter()
            .flatten()
            .map(|(u, _)| u)
            .find(|u| !next.relays.iter().any(|r| same_relay(r, u)))
        {
            return Err(refuse(
                code::INVALID,
                format!("relay_names: {url:?} is not a listed relay"),
            ));
        }
        let proxies_changed = next.proxies != before.proxies;
        if proxies_changed {
            if let Some(key) = self.runtime.stranded(&before, &next) {
                return Err(refuse(
                    code::INVALID,
                    format!(
                        "the {} key's default route would have nothing reachable now, which would cut the gateway off; point it at a proxy or group that is up, or wait until one is back",
                        key.to_lowercase()
                    ),
                ));
            }
        }
        let relays_changed = next.relays != before.relays || next.relay_keys != before.relay_keys;
        self.save(&mut stored, next_file)?;
        drop(stored);
        let detail = audit_detail(patch);
        // Applied: the checks that undo a bad change run whatever happens to
        // the audit log, which is reported after them.
        if relays_changed {
            self.schedule_restart();
        }
        if proxies_changed {
            self.runtime.begin_probation(self, before.settings.proxies);
        }
        self.record(&actor, "update_network", &detail)?;
        Ok(self.view(chain))
    }

    /// Drop every saved network change and go back to the configuration's
    /// relays and proxy (admins only, when remote settings are on).
    pub fn reset_network(&self, c: &Caller, chain: Option<String>) -> Result<NetworkView, Refusal> {
        let actor = self.admin(c)?;
        if !self.cfg.sources.remote {
            return Err(refuse(code::LOCKED, "remote settings are switched off on this gateway"));
        }
        let before = self.settings();
        self.change_stored(|stored, _| *stored = NetworkFile::default())?;
        let next = self.settings();
        if next.relays != before.relays || next.relay_keys != before.relay_keys {
            self.schedule_restart();
        }
        if next.proxies != before.proxies {
            self.runtime.begin_probation(self, before.proxies.clone());
        }
        self.record(&actor, "reset_network", "")?;
        Ok(self.view(chain))
    }

    /// Go back to relays that worked (the gateway's own act).
    pub(crate) fn revert_connection(
        &self,
        relays: Vec<String>,
        relay_keys: BTreeMap<String, Vec<String>>,
        why: &str,
    ) -> Result<(), Refusal> {
        self.change_stored(|stored, base| {
            stored.relays = (relays != base.relays).then_some(relays);
            stored.relay_keys = (!relay_keys.is_empty()).then_some(relay_keys);
        })
        .and_then(|()| self.record("gateway", "revert_connection", why))
    }

    /// The network part of the gateway's health (admins only).
    pub async fn health(
        &self,
        c: &Caller,
        nodes: Vec<crate::gateway::nodes::Health>,
    ) -> Result<GatewayHealth, Refusal> {
        self.admin(c)?;
        let net = &self.runtime;
        Ok(GatewayHealth {
            keys: self.key_infos(),
            relays: NetworkHost::relay_states(self).await,
            proxy: deadhop_net::relay::redact(&net.main_proxy(self).unwrap_or_default()),
            proxy_check: lock(&net.last_proxy_check).clone(),
            proxy_pool: net.pool_health(self),
            relay_health: lock(&net.relay_health).clone(),
            restart_pending: self.restart_pending(),
            warnings: shared_relay_warnings(&self.cfg, &self.topology()),
            nodes,
        })
    }

    /// Wait until a change of relays asks for new connections.
    pub fn restart_requested(&self) -> tokio::sync::futures::Notified<'_> {
        self.restart.notified()
    }

    pub fn restart_pending(&self) -> bool {
        self.restart_pending.load(Ordering::Relaxed)
    }

    pub(crate) fn schedule_restart(&self) {
        self.restart_pending.store(true, Ordering::Relaxed);
        self.restart.notify_one();
    }

    /// Called by the supervisor once the connections were remade.
    pub fn restarted(&self) {
        self.restart_pending.store(false, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl NetworkHost for Network {
    fn topology(&self) -> Topology {
        Topology {
            settings: self.settings(),
            lanes: lanes(),
        }
    }

    fn now(&self) -> u64 {
        self.clock()
    }

    fn connects_while_offline(&self, lane: &str, policy: OfflinePolicy) -> bool {
        // "Admins only" keeps the admin key (the console, node admin) and
        // stops invoices; "invoicing only" the other way round.
        match policy {
            OfflinePolicy::KillSwitch => false,
            OfflinePolicy::AdminOnly => lane == ADMIN_LANE,
            OfflinePolicy::InvoicingOnly => lane == GATEWAY_LANE,
            OfflinePolicy::Open => true,
        }
    }

    fn revert_proxies(&self, previous: ProxySettings, why: &str) -> EngineResult<()> {
        // Locked proxies are the configuration's; nothing saved may replace them.
        if self.cfg.proxy_locked {
            return Err(to_engine(refuse(
                code::LOCKED,
                format!("the proxy settings are locked on the host ({LOCK_SETTING})"),
            )));
        }
        self.change_stored(|stored, base| {
            stored.proxies = (previous != base.proxies).then(|| whole(&previous));
        })
        .and_then(|()| self.record("gateway", "revert_proxies", why))
        .map_err(to_engine)
    }

    fn admit_change(&self, caller: &Caller) -> EngineResult<String> {
        self.admin(caller).map_err(to_engine)
    }

    fn admit_read(&self, caller: &Caller) -> EngineResult<()> {
        self.admin(caller).map(drop).map_err(to_engine)
    }

    fn audit(&self, actor: &str, action: &str, detail: &str) -> EngineResult<()> {
        self.record(actor, action, detail).map_err(to_engine)
    }

    fn proxy_locked(&self) -> bool {
        self.proxies_locked()
    }

    async fn relay_states(&self) -> Vec<RelayState> {
        let mut pools: Vec<(&str, Arc<Pool>)> = self.live_conns().iter().map(|c| (c.lane, c.pool.clone())).collect();
        if let Some(p) = lock(&self.server_pool).clone() {
            pools.push((ADMIN_LANE, p));
        }
        let mut out: Vec<RelayState> = Vec::new();
        for (lane, pool) in pools {
            for (url, relay) in pool.client().relays().await {
                let status = relay.status();
                let connected = status == RelayStatus::Connected;
                let url = url.to_string();
                let i = match out.iter().position(|s| same_relay(&s.url, &url)) {
                    Some(i) => i,
                    None => {
                        out.push(RelayState {
                            url,
                            status: status.to_string().to_lowercase(),
                            connected,
                            keys: Vec::new(),
                        });
                        out.len() - 1
                    }
                };
                let s = &mut out[i];
                if connected {
                    s.connected = true;
                    s.status = status.to_string().to_lowercase();
                }
                if !s.keys.iter().any(|k| k == lane) {
                    s.keys.push(lane.into());
                }
            }
        }
        // Relays with no connection (none yet, or none allowed now): unknown.
        let t = self.topology();
        for url in &t.relays {
            if !out.iter().any(|s| same_relay(&s.url, url)) {
                out.push(RelayState {
                    url: url.clone(),
                    status: "unknown".into(),
                    connected: false,
                    keys: t.relay_users(url),
                });
            }
        }
        out.sort_by(|a, b| a.url.cmp(&b.url));
        out
    }

    fn store_relay_event(&self, row: &RelayEventRow) -> EngineResult<()> {
        let mut events = lock(&self.events);
        if events.len() >= RELAY_EVENTS_KEPT {
            events.pop_front();
        }
        events.push_back(copy(row));
        Ok(())
    }

    fn relay_events_since(&self, since: u64) -> EngineResult<Vec<RelayEventRow>> {
        Ok(lock(&self.events).iter().filter(|e| e.at >= since).map(copy).collect())
    }

    fn audit_facts(&self) -> AuditFacts {
        AuditFacts {
            service: "lnaddr-gateway".into(),
            electrum: None,
            announce: None,
            lock_setting: self.lock_setting().into(),
            test_place: "the console".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::tests::{console_keys, gateway_config_for};
    use crate::node::service::tests::{admin_keys, caller, gateway_keys};
    use deadhop_netengine::proxypool::{Applied, PoolState};
    use deadhop_netengine::routes::Destination;
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::{EventBuilder, Timestamp};
    use serde_json::json;
    use std::path::Path;
    use std::time::Duration;

    fn node(relays: &[&str]) -> NodeConfig {
        NodeConfig {
            pubkey: Keys::generate().public_key(),
            names: None,
            relays: relays.iter().map(|r| r.to_string()).collect(),
            payee: None,
        }
    }

    /// Two nodes: one on relays 1 and 2, one on relay 2 and 3.
    fn cfg(dir: &Path) -> Config {
        gateway_config_for(
            vec![
                node(&["ws://127.0.0.1:1", "ws://127.0.0.1:2"]),
                node(&["ws://127.0.0.1:2/", "ws://127.0.0.1:3"]),
            ],
            dir,
        )
    }

    fn rig(dir: &Path) -> Network {
        Network::new(cfg(dir))
    }

    fn patch(v: serde_json::Value) -> UpdateNetworkParams {
        serde_json::from_value(json!({ "patch": v })).unwrap()
    }

    fn audit_lines(dir: &Path) -> Vec<AuditEntry> {
        std::fs::read_to_string(dir.join(AUDIT_FILE))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn admin() -> Caller {
        caller(&console_keys())
    }

    #[test]
    fn the_baseline_is_every_nodes_relays_once_and_the_configured_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        let direct = baseline(&c);
        assert_eq!(
            direct.relays,
            ["ws://127.0.0.1:1", "ws://127.0.0.1:2", "ws://127.0.0.1:3"]
        );
        assert_eq!(direct.proxies.default, Destination::Direct);
        // `socks5` as before: one proxy, everything through it, nothing
        // straight while it is down.
        c.socks5 = Some("socks5://127.0.0.1:9050".into());
        let via = baseline(&c);
        assert_eq!(via.proxies.list[0].url, "socks5://127.0.0.1:9050");
        assert_eq!(via.proxies.default, Destination::Proxy("socks5".into()));
        assert_eq!(via.proxies.offline, OfflinePolicy::KillSwitch);
        Topology {
            settings: via,
            lanes: lanes(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn nodes_without_a_shared_relay_are_named_per_key() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let mut t = Topology {
            settings: baseline(&c),
            lanes: lanes(),
        };
        assert!(shared_relay_warnings(&c, &t).is_empty());
        t.settings.relays = vec!["ws://127.0.0.1:1".into(), "ws://127.0.0.1:3".into()];
        t.settings.relay_keys = [("ws://127.0.0.1:3".to_string(), vec![ADMIN_LANE.to_string()])].into();
        let w = shared_relay_warnings(&c, &t);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].starts_with("node 2 shares no relay with the gateway key"), "{w:?}");
        assert!(for_node(vec![("ws://127.0.0.1:9".into(), String::new())], &c.nodes[0]).is_none());
    }

    #[tokio::test]
    async fn the_gateway_hosts_its_network_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let net = rig(dir.path());
        let host: &dyn NetworkHost = &net;
        assert_eq!(host.topology().lanes, lanes());
        assert!(host.now() > 1_700_000_000);
        for (lane, policy, connects) in [
            (GATEWAY_LANE, OfflinePolicy::KillSwitch, false),
            (GATEWAY_LANE, OfflinePolicy::AdminOnly, false),
            (ADMIN_LANE, OfflinePolicy::AdminOnly, true),
            (GATEWAY_LANE, OfflinePolicy::InvoicingOnly, true),
            (ADMIN_LANE, OfflinePolicy::InvoicingOnly, false),
            (ADMIN_LANE, OfflinePolicy::Open, true),
        ] {
            assert_eq!(host.connects_while_offline(lane, policy), connects, "{lane} {policy:?}");
        }
        assert!(!host.proxy_locked());
        let facts = host.audit_facts();
        assert_eq!(
            (facts.service.as_str(), facts.lock_setting.as_str()),
            ("lnaddr-gateway", LOCK_SETTING)
        );
        assert_eq!(
            host.admit_change(&admin()).unwrap(),
            console_keys().public_key().to_hex()
        );
        host.admit_read(&admin()).unwrap();
        // Neither the gateway's own keys nor anyone else may manage it.
        for k in [gateway_keys(), admin_keys()] {
            assert_eq!(
                from_engine(host.admit_change(&caller(&k)).unwrap_err()).code,
                code::UNAUTHORIZED
            );
            assert!(host.admit_read(&caller(&k)).is_err());
        }
        // A request must carry its signed event, and a fresh one.
        let me = console_keys();
        let bare = Caller {
            pubkey: Some(me.public_key().to_hex()),
            event: None,
        };
        assert!(net.admin(&bare).unwrap_err().message.contains("missing"));
        let old = EventBuilder::text_note("x")
            .custom_created_at(Timestamp::from(1))
            .sign_with_keys(&me)
            .unwrap();
        let stale = Caller {
            pubkey: Some(me.public_key().to_hex()),
            event: Some(old),
        };
        assert!(net.admin(&stale).unwrap_err().message.contains("too far"));
        host.audit("me", "act", "detail").unwrap();
        assert_eq!(audit_lines(dir.path())[0].action, "act");
        // Not connected: every relay is shown, unknown, with the keys that use it.
        let states = host.relay_states().await;
        assert_eq!(states.len(), 3);
        assert_eq!((states[0].status.as_str(), states[0].connected), ("unknown", false));
        assert_eq!(states[0].keys, [GATEWAY_LANE, ADMIN_LANE]);
        for i in 0..(RELAY_EVENTS_KEPT as u64 + 5) {
            let row = RelayEventRow {
                at: i,
                relay: "ws://r".into(),
                kind: "check".into(),
                ok: true,
                ms: Some(1),
            };
            host.store_relay_event(&row).unwrap();
        }
        let kept = host.relay_events_since(0).unwrap();
        assert_eq!((kept.len(), kept[0].at), (RELAY_EVENTS_KEPT, 5));
        // Going back to proxies saves them, unless they are the configured ones.
        let mut previous = host.topology().proxies.clone();
        previous.offline = OfflinePolicy::Open;
        host.revert_proxies(previous.clone(), "test").unwrap();
        assert_eq!(net.settings().proxies, previous);
        host.revert_proxies(net.baseline().proxies.clone(), "test").unwrap();
        assert_eq!(read_network(dir.path()).unwrap(), NetworkFile::default());
        assert_eq!(audit_lines(dir.path()).last().unwrap().actor, "gateway");
        assert_eq!(net.config().nodes.len(), 2);
    }

    #[tokio::test]
    async fn admins_read_and_change_the_network_and_every_change_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let net = rig(dir.path());
        net.set_pubkey(GATEWAY_LANE, "ab");
        let other = caller(&admin_keys());
        assert_eq!(net.get_network(&other, None).unwrap_err().code, code::UNAUTHORIZED);
        assert_eq!(
            net.update_network(&other, patch(json!({})), None).unwrap_err().code,
            code::UNAUTHORIZED
        );
        assert_eq!(net.reset_network(&other, None).unwrap_err().code, code::UNAUTHORIZED);
        assert!(net.health(&other, Vec::new()).await.is_err());
        let v = net.get_network(&admin(), Some("regtest".into())).unwrap();
        assert_eq!(v.chain, "regtest");
        assert_eq!(net.get_network(&admin(), None).unwrap().chain, "bitcoin");
        assert_eq!(v.keys.len(), 2);
        assert_eq!((v.keys[0].pubkey.as_str(), v.keys[1].pubkey.as_str()), ("ab", ""));
        assert!(v.keys[0].tools.is_empty() && v.keys[1].tools == ["*"] && v.keys[1].operators_only);
        assert!(v.overridden.is_empty() && v.warnings.is_empty() && !v.proxy_locked);

        // A relay the admin key alone uses, named; a proxy (its password hidden).
        let v = net
            .update_network(
                &admin(),
                patch(json!({
                    "relays": ["ws://127.0.0.1:1", "ws://127.0.0.1:2", "ws://127.0.0.1:4"],
                    "relay_keys": { "ws://127.0.0.1:4": ["admin"] },
                    "relay_names": { "ws://127.0.0.1:4": "console" },
                    "proxies": { "list": [{ "url": "socks5://u:secret@127.0.0.1:9050" }], "offline": "open" }
                })),
                None,
            )
            .unwrap();
        assert!(v.restart_pending);
        assert_eq!(v.keys[0].relays, ["ws://127.0.0.1:1", "ws://127.0.0.1:2"]);
        assert_eq!(v.keys[1].relays.len(), 3);
        let last = audit_lines(dir.path()).pop().unwrap();
        assert_eq!(
            (last.action.as_str(), last.actor),
            ("update_network", console_keys().public_key().to_hex())
        );
        assert!(last.detail.contains("u:***@") && !last.detail.contains("secret"));
        net.restarted();

        let bad = |v: serde_json::Value, want: &str| {
            let r = net.update_network(&admin(), patch(v), None).unwrap_err();
            assert!(r.message.contains(want), "{want}: {}", r.message);
        };
        bad(json!({ "relays": [] }), "1 to 8");
        bad(
            json!({ "relay_keys": { "ws://127.0.0.1:2": ["nobody"] } }),
            "no key 'nobody'",
        );
        bad(
            json!({ "relay_names": { "ws://127.0.0.1:9": "x" } }),
            "not a listed relay",
        );
        bad(
            json!({ "proxies": { "list": [{ "url": "socks5://u:***@10.0.0.1:1" }] } }),
            "password is hidden",
        );
        // Every node keeps a relay in common with the gateway key.
        bad(json!({ "relays": ["ws://127.0.0.1:1"] }), "node 2 (npub1");
        bad(
            json!({ "relay_keys": { "ws://127.0.0.1:2": ["admin"] } }),
            "would share no relay with the gateway key",
        );
        assert_eq!(net.settings().relays.len(), 3);

        let h = net.health(&admin(), Vec::new()).await.unwrap();
        assert_eq!(h.keys.len(), 2);
        assert!(h.warnings.is_empty() && h.nodes.is_empty());

        let v = net.reset_network(&admin(), None).unwrap();
        assert!(v.overridden.is_empty() && v.restart_pending);
        assert_eq!(v.settings, v.defaults);
        assert_eq!(audit_lines(dir.path()).pop().unwrap().action, "reset_network");
        net.restarted();
        assert!(!net.reset_network(&admin(), None).unwrap().restart_pending);
    }

    #[tokio::test]
    async fn the_host_can_lock_remote_network_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.proxy_locked = true;
        let net = Network::new(c.clone());
        let r = net
            .update_network(&admin(), patch(json!({ "proxies": { "offline": "open" } })), None)
            .unwrap_err();
        assert_eq!(r.code, code::LOCKED);
        assert!(r.message.contains(LOCK_SETTING));
        net.update_network(
            &admin(),
            patch(json!({ "relay_names": { "ws://127.0.0.1:1": "x" } })),
            None,
        )
        .unwrap();
        let mut other = net.baseline().proxies.clone();
        other.offline = OfflinePolicy::Open;
        assert_eq!(
            from_engine(NetworkHost::revert_proxies(&net, other, "t").unwrap_err()).code,
            code::LOCKED
        );
        // Saved proxies are ignored while locked.
        write_network(
            dir.path(),
            &serde_json::from_value(json!({ "proxies": { "offline": "open" } })).unwrap(),
        )
        .unwrap();
        let again = Network::new(c.clone());
        again.load_network().unwrap();
        assert_eq!(again.settings().proxies, again.baseline().proxies);
        // With remote settings off, nothing changes, nothing is read, and the
        // lock is named after that.
        c.sources = crate::settings::Sources::default();
        c.proxy_locked = false;
        let off = Network::new(c);
        assert_eq!(
            off.update_network(&admin(), patch(json!({})), None).unwrap_err().code,
            code::LOCKED
        );
        assert_eq!(off.reset_network(&admin(), None).unwrap_err().code, code::LOCKED);
        off.load_network().unwrap();
        assert!(off.proxies_locked() && off.get_network(&admin(), None).unwrap().proxy_locked);
        assert_eq!(NetworkHost::audit_facts(&off).lock_setting, REMOTE_OFF);
    }

    #[tokio::test]
    async fn with_remote_settings_off_no_admin_can_pick_a_proxy_to_connect_through() {
        use deadhop_netengine::netruntime::{CheckProxyParams, ResolveI2pNameParams};
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.sources = crate::settings::Sources::default();
        c.socks5 = Some("socks5://127.0.0.1:1".into());
        let net = Network::new(c);
        let raw = CheckProxyParams {
            proxy: Some("socks5://10.9.9.9:1080".into()),
            id: None,
        };
        let r = from_engine(net.runtime.check_proxy(&net, &admin(), raw).await.unwrap_err());
        assert!(r.message.contains(REMOTE_OFF), "{}", r.message);
        let name = ResolveI2pNameParams {
            name: "example.i2p".into(),
        };
        let r = from_engine(net.runtime.resolve_i2p_name(&net, &admin(), name).await.unwrap_err());
        assert!(r.message.contains(REMOTE_OFF), "{}", r.message);
    }

    #[tokio::test]
    async fn saved_network_settings_are_loaded_and_checked_at_start() {
        let dir = tempfile::tempdir().unwrap();
        rig(dir.path()).load_network().unwrap();
        // Saved relays that leave a node out (the configuration changed since)
        // are loaded, and warned about.
        let saved = NetworkFile {
            relays: Some(vec!["ws://127.0.0.1:1".into()]),
            ..Default::default()
        };
        write_network(dir.path(), &saved).unwrap();
        let net = rig(dir.path());
        net.load_network().unwrap();
        assert_eq!(net.settings().relays, ["ws://127.0.0.1:1"]);
        let v = net.get_network(&admin(), None).unwrap();
        assert_eq!(v.overridden, ["relays"]);
        assert_eq!(v.warnings.len(), 2, "{:?}", v.warnings);
        for (bad, want) in [
            (json!({ "relays": [] }), "1 to 8"),
            (json!({ "relay_keys": { "ws://127.0.0.1:1": ["x"] } }), "no key 'x'"),
        ] {
            write_network(dir.path(), &serde_json::from_value(bad).unwrap()).unwrap();
            let e = rig(dir.path()).load_network().unwrap_err();
            assert!(e.contains(NETWORK_FILE) && e.contains(want), "{e}");
        }
        std::fs::write(dir.path().join(NETWORK_FILE), "junk").unwrap();
        assert!(rig(dir.path()).load_network().is_err());
        assert!(Network::for_command(&cfg(dir.path())).await.is_err());
    }

    #[tokio::test]
    async fn a_change_that_cannot_be_saved_or_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.socks5 = Some("socks5://127.0.0.1:1".into());
        let net = Network::new(c);
        std::fs::create_dir(dir.path().join("network.tmp")).unwrap();
        let r = net
            .update_network(
                &admin(),
                patch(json!({ "relay_names": { "ws://127.0.0.1:1": "x" } })),
                None,
            )
            .unwrap_err();
        assert_eq!(r.code, code::INTERNAL);
        assert!(net.settings().relay_names.is_empty());
        std::fs::remove_dir(dir.path().join("network.tmp")).unwrap();
        // The audit log cannot be written: applied, and the ways back armed.
        std::fs::create_dir(dir.path().join(AUDIT_FILE)).unwrap();
        let r = net
            .update_network(
                &admin(),
                patch(json!({
                    "relays": ["ws://127.0.0.1:1", "ws://127.0.0.1:2", "ws://127.0.0.1:4"],
                    "proxies": { "list": [{ "id": "other", "url": "socks5://127.0.0.1:2" }], "default": { "proxy": "other" } }
                })),
                None,
            )
            .unwrap_err();
        assert!(r.code == code::INTERNAL && r.message.contains("record"));
        assert_eq!(net.settings().relays.len(), 3);
        assert!(net.restart_pending());
        assert!(net.runtime.pool.lock().unwrap().probation.is_some());
        net.restarted();
        assert_eq!(net.reset_network(&admin(), None).unwrap_err().code, code::INTERNAL);
        assert_eq!(net.settings(), *net.baseline());
        assert!(net.restart_pending());
    }

    #[tokio::test]
    async fn a_default_route_to_a_proxy_that_is_down_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let net = rig(dir.path());
        net.update_network(
            &admin(),
            patch(json!({ "proxies": { "list": [
                { "id": "up", "url": "socks5://127.0.0.1:2" },
                { "id": "down", "url": "socks5://127.0.0.1:1" }
            ] } })),
            None,
        )
        .unwrap();
        let probe = |status: &str| ProxyCheck {
            proxy: String::new(),
            status: status.into(),
            checked_at: 1,
            relays: Vec::new(),
        };
        net.runtime.record_probe("down", probe("failed"));
        net.runtime.record_probe("up", probe("connected"));
        let r = net
            .update_network(
                &admin(),
                patch(json!({ "proxies": { "default": { "proxy": "down" } } })),
                None,
            )
            .unwrap_err();
        assert!(r.message.contains("key's default route"), "{}", r.message);
    }

    fn plan(net: &Network, lane: &str, url: Option<&str>) {
        net.runtime.pool.lock().unwrap().applied.insert(
            lane.into(),
            Applied {
                active: url.map(|_| "socks5".into()),
                active_url: url.map(String::from),
                state: if url.is_some() {
                    PoolState::Active
                } else {
                    PoolState::Offline
                },
                next_switch_at: None,
                reachable: usize::from(url.is_some()),
            },
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn node_connections_follow_the_routes_and_report_their_relays() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let (a, _pa) = deadhop_net::testing::socks5_proxy(None).await;
        let (b, _pb) = deadhop_net::testing::socks5_proxy(None).await;
        let (a, b) = (format!("socks5://127.0.0.1:{a}"), format!("socks5://127.0.0.1:{b}"));
        let dir = tempfile::tempdir().unwrap();
        let mut c = gateway_config_for(vec![node(&[&url])], dir.path());
        c.socks5 = Some(a.clone());
        let net = Arc::new(Network::new(c));
        net.runtime.refresh_pool(&*net).await;
        let n = net.config().nodes[0].clone();
        let t = Duration::from_secs(5);
        let (_gc, gw) = net.connect_node(GATEWAY_LANE, Keys::generate(), &n, t).await.unwrap();
        let (_ac, ad) = net.connect_node(ADMIN_LANE, Keys::generate(), &n, t).await.unwrap();
        let (_sc, server) = net.connect_node(ADMIN_LANE, Keys::generate(), &n, t).await.unwrap();
        net.set_server_pool(Some(server.pool.clone()));
        tokio::time::sleep(Duration::from_millis(500)).await;
        let states = NetworkHost::relay_states(&*net).await;
        assert_eq!(states.len(), 1, "{states:?}");
        assert!(states[0].connected);
        assert_eq!(states[0].keys, [GATEWAY_LANE, ADMIN_LANE]);
        // Nothing moved: nothing happens.
        net.move_conns().await;
        assert!(!gw.stale() && !ad.stale());
        // The gateway key's proxy moves: same relays, moved in place.
        plan(&net, GATEWAY_LANE, Some(&b));
        net.move_conns().await;
        assert!(!gw.stale());
        assert_eq!(gw.routes.lock().unwrap()[0].1, b);
        // A route that cannot be used, and the kill switch: closed.
        plan(&net, ADMIN_LANE, Some("unusable"));
        plan(&net, GATEWAY_LANE, None);
        net.move_conns().await;
        assert!(gw.stale() && ad.stale());
        let e = net
            .connect_node(GATEWAY_LANE, Keys::generate(), &n, t)
            .await
            .err()
            .unwrap();
        assert!(e.contains("no relay of this node has a route"), "{e}");
        assert!(net.connect_node(ADMIN_LANE, Keys::generate(), &n, t).await.is_err());
        // Relays changed: every connection is closed.
        plan(&net, GATEWAY_LANE, Some(&a));
        let (_fc, fresh) = net.connect_node(GATEWAY_LANE, Keys::generate(), &n, t).await.unwrap();
        assert!(!fresh.stale());
        net.drop_conns().await;
        assert!(fresh.stale());
        net.set_server_pool(None);
    }
}
