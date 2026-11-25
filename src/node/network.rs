//! The node's network on the shared network engine: its relays and proxies
//! as one lane (`node`), routing rules, proxy groups, relay health and the
//! privacy audit, for admins only.
//!
//! The relays and proxy from the configuration are the baseline. What an
//! admin changes over ContextVM is saved in `network.json` in the data
//! directory, a patch over that baseline (read and written only while remote
//! settings are on, like `remote.toml`). Every change, and every change the
//! node makes by itself (going back to the previous proxies or relays), is
//! appended to `audit.jsonl`, which is kept under [`AUDIT_MAX_BYTES`]. Relay
//! results (health checks, replies sent) are kept in memory only, the last
//! [`RELAY_EVENTS_KEPT`]: they are gone after a restart.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use deadhop_netengine::error::{Error as EngineError, Result as EngineResult};
use deadhop_netengine::netruntime::{AuditFacts, NetworkHost, NetworkRuntime, RelayEventRow, RelayState};
use deadhop_netengine::network::{Lane, NetworkSettings, OfflinePolicy, ProxyPatch, ProxySettings, Topology};
use deadhop_netengine::privacy::ProxyCheck;
use deadhop_netengine::proxypool::PoolHealth;
use deadhop_netengine::relayhealth::RelayHealth;
use deadhop_netengine::view::{KeyInfo, NetworkPatch, NetworkView, UpdateNetworkParams};
use nostr_sdk::RelayStatus;
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::node::config::Config;
use crate::node::service::{refuse, Caller, Refusal, Service};
use crate::pool::Pool;
use crate::proto::code;

/// The node's one lane: its single key, used by gateways and admins alike.
pub const LANE: &str = "node";
pub const LANE_LABEL: &str = "Node";
/// Remotely changed network settings, inside the data directory.
pub const NETWORK_FILE: &str = "network.json";
/// The audit log, inside the data directory.
pub const AUDIT_FILE: &str = "audit.jsonl";
/// Largest size of the audit log. When an entry would pass it, the oldest
/// entries are dropped until the log is at most half of it.
pub const AUDIT_MAX_BYTES: u64 = 1 << 20;
/// Relay results kept in memory (about a week of checks and replies on a
/// busy node); older ones are dropped first.
pub const RELAY_EVENTS_KEPT: usize = 20_000;
/// Most relays the node connects to.
pub const MAX_RELAYS: usize = 8;
/// The host setting that keeps the proxies host-only.
pub const LOCK_SETTING: &str = "LNADDR_NODE_PROXY_LOCKED";
/// How the lock is named while remote settings are off (which also keeps
/// the proxies host-only).
pub const REMOTE_OFF: &str = "remote settings off: LNADDR_NODE_REMOTE";

/// The node's lanes: one.
pub fn lanes() -> Vec<Lane> {
    vec![Lane {
        id: LANE.into(),
        label: LANE_LABEL.into(),
    }]
}

/// The network settings the configuration gives: its relays, and its one
/// proxy (`socks5`) as the default route, read the way the payment service
/// reads its single `DEADHOP_PROXY` (a list of one, the default route through
/// it, the kill switch while it is down: as before, never a direct connection).
pub fn baseline(cfg: &Config) -> NetworkSettings {
    use deadhop_netengine::legacy;
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
        relays: cfg.relays.clone(),
        relay_keys: BTreeMap::new(),
        relay_names: BTreeMap::new(),
        proxies: legacy::convert(&old, &lanes()),
    }
}

/// What `network.json` holds: the network settings an admin changed, each
/// replacing the configured value (proxy settings field by field).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_keys: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_names: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxies: Option<ProxyPatch>,
}

impl NetworkFile {
    /// Add a change on top.
    pub fn merge(&mut self, p: &NetworkPatch) {
        if p.relays.is_some() {
            self.relays.clone_from(&p.relays);
        }
        if p.relay_keys.is_some() {
            self.relay_keys.clone_from(&p.relay_keys);
        }
        if p.relay_names.is_some() {
            self.relay_names.clone_from(&p.relay_names);
        }
        if let Some(px) = &p.proxies {
            self.proxies.get_or_insert_with(ProxyPatch::default).merge(px);
        }
    }

    /// The settings these changes make of `base`.
    pub fn apply(&self, base: &NetworkSettings) -> NetworkSettings {
        let mut s = base.clone();
        if let Some(r) = &self.relays {
            s.relays.clone_from(r);
        }
        if let Some(k) = &self.relay_keys {
            s.relay_keys.clone_from(k);
        }
        if let Some(n) = &self.relay_names {
            s.relay_names.clone_from(n);
        }
        if let Some(px) = &self.proxies {
            px.apply(&mut s.proxies);
        }
        s
    }

    /// The names of the settings changed, as `get_network` lists them.
    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = [
            ("relays", self.relays.is_some()),
            ("relay_keys", self.relay_keys.is_some()),
            ("relay_names", self.relay_names.is_some()),
        ]
        .iter()
        .filter(|f| f.1)
        .map(|f| f.0.to_string())
        .collect();
        if let Some(px) = &self.proxies {
            px.names(&mut out);
        }
        out
    }
}

/// The saved network settings; none saved is no change.
pub fn read_network(data_dir: &Path) -> Result<NetworkFile, String> {
    let path = data_dir.join(NETWORK_FILE);
    match crate::files::read_private(&path)? {
        Some(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        None => Ok(NetworkFile::default()),
    }
}

pub fn write_network(data_dir: &Path, file: &NetworkFile) -> Result<(), String> {
    let text = serde_json::to_string_pretty(file).expect("network settings always serialise");
    crate::files::write_private(&data_dir.join(NETWORK_FILE), &text)
}

/// One line of `audit.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: u64,
    /// The admin's hex public key, or `node` for what the node did itself.
    pub actor: String,
    pub action: String,
    pub detail: String,
}

/// Append one entry to the audit log at `path`, dropping the oldest entries
/// first when it would grow past `max` bytes.
/// Appends one at a time, so two at the size limit cannot drop each other's entries.
pub fn append_audit(path: &Path, entry: &AuditEntry, max: u64) -> Result<(), String> {
    static APPENDING: Mutex<()> = Mutex::new(());
    let _one = lock(&APPENDING);
    let line = serde_json::to_string(entry).expect("audit entries always serialise") + "\n";
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let size = std::fs::metadata(path).map_or(0, |m| m.len());
    if size + line.len() as u64 > max {
        let old = std::fs::read(path).map_err(err)?;
        let old = String::from_utf8_lossy(&old);
        let mut kept: Vec<&str> = Vec::new();
        let mut total = line.len() as u64;
        for l in old.lines().rev() {
            total += l.len() as u64 + 1;
            if total > max / 2 {
                break;
            }
            kept.push(l);
        }
        kept.reverse();
        let mut text: String = kept.iter().map(|l| format!("{l}\n")).collect();
        text.push_str(&line);
        return crate::files::write_private(path, &text);
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(err)?;
    f.write_all(line.as_bytes()).map_err(err)
}

/// The network part of the node's health: what the network views read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct NodeHealth {
    /// The node's key, with its relays.
    pub keys: Vec<KeyInfo>,
    pub relays: Vec<RelayState>,
    /// Proxy relay connections go through now (password hidden), empty if direct.
    pub proxy: String,
    /// The last test of that proxy, if one ran.
    pub proxy_check: Option<ProxyCheck>,
    /// Every proxy, which one is in use and what happens when none works.
    pub proxy_pool: PoolHealth,
    /// The last health check of every live relay (empty until the first ran).
    pub relay_health: Vec<RelayHealth>,
    /// A relay change is waiting for the connections to be remade.
    pub restart_pending: bool,
}

/// What the network console reads when an admin signs in. The node makes no
/// payments of its own: the payment fields describe what it lets through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct NodeInfo {
    pub name: String,
    pub version: String,
    pub network: String,
    /// Always false: only listed gateways get invoices.
    pub public_invoicing: bool,
    /// Always 0: no proof of work is asked.
    pub pow_bits: u32,
    pub pow_window_secs: u64,
    /// Not used by the node (Lightning invoices); always 1.
    pub min_confirmations: u32,
    /// How long each invoice stays payable.
    pub default_expiry_secs: u64,
    pub max_expiry_secs: u64,
    /// The smallest and largest amounts the node's addresses take, in satoshis.
    pub min_amount_sat: u64,
    pub max_amount_sat: u64,
    /// Always true: only admins are answered.
    pub is_admin: bool,
}

/// The node's network state (never saved, except through `network.json`).
pub struct NodeNet {
    pub runtime: NetworkRuntime,
    baseline: NetworkSettings,
    live: RwLock<NetworkSettings>,
    /// What `network.json` holds; its lock also keeps changes one at a time.
    stored: Mutex<NetworkFile>,
    events: Mutex<VecDeque<RelayEventRow>>,
    /// The relay pool of the live connections, for their states.
    pool: Mutex<Option<Arc<Pool>>>,
    restart: tokio::sync::Notify,
    restart_pending: AtomicBool,
    pubkey: Mutex<String>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl NodeNet {
    pub fn new(cfg: &Config) -> Self {
        let baseline = baseline(cfg);
        NodeNet {
            runtime: NetworkRuntime::default(),
            live: RwLock::new(baseline.clone()),
            baseline,
            stored: Mutex::new(NetworkFile::default()),
            events: Mutex::new(VecDeque::new()),
            pool: Mutex::new(None),
            restart: tokio::sync::Notify::new(),
            restart_pending: AtomicBool::new(false),
            pubkey: Mutex::new(String::new()),
        }
    }

    pub fn baseline(&self) -> &NetworkSettings {
        &self.baseline
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
}

/// An engine error as the node's refusal (the node's own come back as they were).
pub fn from_engine(e: EngineError) -> Refusal {
    match e {
        EngineError::InvalidParams(why) => refuse(code::INVALID, why),
        EngineError::RateLimited => refuse(code::RATE_LIMITED, "too many checks; try again in a minute"),
        EngineError::Host(e) => match e.downcast::<Refusal>() {
            Ok(own) => *own,
            Err(other) => refuse(code::INTERNAL, other.to_string()),
        },
    }
}

/// The node's refusal, to hand to the engine and get back unchanged.
pub fn to_engine(r: Refusal) -> EngineError {
    EngineError::Host(Box::new(r))
}

/// The relays a pool knows and how each is doing.
pub async fn pool_states(pool: &Pool) -> Vec<RelayState> {
    let mut out: Vec<RelayState> = pool
        .client()
        .relays()
        .await
        .into_iter()
        .map(|(url, relay)| {
            let status = relay.status();
            RelayState {
                url: url.to_string(),
                status: status.to_string().to_lowercase(),
                connected: status == RelayStatus::Connected,
                keys: vec![LANE.into()],
            }
        })
        .collect();
    out.sort_by(|a, b| a.url.cmp(&b.url));
    out
}

#[async_trait::async_trait]
impl NetworkHost for Service {
    fn topology(&self) -> Topology {
        Topology {
            settings: self.net.settings(),
            lanes: lanes(),
        }
    }

    fn now(&self) -> u64 {
        self.clock()
    }

    fn connects_while_offline(&self, _lane: &str, policy: OfflinePolicy) -> bool {
        // The one lane serves gateways and admins alike. Under "admins only"
        // and "invoicing only" it connects straight, and the node then serves
        // only admins or only gateways (see `Service::role`).
        policy != OfflinePolicy::KillSwitch
    }

    fn revert_proxies(&self, previous: ProxySettings, why: &str) -> EngineResult<()> {
        // Locked proxies are the configuration's; nothing saved may replace them.
        if self.config().proxy_locked {
            return Err(to_engine(refuse(
                code::LOCKED,
                format!("the proxy settings are locked on the host ({LOCK_SETTING})"),
            )));
        }
        self.change_stored(|stored, base| {
            stored.proxies = (previous != base.proxies).then(|| whole(&previous));
        })
        .and_then(|()| self.record("node", "revert_proxies", why))
        .map_err(to_engine)
    }

    fn admit_change(&self, caller: &Caller) -> EngineResult<String> {
        self.admin_actor(caller).map_err(to_engine)
    }

    fn admit_read(&self, caller: &Caller) -> EngineResult<()> {
        self.admin_actor(caller).map(drop).map_err(to_engine)
    }

    fn audit(&self, actor: &str, action: &str, detail: &str) -> EngineResult<()> {
        self.record(actor, action, detail).map_err(to_engine)
    }

    fn proxy_locked(&self) -> bool {
        self.proxies_locked()
    }

    async fn relay_states(&self) -> Vec<RelayState> {
        let pool = lock(&self.net.pool).clone();
        let mut out = match pool {
            Some(p) => pool_states(&p).await,
            None => Vec::new(),
        };
        // Relays with no connection (none yet, or none allowed now): unknown.
        for url in self.net.settings().relays {
            if !out.iter().any(|s| deadhop_netengine::network::same_relay(&s.url, &url)) {
                out.push(RelayState {
                    url,
                    status: "unknown".into(),
                    connected: false,
                    keys: vec![LANE.into()],
                });
            }
        }
        out
    }

    fn store_relay_event(&self, row: &RelayEventRow) -> EngineResult<()> {
        let mut events = lock(&self.net.events);
        if events.len() >= RELAY_EVENTS_KEPT {
            events.pop_front();
        }
        events.push_back(copy(row));
        Ok(())
    }

    fn relay_events_since(&self, since: u64) -> EngineResult<Vec<RelayEventRow>> {
        Ok(lock(&self.net.events)
            .iter()
            .filter(|e| e.at >= since)
            .map(copy)
            .collect())
    }

    fn audit_facts(&self) -> AuditFacts {
        AuditFacts {
            service: "lnaddr-node".into(),
            electrum: None,
            announce: None,
            lock_setting: self.lock_setting().into(),
            test_place: "the console".into(),
        }
    }
}

pub(crate) fn copy(e: &RelayEventRow) -> RelayEventRow {
    RelayEventRow {
        at: e.at,
        relay: e.relay.clone(),
        kind: e.kind.clone(),
        ok: e.ok,
        ms: e.ms,
    }
}

/// A patch that sets every proxy setting to `s`.
pub(crate) fn whole(s: &ProxySettings) -> ProxyPatch {
    ProxyPatch {
        list: ProxyPatch::with_list(&s.list).list,
        groups: Some(s.groups.clone()),
        default: Some(s.default.clone()),
        default_keys: Some(s.default_keys.clone()),
        offline: Some(s.offline),
        transparent: Some(s.transparent),
        rules: Some(s.rules.clone()),
        i2p_registries: Some(s.i2p_registries.clone()),
        ..ProxyPatch::default()
    }
}

/// A change as the audit log records it: proxy passwords hidden.
pub(crate) fn audit_detail(patch: NetworkPatch) -> String {
    let mut shown = NetworkFile {
        relays: patch.relays,
        relay_keys: patch.relay_keys,
        relay_names: patch.relay_names,
        proxies: patch.proxies,
    };
    if let Some(px) = &mut shown.proxies {
        for e in px.list.iter_mut().flatten() {
            e.url = deadhop_net::relay::redact(&e.url);
        }
    }
    serde_json::to_string(&shown).expect("patches always serialise")
}

/// Check the relays an admin sends: one to [`MAX_RELAYS`], each a relay the
/// node can use, none twice.
pub(crate) fn check_relays(relays: &[String]) -> Result<(), Refusal> {
    if relays.is_empty() || relays.len() > MAX_RELAYS {
        return Err(refuse(code::INVALID, format!("relays: 1 to {MAX_RELAYS} are needed")));
    }
    for (i, r) in relays.iter().enumerate() {
        crate::settings::relay(r).map_err(|e| refuse(code::INVALID, e))?;
        if relays[..i].iter().any(|o| deadhop_netengine::network::same_relay(o, r)) {
            return Err(refuse(code::INVALID, format!("relay {r:?} is listed twice")));
        }
    }
    Ok(())
}

impl Service {
    /// The admin calling, by hex public key.
    /// Whether admins may not touch the proxies: locked on the host, or remote
    /// settings off. Then only the listed proxies can be tested and no I2P
    /// name looked up, so no admin key can make the node connect out through a
    /// proxy of its choosing.
    pub fn proxies_locked(&self) -> bool {
        self.config().proxy_locked || !self.config().sources.remote
    }

    /// The host setting that keeps the proxies from admins now.
    fn lock_setting(&self) -> &'static str {
        if self.config().proxy_locked || self.config().sources.remote {
            LOCK_SETTING
        } else {
            REMOTE_OFF
        }
    }

    pub(crate) fn admin_actor(&self, c: &Caller) -> Result<String, Refusal> {
        self.admin(c)?;
        Ok(c.pubkey.clone().unwrap_or_default())
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
        append_audit(&self.config().data_dir.join(AUDIT_FILE), &entry, AUDIT_MAX_BYTES).map_err(|e| {
            tracing::error!(error = %e, "could not write the audit log");
            refuse(code::INTERNAL, "the node could not record the change")
        })
    }

    /// Read `network.json` (when remote settings are on) and run on it.
    /// Called once at start; saved settings that do not fit the
    /// configuration stop the node with the reason.
    pub fn load_network(&self) -> Result<(), String> {
        if !self.config().sources.remote {
            return Ok(());
        }
        let mut stored = read_network(&self.config().data_dir)?;
        if self.config().proxy_locked && stored.proxies.take().is_some() {
            tracing::warn!(
                "{NETWORK_FILE}: the proxies are locked on the host ({LOCK_SETTING}); the saved ones are ignored"
            );
        }
        let next = stored.apply(self.net.baseline());
        if let Some(r) = &stored.relays {
            check_relays(r).map_err(|e| format!("{NETWORK_FILE}: {}", e.message))?;
        }
        Topology {
            settings: next.clone(),
            lanes: lanes(),
        }
        .validate()
        .map_err(|e| format!("{NETWORK_FILE}: {e}"))?;
        *lock(&self.net.stored) = stored;
        self.net.set(next);
        Ok(())
    }

    /// Save `stored` changed by `f` and run on what it makes of the baseline.
    fn change_stored(&self, f: impl FnOnce(&mut NetworkFile, &NetworkSettings)) -> Result<(), Refusal> {
        let mut stored = lock(&self.net.stored);
        let mut next = stored.clone();
        f(&mut next, self.net.baseline());
        self.save(&mut stored, next)
    }

    fn save(&self, stored: &mut NetworkFile, next: NetworkFile) -> Result<(), Refusal> {
        write_network(&self.config().data_dir, &next).map_err(|e| {
            tracing::error!(error = %e, "could not save the network settings");
            refuse(code::INTERNAL, "the node could not save the change")
        })?;
        self.net.set(next.apply(self.net.baseline()));
        *stored = next;
        Ok(())
    }

    /// The node's key, with its relays.
    pub fn key_infos(&self) -> Vec<KeyInfo> {
        vec![KeyInfo {
            id: LANE.into(),
            label: LANE_LABEL.into(),
            pubkey: lock(&self.net.pubkey).clone(),
            tools: vec!["*".into()],
            operators_only: false,
            relays: self.topology().relays_for(LANE),
        }]
    }

    /// Tell the node its own public key, for the network views.
    pub fn set_pubkey(&self, hex: &str) {
        hex.clone_into(&mut lock(&self.net.pubkey));
    }

    fn view(&self) -> NetworkView {
        let hide = |mut s: NetworkSettings| {
            s.proxies = s.proxies.redacted();
            s
        };
        NetworkView {
            settings: hide(self.net.settings()),
            defaults: hide(self.net.baseline().clone()),
            overridden: lock(&self.net.stored).names(),
            chain: crate::node::service::network_name(self.config().network).into(),
            keys: self.key_infos(),
            proxy_locked: self.proxies_locked(),
            restart_pending: self.net.restart_pending.load(Ordering::Relaxed),
            warnings: Vec::new(),
        }
    }

    /// The network settings (admins only).
    pub fn get_network(&self, c: &Caller) -> Result<NetworkView, Refusal> {
        self.admin(c)?;
        Ok(self.view())
    }

    /// Change the network settings (admins only, when remote settings are
    /// on). Saved before they take effect; a new relay list remakes the
    /// connections, and goes back to the previous one if none connects.
    pub fn update_network(&self, c: &Caller, p: UpdateNetworkParams) -> Result<NetworkView, Refusal> {
        let actor = self.admin_actor(c)?;
        if !self.config().sources.remote {
            return Err(refuse(code::LOCKED, "remote settings are switched off on this node"));
        }
        let mut patch = p.patch;
        if self.config().proxy_locked && patch.proxies.is_some() {
            return Err(refuse(
                code::LOCKED,
                format!("the proxy settings are locked on the host ({LOCK_SETTING})"),
            ));
        }
        let mut stored = lock(&self.net.stored);
        let before = self.topology();
        if let Some(px) = &mut patch.proxies {
            px.resolve(&before.proxies.list).map_err(from_engine)?;
        }
        let mut next_file = stored.clone();
        next_file.merge(&patch);
        let next = Topology {
            settings: next_file.apply(self.net.baseline()),
            lanes: lanes(),
        };
        if let Some(r) = &patch.relays {
            check_relays(r)?;
            // The gateways were set up with the configured relays: a list that
            // keeps none of them would cut every gateway off, and nothing would
            // undo it because the new relays do connect.
            let configured = &self.net.baseline().relays;
            if !r
                .iter()
                .any(|x| configured.iter().any(|c| deadhop_netengine::network::same_relay(c, x)))
            {
                return Err(refuse(
                    code::INVALID,
                    format!(
                        "relays: keep at least one of the configured relays ({}), which the gateways use to reach the node",
                        configured.join(", ")
                    ),
                ));
            }
        }
        next.validate().map_err(from_engine)?;
        if let Some(url) = patch
            .relay_names
            .iter()
            .flatten()
            .map(|(u, _)| u)
            .find(|u| !next.relays.iter().any(|r| deadhop_netengine::network::same_relay(r, u)))
        {
            return Err(refuse(
                code::INVALID,
                format!("relay_names: {url:?} is not a listed relay"),
            ));
        }
        let proxies_changed = next.proxies != before.proxies;
        if proxies_changed {
            if let Some(key) = self.net.runtime.stranded(&before, &next) {
                return Err(refuse(
                    code::INVALID,
                    format!(
                        "the {} key's default route would have nothing reachable now, which would cut the node off; point it at a proxy or group that is up, or wait until one is back",
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
            self.net.runtime.begin_probation(self, before.settings.proxies);
        }
        self.record(&actor, "update_network", &detail)?;
        Ok(self.view())
    }

    /// Drop every saved network change and go back to the configuration's
    /// relays and proxy (admins only, when remote settings are on).
    pub fn reset_network(&self, c: &Caller) -> Result<NetworkView, Refusal> {
        let actor = self.admin_actor(c)?;
        if !self.config().sources.remote {
            return Err(refuse(code::LOCKED, "remote settings are switched off on this node"));
        }
        let before = self.net.settings();
        self.change_stored(|stored, _| *stored = NetworkFile::default())?;
        let next = self.net.settings();
        if next.relays != before.relays || next.relay_keys != before.relay_keys {
            self.schedule_restart();
        }
        if next.proxies != before.proxies {
            self.net.runtime.begin_probation(self, before.proxies.clone());
        }
        self.record(&actor, "reset_network", "")?;
        Ok(self.view())
    }

    /// Go back to relays that worked (the node's own act, when new ones
    /// could not connect or saved ones stayed unreachable).
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
        .and_then(|()| self.record("node", "revert_connection", why))
    }

    /// The network part of the node's health (admins only).
    pub async fn health(&self, c: &Caller) -> Result<NodeHealth, Refusal> {
        self.admin(c)?;
        let net = &self.net.runtime;
        Ok(NodeHealth {
            keys: self.key_infos(),
            relays: NetworkHost::relay_states(self).await,
            proxy: deadhop_net::relay::redact(&net.main_proxy(self).unwrap_or_default()),
            proxy_check: lock(&net.last_proxy_check).clone(),
            proxy_pool: net.pool_health(self),
            relay_health: lock(&net.relay_health).clone(),
            restart_pending: self.net.restart_pending.load(Ordering::Relaxed),
        })
    }

    /// What the console reads when an admin signs in (admins only).
    pub fn info(&self, c: &Caller) -> Result<NodeInfo, Refusal> {
        self.admin(c)?;
        let (min, max, expiry) = self.amounts();
        Ok(NodeInfo {
            name: "deadhop lnaddr node".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            network: crate::node::service::network_name(self.config().network).into(),
            public_invoicing: false,
            pow_bits: 0,
            pow_window_secs: 60,
            min_confirmations: 1,
            default_expiry_secs: expiry,
            max_expiry_secs: expiry,
            min_amount_sat: min,
            max_amount_sat: max,
            is_admin: true,
        })
    }

    /// Wait until a change of relays asks for new connections.
    pub fn restart_requested(&self) -> tokio::sync::futures::Notified<'_> {
        self.net.restart.notified()
    }

    /// Whether a change of relays waits for the connections to be remade.
    pub fn restart_pending(&self) -> bool {
        self.net.restart_pending.load(Ordering::Relaxed)
    }

    pub(crate) fn schedule_restart(&self) {
        self.net.restart_pending.store(true, Ordering::Relaxed);
        self.net.restart.notify_one();
    }

    /// Called by the supervisor once the connections were remade.
    pub fn restarted(&self) {
        self.net.restart_pending.store(false, Ordering::Relaxed);
    }

    /// The relay pool of the live connections (`None`: not connected).
    pub fn set_relay_pool(&self, pool: Option<Arc<Pool>>) {
        *lock(&self.net.pool) = pool;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::backend::Kind;
    use crate::node::service::tests::{admin_keys, caller, gateway_keys, test_config};
    use deadhop_netengine::proxypool::Posture;
    use deadhop_netengine::routes::Destination;
    use serde_json::json;

    fn rig(dir: &Path) -> Service {
        Service::new(test_config("http://127.0.0.1:1", Kind::Lnd, dir))
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

    #[test]
    fn the_configured_proxy_becomes_the_default_route_and_old_configs_keep_working() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config("http://127.0.0.1:1", Kind::Lnd, dir.path());
        let direct = baseline(&cfg);
        assert_eq!(direct.relays, cfg.relays);
        assert!(direct.proxies.list.is_empty());
        assert_eq!(direct.proxies.default, Destination::Direct);
        // `socks5` as before: one proxy, everything through it, nothing
        // straight while it is down.
        cfg.socks5 = Some("socks5://127.0.0.1:9050".into());
        let via = baseline(&cfg);
        assert_eq!(via.proxies.list.len(), 1);
        assert_eq!(via.proxies.list[0].url, "socks5://127.0.0.1:9050");
        assert_eq!(via.proxies.default, Destination::Proxy("socks5".into()));
        assert_eq!(via.proxies.offline, OfflinePolicy::KillSwitch);
        assert!(via.proxies.groups.is_empty());
        Topology {
            settings: via,
            lanes: lanes(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn saved_changes_merge_apply_and_name_themselves() {
        let dir = tempfile::tempdir().unwrap();
        let base = baseline(&test_config("http://127.0.0.1:1", Kind::Lnd, dir.path()));
        let mut f = NetworkFile::default();
        assert_eq!(f.apply(&base), base);
        assert!(f.names().is_empty());
        let p: NetworkPatch = serde_json::from_value(json!({
            "relays": ["ws://127.0.0.1:2"],
            "relay_keys": { "ws://127.0.0.1:2": ["node"] },
            "relay_names": { "ws://127.0.0.1:2": "home" },
            "proxies": { "offline": "open" }
        }))
        .unwrap();
        f.merge(&p);
        f.merge(&serde_json::from_value(json!({ "proxies": { "transparent": true } })).unwrap());
        let s = f.apply(&base);
        assert_eq!(s.relays, ["ws://127.0.0.1:2"]);
        assert_eq!(s.relay_names["ws://127.0.0.1:2"], "home");
        assert_eq!(s.relay_keys["ws://127.0.0.1:2"], ["node"]);
        assert_eq!(s.proxies.offline, OfflinePolicy::Open);
        assert!(s.proxies.transparent);
        assert_eq!(
            f.names(),
            [
                "relays",
                "relay_keys",
                "relay_names",
                "proxies.offline",
                "proxies.transparent"
            ]
        );
        // Saved and read back; nothing saved is no change; junk is an error.
        assert_eq!(read_network(dir.path()).unwrap(), NetworkFile::default());
        write_network(dir.path(), &f).unwrap();
        assert_eq!(read_network(dir.path()).unwrap(), f);
        std::fs::write(dir.path().join(NETWORK_FILE), "{\"mode\": 1}").unwrap();
        let e = read_network(dir.path()).unwrap_err();
        assert!(e.contains(NETWORK_FILE), "{e}");
    }

    #[test]
    fn the_audit_log_is_appended_and_kept_small() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_FILE);
        let entry = |i: u64| AuditEntry {
            at: i,
            actor: "a".into(),
            action: "x".into(),
            detail: "d".repeat(50),
        };
        for i in 0..30 {
            append_audit(&path, &entry(i), 1_000).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.len() <= 1_000, "{}", text.len());
        let kept: Vec<AuditEntry> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(kept.last().unwrap().at, 29, "the newest entry is kept");
        assert!(kept.len() < 30 && kept.windows(2).all(|w| w[0].at + 1 == w[1].at));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // A log that cannot be read or written is an error.
        let missing = dir.path().join("missing").join(AUDIT_FILE);
        assert!(append_audit(&missing, &entry(0), 1_000).is_err());
        let a_dir = dir.path().join("a-dir");
        std::fs::create_dir(&a_dir).unwrap();
        assert!(append_audit(&a_dir, &entry(0), 1).is_err());
    }

    #[test]
    fn engine_errors_become_refusals_and_back() {
        let r = from_engine(EngineError::InvalidParams("bad".into()));
        assert_eq!((r.code, r.message.as_str()), (code::INVALID, "bad"));
        assert_eq!(from_engine(EngineError::RateLimited).code, code::RATE_LIMITED);
        let own = refuse(code::LOCKED, "locked");
        assert_eq!(from_engine(to_engine(own.clone())), own);
        let other = from_engine(EngineError::Host(Box::new(std::io::Error::other("boom"))));
        assert_eq!((other.code, other.message.as_str()), (code::INTERNAL, "boom"));
        assert_eq!(String::from(own.clone()), "locked");
        assert_eq!(own.to_string(), "locked");
    }

    #[tokio::test]
    async fn the_node_hosts_its_network_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let svc = rig(dir.path());
        let host: &dyn NetworkHost = &svc;
        assert_eq!(host.topology().lanes, lanes());
        assert!(host.now() > 1_700_000_000);
        assert!(!host.connects_while_offline(LANE, OfflinePolicy::KillSwitch));
        for p in [
            OfflinePolicy::AdminOnly,
            OfflinePolicy::InvoicingOnly,
            OfflinePolicy::Open,
        ] {
            assert!(host.connects_while_offline(LANE, p));
        }
        assert!(!host.proxy_locked());
        let facts = host.audit_facts();
        assert_eq!((facts.electrum, facts.announce), (None, None));
        assert_eq!(facts.lock_setting, LOCK_SETTING);
        let admin = caller(&admin_keys());
        let gw = caller(&gateway_keys());
        assert_eq!(host.admit_change(&admin).unwrap(), admin_keys().public_key().to_hex());
        host.admit_read(&admin).unwrap();
        assert_eq!(
            from_engine(host.admit_change(&gw).unwrap_err()).code,
            code::UNAUTHORIZED
        );
        assert!(host.admit_read(&gw).is_err());
        host.audit("me", "act", "detail").unwrap();
        assert_eq!(audit_lines(dir.path())[0].action, "act");
        // Not connected: every configured relay is shown, unknown.
        let states = host.relay_states().await;
        assert_eq!(states.len(), 1);
        assert_eq!((states[0].status.as_str(), states[0].connected), ("unknown", false));
        // Relay results are kept in memory, the newest ones.
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
        assert_eq!(kept.len(), RELAY_EVENTS_KEPT);
        assert_eq!(kept[0].at, 5);
        assert_eq!(host.relay_events_since(RELAY_EVENTS_KEPT as u64).unwrap().len(), 5);
        // Going back to proxies saves them, unless they are the configured ones.
        let mut previous = host.topology().proxies.clone();
        previous.offline = OfflinePolicy::Open;
        host.revert_proxies(previous.clone(), "test").unwrap();
        assert_eq!(svc.net.settings().proxies, previous);
        assert!(read_network(dir.path()).unwrap().proxies.is_some());
        host.revert_proxies(svc.net.baseline().proxies.clone(), "test").unwrap();
        assert_eq!(read_network(dir.path()).unwrap(), NetworkFile::default());
        assert_eq!(audit_lines(dir.path()).last().unwrap().action, "revert_proxies");
    }

    #[tokio::test]
    async fn admins_read_and_change_the_network_and_every_change_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let svc = rig(dir.path());
        svc.set_pubkey("ab");
        let admin = caller(&admin_keys());
        let gw = caller(&gateway_keys());
        assert_eq!(svc.get_network(&gw).unwrap_err().code, code::UNAUTHORIZED);
        assert_eq!(
            svc.update_network(&gw, patch(json!({}))).unwrap_err().code,
            code::UNAUTHORIZED
        );
        assert_eq!(svc.reset_network(&gw).unwrap_err().code, code::UNAUTHORIZED);
        assert!(svc.health(&gw).await.is_err() && svc.info(&gw).is_err());
        let v = svc.get_network(&admin).unwrap();
        assert_eq!(v.keys[0].pubkey, "ab");
        assert_eq!((v.keys[0].id.as_str(), v.chain.as_str()), (LANE, "regtest"));
        assert!(v.overridden.is_empty() && !v.restart_pending && !v.proxy_locked);

        // A proxy (its password hidden everywhere but network.json) and a new relay.
        let v = svc
            .update_network(
                &admin,
                patch(json!({
                    "relays": ["ws://127.0.0.1:1", "ws://127.0.0.1:2"],
                    "relay_names": { "ws://127.0.0.1:2": "home" },
                    "proxies": { "list": [{ "url": "socks5://u:secret@127.0.0.1:9050" }], "offline": "open" }
                })),
            )
            .unwrap();
        assert!(v.restart_pending);
        assert_eq!(v.settings.proxies.list[0].url, "socks5://u:***@127.0.0.1:9050");
        assert_eq!(
            v.overridden,
            ["relays", "relay_names", "proxies.list", "proxies.offline"]
        );
        let saved = std::fs::read_to_string(dir.path().join(NETWORK_FILE)).unwrap();
        assert!(saved.contains("secret"));
        let last = audit_lines(dir.path()).pop().unwrap();
        assert_eq!(last.action, "update_network");
        assert_eq!(last.actor, admin_keys().public_key().to_hex());
        assert!(
            last.detail.contains("u:***@") && !last.detail.contains("secret"),
            "{}",
            last.detail
        );
        // The hidden password is kept when the list is sent back as shown.
        let id = v.settings.proxies.list[0].id.clone();
        svc.update_network(
            &admin,
            patch(json!({ "proxies": { "list": [{ "id": id, "url": "socks5://u:***@127.0.0.1:9050" }] } })),
        )
        .unwrap();
        assert!(svc.net.settings().proxies.list[0].url.contains("secret"));
        svc.restarted();

        // Mistakes are named and change nothing.
        let bad = |v: serde_json::Value, want: &str| {
            let r = svc.update_network(&admin, patch(v)).unwrap_err();
            assert!(r.message.contains(want), "{want}: {}", r.message);
        };
        bad(json!({ "relays": [] }), "1 to 8");
        bad(json!({ "relays": ["ws://relay.example.com"] }), "wss://");
        bad(
            json!({ "relays": ["ws://127.0.0.1:2", "ws://127.0.0.1:2/"] }),
            "listed twice",
        );
        bad(
            json!({ "relay_keys": { "ws://127.0.0.1:2": ["admin"] } }),
            "no key 'admin'",
        );
        bad(
            json!({ "relay_names": { "ws://127.0.0.1:3": "x" } }),
            "not a listed relay",
        );
        bad(
            json!({ "proxies": { "list": [{ "url": "socks5://u:***@10.0.0.1:1" }] } }),
            "password is hidden",
        );
        bad(
            json!({ "relays": ["ws://127.0.0.1:2"] }),
            "keep at least one of the configured relays",
        );
        assert_eq!(svc.net.settings().relays, ["ws://127.0.0.1:1", "ws://127.0.0.1:2"]);

        let h = svc.health(&admin).await.unwrap();
        assert_eq!(h.keys.len(), 1);
        assert_eq!(h.proxy_pool.offline, OfflinePolicy::Open);
        let i = svc.info(&admin).unwrap();
        assert!(i.is_admin && !i.public_invoicing);
        assert_eq!(
            (i.min_amount_sat, i.max_amount_sat, i.default_expiry_secs),
            (1, 1_000_000, 600)
        );

        // Reset: back to the configuration, recorded.
        let v = svc.reset_network(&admin).unwrap();
        assert!(v.overridden.is_empty() && v.restart_pending);
        assert_eq!(v.settings, v.defaults);
        assert_eq!(audit_lines(dir.path()).pop().unwrap().action, "reset_network");
        // A reset with nothing to undo changes nothing.
        svc.restarted();
        assert!(!svc.reset_network(&admin).unwrap().restart_pending);
    }

    #[tokio::test]
    async fn the_host_can_lock_remote_network_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config("http://127.0.0.1:1", Kind::Lnd, dir.path());
        cfg.proxy_locked = true;
        let svc = Service::new(cfg.clone());
        let admin = caller(&admin_keys());
        let r = svc
            .update_network(&admin, patch(json!({ "proxies": { "offline": "open" } })))
            .unwrap_err();
        assert_eq!(r.code, code::LOCKED);
        assert!(r.message.contains(LOCK_SETTING));
        // Relays stay changeable while the proxies are locked.
        svc.update_network(&admin, patch(json!({ "relay_names": { "ws://127.0.0.1:1": "x" } })))
            .unwrap();
        // With remote settings off, nothing changes and nothing is read.
        cfg.sources = crate::settings::Sources::default();
        let off = Service::new(cfg);
        let r = off.update_network(&admin, patch(json!({}))).unwrap_err();
        assert_eq!(r.code, code::LOCKED);
        assert_eq!(off.reset_network(&admin).unwrap_err().code, code::LOCKED);
        off.load_network().unwrap();
        assert!(off.net.settings().relay_names.is_empty());
        assert!(off.get_network(&admin).is_ok());
    }

    #[tokio::test]
    async fn saved_network_settings_are_loaded_and_checked_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let svc = rig(dir.path());
        svc.load_network().unwrap();
        let saved = NetworkFile {
            relay_names: Some([("ws://127.0.0.1:1".to_string(), "one".to_string())].into()),
            ..Default::default()
        };
        write_network(dir.path(), &saved).unwrap();
        let svc = rig(dir.path());
        svc.load_network().unwrap();
        assert_eq!(svc.net.settings().relay_names["ws://127.0.0.1:1"], "one");
        assert_eq!(
            svc.get_network(&caller(&admin_keys())).unwrap().overridden,
            ["relay_names"]
        );
        for (bad, want) in [
            (json!({ "relays": [] }), "1 to 8"),
            (json!({ "relay_keys": { "ws://127.0.0.1:1": ["x"] } }), "no key 'x'"),
        ] {
            let f: NetworkFile = serde_json::from_value(bad).unwrap();
            write_network(dir.path(), &f).unwrap();
            let e = rig(dir.path()).load_network().unwrap_err();
            assert!(e.contains(NETWORK_FILE) && e.contains(want), "{e}");
        }
        std::fs::write(dir.path().join(NETWORK_FILE), "junk").unwrap();
        assert!(rig(dir.path()).load_network().is_err());
    }

    #[tokio::test]
    async fn changes_that_cannot_be_saved_or_recorded_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let svc = rig(dir.path());
        let admin = caller(&admin_keys());
        // network.json cannot be written (its temporary file is a directory).
        std::fs::create_dir(dir.path().join("network.tmp")).unwrap();
        let r = svc
            .update_network(&admin, patch(json!({ "relay_names": { "ws://127.0.0.1:1": "x" } })))
            .unwrap_err();
        assert_eq!(r.code, code::INTERNAL);
        assert!(svc.net.settings().relay_names.is_empty(), "nothing changed");
        std::fs::remove_dir(dir.path().join("network.tmp")).unwrap();
        // The audit log cannot be written.
        std::fs::create_dir(dir.path().join(AUDIT_FILE)).unwrap();
        let r = svc.reset_network(&admin).unwrap_err();
        assert_eq!(r.code, code::INTERNAL);
        assert!(r.message.contains("record"));
    }

    #[tokio::test]
    async fn without_a_proxy_the_offline_policy_decides_who_is_served() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config("http://127.0.0.1:1", Kind::Lnd, dir.path());
        cfg.socks5 = Some("socks5://127.0.0.1:1".into());
        let svc = Service::new(cfg.clone());
        let admin = caller(&admin_keys());
        let gw = caller(&gateway_keys());
        svc.net.runtime.refresh_pool(&svc).await;
        assert_eq!(svc.net.runtime.posture(&svc), Posture::Off);
        assert!(svc.list_addresses(&gw).is_ok() && svc.status(&admin).is_ok());
        // The proxy is down either way, so moving the policy strands nothing.
        svc.update_network(&admin, patch(json!({ "proxies": { "offline": "admin_only" } })))
            .unwrap();
        assert_eq!(svc.net.runtime.posture(&svc), Posture::AdminOnly);
        assert_eq!(svc.list_addresses(&gw).unwrap_err().code, code::UNAVAILABLE);
        assert!(svc.status(&admin).is_ok());
        svc.update_network(&admin, patch(json!({ "proxies": { "offline": "invoicing_only" } })))
            .unwrap();
        assert_eq!(svc.status(&admin).unwrap_err().code, code::UNAUTHORIZED);
        assert!(svc.list_addresses(&gw).is_ok());
        // A key listed as both acts as a gateway meanwhile.
        cfg.gateways.push(admin_keys().public_key());
        cfg.proxy_locked = false;
        let both = Service::new(cfg);
        write_network(
            dir.path(),
            &serde_json::from_value(json!({ "proxies": { "offline": "invoicing_only" } })).unwrap(),
        )
        .unwrap();
        both.load_network().unwrap();
        both.net.runtime.refresh_pool(&both).await;
        assert!(both.list_addresses(&admin).is_ok());
        assert_eq!(both.status(&admin).unwrap_err().code, code::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_default_route_to_a_proxy_that_is_down_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let svc = rig(dir.path());
        let admin = caller(&admin_keys());
        svc.update_network(
            &admin,
            patch(json!({ "proxies": { "list": [
                { "id": "up", "url": "socks5://127.0.0.1:2" },
                { "id": "down", "url": "socks5://127.0.0.1:1" }
            ] } })),
        )
        .unwrap();
        let probe = |status: &str| ProxyCheck {
            proxy: String::new(),
            status: status.into(),
            checked_at: 1,
            relays: Vec::new(),
        };
        svc.net.runtime.record_probe("down", probe("failed"));
        svc.net.runtime.record_probe("up", probe("connected"));
        let r = svc
            .update_network(&admin, patch(json!({ "proxies": { "default": { "proxy": "down" } } })))
            .unwrap_err();
        assert!(r.message.contains("node key's default route"), "{}", r.message);
        svc.update_network(&admin, patch(json!({ "proxies": { "default": { "proxy": "up" } } })))
            .unwrap();
    }

    #[tokio::test]
    async fn with_remote_settings_off_no_admin_can_pick_a_proxy_to_connect_through() {
        use deadhop_netengine::netruntime::{CheckProxyParams, ResolveI2pNameParams};
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config("http://127.0.0.1:1", Kind::Lnd, dir.path());
        cfg.sources = crate::settings::Sources::default();
        cfg.socks5 = Some("socks5://127.0.0.1:1".into());
        let svc = Service::new(cfg);
        let admin = caller(&admin_keys());
        assert!(svc.proxies_locked());
        assert!(svc.get_network(&admin).unwrap().proxy_locked);
        let net = &svc.net.runtime;
        let raw = CheckProxyParams {
            proxy: Some("socks5://10.9.9.9:1080".into()),
            id: None,
        };
        let r = from_engine(net.check_proxy(&svc, &admin, raw).await.unwrap_err());
        assert!(
            r.message.contains(REMOTE_OFF) && r.message.contains("only the listed"),
            "{}",
            r.message
        );
        let name = ResolveI2pNameParams {
            name: "example.i2p".into(),
        };
        let r = from_engine(net.resolve_i2p_name(&svc, &admin, name).await.unwrap_err());
        assert!(r.message.contains(REMOTE_OFF), "{}", r.message);
        // The configured proxy can still be tested.
        let listed = CheckProxyParams {
            proxy: None,
            id: Some("socks5".into()),
        };
        assert_eq!(net.check_proxy(&svc, &admin, listed).await.unwrap().status, "failed");
        assert_eq!(NetworkHost::audit_facts(&svc).lock_setting, REMOTE_OFF);
    }

    #[tokio::test]
    async fn a_change_that_cannot_be_recorded_is_still_checked() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config("http://127.0.0.1:1", Kind::Lnd, dir.path());
        cfg.socks5 = Some("socks5://127.0.0.1:1".into());
        let svc = Service::new(cfg);
        let admin = caller(&admin_keys());
        std::fs::create_dir(dir.path().join(AUDIT_FILE)).unwrap();
        let r = svc
            .update_network(
                &admin,
                patch(json!({
                    "relays": ["ws://127.0.0.1:1", "ws://127.0.0.1:2"],
                    "proxies": { "list": [{ "id": "other", "url": "socks5://127.0.0.1:2" }], "default": { "proxy": "other" } }
                })),
            )
            .unwrap_err();
        assert_eq!(r.code, code::INTERNAL);
        // Applied, so the ways back are armed: new relays are checked, new proxies on probation.
        assert_eq!(svc.net.settings().relays.len(), 2);
        assert!(svc.restart_pending());
        assert!(svc.net.runtime.pool.lock().unwrap().probation.is_some());
        svc.restarted();
        assert_eq!(svc.reset_network(&admin).unwrap_err().code, code::INTERNAL);
        assert_eq!(svc.net.settings(), *svc.net.baseline());
        assert!(svc.restart_pending());
    }

    #[test]
    fn audit_entries_written_at_once_are_all_kept_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_FILE);
        let threads: Vec<_> = (0..8u64)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..40 {
                        let e = AuditEntry {
                            at: t * 100 + i,
                            actor: "a".into(),
                            action: "x".into(),
                            detail: "d".repeat(40),
                        };
                        append_audit(&path, &e, 2_000).unwrap();
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.len() <= 2_000);
        for l in text.lines() {
            serde_json::from_str::<AuditEntry>(l).unwrap();
        }
    }

    #[tokio::test]
    async fn locked_proxies_are_the_configurations_even_when_saved_ones_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config("http://127.0.0.1:1", Kind::Lnd, dir.path());
        cfg.proxy_locked = true;
        let saved: NetworkFile = serde_json::from_value(json!({
            "relay_names": { "ws://127.0.0.1:1": "one" },
            "proxies": { "offline": "open" }
        }))
        .unwrap();
        write_network(dir.path(), &saved).unwrap();
        let svc = Service::new(cfg);
        svc.load_network().unwrap();
        assert_eq!(svc.net.settings().relay_names["ws://127.0.0.1:1"], "one");
        assert_eq!(svc.net.settings().proxies, svc.net.baseline().proxies);
        // Nor can a probation put other proxies back.
        let mut other = svc.net.baseline().proxies.clone();
        other.offline = OfflinePolicy::Open;
        let host: &dyn NetworkHost = &svc;
        assert_eq!(
            from_engine(host.revert_proxies(other, "test").unwrap_err()).code,
            code::LOCKED
        );
        assert_eq!(svc.net.settings().proxies, svc.net.baseline().proxies);
    }
}
