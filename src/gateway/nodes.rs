//! The gateway's view of its nodes: a ContextVM client per node, a cache of
//! the addresses each serves, and the invoice path.
//!
//! Performance: the first LNURL request (the address's parameters) is
//! answered from the cache, so only the callback crosses Nostr. The cache is
//! refreshed in the background and kept, stale, while a node is unreachable.
//!
//! Failure handling: a call that times out is retried once while the
//! deadline allows (calls are stateless, so a retry is a fresh request); a
//! client whose relay connection died is rebuilt; and an invoice is only
//! handed out after it is checked against the amount, the metadata hash,
//! the network and, when pinned, the Lightning node that must sign it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Keys, ToBech32};
use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;
use serde_json::{json, Value};

use crate::bolt11::{self, Expect, Network};
use crate::cvm::{CallError, NodeClient};
use crate::gateway::config::NodeConfig;
use crate::gateway::network::{Conn, Network as Net, GATEWAY_LANE};
use crate::lnurl;
use crate::proto::{self, code, AddressInfo, AddressList, MadeInvoice};

/// A refused or failed request, as the public HTTP side reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    NotFound,
    Invalid(String),
    RateLimited,
    Unavailable,
    BadInvoice,
}

impl Fail {
    pub fn status(&self) -> u16 {
        match self {
            Fail::NotFound => 404,
            Fail::Invalid(_) => 400,
            Fail::RateLimited => 429,
            Fail::Unavailable => 503,
            Fail::BadInvoice => 502,
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Fail::NotFound => "no such Lightning address".into(),
            Fail::Invalid(r) => r.clone(),
            Fail::RateLimited => "too many requests; try again in a minute".into(),
            Fail::Unavailable => "the Lightning node is not reachable right now; try again shortly".into(),
            Fail::BadInvoice => "the Lightning node returned an invoice that does not match the request".into(),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the gateway knows about one node right now.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
pub struct Health {
    pub npub: String,
    pub reachable: bool,
    pub last_ok: Option<u64>,
    pub last_error: Option<String>,
    pub latency_ms: Option<u64>,
    pub addresses: usize,
    pub cache_age_secs: Option<u64>,
    pub payee: Option<String>,
    pub relays_connected: usize,
}

struct Snapshot {
    list: AddressList,
    at: Instant,
}

/// A live client and the relay pool it runs on.
type Client = (Arc<NodeClient>, Arc<Conn>);

pub struct NodeLink {
    pub cfg: NodeConfig,
    keys: Keys,
    /// The lane (key) it calls with, and the network that routes it.
    lane: &'static str,
    net: Arc<Net>,
    timeout: Duration,
    client: tokio::sync::Mutex<Option<Client>>,
    cache: RwLock<Option<Snapshot>>,
    last_refresh_try: Mutex<Option<Instant>>,
    health: Mutex<Health>,
}

impl NodeLink {
    pub fn new(cfg: NodeConfig, keys: Keys, lane: &'static str, net: Arc<Net>, timeout: Duration) -> Self {
        let health = Health {
            npub: cfg.pubkey.to_bech32().expect("keys encode"),
            ..Default::default()
        };
        NodeLink {
            cfg,
            keys,
            lane,
            net,
            timeout,
            client: tokio::sync::Mutex::new(None),
            cache: RwLock::new(None),
            last_refresh_try: Mutex::new(None),
            health: Mutex::new(health),
        }
    }

    /// The client, made on the lane's routes now if there is none or the
    /// network moved the one there was off its relays.
    async fn client(&self) -> Result<Arc<NodeClient>, CallError> {
        let mut slot = self.client.lock().await;
        if let Some((c, conn)) = slot.as_ref() {
            if !conn.stale() {
                return Ok(c.clone());
            }
            close_client(slot.take()).await;
        }
        let (c, conn) = self
            .net
            .connect_node(self.lane, self.keys.clone(), &self.cfg, self.timeout)
            .await
            .map_err(CallError::Closed)?;
        let c = Arc::new(c);
        *slot = Some((c.clone(), conn));
        Ok(c)
    }

    /// Call a tool, rebuilding the client once if its connection is gone.
    pub async fn call<T: serde::de::DeserializeOwned>(&self, tool: &'static str, args: Value) -> Result<T, CallError> {
        self.call_value(tool, args).await.and_then(crate::cvm::decode)
    }

    async fn call_value(&self, tool: &'static str, args: Value) -> Result<Value, CallError> {
        let started = Instant::now();
        let mut outcome = self.client().await?.call_value(tool, args.clone()).await;
        if matches!(outcome, Err(CallError::Closed(_))) {
            close_client(self.client.lock().await.take()).await;
            outcome = self.client().await?.call_value(tool, args).await;
        }
        let mut h = lock(&self.health);
        match &outcome {
            Ok(_) | Err(CallError::Refused { .. }) => {
                h.reachable = true;
                h.last_ok = Some(crate::unix_now());
                h.latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            Err(e) => {
                h.reachable = false;
                h.last_error = Some(e.to_string());
            }
        }
        outcome
    }

    /// Fetch the node's address list into the cache.
    pub async fn refresh(&self) -> Result<(), CallError> {
        *lock(&self.last_refresh_try) = Some(Instant::now());
        let list: AddressList = self.call(proto::LIST_ADDRESSES, json!({})).await?;
        *write(&self.cache) = Some(Snapshot {
            list,
            at: Instant::now(),
        });
        Ok(())
    }

    /// Refresh unless one was tried within `min_gap`: a burst of requests for
    /// unknown names must not turn into a burst of node calls.
    async fn refresh_if_due(&self, min_gap: Duration) {
        let due = lock(&self.last_refresh_try).is_none_or(|t| t.elapsed() >= min_gap);
        if due {
            let _ = self.refresh().await;
        }
    }

    /// The address `name`, if this node serves it under `domain`.
    fn lookup(&self, name: &str, domain: &str) -> Option<(AddressInfo, Option<Network>)> {
        if let Some(names) = &self.cfg.names {
            if !names.iter().any(|n| n == name) {
                return None;
            }
        }
        let cache = read(&self.cache);
        let snap = cache.as_ref()?;
        let a = snap
            .list
            .addresses
            .iter()
            .find(|a| a.name == name && a.serves(domain))?;
        Some((a.clone(), snap.list.network.parse().ok()))
    }

    pub async fn health(&self) -> Health {
        let mut h = lock(&self.health).clone();
        if let Some(s) = read(&self.cache).as_ref() {
            h.addresses = s.list.addresses.len();
            h.cache_age_secs = Some(s.at.elapsed().as_secs());
            h.payee = s.list.payee.clone();
        }
        let client = self.client.lock().await.clone();
        if let Some((c, _)) = client {
            h.relays_connected = c.relays_connected().await;
        }
        h
    }

    pub fn addresses(&self) -> Vec<AddressInfo> {
        read(&self.cache)
            .as_ref()
            .map(|s| s.list.addresses.clone())
            .unwrap_or_default()
    }

    pub async fn close(&self) {
        close_client(self.client.lock().await.take()).await;
    }
}

/// Close a client. Only the last holder closes it; a call still in flight
/// keeps it alive.
async fn close_client(client: Option<Client>) {
    if let Some(c) = client.and_then(|(c, _)| Arc::try_unwrap(c).ok()) {
        c.close().await;
    }
}

/// Counters and recent latencies, for the status page and the CLI.
#[derive(Default)]
pub struct Metrics {
    pub metadata: AtomicU64,
    pub invoices: AtomicU64,
    pub failures: AtomicU64,
    pub retries: AtomicU64,
    latencies: Mutex<VecDeque<u64>>,
    recent: Mutex<VecDeque<(u64, String)>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsView {
    pub metadata: u64,
    pub invoices: u64,
    pub failures: u64,
    pub retries: u64,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub recent_failures: Vec<(u64, String)>,
}

impl Metrics {
    fn latency(&self, ms: u64) {
        let mut l = lock(&self.latencies);
        if l.len() == 200 {
            l.pop_front();
        }
        l.push_back(ms);
    }

    fn failed(&self, what: String) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let mut r = lock(&self.recent);
        if r.len() == 20 {
            r.pop_front();
        }
        r.push_back((crate::unix_now(), what));
    }

    pub fn view(&self) -> MetricsView {
        let mut l: Vec<u64> = lock(&self.latencies).iter().copied().collect();
        l.sort_unstable();
        let pick = |q: f64| (!l.is_empty()).then(|| l[((l.len() - 1) as f64 * q).round() as usize]);
        MetricsView {
            metadata: self.metadata.load(Ordering::Relaxed),
            invoices: self.invoices.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            p50_ms: pick(0.5),
            p95_ms: pick(0.95),
            recent_failures: lock(&self.recent).iter().rev().cloned().collect(),
        }
    }
}

pub struct Directory {
    pub nodes: Vec<NodeLink>,
    pub metrics: Metrics,
    timeout: Duration,
}

/// Shortest time between two refreshes caused by a miss.
const MISS_REFRESH_GAP: Duration = Duration::from_secs(10);

impl Directory {
    /// The nodes, called with `keys` on the gateway lane of `net`.
    pub fn new(nodes: Vec<NodeConfig>, keys: Keys, net: Arc<Net>, timeout: Duration) -> Self {
        // Each call gets a share of the request's deadline so a retry still fits.
        let per_call = timeout.mul_f64(0.45);
        Directory {
            nodes: nodes
                .into_iter()
                .map(|n| NodeLink::new(n, keys.clone(), GATEWAY_LANE, net.clone(), per_call))
                .collect(),
            metrics: Metrics::default(),
            timeout,
        }
    }

    /// The bitcoin network the nodes report (the first one heard from).
    pub fn chain(&self) -> Option<String> {
        self.nodes
            .iter()
            .find_map(|n| read(&n.cache).as_ref().map(|s| s.list.network.clone()))
    }

    /// The smallest and largest amounts the nodes' addresses take, in
    /// satoshis (0 to 0 before any node was heard from).
    pub fn amounts(&self) -> (u64, u64) {
        let all: Vec<AddressInfo> = self.nodes.iter().flat_map(NodeLink::addresses).collect();
        let min = all.iter().map(|a| a.min_sendable.div_ceil(1000)).min();
        let max = all.iter().map(|a| a.max_sendable / 1000).max();
        (min.unwrap_or(0), max.unwrap_or(0))
    }

    /// How every node answered lately.
    pub async fn healths(&self) -> Vec<Health> {
        let mut out = Vec::new();
        for n in &self.nodes {
            out.push(n.health().await);
        }
        out
    }

    pub async fn refresh_all(&self) {
        futures_join_all(self.nodes.iter().map(|n| async move {
            if let Err(e) = n.refresh().await {
                tracing::warn!(node = %n.cfg.pubkey, error = %e, "could not refresh addresses");
            }
        }))
        .await;
    }

    fn find_cached(&self, name: &str, domain: &str) -> Option<(usize, AddressInfo, Option<Network>)> {
        self.nodes
            .iter()
            .enumerate()
            .find_map(|(i, n)| n.lookup(name, domain).map(|(a, net)| (i, a, net)))
    }

    /// The address `name@domain`, refreshing (rate-limited) on a miss.
    pub async fn find(&self, name: &str, domain: &str) -> Result<(usize, AddressInfo, Option<Network>), Fail> {
        if let Some(hit) = self.find_cached(name, domain) {
            return Ok(hit);
        }
        futures_join_all(self.nodes.iter().map(|n| n.refresh_if_due(MISS_REFRESH_GAP))).await;
        // A node never heard from might serve the name: say so, rather than "no such address".
        let unknown = if self.nodes.iter().any(|n| read(&n.cache).is_none()) {
            Fail::Unavailable
        } else {
            Fail::NotFound
        };
        self.find_cached(name, domain).ok_or(unknown)
    }

    /// The LUD-06 parameters of `name@domain`.
    pub async fn pay_params(&self, name: &str, domain: &str) -> Result<AddressInfo, Fail> {
        let (_, a, _) = self.find(name, domain).await?;
        self.metrics.metadata.fetch_add(1, Ordering::Relaxed);
        Ok(a)
    }

    /// An invoice for `amount_msat` to `name@domain`, checked before it is returned.
    pub async fn invoice(
        &self,
        name: &str,
        domain: &str,
        amount_msat: u64,
        comment: Option<String>,
    ) -> Result<String, Fail> {
        let outcome = self.invoice_inner(name, domain, amount_msat, comment).await;
        match &outcome {
            Ok(_) => {
                self.metrics.invoices.fetch_add(1, Ordering::Relaxed);
            }
            Err(f) => self.metrics.failed(format!("{name}@{domain}: {}", f.reason())),
        }
        outcome
    }

    async fn invoice_inner(
        &self,
        name: &str,
        domain: &str,
        amount_msat: u64,
        comment: Option<String>,
    ) -> Result<String, Fail> {
        let started = Instant::now();
        let (i, addr, network) = self.find(name, domain).await?;
        if amount_msat < addr.min_sendable || amount_msat > addr.max_sendable {
            return Err(Fail::Invalid(format!(
                "amount must be {} to {} msat",
                addr.min_sendable, addr.max_sendable
            )));
        }
        if let Some(c) = &comment {
            if !lnurl::comment_fits(c, addr.comment_allowed) {
                return Err(Fail::Invalid(format!(
                    "comments are at most {} characters",
                    addr.comment_allowed
                )));
            }
        }
        let node = &self.nodes[i];
        let args = json!(proto::MakeInvoiceParams {
            name: name.into(),
            domain: domain.into(),
            amount_msat,
            comment
        });
        let mut made: Result<MadeInvoice, CallError> = node.call(proto::MAKE_INVOICE, args.clone()).await;
        if made == Err(CallError::Timeout) && started.elapsed() < self.timeout / 2 {
            self.metrics.retries.fetch_add(1, Ordering::Relaxed);
            made = node.call(proto::MAKE_INVOICE, args).await;
        }
        let made = made.map_err(|e| match e {
            CallError::Refused { code, message } => match code.as_str() {
                code::INVALID => Fail::Invalid(message),
                code::NOT_FOUND => Fail::NotFound,
                code::RATE_LIMITED | code::BUSY => Fail::RateLimited,
                _ => Fail::Unavailable,
            },
            _ => Fail::Unavailable,
        })?;
        let mut description = addr.description.clone();
        let mut checked = self.check(node, &made.pr, name, domain, &description, amount_msat, network);
        if checked.is_err() {
            // The description may have just changed on the node: refresh once and recheck.
            let _ = node.refresh().await;
            description = node
                .lookup(name, domain)
                .map_or(description, |(fresh, _)| fresh.description);
            checked = self.check(node, &made.pr, name, domain, &description, amount_msat, network);
        }
        if let Err(e) = checked {
            tracing::error!(%name, %domain, error = %e, "refused an invoice from the node");
            return Err(Fail::BadInvoice);
        }
        self.metrics.latency(started.elapsed().as_millis() as u64);
        Ok(made.pr)
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        node: &NodeLink,
        pr: &str,
        name: &str,
        domain: &str,
        description: &str,
        amount_msat: u64,
        network: Option<Network>,
    ) -> Result<(), String> {
        let want = Expect {
            amount_msat,
            description_hash: lnurl::description_hash(&lnurl::metadata(name, domain, description)),
            network,
            payee: node.cfg.payee.as_deref(),
            now: crate::unix_now(),
            min_expiry: Duration::from_secs(30),
        };
        bolt11::check(pr, &want).map(|_| ())
    }

    pub async fn close(&self) {
        for n in &self.nodes {
            n.close().await;
        }
    }
}

/// Run futures concurrently and wait for all of them.
pub async fn futures_join_all<F: std::future::Future<Output = ()>>(fs: impl Iterator<Item = F>) {
    futures_util::future::join_all(fs).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_keep_bounded_history() {
        let m = Metrics::default();
        assert_eq!(m.view().p50_ms, None);
        for ms in 0..250 {
            m.latency(ms);
        }
        for i in 0..25 {
            m.failed(format!("f{i}"));
        }
        let v = m.view();
        assert_eq!((v.p50_ms, v.p95_ms), (Some(150), Some(239)));
        assert_eq!(v.recent_failures.len(), 20);
        assert_eq!(v.recent_failures[0].1, "f24");
        assert_eq!(v.failures, 25);
    }

    #[tokio::test]
    async fn a_link_without_a_client_reports_no_relays() {
        let cfg = NodeConfig {
            pubkey: Keys::generate().public_key(),
            names: None,
            relays: vec!["ws://127.0.0.1:9".into()],
            payee: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let net = Arc::new(Net::new(crate::gateway::tests::gateway_config_for(
            vec![cfg.clone()],
            dir.path(),
        )));
        let link = NodeLink::new(cfg, Keys::generate(), GATEWAY_LANE, net, Duration::from_secs(1));
        let h = link.health().await;
        assert_eq!((h.relays_connected, h.reachable, h.addresses), (0, false, 0));
        assert!(link.addresses().is_empty());
        link.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_whose_connection_died_is_rebuilt() {
        let s = crate::gateway::tests::stack().await;
        let link = &s.gw().dir.nodes[0];
        let client = link.client().await.unwrap();
        client.service_token().cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(client);
        let list: AddressList = link.call(proto::LIST_ADDRESSES, json!({})).await.unwrap();
        assert_eq!(list.addresses.len(), 2);
        s.stop().await;
    }

    #[test]
    fn poisoned_locks_are_survived() {
        let m = Arc::new(Mutex::new(1));
        let rw = Arc::new(RwLock::new(2));
        let (m2, rw2) = (m.clone(), rw.clone());
        let _ = std::thread::spawn(move || {
            let _a = m2.lock().unwrap();
            let _b = rw2.write().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(*lock(&m), 1);
        assert_eq!(*read(&rw), 2);
        assert_eq!(*write(&rw), 2);
    }
}
