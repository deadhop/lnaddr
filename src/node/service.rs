//! What the node does for each request. The gateway is not trusted here:
//! every bound (amount, comment, domain, rate, concurrency) is the node's
//! own, and every invoice the backend returns is checked before it leaves.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{PublicKey, ToBech32};
use tokio::sync::Semaphore;

use crate::bolt11::{self, Expect, Network};
use crate::lnurl;
use crate::node::backend::{Backend, Request};
use crate::node::config::{self, Address, Config, Limits, Remote};
use crate::node::invoices::{Ledger, Record};
use crate::node::network::NodeNet;
use crate::proto::{
    self, code, AddressInfo, AddressList, ConfigView, InvoiceList, InvoiceView, ListInvoicesParams,
    LookupInvoiceParams, MadeInvoice, MakeInvoiceParams, Status, Verified, VerifyInvoiceParams,
};
use crate::ratelimit::RateLimiter;
use deadhop_netengine::proxypool::Posture;

/// How far a request's timestamp may be from the node's clock.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// The backend is asked about one invoice at most this often: a payer's
/// wallet polling LUD-21 must not turn into a stream of backend calls.
pub const CHECK_GAP_SECS: u64 = 2;
/// Backend lookups at once while listing.
const LOOKUPS_AT_ONCE: usize = 8;
/// Invoices per page of `list_invoices`.
const DEFAULT_PAGE: u32 = 100;
const MAX_PAGE: u32 = 1000;

/// A refusal with a stable code and a message safe to send to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

/// A refusal as the text the command line and the supervisor report.
impl From<Refusal> for String {
    fn from(r: Refusal) -> String {
        r.message
    }
}

pub(crate) fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

// Who is asking: the shared ContextVM crate's caller.
pub use deadhop_cvm::caller::Caller;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Gateway,
    Admin,
}

/// One change to the settings an admin may make.
type Change<'a> = Box<dyn FnOnce(&mut Mutable) -> Result<(), Refusal> + 'a>;

struct Mutable {
    addresses: BTreeMap<String, Address>,
    limits: Limits,
    limiter: std::sync::Arc<RateLimiter>,
}

pub struct Service {
    cfg: Config,
    /// Relays, proxies and their state (see [`crate::node::network`]).
    pub net: NodeNet,
    backend: Backend,
    state: RwLock<Mutable>,
    permits: Semaphore,
    made: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
    payee: Mutex<Option<String>>,
    /// The invoices made here, and when the backend was last asked about each.
    ledger: Mutex<Ledger>,
    checked: Mutex<std::collections::HashMap<String, u64>>,
    started: Instant,
    now: fn() -> u64,
}

/// `<seconds>:<payment hash>`, as `list_invoices` gives it.
fn parse_cursor(c: &str) -> Option<(u64, String)> {
    let (t, h) = c.split_once(':')?;
    proto::valid_payment_hash(h).then_some(())?;
    Some((t.parse().ok()?, h.to_string()))
}

pub(crate) fn network_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

fn npub(k: &PublicKey) -> String {
    k.to_bech32().expect("a public key always encodes as bech32")
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Service {
    pub fn new(cfg: Config) -> Self {
        Self::with_clock(cfg, crate::unix_now)
    }

    pub fn with_clock(cfg: Config, now: fn() -> u64) -> Self {
        let b = &cfg.backend;
        let backend = Backend::new(b.kind, &b.url, b.secret.clone(), b.pin.clone(), b.timeout);
        let limiter = std::sync::Arc::new(RateLimiter::new(
            cfg.limits.invoices_per_minute,
            cfg.limits.per_caller_per_minute,
        ));
        Service {
            net: NodeNet::new(&cfg),
            state: RwLock::new(Mutable {
                addresses: cfg.addresses.clone(),
                limits: cfg.limits.clone(),
                limiter,
            }),
            permits: Semaphore::new(cfg.limits.concurrent as usize),
            backend,
            ledger: Mutex::new(Ledger::open(&cfg.data_dir, now())),
            checked: Mutex::new(std::collections::HashMap::new()),
            cfg,
            made: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            last_error: Mutex::new(None),
            payee: Mutex::new(None),
            started: Instant::now(),
            now,
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Seconds since the Unix epoch, by the node's clock.
    pub fn clock(&self) -> u64 {
        (self.now)()
    }

    /// The smallest and largest amounts the addresses take (in satoshis,
    /// 0 to 0 with none), and how long an invoice stays payable.
    pub(crate) fn amounts(&self) -> (u64, u64, u64) {
        let s = self.read();
        let min = s.addresses.values().map(|a| a.min_sendable.div_ceil(1000)).min();
        let max = s.addresses.values().map(|a| a.max_sendable / 1000).max();
        (
            min.unwrap_or(0),
            max.unwrap_or(0),
            u64::from(s.limits.invoice_expiry_secs),
        )
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Mutable> {
        self.state.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Mutable> {
        self.state.write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Who the caller is, and whether its request is fresh. While no proxy
    /// is reachable, the offline policy decides who is served: under
    /// "admins only" no gateway is, under "invoicing only" no admin is (a key
    /// listed as both then acts as a gateway).
    pub(crate) fn role(&self, c: &Caller) -> Result<Role, Refusal> {
        let key = c.pubkey.as_deref().and_then(|k| PublicKey::from_hex(k).ok());
        let posture = self.net.runtime.posture(self);
        let role = match key {
            Some(k) if self.cfg.admins.contains(&k) && posture != Posture::InvoicingOnly => Role::Admin,
            Some(k) if self.cfg.gateways.contains(&k) => {
                if posture == Posture::AdminOnly {
                    return Err(refuse(code::UNAVAILABLE, "the node is not serving invoices now"));
                }
                Role::Gateway
            }
            _ => return Err(refuse(code::UNAUTHORIZED, "this key may not use this node")),
        };
        // The signed event is what proves the request is fresh: without it
        // there is nothing to check, so the request is refused.
        let e = c
            .event
            .as_ref()
            .ok_or_else(|| refuse(code::UNAUTHORIZED, "request event missing"))?;
        if e.created_at.as_secs().abs_diff((self.now)()) > MAX_CLOCK_SKEW_SECS {
            return Err(refuse(
                code::UNAUTHORIZED,
                "the request's timestamp is too far from the node's clock",
            ));
        }
        Ok(role)
    }

    pub(crate) fn admin(&self, c: &Caller) -> Result<(), Refusal> {
        match self.role(c)? {
            Role::Admin => Ok(()),
            Role::Gateway => Err(refuse(code::UNAUTHORIZED, "admins only")),
        }
    }

    pub fn list_addresses(&self, c: &Caller) -> Result<AddressList, Refusal> {
        self.role(c)?;
        let addresses = self
            .read()
            .addresses
            .iter()
            .map(|(n, a)| AddressInfo::new(n, a))
            .collect();
        Ok(AddressList {
            addresses,
            payee: lock(&self.payee).clone(),
            network: network_name(self.cfg.network).into(),
            verifies: true,
        })
    }

    pub async fn make_invoice(&self, c: &Caller, p: MakeInvoiceParams) -> Result<MadeInvoice, Refusal> {
        self.role(c)?;
        self.invoice(c.pubkey.as_deref().unwrap_or_default(), p).await
    }

    /// Make an invoice for an already authorized request, rate-limited under
    /// `limit_key`. `lnaddr-node check` calls this directly: it runs locally
    /// and has no signed request to authorize.
    pub(crate) async fn invoice(&self, limit_key: &str, p: MakeInvoiceParams) -> Result<MadeInvoice, Refusal> {
        let (address, limits, limiter) = {
            let s = self.read();
            (s.addresses.get(&p.name).cloned(), s.limits.clone(), s.limiter.clone())
        };
        let address = address.ok_or_else(|| refuse(code::NOT_FOUND, format!("no address {:?} here", p.name)))?;
        if !lnurl::valid_domain(&p.domain) || !(address.domains.is_empty() || address.domains.contains(&p.domain)) {
            return Err(refuse(
                code::NOT_FOUND,
                format!("{} is not served under {}", p.name, p.domain),
            ));
        }
        if p.amount_msat < address.min_sendable || p.amount_msat > address.max_sendable {
            return Err(refuse(
                code::INVALID,
                format!(
                    "amount must be {} to {} msat",
                    address.min_sendable, address.max_sendable
                ),
            ));
        }
        if self.backend.kind().whole_sats() && !p.amount_msat.is_multiple_of(1000) {
            return Err(refuse(code::INVALID, "amount must be whole satoshis"));
        }
        let comment = p.comment.as_deref().unwrap_or("");
        if !lnurl::comment_fits(comment, address.comment_allowed) {
            return Err(refuse(
                code::INVALID,
                format!("comments are at most {} characters", address.comment_allowed),
            ));
        }
        if !limiter.allow(limit_key, (self.now)()) {
            return Err(refuse(code::RATE_LIMITED, "too many invoices; try again in a minute"));
        }
        // Waiting longer than half the backend's timeout leaves too little for the backend.
        let _permit = tokio::time::timeout(self.cfg.backend.timeout / 2, self.permits.acquire())
            .await
            .map_err(|_| refuse(code::BUSY, "the node is busy; try again"))?
            .expect("the semaphore is never closed");
        let metadata = lnurl::metadata(&p.name, &p.domain, &address.description);
        let label = format!(
            "lnaddr-{}-{}",
            p.name,
            hex::encode(nostr_sdk::Keys::generate().public_key().to_bytes())[..16].to_owned()
        );
        let req = Request {
            amount_msat: p.amount_msat,
            metadata: &metadata,
            expiry_secs: limits.invoice_expiry_secs,
            label: &label,
        };
        let pr = match self.backend.create_invoice(&req).await {
            Ok(pr) => pr,
            Err(e) => return Err(self.failure(e)),
        };
        let want = Expect {
            amount_msat: p.amount_msat,
            description_hash: lnurl::description_hash(&metadata),
            network: Some(self.cfg.network),
            payee: None,
            now: (self.now)(),
            min_expiry: Duration::from_secs(30),
        };
        let checked =
            bolt11::check(&pr, &want).map_err(|e| self.failure(format!("the backend's invoice was refused: {e}")))?;
        *lock(&self.payee) = Some(checked.payee);
        self.made.fetch_add(1, Ordering::Relaxed);
        tracing::info!(name = %p.name, msat = p.amount_msat, comment = ?comment, "invoice made");
        let now = (self.now)();
        let record = Record {
            payment_hash: checked.payment_hash.clone(),
            name: p.name,
            domain: p.domain,
            amount_msat: p.amount_msat,
            comment: (!comment.is_empty()).then(|| comment.to_string()),
            pr: pr.clone(),
            created_at: now,
            expires_at: checked.expires_at,
            settled_at: None,
            preimage: None,
        };
        if let Err(e) = lock(&self.ledger).add(record, now) {
            tracing::warn!(error = %e, "the invoice was made but not recorded");
        }
        Ok(MadeInvoice {
            pr,
            payment_hash: checked.payment_hash,
        })
    }

    /// The invoice made here with this hash, after asking the backend
    /// whether it was paid (unless it was, or it is long expired, or the
    /// backend was asked a moment ago).
    async fn refreshed(&self, payment_hash: &str) -> Result<Record, Refusal> {
        if !proto::valid_payment_hash(payment_hash) {
            return Err(refuse(code::INVALID, "payment_hash must be 64 lower-case hex digits"));
        }
        let now = (self.now)();
        let r = lock(&self.ledger)
            .get(payment_hash)
            .cloned()
            .ok_or_else(|| refuse(code::NOT_FOUND, "no invoice with that payment hash was made here"))?;
        if !r.open(now) || !self.due(payment_hash, now) {
            return Ok(r);
        }
        let paid = match self.backend.lookup_invoice(payment_hash).await {
            Ok(Some(paid)) => paid,
            Ok(None) => return Ok(r),
            Err(e) => return Err(self.lookup_failure(e)),
        };
        let matches = hex::decode(&paid.preimage).is_ok_and(|p| hex::encode(lnurl::sha256(&p)) == payment_hash);
        if !matches {
            return Err(self.lookup_failure("the backend's preimage does not match the payment hash".into()));
        }
        let at = paid.at.unwrap_or(now);
        if let Err(e) = lock(&self.ledger).settle(payment_hash, at, &paid.preimage) {
            tracing::warn!(error = %e, "the payment was seen but not recorded");
        }
        tracing::info!(name = %r.name, msat = r.amount_msat, "invoice paid");
        Ok(Record {
            settled_at: Some(at),
            preimage: Some(paid.preimage),
            ..r
        })
    }

    /// Whether the backend may be asked about this invoice now; if so, the
    /// time is taken, so callers at the same moment ask only once.
    fn due(&self, payment_hash: &str, now: u64) -> bool {
        let mut checked = lock(&self.checked);
        if checked.get(payment_hash).is_some_and(|t| now < t + CHECK_GAP_SECS) {
            return false;
        }
        checked.retain(|_, t| now < *t + 60);
        checked.insert(payment_hash.to_string(), now);
        true
    }

    fn lookup_failure(&self, detail: String) -> Refusal {
        tracing::warn!(error = %detail, "invoice lookup failed");
        *lock(&self.last_error) = Some(detail);
        refuse(
            code::BACKEND,
            "the Lightning node did not say whether the invoice was paid",
        )
    }

    fn invoice_view(r: &Record, now: u64) -> InvoiceView {
        InvoiceView {
            payment_hash: r.payment_hash.clone(),
            name: r.name.clone(),
            domain: r.domain.clone(),
            amount_msat: r.amount_msat,
            comment: r.comment.clone(),
            pr: r.pr.clone(),
            state: r.state(now).into(),
            created_at: r.created_at,
            expires_at: r.expires_at,
            settled_at: r.settled_at,
            preimage: r.preimage.clone(),
        }
    }

    /// Admins only: the invoices made here, oldest first, a page at a time.
    /// Invoices that may still be paid are checked with the backend first.
    pub async fn list_invoices(&self, c: &Caller, p: ListInvoicesParams) -> Result<InvoiceList, Refusal> {
        use futures_util::StreamExt;
        self.admin(c)?;
        let status = p.status.as_deref().unwrap_or("settled");
        if !matches!(status, "settled" | "pending" | "expired" | "all") {
            return Err(refuse(code::INVALID, "status must be settled, pending, expired or all"));
        }
        let after = match p.cursor.as_deref() {
            None => None,
            Some(c) => Some(parse_cursor(c).ok_or_else(|| refuse(code::INVALID, "cursor is not one this node gave"))?),
        };
        let limit = p.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize;
        let now = (self.now)();
        let (open, record_error): (Vec<String>, Option<String>) = {
            let l = lock(&self.ledger);
            let open = l
                .records()
                .filter(|r| r.open(now))
                .map(|r| r.payment_hash.clone())
                .collect();
            (open, l.broken().map(str::to_string))
        };
        // A lookup that fails leaves the invoice as it was recorded.
        let fresh: Vec<Record> = futures_util::stream::iter(open)
            .map(|h| async move { self.refreshed(&h).await })
            .buffer_unordered(LOOKUPS_AT_ONCE)
            .filter_map(|r| async move { r.ok() })
            .collect()
            .await;
        let mut all: Vec<Record> = {
            let l = lock(&self.ledger);
            let fresh: std::collections::HashMap<&str, &Record> =
                fresh.iter().map(|r| (r.payment_hash.as_str(), r)).collect();
            l.records()
                .map(|r| (*fresh.get(r.payment_hash.as_str()).unwrap_or(&r)).clone())
                .collect()
        };
        let key = |r: &Record| {
            (
                if status == "settled" {
                    r.settled_at.unwrap_or(0)
                } else {
                    r.created_at
                },
                r.payment_hash.clone(),
            )
        };
        all.retain(|r| {
            let k = key(r);
            (status == "all" || r.state(now) == status)
                && p.since.is_none_or(|s| k.0 >= s)
                && after.as_ref().is_none_or(|a| &k > a)
        });
        all.sort_by_key(key);
        let more = all.len() > limit;
        all.truncate(limit);
        let next_cursor = more.then(|| {
            let (t, h) = key(all.last().expect("a page that has more is not empty"));
            format!("{t}:{h}")
        });
        Ok(InvoiceList {
            invoices: all.iter().map(|r| Self::invoice_view(r, now)).collect(),
            next_cursor,
            record_error,
        })
    }

    /// Admins only: one invoice made here, checked with the backend.
    pub async fn lookup_invoice(&self, c: &Caller, p: LookupInvoiceParams) -> Result<InvoiceView, Refusal> {
        self.admin(c)?;
        let r = self.refreshed(&p.payment_hash).await?;
        Ok(Self::invoice_view(&r, (self.now)()))
    }

    /// LUD-21 for gateways: whether an invoice made here for `name` was
    /// paid. Only what the payer already knows, or learns by paying.
    pub async fn verify_invoice(&self, c: &Caller, p: VerifyInvoiceParams) -> Result<Verified, Refusal> {
        self.role(c)?;
        let r = self.refreshed(&p.payment_hash).await?;
        if r.name != p.name {
            return Err(refuse(
                code::NOT_FOUND,
                "no invoice with that payment hash was made here",
            ));
        }
        Ok(Verified {
            settled: r.settled_at.is_some(),
            preimage: r.preimage.filter(|_| r.settled_at.is_some()),
            pr: r.pr,
        })
    }

    /// Record a backend failure; the caller learns only that it failed.
    fn failure(&self, detail: String) -> Refusal {
        tracing::warn!(error = %detail, "invoice failed");
        self.failed.fetch_add(1, Ordering::Relaxed);
        *lock(&self.last_error) = Some(detail);
        refuse(code::BACKEND, "the Lightning node did not make an invoice")
    }

    /// The last backend failure, for this host's own diagnostics.
    pub fn last_error(&self) -> Option<String> {
        lock(&self.last_error).clone()
    }

    pub fn status(&self, c: &Caller) -> Result<Status, Refusal> {
        self.admin(c)?;
        Ok(Status {
            version: env!("CARGO_PKG_VERSION").into(),
            backend: self.backend.kind().name().into(),
            network: network_name(self.cfg.network).into(),
            addresses: self.read().addresses.len(),
            remote_settings: self.cfg.sources.remote,
            invoices_made: self.made.load(Ordering::Relaxed),
            invoices_failed: self.failed.load(Ordering::Relaxed),
            last_error: lock(&self.last_error).clone(),
            uptime_secs: self.started.elapsed().as_secs(),
            payee: lock(&self.payee).clone(),
        })
    }

    pub fn config_view(&self, c: &Caller) -> Result<ConfigView, Refusal> {
        self.admin(c)?;
        let s = self.read();
        let b = &self.cfg.backend;
        Ok(ConfigView {
            relays: self.cfg.relays.clone(),
            gateways: self.cfg.gateways.iter().map(npub).collect(),
            admins: self.cfg.admins.iter().map(npub).collect(),
            network: network_name(self.cfg.network).into(),
            backend: proto::BackendView {
                kind: b.kind.name().into(),
                url: b.url.clone(),
                secret: crate::settings::redact(true).into(),
                tls_pin: b.pin.as_deref().map(crate::tls::pins_text),
            },
            limits: proto::LimitsView {
                invoices_per_minute: s.limits.invoices_per_minute,
                per_caller_per_minute: s.limits.per_caller_per_minute,
                concurrent: s.limits.concurrent,
                invoice_expiry_secs: s.limits.invoice_expiry_secs,
            },
            addresses: s.addresses.iter().map(|(n, a)| AddressInfo::new(n, a)).collect(),
            sources: proto::SourcesView {
                file: self.cfg.sources.file,
                env: self.cfg.sources.env,
                remote: self.cfg.sources.remote,
            },
        })
    }

    /// Change settings over ContextVM: admins only, and only when remote
    /// settings are switched on. The change is saved before it takes effect.
    fn change(&self, c: &Caller, f: Change<'_>) -> Result<ConfigView, Refusal> {
        self.admin(c)?;
        if !self.cfg.sources.remote {
            return Err(refuse(code::LOCKED, "remote settings are switched off on this node"));
        }
        {
            let mut s = self.write();
            let mut next = Mutable {
                addresses: s.addresses.clone(),
                limits: s.limits.clone(),
                limiter: s.limiter.clone(),
            };
            f(&mut next)?;
            next.limits.validate().map_err(|e| refuse(code::INVALID, e))?;
            let saved = Remote {
                addresses: Some(next.addresses.clone()),
                limits: Some(config::LimitsLayer {
                    invoices_per_minute: Some(next.limits.invoices_per_minute),
                    per_caller_per_minute: Some(next.limits.per_caller_per_minute),
                    concurrent: None,
                    invoice_expiry_secs: Some(next.limits.invoice_expiry_secs),
                }),
            };
            config::write_remote(&self.cfg.data_dir, &saved).map_err(|e| {
                tracing::error!(error = %e, "could not save remote settings");
                refuse(code::INTERNAL, "the node could not save the change")
            })?;
            if next.limits != s.limits {
                next.limiter = std::sync::Arc::new(RateLimiter::new(
                    next.limits.invoices_per_minute,
                    next.limits.per_caller_per_minute,
                ));
            }
            *s = next;
        }
        tracing::info!(
            by = c.pubkey.as_deref().unwrap_or_default(),
            "settings changed over ContextVM"
        );
        self.config_view(c)
    }

    pub fn set_address(&self, c: &Caller, p: proto::SetAddressParams) -> Result<ConfigView, Refusal> {
        let kind = self.backend.kind();
        self.change(
            c,
            Box::new(|s| {
                let a = p.address();
                a.validate(&p.name, kind).map_err(|e| refuse(code::INVALID, e))?;
                s.addresses.insert(p.name.clone(), a);
                Ok(())
            }),
        )
    }

    pub fn remove_address(&self, c: &Caller, p: proto::RemoveAddressParams) -> Result<ConfigView, Refusal> {
        self.change(
            c,
            Box::new(|s| match s.addresses.remove(&p.name) {
                Some(_) => Ok(()),
                None => Err(refuse(code::NOT_FOUND, format!("no address {:?} here", p.name))),
            }),
        )
    }

    pub fn set_limits(&self, c: &Caller, p: proto::SetLimitsParams) -> Result<ConfigView, Refusal> {
        self.change(
            c,
            Box::new(|s| {
                let l = p.layer();
                s.limits.invoices_per_minute = l.invoices_per_minute.unwrap_or(s.limits.invoices_per_minute);
                s.limits.per_caller_per_minute = l.per_caller_per_minute.unwrap_or(s.limits.per_caller_per_minute);
                s.limits.invoice_expiry_secs = l.invoice_expiry_secs.unwrap_or(s.limits.invoice_expiry_secs);
                Ok(())
            }),
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::node::backend::testutil::{serve, Fake, SECRET};
    use crate::node::backend::Kind;
    use crate::node::config::{BackendConfig, Limits};
    use crate::settings::{Sources, SourcesLayer};
    use nostr_sdk::prelude::{EventBuilder, Keys, Timestamp};
    use std::sync::Arc;

    pub fn gateway_keys() -> Keys {
        Keys::parse(&"11".repeat(32)).unwrap()
    }
    pub fn admin_keys() -> Keys {
        Keys::parse(&"22".repeat(32)).unwrap()
    }

    pub fn test_config(url: &str, kind: Kind, data_dir: &std::path::Path) -> Config {
        let mut addresses = BTreeMap::new();
        addresses.insert(
            "alice".to_string(),
            Address {
                comment_allowed: 10,
                ..Address::default_for("alice")
            },
        );
        addresses.insert(
            "bob".to_string(),
            Address {
                domains: vec!["bob.example".into()],
                ..Address::default_for("bob")
            },
        );
        let mut sources = Sources::default();
        sources.apply(&SourcesLayer {
            remote: Some(true),
            ..Default::default()
        });
        Config {
            data_dir: data_dir.to_path_buf(),
            relays: vec!["ws://127.0.0.1:1".into()],
            gateways: vec![gateway_keys().public_key()],
            admins: vec![admin_keys().public_key()],
            socks5: None,
            proxy_locked: false,
            network: Network::Regtest,
            backend: BackendConfig {
                kind,
                url: url.into(),
                secret: SECRET.into(),
                pin: None,
                timeout: Duration::from_secs(5),
            },
            limits: Limits::default(),
            addresses,
            sources,
        }
    }

    pub fn caller(keys: &Keys) -> Caller {
        let event = EventBuilder::text_note("req").sign_with_keys(keys).unwrap();
        Caller {
            pubkey: Some(keys.public_key().to_hex()),
            event: Some(event),
        }
    }

    fn params(name: &str, msat: u64) -> MakeInvoiceParams {
        MakeInvoiceParams {
            name: name.into(),
            domain: "pay.example".into(),
            amount_msat: msat,
            comment: None,
        }
    }

    async fn rig(kind: Kind) -> (Service, Arc<Fake>, tempfile::TempDir) {
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        (Service::new(test_config(&url, kind, dir.path())), fake, dir)
    }

    #[tokio::test]
    async fn a_gateway_gets_a_checked_invoice() {
        let (svc, _fake, _dir) = rig(Kind::Lnd).await;
        let gw = caller(&gateway_keys());
        let list = svc.list_addresses(&gw).unwrap();
        assert_eq!(list.addresses.len(), 2);
        assert_eq!(list.network, "regtest");
        assert_eq!(list.payee, None);
        let mut p = params("alice", 21_500);
        p.comment = Some("thanks".into());
        let made = svc.make_invoice(&gw, p).await.unwrap();
        let want = Expect {
            amount_msat: 21_500,
            description_hash: lnurl::description_hash(&lnurl::metadata("alice", "pay.example", "Pay alice")),
            network: Some(Network::Regtest),
            payee: None,
            now: crate::unix_now(),
            min_expiry: Duration::from_secs(60),
        };
        assert_eq!(bolt11::check(&made.pr, &want).unwrap().payment_hash, made.payment_hash);
        assert_eq!(
            svc.list_addresses(&gw).unwrap().payee,
            Some(crate::bolt11::testutil::node_pubkey())
        );
        assert_eq!(svc.config().backend.kind, Kind::Lnd);
    }

    fn list(
        status: Option<&str>,
        since: Option<u64>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> ListInvoicesParams {
        ListInvoicesParams {
            status: status.map(str::to_string),
            since,
            cursor,
            limit,
        }
    }

    fn verify(name: &str, hash: &str) -> VerifyInvoiceParams {
        VerifyInvoiceParams {
            name: name.into(),
            payment_hash: hash.into(),
        }
    }

    #[tokio::test]
    async fn invoices_are_recorded_with_their_comment_and_payments_are_seen() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        NOW.store(crate::unix_now(), Ordering::SeqCst);
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&url, Kind::Lnd, dir.path());
        let svc = Service::with_clock(cfg.clone(), || NOW.load(Ordering::SeqCst));
        let (gw, admin) = (caller(&gateway_keys()), caller(&admin_keys()));
        assert!(svc.list_addresses(&gw).unwrap().verifies);
        let mut hashes = Vec::new();
        for (i, comment) in [Some("order 42"), None, Some("")].into_iter().enumerate() {
            let mut p = params("alice", 1_000 * (i as u64 + 1));
            p.comment = comment.map(str::to_string);
            hashes.push(svc.make_invoice(&gw, p).await.unwrap().payment_hash);
        }
        let (paid, other, third) = (&hashes[0], &hashes[1], &hashes[2]);

        // Unpaid: pending, no preimage.
        let v = svc.verify_invoice(&gw, verify("alice", paid)).await.unwrap();
        assert!(!v.settled && v.preimage.is_none() && v.pr.starts_with("lnbcrt"));
        let all = svc
            .list_invoices(&admin, list(Some("pending"), None, None, None))
            .await
            .unwrap();
        assert_eq!(all.invoices.len(), 3);
        assert!(all.next_cursor.is_none() && all.record_error.is_none());
        assert!(svc
            .list_invoices(&admin, list(None, None, None, None))
            .await
            .unwrap()
            .invoices
            .is_empty());

        // Paid: the backend was asked a moment ago, so it is asked again only after the gap.
        fake.pay(paid);
        let calls = fake.calls.load(Ordering::SeqCst);
        assert!(!svc.verify_invoice(&gw, verify("alice", paid)).await.unwrap().settled);
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls, "not asked again so soon");
        NOW.fetch_add(CHECK_GAP_SECS, Ordering::SeqCst);
        let v = svc.verify_invoice(&gw, verify("alice", paid)).await.unwrap();
        assert!(v.settled && v.preimage.is_some());
        // Settled is final: the backend is not asked any more.
        let calls = fake.calls.load(Ordering::SeqCst);
        NOW.fetch_add(CHECK_GAP_SECS, Ordering::SeqCst);
        assert!(svc.verify_invoice(&gw, verify("alice", paid)).await.unwrap().settled);
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls);

        let one = svc
            .lookup_invoice(
                &admin,
                LookupInvoiceParams {
                    payment_hash: paid.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(one.comment.as_deref(), Some("order 42"));
        assert_eq!(
            (one.state.as_str(), one.name.as_str(), one.amount_msat),
            ("settled", "alice", 1_000)
        );
        assert_eq!(one.settled_at, Some(1_700_000_000));
        assert!(one.expires_at > one.created_at);
        let settled = svc.list_invoices(&admin, list(None, None, None, None)).await.unwrap();
        assert_eq!(settled.invoices, vec![one.clone()]);
        assert!(svc
            .list_invoices(&admin, list(None, Some(1_700_000_001), None, None))
            .await
            .unwrap()
            .invoices
            .is_empty());

        // Paged, oldest first, with no comment where none (or an empty one) was sent.
        fake.pay(other);
        fake.pay(third);
        NOW.fetch_add(CHECK_GAP_SECS, Ordering::SeqCst);
        let page = svc
            .list_invoices(&admin, list(Some("all"), None, None, Some(2)))
            .await
            .unwrap();
        assert_eq!(page.invoices.len(), 2);
        let next = svc
            .list_invoices(&admin, list(Some("all"), None, page.next_cursor.clone(), Some(2)))
            .await
            .unwrap();
        assert_eq!(next.invoices.len(), 1);
        assert!(next.next_cursor.is_none());
        let mut seen: Vec<String> = page
            .invoices
            .iter()
            .chain(&next.invoices)
            .map(|i| i.payment_hash.clone())
            .collect();
        seen.sort();
        let mut want = hashes.clone();
        want.sort();
        assert_eq!(seen, want);
        assert!(page.invoices.iter().chain(&next.invoices).all(|i| i.state == "settled"));
        assert!(page
            .invoices
            .iter()
            .chain(&next.invoices)
            .filter(|i| i.payment_hash != *paid)
            .all(|i| i.comment.is_none()));

        // Kept across a restart.
        let again = Service::with_clock(cfg, || NOW.load(Ordering::SeqCst));
        let v = again.verify_invoice(&gw, verify("alice", paid)).await.unwrap();
        assert!(v.settled);
        svc.make_invoice(&gw, params("alice", 5_000)).await.unwrap();
        // The test backend's invoices last an hour.
        let later = NOW.fetch_add(3601, Ordering::SeqCst) + 3601;
        let event = EventBuilder::text_note("req")
            .custom_created_at(Timestamp::from(later))
            .sign_with_keys(&admin_keys())
            .unwrap();
        let admin = Caller {
            event: Some(event),
            ..admin
        };
        let expired = svc
            .list_invoices(&admin, list(Some("expired"), None, None, None))
            .await
            .unwrap();
        assert_eq!(expired.invoices.len(), 1);
    }

    #[tokio::test]
    async fn only_invoices_made_here_are_answered_and_only_admins_see_them_all() {
        let (svc, fake, _dir) = rig(Kind::Lnd).await;
        let (gw, admin) = (caller(&gateway_keys()), caller(&admin_keys()));
        let hash = svc
            .make_invoice(&gw, params("alice", 1_000))
            .await
            .unwrap()
            .payment_hash;
        let code_of = |r: Result<Verified, Refusal>| r.unwrap_err().code;
        // Not made here: the backend is never asked.
        let calls = fake.calls.load(Ordering::SeqCst);
        assert_eq!(
            code_of(svc.verify_invoice(&gw, verify("alice", &"00".repeat(32))).await),
            code::NOT_FOUND
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls);
        assert_eq!(
            code_of(svc.verify_invoice(&gw, verify("bob", &hash)).await),
            code::NOT_FOUND
        );
        assert_eq!(
            code_of(svc.verify_invoice(&gw, verify("alice", "nope")).await),
            code::INVALID
        );
        assert_eq!(
            code_of(
                svc.verify_invoice(&caller(&Keys::generate()), verify("alice", &hash))
                    .await
            ),
            code::UNAUTHORIZED
        );
        assert_eq!(
            svc.list_invoices(&gw, list(None, None, None, None))
                .await
                .unwrap_err()
                .code,
            code::UNAUTHORIZED
        );
        assert_eq!(
            svc.lookup_invoice(
                &gw,
                LookupInvoiceParams {
                    payment_hash: hash.clone()
                }
            )
            .await
            .unwrap_err()
            .code,
            code::UNAUTHORIZED
        );
        for bad in [
            list(Some("paid"), None, None, None),
            list(None, None, Some("x".into()), None),
            list(None, None, Some(format!("1:{}", "Z".repeat(64))), None),
            list(None, None, Some(format!("t:{hash}")), None),
        ] {
            assert_eq!(svc.list_invoices(&admin, bad).await.unwrap_err().code, code::INVALID);
        }
    }

    #[tokio::test]
    async fn a_backend_that_cannot_say_or_lies_is_not_believed() {
        let (svc, fake, _dir) = rig(Kind::Lnd).await;
        let (gw, admin) = (caller(&gateway_keys()), caller(&admin_keys()));
        let hash = svc
            .make_invoice(&gw, params("alice", 1_000))
            .await
            .unwrap()
            .payment_hash;
        fake.pay(&hash);
        *fake.wrong_preimage.lock().unwrap() = Some("11".repeat(32));
        let e = svc.verify_invoice(&gw, verify("alice", &hash)).await.unwrap_err();
        assert_eq!(e.code, code::BACKEND);
        assert!(svc.last_error().unwrap().contains("does not match"));
        *fake.wrong_preimage.lock().unwrap() = None;
        *fake.fail.lock().unwrap() = Some((500, "down".into()));
        tokio::time::sleep(Duration::from_secs(CHECK_GAP_SECS)).await;
        assert_eq!(
            svc.verify_invoice(&gw, verify("alice", &hash)).await.unwrap_err().code,
            code::BACKEND
        );
        // A listing leaves an invoice the backend could not say about as it was.
        tokio::time::sleep(Duration::from_secs(CHECK_GAP_SECS)).await;
        let all = svc
            .list_invoices(&admin, list(Some("all"), None, None, None))
            .await
            .unwrap();
        assert_eq!(all.invoices[0].state, "pending");
    }

    #[tokio::test]
    async fn invoices_are_still_made_when_they_cannot_be_recorded() {
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(crate::node::invoices::FILE);
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        let svc = Service::new(test_config(&url, Kind::Lnd, dir.path()));
        let (gw, admin) = (caller(&gateway_keys()), caller(&admin_keys()));
        assert!(svc.make_invoice(&gw, params("alice", 1_000)).await.is_ok());
        let l = svc
            .list_invoices(&admin, list(Some("all"), None, None, None))
            .await
            .unwrap();
        assert!(l.invoices.is_empty() && l.record_error.unwrap().contains("readable by other users"));
        // A payment seen then cannot be recorded either, and is still reported.
        let mut r = crate::node::invoices::Record {
            payment_hash: "ab".repeat(32),
            name: "alice".into(),
            domain: "pay.example".into(),
            amount_msat: 1,
            comment: None,
            pr: "lnbcrt1".into(),
            created_at: crate::unix_now(),
            expires_at: crate::unix_now() + 600,
            settled_at: None,
            preimage: None,
        };
        // One in memory as if it had been read, and paid on the backend.
        let pr = backend_invoice(&url).await;
        r.payment_hash = crate::bolt11::payment_hash(&pr).unwrap();
        r.pr = pr;
        fake.pay(&r.payment_hash);
        lock(&svc.ledger).insert(r.clone());
        let v = svc.verify_invoice(&gw, verify("alice", &r.payment_hash)).await.unwrap();
        assert!(v.settled);
    }

    async fn backend_invoice(url: &str) -> String {
        let b = Backend::new(Kind::Lnd, url, SECRET.into(), None, Duration::from_secs(5));
        b.create_invoice(&Request {
            amount_msat: 1_000,
            metadata: "[]",
            expiry_secs: 600,
            label: "l",
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_node_keeps_its_own_bounds() {
        let (svc, _fake, _dir) = rig(Kind::Phoenixd).await;
        let gw = caller(&gateway_keys());
        let e = |r: Result<MadeInvoice, Refusal>| r.unwrap_err();
        assert_eq!(
            e(svc.make_invoice(&gw, params("nobody", 1000)).await).code,
            code::NOT_FOUND
        );
        assert_eq!(
            e(svc.make_invoice(&gw, params("bob", 1000)).await).code,
            code::NOT_FOUND
        );
        let mut bad_domain = params("alice", 1000);
        bad_domain.domain = "Bad Domain".into();
        assert_eq!(e(svc.make_invoice(&gw, bad_domain).await).code, code::NOT_FOUND);
        assert!(e(svc.make_invoice(&gw, params("alice", 999)).await)
            .message
            .contains("1000 to"));
        assert_eq!(
            e(svc.make_invoice(&gw, params("alice", 2_000_000_000)).await).code,
            code::INVALID
        );
        assert!(e(svc.make_invoice(&gw, params("alice", 1500)).await)
            .message
            .contains("whole satoshis"));
        let mut long = params("alice", 1000);
        long.comment = Some("x".repeat(11));
        assert!(e(svc.make_invoice(&gw, long).await).message.contains("at most 10"));
        let mut bob = params("bob", 1000);
        bob.domain = "bob.example".into();
        assert!(svc.make_invoice(&gw, bob).await.is_ok());
    }

    #[tokio::test]
    async fn strangers_stale_requests_and_gateways_acting_as_admins_are_refused() {
        let (svc, _fake, _dir) = rig(Kind::Lnd).await;
        let stranger = caller(&Keys::generate());
        assert_eq!(svc.list_addresses(&stranger).unwrap_err().code, code::UNAUTHORIZED);
        assert_eq!(
            svc.list_addresses(&Caller::default()).unwrap_err().code,
            code::UNAUTHORIZED
        );
        let bad_hex = Caller {
            pubkey: Some("zz".into()),
            event: None,
        };
        assert_eq!(svc.list_addresses(&bad_hex).unwrap_err().code, code::UNAUTHORIZED);
        let keys = gateway_keys();
        let old = EventBuilder::text_note("old")
            .custom_created_at(Timestamp::from(1_000))
            .sign_with_keys(&keys)
            .unwrap();
        let stale = Caller {
            pubkey: Some(keys.public_key().to_hex()),
            event: Some(old),
        };
        assert!(svc.list_addresses(&stale).unwrap_err().message.contains("timestamp"));
        let gw = caller(&gateway_keys());
        assert!(svc.status(&gw).unwrap_err().message.contains("admins only"));
        assert!(svc.config_view(&gw).is_err());
        let p = proto::RemoveAddressParams { name: "alice".into() };
        assert!(svc.remove_address(&gw, p).is_err());
        // A known key without its signed event is refused: freshness cannot
        // be checked without it.
        let bare = Caller {
            pubkey: Some(admin_keys().public_key().to_hex()),
            event: None,
        };
        let r = svc.status(&bare).unwrap_err();
        assert_eq!(r.code, code::UNAUTHORIZED);
        assert!(r.message.contains("request event missing"), "{}", r.message);
    }

    #[tokio::test]
    async fn backend_trouble_is_counted_and_kept_from_the_gateway() {
        let (svc, fake, _dir) = rig(Kind::Lnd).await;
        let gw = caller(&gateway_keys());
        let admin = caller(&admin_keys());
        *fake.fail.lock().unwrap() = Some((500, "secret internals".into()));
        let r = svc.make_invoice(&gw, params("alice", 1000)).await.unwrap_err();
        assert_eq!(r.code, code::BACKEND);
        assert!(!r.message.contains("internals"));
        *fake.fail.lock().unwrap() = None;
        *fake.wrong_amount.lock().unwrap() = Some(1);
        assert_eq!(
            svc.make_invoice(&gw, params("alice", 1000)).await.unwrap_err().code,
            code::BACKEND
        );
        let st = svc.status(&admin).unwrap();
        assert_eq!((st.invoices_made, st.invoices_failed), (0, 2));
        assert!(st.last_error.unwrap().contains("refused"));
        assert_eq!(st.backend, "lnd");
        assert!(st.remote_settings);
    }

    #[tokio::test]
    async fn rates_and_concurrency_are_bounded() {
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(&url, Kind::Cln, dir.path());
        cfg.limits.per_caller_per_minute = 1;
        cfg.limits.concurrent = 1;
        cfg.backend.timeout = Duration::from_millis(1000);
        let svc = Arc::new(Service::new(cfg));
        let gw = caller(&gateway_keys());
        let admin = caller(&admin_keys());
        *fake.delay.lock().unwrap() = Some(Duration::from_millis(2500));
        let slow = {
            let (svc, gw) = (svc.clone(), gw.clone());
            tokio::spawn(async move { svc.make_invoice(&gw, params("alice", 1000)).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            svc.make_invoice(&gw, params("alice", 1000)).await.unwrap_err().code,
            code::RATE_LIMITED
        );
        assert_eq!(
            svc.make_invoice(&admin, params("alice", 1000)).await.unwrap_err().code,
            code::BUSY
        );
        assert_eq!(slow.await.unwrap().unwrap_err().code, code::BACKEND);
    }

    #[tokio::test]
    async fn admins_change_addresses_and_limits_and_the_change_is_saved() {
        let (svc, _fake, dir) = rig(Kind::Lnd).await;
        let admin = caller(&admin_keys());
        let view = svc.config_view(&admin).unwrap();
        assert_eq!(view.backend.secret, "(set)");
        assert!(view.gateways[0].starts_with("npub1"));
        assert_eq!(view.addresses.len(), 2);
        let set = proto::SetAddressParams {
            name: "carol".into(),
            min_sendable: 1000,
            max_sendable: 9000,
            description: "Carol".into(),
            comment_allowed: 0,
            domains: vec![],
        };
        let after = svc.set_address(&admin, set.clone()).unwrap();
        assert_eq!(after.addresses.len(), 3);
        let bad = proto::SetAddressParams {
            name: "Bad".into(),
            ..set
        };
        assert_eq!(svc.set_address(&admin, bad).unwrap_err().code, code::INVALID);
        svc.remove_address(&admin, proto::RemoveAddressParams { name: "alice".into() })
            .unwrap();
        let gone = svc
            .remove_address(&admin, proto::RemoveAddressParams { name: "alice".into() })
            .unwrap_err();
        assert_eq!(gone.code, code::NOT_FOUND);
        let limits = proto::SetLimitsParams {
            invoices_per_minute: Some(1),
            per_caller_per_minute: None,
            invoice_expiry_secs: None,
        };
        assert_eq!(svc.set_limits(&admin, limits).unwrap().limits.invoices_per_minute, 1);
        let same = proto::SetLimitsParams {
            invoices_per_minute: None,
            per_caller_per_minute: None,
            invoice_expiry_secs: None,
        };
        svc.set_limits(&admin, same).unwrap();
        let bad_limits = proto::SetLimitsParams {
            invoices_per_minute: None,
            per_caller_per_minute: None,
            invoice_expiry_secs: Some(5),
        };
        assert_eq!(svc.set_limits(&admin, bad_limits).unwrap_err().code, code::INVALID);
        let saved = config::read_remote(dir.path()).unwrap().unwrap();
        assert_eq!(saved.addresses.unwrap().keys().collect::<Vec<_>>(), ["bob", "carol"]);
        assert_eq!(saved.limits.unwrap().invoices_per_minute, Some(1));
        // The new global limit applies at once.
        let gw = caller(&gateway_keys());
        let mut p = params("carol", 1000);
        assert!(svc.make_invoice(&gw, p.clone()).await.is_ok());
        p.amount_msat = 2000;
        assert_eq!(svc.make_invoice(&gw, p).await.unwrap_err().code, code::RATE_LIMITED);
    }

    #[tokio::test]
    async fn remote_changes_need_the_switch_and_a_writable_data_dir() {
        let fake = Arc::new(Fake::default());
        let url = serve(fake).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(&url, Kind::Lnd, dir.path());
        cfg.sources = Sources::default();
        let svc = Service::new(cfg.clone());
        let admin = caller(&admin_keys());
        let rm = || proto::RemoveAddressParams { name: "alice".into() };
        assert_eq!(svc.remove_address(&admin, rm()).unwrap_err().code, code::LOCKED);
        let mut on = cfg;
        on.sources.apply(&SourcesLayer {
            remote: Some(true),
            ..Default::default()
        });
        on.data_dir = dir.path().join("missing");
        let svc = Service::new(on);
        assert_eq!(svc.remove_address(&admin, rm()).unwrap_err().code, code::INTERNAL);
        assert!(svc
            .config_view(&admin)
            .unwrap()
            .addresses
            .iter()
            .any(|a| a.name == "alice"));
    }

    #[test]
    fn networks_have_names_and_poisoned_locks_are_survived() {
        assert_eq!(network_name(Network::Bitcoin), "bitcoin");
        assert_eq!(network_name(Network::Testnet), "testnet");
        assert_eq!(network_name(Network::Signet), "signet");
        let m = Arc::new(Mutex::new(1));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(*lock(&m), 1);
    }

    #[tokio::test]
    async fn a_poisoned_state_lock_is_survived() {
        let (svc, _fake, _dir) = rig(Kind::Lnd).await;
        let svc = Arc::new(svc);
        let s2 = svc.clone();
        let _ = std::thread::spawn(move || {
            let _g = s2.state.write().unwrap();
            panic!("poison");
        })
        .join();
        let admin = caller(&admin_keys());
        assert!(svc.list_addresses(&admin).is_ok());
        assert!(svc
            .remove_address(&admin, proto::RemoveAddressParams { name: "alice".into() })
            .is_ok());
    }
}
