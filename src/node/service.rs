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
use crate::proto::{self, code, AddressInfo, AddressList, ConfigView, MadeInvoice, MakeInvoiceParams, Status};
use crate::ratelimit::RateLimiter;

/// How far a request's timestamp may be from the node's clock.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// A refusal with a stable code and a message safe to send to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

// Who is asking: the shared ContextVM crate's caller.
pub use deadhop_cvm::caller::Caller;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
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
    backend: Backend,
    state: RwLock<Mutable>,
    permits: Semaphore,
    made: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
    payee: Mutex<Option<String>>,
    started: Instant,
    now: fn() -> u64,
}

fn network_name(n: Network) -> &'static str {
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
            state: RwLock::new(Mutable {
                addresses: cfg.addresses.clone(),
                limits: cfg.limits.clone(),
                limiter,
            }),
            permits: Semaphore::new(cfg.limits.concurrent as usize),
            backend,
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

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Mutable> {
        self.state.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Mutable> {
        self.state.write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Who the caller is, and whether its request is fresh.
    fn role(&self, c: &Caller) -> Result<Role, Refusal> {
        let key = c.pubkey.as_deref().and_then(|k| PublicKey::from_hex(k).ok());
        let role = match key {
            Some(k) if self.cfg.admins.contains(&k) => Role::Admin,
            Some(k) if self.cfg.gateways.contains(&k) => Role::Gateway,
            _ => return Err(refuse(code::UNAUTHORIZED, "this key may not use this node")),
        };
        if let Some(e) = &c.event {
            if e.created_at.as_secs().abs_diff((self.now)()) > MAX_CLOCK_SKEW_SECS {
                return Err(refuse(
                    code::UNAUTHORIZED,
                    "the request's timestamp is too far from the node's clock",
                ));
            }
        }
        Ok(role)
    }

    fn admin(&self, c: &Caller) -> Result<(), Refusal> {
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
        })
    }

    pub async fn make_invoice(&self, c: &Caller, p: MakeInvoiceParams) -> Result<MadeInvoice, Refusal> {
        self.role(c)?;
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
        if !limiter.allow(c.pubkey.as_deref().unwrap_or_default(), (self.now)()) {
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
        Ok(MadeInvoice {
            pr,
            payment_hash: checked.payment_hash,
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
        // Without an event (a test transport) the key alone decides.
        let bare = Caller {
            pubkey: Some(admin_keys().public_key().to_hex()),
            event: None,
        };
        assert!(svc.status(&bare).is_ok());
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
