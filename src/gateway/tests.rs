//! Whole-system tests: a wallet's HTTP requests to the gateway, over a relay
//! to the node, to a fake Lightning backend, and back.

use std::time::Duration;

use nostr_sdk::prelude::Keys;
use serde_json::Value;

use crate::gateway::app::{self, Gateway};
use crate::gateway::config::{Config, Limits, Listen, NodeConfig};
use crate::lnurl;
use crate::node::app::tests::{node_rig, NodeRig};
use crate::node::backend::Kind;
use crate::node::service::tests::{admin_keys, gateway_keys};
use crate::settings::Sources;

pub struct Stack {
    pub node_rig: NodeRig,
    pub node: Option<crate::node::app::Running>,
    pub node_keys: Keys,
    pub gw: Option<Gateway>,
    pub cfg: Config,
    pub http: reqwest::Client,
}

pub fn gateway_config(r: &NodeRig, node: &Keys, data: &std::path::Path) -> Config {
    let nodes = vec![NodeConfig {
        pubkey: node.public_key(),
        names: None,
        relays: vec![r.relay_url.clone()],
        payee: None,
    }];
    gateway_config_for(nodes, data)
}

pub fn gateway_config_for(nodes: Vec<NodeConfig>, data: &std::path::Path) -> Config {
    Config {
        data_dir: data.to_path_buf(),
        listen: Listen::Tcp("127.0.0.1:0".parse().unwrap()),
        domains: vec!["pay.example".into()],
        scheme_override: Some("http".into()),
        trusted_proxies: vec![],
        socks5: None,
        nodes,
        limits: Limits {
            per_ip_per_minute: 1000,
            global_per_minute: 1000,
            timeout: Duration::from_secs(10),
            cache: Duration::from_secs(60),
            max_connections: 64,
        },
        admin_listen: Some(Listen::Tcp("127.0.0.1:0".parse().unwrap())),
        secure_cookie: false,
        sources: Sources::default(),
    }
}

/// Write the gateway's keys where the node expects them (the test keys).
pub fn seed_keys(data: &std::path::Path) {
    crate::files::open_dir(data).unwrap();
    for (file, keys) in [
        (crate::gateway::config::KEY_FILE, gateway_keys()),
        (crate::gateway::config::ADMIN_KEY_FILE, admin_keys()),
    ] {
        let nsec = nostr_sdk::ToBech32::to_bech32(keys.secret_key()).unwrap();
        crate::files::write_private(&data.join(file), &nsec).unwrap();
    }
}

pub async fn stack_with(kind: Kind, tweak: impl FnOnce(&mut Config)) -> Stack {
    stack_on(node_rig(kind).await, tweak).await
}

/// A stack whose node and gateway both use only `relay`.
pub async fn stack_on_relay(relay: &str, tweak: impl FnOnce(&mut Config)) -> Stack {
    let mut rig = node_rig(Kind::Lnd).await;
    rig.cfg.relays = vec![relay.to_string()];
    rig.relay_url = relay.to_string();
    stack_on(rig, tweak).await
}

pub async fn stack_on(node_rig: NodeRig, tweak: impl FnOnce(&mut Config)) -> Stack {
    let node = crate::node::app::start(node_rig.cfg.clone()).await.unwrap();
    let node_keys = node.keys.clone();
    let data = node_rig.dir.path().join("gateway");
    seed_keys(&data);
    let mut cfg = gateway_config(&node_rig, &node_keys, &data);
    tweak(&mut cfg);
    let gw = app::start(cfg.clone()).await.unwrap();
    let http = crate::tls::http_client(Duration::from_secs(20));
    let s = Stack {
        node_rig,
        node: Some(node),
        node_keys,
        gw: Some(gw),
        cfg,
        http,
    };
    s.wait_for_cache().await;
    s
}

pub async fn stack() -> Stack {
    stack_with(Kind::Lnd, |_| {}).await
}

impl Stack {
    pub fn gw(&self) -> &Gateway {
        self.gw.as_ref().unwrap()
    }

    pub fn base(&self) -> String {
        format!("http://{}", self.gw().public)
    }

    pub fn admin_base(&self) -> String {
        format!("http://{}", self.gw().admin.as_ref().unwrap())
    }

    pub async fn wait_for_cache(&self) {
        for _ in 0..100 {
            if self.gw().dir.nodes.iter().all(|n| !n.addresses().is_empty()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the gateway never cached the node's addresses");
    }

    pub async fn get(&self, path: &str) -> (u16, Value) {
        let r = self.http.get(format!("{}{path}", self.base())).send().await.unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    pub async fn stop(mut self) {
        if let Some(gw) = self.gw.take() {
            gw.until(Box::pin(async {})).await;
        }
        if let Some(node) = self.node.take() {
            node.until(Box::pin(async {})).await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_pays_a_lightning_address_end_to_end() {
    let s = stack().await;
    let (status, params) = s.get("/.well-known/lnurlp/alice").await;
    assert_eq!(status, 200, "{params}");
    assert_eq!(params["tag"], "payRequest");
    assert_eq!(params["minSendable"], 1000);
    assert_eq!(params["commentAllowed"], 10);
    let callback = params["callback"].as_str().unwrap();
    assert_eq!(callback, "http://pay.example/.well-known/lnurlp/alice/callback");
    let metadata = params["metadata"].as_str().unwrap().to_string();
    assert!(metadata.contains("alice@pay.example"));

    let path = callback.trim_start_matches("http://pay.example");
    let (status, inv) = s.get(&format!("{path}?amount=21000&comment=thanks")).await;
    assert_eq!(status, 200, "{inv}");
    assert_eq!(inv["routes"], serde_json::json!([]));
    // What a wallet checks: the amount, and that the invoice commits to the metadata it was shown.
    let want = crate::bolt11::Expect {
        amount_msat: 21_000,
        description_hash: lnurl::description_hash(&metadata),
        network: None,
        payee: None,
        now: crate::unix_now(),
        min_expiry: Duration::from_secs(60),
    };
    crate::bolt11::check(inv["pr"].as_str().unwrap(), &want).unwrap();
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_public_listener_serves_lnurl_paths_and_nothing_else() {
    let s = stack().await;
    let r = s
        .http
        .get(format!("{}/.well-known/lnurlp/alice", s.base()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    assert_eq!(r.headers()["content-type"], "application/json");
    assert_eq!(r.headers()["cache-control"], "public, max-age=60");
    let pre = s
        .http
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/.well-known/lnurlp/alice/callback", s.base()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(pre.status().as_u16(), 204);
    assert_eq!(pre.headers()["access-control-allow-methods"], "GET");
    for admin_path in [
        "/",
        "/login",
        "/logout",
        "/nodes/0",
        "/nodes/0/address",
        "/assets/app.css",
        "/admin",
    ] {
        let (status, body) = s.get(admin_path).await;
        assert_eq!(status, 404, "{admin_path}");
        assert_eq!(body["status"], "ERROR");
        let post = s.http.post(format!("{}{admin_path}", s.base())).send().await.unwrap();
        assert!(
            post.status().as_u16() == 404 || post.status().as_u16() == 405,
            "{admin_path}"
        );
    }
    let (status, health) = s.get("/healthz").await;
    assert_eq!((status, health["status"].as_str()), (200, Some("ok")));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn names_tags_and_amounts_are_checked_before_the_node_is_asked() {
    let s = stack().await;
    let calls = || s.node_rig.fake.calls.load(std::sync::atomic::Ordering::SeqCst);
    // Upper case and +tags reach the same address.
    let (status, p) = s.get("/.well-known/lnurlp/Alice+tips").await;
    assert_eq!(status, 200);
    assert!(p["metadata"].as_str().unwrap().contains("alice@pay.example"));
    for (path, code, reason) in [
        ("/.well-known/lnurlp/nobody", 404, "no such Lightning address"),
        ("/.well-known/lnurlp/bad%20name", 404, "no such"),
        ("/.well-known/lnurlp/bad%20name/callback?amount=1000", 404, "no such"),
        (
            "/.well-known/lnurlp/alice/callback",
            400,
            "amount (millisatoshis) is required",
        ),
        ("/.well-known/lnurlp/alice/callback?amount=lots", 400, "amount"),
        (
            "/.well-known/lnurlp/alice/callback?amount=999",
            400,
            "amount must be 1000 to",
        ),
        (
            "/.well-known/lnurlp/alice/callback?amount=1000&comment=12345678901",
            400,
            "at most 10",
        ),
        ("/.well-known/lnurlp/bob/callback?amount=1000", 404, "no such"),
    ] {
        let (status, body) = s.get(path).await;
        assert_eq!(status, code, "{path}: {body}");
        assert_eq!(body["status"], "ERROR");
        assert!(body["reason"].as_str().unwrap().contains(reason), "{path}: {body}");
    }
    let long = format!(
        "/.well-known/lnurlp/alice/callback?amount=1000&comment={}",
        "x".repeat(5000)
    );
    assert!(s.get(&long).await.1["reason"].as_str().unwrap().contains("too long"));
    assert_eq!(calls(), 0, "nothing invalid reached the backend");
    // An empty comment is no comment.
    assert_eq!(
        s.get("/.well-known/lnurlp/alice/callback?amount=1000&comment=").await.0,
        200
    );
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn several_domains_are_told_apart_by_host_and_forwarded_host_only_from_proxies() {
    let s = stack_with(Kind::Lnd, |c| {
        c.domains = vec!["pay.example".into(), "bob.example".into()];
        c.trusted_proxies = vec![crate::gateway::config::Net::parse("127.0.0.1").unwrap()];
    })
    .await;
    let get = |host: &'static str, fwd: Option<&'static str>| {
        let mut r = s
            .http
            .get(format!("{}/.well-known/lnurlp/bob", s.base()))
            .header("host", host);
        if let Some(f) = fwd {
            r = r.header("x-forwarded-host", f);
        }
        async move { r.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(get("bob.example", None).await, 200);
    assert_eq!(get("BOB.example.", None).await, 200);
    assert_eq!(
        get("pay.example", None).await,
        404,
        "bob is only served under bob.example"
    );
    assert_eq!(get("evil.example", None).await, 404);
    assert_eq!(
        get("127.0.0.1", Some("bob.example")).await,
        200,
        "the proxy's forwarded host counts"
    );
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_hosts_from_strangers_are_ignored() {
    let s = stack_with(Kind::Lnd, |c| {
        c.domains = vec!["pay.example".into(), "bob.example".into()]
    })
    .await;
    let r = s
        .http
        .get(format!("{}/.well-known/lnurlp/bob", s.base()))
        .header("host", "x.example")
        .header("x-forwarded-host", "bob.example");
    assert_eq!(r.send().await.unwrap().status().as_u16(), 404);
    let cb = format!("{}/.well-known/lnurlp/bob/callback?amount=1000", s.base());
    assert_eq!(
        s.http
            .get(cb)
            .header("host", "x.example")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clients_are_rate_limited_by_their_real_address() {
    let s = stack_with(Kind::Lnd, |c| {
        c.limits.per_ip_per_minute = 2;
        c.trusted_proxies = vec![crate::gateway::config::Net::parse("127.0.0.0/8").unwrap()];
    })
    .await;
    let cb = |ip: &'static str| {
        let r = s
            .http
            .get(format!("{}/.well-known/lnurlp/alice/callback?amount=1000", s.base()))
            .header("x-forwarded-for", format!("{ip}, 127.0.0.2"));
        async move { r.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(cb("203.0.113.1").await, 200);
    assert_eq!(cb("203.0.113.1").await, 200);
    assert_eq!(cb("203.0.113.1").await, 429);
    assert_eq!(cb("203.0.113.2").await, 200, "another client has its own budget");
    // Lookups have a larger budget of their own.
    for _ in 0..8 {
        let r = s
            .http
            .get(format!("{}/.well-known/lnurlp/alice", s.base()))
            .header("x-forwarded-for", "198.51.100.7");
        assert_eq!(r.send().await.unwrap().status().as_u16(), 200);
    }
    let r = s
        .http
        .get(format!("{}/.well-known/lnurlp/alice", s.base()))
        .header("x-forwarded-for", "198.51.100.7");
    assert_eq!(r.send().await.unwrap().status().as_u16(), 429);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn node_refusals_and_bad_invoices_reach_the_wallet_as_lnurl_errors() {
    let s = stack().await;
    *s.node_rig.fake.fail.lock().unwrap() = Some((500, "down".into()));
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=1000").await;
    assert_eq!(status, 503, "{body}");
    assert!(body["reason"].as_str().unwrap().contains("not reachable"));
    *s.node_rig.fake.fail.lock().unwrap() = None;
    // The node checks the backend's invoice itself, so a wrong amount is a node failure...
    *s.node_rig.fake.wrong_amount.lock().unwrap() = Some(5);
    assert_eq!(s.get("/.well-known/lnurlp/alice/callback?amount=1000").await.0, 503);
    *s.node_rig.fake.wrong_amount.lock().unwrap() = None;
    let m = s.gw().dir.metrics.view();
    assert_eq!(m.failures, 2);
    assert!(m.recent_failures[0].1.contains("alice@pay.example"));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_payee_that_does_not_sign_is_refused() {
    let s = stack_with(Kind::Lnd, |c| c.nodes[0].payee = Some(format!("02{}", "ab".repeat(32)))).await;
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=1000").await;
    assert_eq!(status, 502, "{body}");
    assert!(body["reason"].as_str().unwrap().contains("does not match"));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_node_down_lookups_are_served_from_cache_and_invoices_fail_fast() {
    let mut s = stack_with(Kind::Lnd, |c| c.limits.timeout = Duration::from_secs(3)).await;
    s.node.take().unwrap().until(Box::pin(async {})).await.unwrap();
    let (status, _) = s.get("/.well-known/lnurlp/alice").await;
    assert_eq!(status, 200, "the cache still answers");
    let started = std::time::Instant::now();
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=1000").await;
    assert_eq!(status, 503, "{body}");
    assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
    assert!(s.gw().dir.metrics.view().retries >= 1);
    // Back up: the next invoice works without restarting the gateway.
    s.node = Some(crate::node::app::start(s.node_rig.cfg.clone()).await.unwrap());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.get("/.well-known/lnurlp/alice/callback?amount=1000").await.0, 200);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn health_is_degraded_when_no_node_answers() {
    let mut s = stack_with(Kind::Lnd, |c| c.limits.timeout = Duration::from_secs(2)).await;
    s.node.take().unwrap().until(Box::pin(async {})).await.unwrap();
    // An unknown name right after the start refresh is not worth a node call.
    assert_eq!(s.get("/.well-known/lnurlp/zed").await.0, 404);
    // An invoice that cannot be made marks the node unreachable.
    assert_eq!(s.get("/.well-known/lnurlp/alice/callback?amount=1000").await.0, 503);
    let (status, body) = s.get("/healthz").await;
    assert_eq!((status, body["status"].as_str()), (503, Some("degraded")));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_description_changed_on_the_node_is_picked_up_without_waiting_for_the_cache() {
    let s = stack().await;
    let admin = crate::node::app::tests::client(&s.node_rig, admin_keys(), &s.node_keys, Duration::from_secs(10)).await;
    let _: crate::proto::ConfigView = admin
        .call(crate::proto::SET_ADDRESS, serde_json::json!({ "name": "alice", "min_sendable": 1000, "max_sendable": 9_000_000, "description": "New words", "comment_allowed": 10 }))
        .await
        .unwrap();
    // The gateway's cache still has the old description; the invoice commits to the new one.
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=2000").await;
    assert_eq!(status, 200, "{body}");
    let (_, params) = s.get("/.well-known/lnurlp/alice").await;
    assert!(params["metadata"].as_str().unwrap().contains("New words"));
    admin.close().await;
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn names_listed_for_a_node_limit_what_it_serves() {
    let s = stack_with(Kind::Lnd, |c| c.nodes[0].names = Some(vec!["alice".into()])).await;
    assert_eq!(s.get("/.well-known/lnurlp/alice").await.0, 200);
    assert_eq!(s.get("/.well-known/lnurlp/bob").await.0, 404);
    s.stop().await;
}

/// A request over the gateway's Unix socket carrying `xff`: its status line.
async fn over_socket(sock: &std::path::Path, xff: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut c = tokio::net::UnixStream::connect(sock).await.unwrap();
    let req = format!("GET /.well-known/lnurlp/alice/callback?amount=1000 HTTP/1.1\r\nhost: pay.example\r\nx-forwarded-for: {xff}\r\nconnection: close\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).await.unwrap();
    out.lines().next().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_unix_socket_listener_trusts_a_listed_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("gw.sock");
    let s = stack_with(Kind::Lnd, |c| {
        c.listen = Listen::Unix(sock.clone());
        c.trusted_proxies = vec![crate::gateway::config::Net::parse("127.0.0.1").unwrap()];
        c.limits.per_ip_per_minute = 1;
    })
    .await;
    let fetch = |xff: &'static str| over_socket(&sock, xff);
    assert!(fetch("203.0.113.9").await.contains("200"));
    assert!(fetch("203.0.113.9").await.contains("429"));
    // An appending proxy: the last address that is not a proxy is the client.
    assert!(fetch("198.51.100.1, 203.0.113.10, 127.0.0.1").await.contains("200"));
    assert!(fetch("203.0.113.10").await.contains("429"));
    assert!(
        fetch("not-an-ip").await.contains("200"),
        "no usable address: the socket's own budget"
    );
    assert!(fetch("also-not").await.contains("429"));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_unix_socket_without_trusted_proxies_shares_one_budget() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("gw.sock");
    let s = stack_with(Kind::Lnd, |c| {
        c.listen = Listen::Unix(sock.clone());
        c.limits.per_ip_per_minute = 1;
    })
    .await;
    let fetch = |xff: &'static str| over_socket(&sock, xff);
    assert!(fetch("203.0.113.9").await.contains("200"));
    // A spoofed X-Forwarded-For, passed through by a proxy that does not
    // append, cannot steer the limiter to a fresh bucket.
    assert!(fetch("203.0.113.10").await.contains("429"));
    assert!(fetch("198.51.100.77").await.contains("429"));
    s.stop().await;
}

#[test]
fn failures_have_statuses_and_reasons() {
    use crate::gateway::nodes::Fail;
    assert_eq!(Fail::Invalid("x".into()).reason(), "x");
    assert_eq!(Fail::RateLimited.status(), 429);
    assert_eq!(Fail::BadInvoice.status(), 502);
    assert_eq!(Fail::Unavailable.status(), 503);
    assert_eq!(Fail::NotFound.status(), 404);
    assert!(crate::gateway::http::normalise("").is_none());
    assert_eq!(crate::gateway::http::normalise("_").as_deref(), Some("_"));
}

// ---- admin web interface ----

pub struct Browser {
    base: String,
    data_dir: std::path::PathBuf,
    pub cookie: Option<String>,
}

pub struct Page {
    pub status: u16,
    pub location: Option<String>,
    pub set_cookie: Option<String>,
    pub csp: Option<String>,
    pub body: String,
}

impl Browser {
    pub fn new(s: &Stack) -> Self {
        Browser {
            base: s.admin_base(),
            data_dir: s.cfg.data_dir.clone(),
            cookie: None,
        }
    }

    fn no_redirects() -> reqwest::Client {
        reqwest::Client::builder()
            .use_preconfigured_tls(crate::tls::client_config(None))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    async fn page(r: reqwest::Response) -> Page {
        let h = |k: &str| r.headers().get(k).map(|v| v.to_str().unwrap().to_string());
        let (status, location, set_cookie, csp) = (
            r.status().as_u16(),
            h("location"),
            h("set-cookie"),
            h("content-security-policy"),
        );
        Page {
            status,
            location,
            set_cookie,
            csp,
            body: r.text().await.unwrap(),
        }
    }

    pub async fn get(&self, path: &str) -> Page {
        let mut r = Self::no_redirects().get(format!("{}{path}", self.base));
        if let Some(c) = &self.cookie {
            r = r.header("cookie", format!("other=1; lnaddr_session={c}"));
        }
        Self::page(r.send().await.unwrap()).await
    }

    pub async fn post(&self, path: &str, form: &[(&str, &str)], origin: Option<&str>) -> Page {
        let mut r = Self::no_redirects().post(format!("{}{path}", self.base)).form(form);
        if let Some(c) = &self.cookie {
            r = r.header("cookie", format!("lnaddr_session={c}"));
        }
        if let Some(o) = origin {
            r = r.header("origin", o);
        }
        Self::page(r.send().await.unwrap()).await
    }

    pub async fn sign_in(&mut self) {
        let token = app::admin_token(&self.data_dir).unwrap();
        let p = self.post("/login", &[("token", &token)], None).await;
        assert_eq!(p.status, 303);
        let c = p.set_cookie.unwrap();
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Strict") && !c.contains("Secure"),
            "{c}"
        );
        self.cookie = Some(
            c.split(';')
                .next()
                .unwrap()
                .trim_start_matches("lnaddr_session=")
                .to_string(),
        );
    }

    pub fn csrf(body: &str) -> String {
        let at = body.find("name=\"csrf\" value=\"").unwrap() + 19;
        body[at..at + 64].to_string()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_signs_in_and_changes_addresses_on_the_node() {
    let s = stack().await;
    let mut b = Browser::new(&s);
    let p = b.get("/").await;
    assert_eq!((p.status, p.location.as_deref()), (303, Some("/login")));
    let p = b.get("/login").await;
    assert_eq!(p.status, 200);
    assert!(p.csp.unwrap().contains("default-src 'none'"));
    assert!(p.body.contains("Sign in."));
    let p = b.post("/login", &[("token", "wrong")], None).await;
    assert_eq!(p.status, 401);
    assert!(p.body.contains("not right"));
    b.sign_in().await;
    assert_eq!(b.get("/login").await.location.as_deref(), Some("/"));

    let p = b.get("/").await;
    assert_eq!(p.status, 200);
    for want in ["Serving.", "alice@pay.example", "Invoices", "Nodes", "None."] {
        assert!(p.body.contains(want), "{want}");
    }
    // A failed invoice shows up as the node's last error.
    *s.node_rig.fake.fail.lock().unwrap() = Some((500, "flat tyre".into()));
    let _ = s.get("/.well-known/lnurlp/alice/callback?amount=1000").await;
    *s.node_rig.fake.fail.lock().unwrap() = None;
    let p = b.get("/nodes/0").await;
    assert!(
        p.body.contains("Status") && p.body.contains("Add an address") && p.body.contains("lnd"),
        "{}",
        p.body
    );
    assert!(
        p.body.contains("Last error: the lnd backend answered 500: flat tyre"),
        "{}",
        p.body
    );
    let csrf = Browser::csrf(&p.body);

    let add = [
        ("csrf", csrf.as_str()),
        ("name", "carol"),
        ("min_sats", "1"),
        ("max_sats", "50,000"),
        ("description", "Carol's tips"),
        ("comment_allowed", "20"),
        ("domains", ""),
    ];
    let p = b.post("/nodes/0/address", &add, None).await;
    assert_eq!((p.status, p.location.as_deref()), (303, Some("/nodes/0?saved=1")));
    let p = b.get("/nodes/0?saved=1").await;
    assert!(p.body.contains("Saved on the node.") && p.body.contains("carol"));
    // The public side knows at once.
    assert_eq!(s.get("/.well-known/lnurlp/carol").await.0, 200);
    let p = b.get("/nodes/0?edit=carol").await;
    assert!(p.body.contains("Edit carol") && p.body.contains("Carol&#39;s tips"));

    let bad_number = [
        ("csrf", csrf.as_str()),
        ("name", "dan"),
        ("min_sats", "one"),
        ("max_sats", "2"),
        ("description", "d"),
    ];
    assert!(b
        .post("/nodes/0/address", &bad_number, None)
        .await
        .body
        .contains("Not saved. Min sats"));
    let bad_name = [
        ("csrf", csrf.as_str()),
        ("name", "Dan"),
        ("min_sats", "1"),
        ("max_sats", "2"),
        ("description", "d"),
    ];
    assert!(b
        .post("/nodes/0/address", &bad_name, None)
        .await
        .body
        .contains("Not saved."));

    let p = b
        .post("/nodes/0/remove", &[("csrf", &csrf), ("name", "carol")], None)
        .await;
    assert_eq!(p.status, 303);
    let limits = [
        ("csrf", csrf.as_str()),
        ("invoices_per_minute", "90"),
        ("per_caller_per_minute", "30"),
        ("invoice_expiry_secs", "900"),
    ];
    assert_eq!(b.post("/nodes/0/limits", &limits, None).await.status, 303);
    assert!(b.get("/nodes/0").await.body.contains("value=\"90\""));
    let bad_limits = [
        ("csrf", csrf.as_str()),
        ("invoices_per_minute", "x"),
        ("per_caller_per_minute", "1"),
        ("invoice_expiry_secs", "1"),
    ];
    assert!(b
        .post("/nodes/0/limits", &bad_limits, None)
        .await
        .body
        .contains("Not saved."));

    // Forged requests are refused.
    let forged = [("csrf", "0".repeat(64)), ("name", "alice".to_string())];
    let forged: Vec<(&str, &str)> = forged.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(b.post("/nodes/0/remove", &forged, None).await.status, 403);
    assert_eq!(
        b.post(
            "/nodes/0/remove",
            &[("csrf", &csrf), ("name", "alice")],
            Some("https://evil.example")
        )
        .await
        .status,
        403
    );
    let same_origin = format!("http://{}", s.gw().admin.as_ref().unwrap());
    let limits_ok = [
        ("csrf", csrf.as_str()),
        ("invoices_per_minute", "90"),
        ("per_caller_per_minute", "30"),
        ("invoice_expiry_secs", "900"),
    ];
    assert_eq!(
        b.post("/nodes/0/limits", &limits_ok, Some(&same_origin)).await.status,
        303
    );

    assert_eq!(b.get("/nodes/9").await.status, 404);
    for (asset, ctype) in [
        ("app.css", "text/css"),
        ("favicon.svg", "image/svg"),
        ("geist.woff2", "font/woff2"),
        ("martian-mono.woff2", "font/woff2"),
        ("schibsted-grotesk.woff2", "font/woff2"),
    ] {
        let r = s
            .http
            .get(format!("{}/assets/{asset}", s.admin_base()))
            .send()
            .await
            .unwrap();
        assert!(
            r.headers()["content-type"].to_str().unwrap().starts_with(ctype),
            "{asset}"
        );
    }
    assert_eq!(b.get("/assets/nope").await.status, 404);
    assert!(b.get("/nowhere").await.body.contains("Not found."));

    // Another site cannot sign the operator out: without the token, or from
    // another origin, the post is refused and the session lives on.
    assert_eq!(b.post("/logout", &[], None).await.status, 403);
    assert_eq!(
        b.post("/logout", &[("csrf", &csrf)], Some("https://evil.example"))
            .await
            .status,
        403
    );
    assert_eq!(b.get("/").await.status, 200);
    // The sign-out form on every page carries the token.
    let overview = b.get("/").await.body;
    assert!(
        overview.contains(&format!(
            "action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">"
        )),
        "{overview}"
    );
    let p = b.post("/logout", &[("csrf", &csrf)], None).await;
    assert!(p.set_cookie.unwrap().contains("Max-Age=0"));
    assert_eq!(b.get("/").await.location.as_deref(), Some("/login"));
    // Without a session, form posts go to the sign-in page.
    assert_eq!(
        b.post("/nodes/0/remove", &[("csrf", &csrf), ("name", "alice")], None)
            .await
            .location
            .as_deref(),
        Some("/login")
    );
    assert_eq!(
        b.post("/nodes/0/address", &add, None).await.location.as_deref(),
        Some("/login")
    );
    assert_eq!(
        b.post("/nodes/0/limits", &limits, None).await.location.as_deref(),
        Some("/login")
    );
    assert_eq!(b.get("/nodes/0").await.location.as_deref(), Some("/login"));
    // A logout without a cookie is harmless.
    assert_eq!(Browser::new(&s).post("/logout", &[], None).await.status, 303);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_attempts_are_limited() {
    let s = stack().await;
    let b = Browser::new(&s);
    for _ in 0..5 {
        assert!(b
            .post("/login", &[("token", "nope")], None)
            .await
            .body
            .contains("not right"));
    }
    assert!(b
        .post("/login", &[("token", "nope")], None)
        .await
        .body
        .contains("Too many attempts"));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_admin_key_the_interface_is_read_only() {
    let s = stack_with(Kind::Lnd, |c| {
        let _ = std::fs::remove_file(c.data_dir.join(crate::gateway::config::ADMIN_KEY_FILE));
    })
    .await;
    let mut b = Browser::new(&s);
    b.sign_in().await;
    let p = b.get("/nodes/0").await;
    assert!(p.body.contains("Read only") && p.body.contains("alice"), "{}", p.body);
    let token = Browser::csrf(&format!("name=\"csrf\" value=\"{}\"", "a".repeat(64)));
    // A valid session but a made-up form token is still refused.
    assert_eq!(
        b.post("/nodes/0/remove", &[("csrf", &token), ("name", "alice")], None)
            .await
            .status,
        403
    );
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_interface_explains_what_the_node_will_not_do() {
    // Remote settings off on the node.
    let mut s = stack().await;
    s.node.take().unwrap().until(Box::pin(async {})).await.unwrap();
    let mut cfg = s.node_rig.cfg.clone();
    cfg.sources = crate::settings::Sources::default();
    s.node = Some(crate::node::app::start(cfg.clone()).await.unwrap());
    let mut b = Browser::new(&s);
    b.sign_in().await;
    let p = b.get("/nodes/0").await;
    assert!(p.body.contains("Remote settings are switched off"), "{}", p.body);
    // Remove the admin from the node: the gateway's admin key is no longer listed.
    s.node.take().unwrap().until(Box::pin(async {})).await.unwrap();
    cfg.gateways.push(admin_keys().public_key());
    cfg.admins.clear();
    s.node = Some(crate::node::app::start(cfg).await.unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let p = b.get("/nodes/0").await;
    assert!(
        p.body.contains("does not list this gateway&#39;s admin key"),
        "{}",
        p.body
    );
    // The node gone: the page says so, and the overview shows the failure.
    s.node.take().unwrap().until(Box::pin(async {})).await.unwrap();
    let p = b.get("/nodes/0").await;
    assert!(p.body.contains("did not answer"), "{}", p.body);
    let _ = s.get("/.well-known/lnurlp/alice/callback?amount=1000").await;
    let p = b.get("/").await;
    assert!(p.body.contains("dot bad") && p.body.contains("When"), "{}", p.body);
    s.stop().await;
}

// ---- command line ----

fn env_for(s: &Stack) -> Vec<(String, String)> {
    vec![
        ("LNADDR_GATEWAY_DATA_DIR".into(), s.cfg.data_dir.display().to_string()),
        ("LNADDR_GATEWAY_DOMAIN".into(), "pay.example".into()),
        ("LNADDR_GATEWAY_NODE".into(), s.node_keys.public_key().to_hex()),
        ("LNADDR_GATEWAY_RELAYS".into(), s.node_rig.relay_url.clone()),
        ("LNADDR_GATEWAY_TIMEOUT_SECS".into(), "6".into()),
        ("LNADDR_GATEWAY_LISTEN".into(), "127.0.0.1:0".into()),
        ("LNADDR_GATEWAY_SCHEME".into(), "http".into()),
    ]
}

async fn run(env: &[(String, String)], args: &[&str]) -> (ExitCode, String) {
    let env = env.to_vec();
    let lookup = move |k: &str| env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let mut out = Vec::new();
    let code = app::command(&args, Box::new(lookup), Box::pin(async {}), &mut out).await;
    (code, String::from_utf8(out).unwrap())
}

use std::process::ExitCode;

#[tokio::test(flavor = "multi_thread")]
async fn the_command_line_tests_addresses_and_manages_nodes() {
    let s = stack().await;
    let env = env_for(&s);
    let (code, out) = run(&env, &["version"]).await;
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(out.starts_with("lnaddr-gateway 0."));
    assert!(run(&env, &["help"]).await.1.contains("node set-address"));
    assert_eq!(run(&env, &["bogus"]).await.0, ExitCode::from(2));
    assert_eq!(run(&env, &["pubkey", "extra"]).await.0, ExitCode::from(2));
    let (_, pk) = run(&env, &["pubkey"]).await;
    assert_eq!(
        pk.trim(),
        nostr_sdk::ToBech32::to_bech32(&gateway_keys().public_key()).unwrap()
    );
    let (_, apk) = run(&env, &["admin-pubkey"]).await;
    assert_eq!(
        apk.trim(),
        nostr_sdk::ToBech32::to_bech32(&admin_keys().public_key()).unwrap()
    );
    let (_, token) = run(&env, &["admin-token"]).await;
    assert_eq!(token.trim(), app::admin_token(&s.cfg.data_dir).unwrap());

    let (code, out) = run(&env, &["status"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert!(
        out.contains("node 1") && out.contains("ok in") && out.contains("alice@pay.example"),
        "{out}"
    );
    let (code, out) = run(&env, &["test", "alice", "21"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert!(
        out.contains("invoice    lnbcrt") && out.contains("checked    amount 21 sat"),
        "{out}"
    );
    let (code, out) = run(&env, &["test", "Alice@pay.example"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    for (args, want) in [
        (vec!["test"], "test needs NAME"),
        (vec!["test", "alice", "lots"], "not a number of sats"),
        (vec!["test", "Bad Name"], "not a valid name"),
        (vec!["test", "alice@other.example"], "not one of this gateway's domains"),
        (vec!["test", "nobody"], "no such Lightning address"),
        (vec!["test", "alice", "999999999"], "amount must be"),
    ] {
        let (code, out) = run(&env, &args).await;
        assert_eq!(code, ExitCode::FAILURE, "{args:?}");
        assert!(out.contains(want), "{args:?}: {out}");
    }

    let (code, out) = run(&env, &["node", "status"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert!(
        out.contains("backend   lnd (regtest)") && out.contains("remote    on"),
        "{out}"
    );
    let (code, out) = run(&env, &["node", "config", "1"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert!(
        out.contains("credential (set)") && out.contains("address   alice"),
        "{out}"
    );
    let (code, out) = run(&env, &["node", "set-address", "1", "erin", "1", "2_000", "Erin", "50"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert!(out.contains("address   erin"), "{out}");
    assert!(run(&env, &["node", "set-address", "1", "frank", "1", "2", "Frank"])
        .await
        .1
        .contains("address   frank"));
    assert!(run(&env, &["node", "remove-address", "1", "erin"])
        .await
        .1
        .contains("address   alice"));
    assert!(run(&env, &["node", "set-limits", "1", "100", "50", "600"])
        .await
        .1
        .contains("100/min"));
    for (args, want) in [
        (vec!["node", "status", "2"], "there is no node 2"),
        (vec!["node", "status", "0"], "there is no node 0"),
        (vec!["node", "status", "x"], "not a node number"),
        (vec!["node", "dance", "1"], "unknown node command"),
        (
            vec!["node", "set-address", "1", "g", "x", "2", "G"],
            "not a whole number",
        ),
        (vec!["node", "set-limits", "1", "1", "1", "x"], "not a whole number"),
        (vec!["node", "remove-address", "1", "nobody"], "no address"),
    ] {
        let (code, out) = run(&env, &args).await;
        assert_eq!(code, ExitCode::FAILURE, "{args:?}");
        assert!(out.contains(want), "{args:?}: {out}");
    }
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_command_line_reports_what_is_missing() {
    let s = stack().await;
    let mut env = env_for(&s);
    // A fresh data directory: no admin key yet.
    let fresh = s.node_rig.dir.path().join("fresh");
    env.retain(|(k, _)| k != "LNADDR_GATEWAY_DATA_DIR");
    env.push(("LNADDR_GATEWAY_DATA_DIR".into(), fresh.display().to_string()));
    let (code, out) = run(&env, &["node", "status"]).await;
    assert_eq!(code, ExitCode::FAILURE);
    assert!(out.contains("no admin key yet"), "{out}");
    // Its gateway key is not one the node knows: nothing answers.
    let (code, out) = run(&env, &["status"]).await;
    assert_eq!(code, ExitCode::FAILURE);
    assert!(
        out.contains("NOT REACHABLE") && out.contains("no node answered"),
        "{out}"
    );
    // Broken configuration.
    let bad = vec![("LNADDR_GATEWAY_DATA_DIR".to_string(), fresh.display().to_string())];
    for cmd in [&["status"][..], &["test", "alice"], &["node", "status"], &[]] {
        let (code, out) = run(&bad, cmd).await;
        assert_eq!(code, ExitCode::FAILURE, "{cmd:?}");
        assert!(out.contains("set the domain"), "{out}");
    }
    assert!(run(&bad, &["--config"]).await.1.contains("needs a file"));
    let (code, out) = run(&bad, &["status", "--config", "/does/not/exist"]).await;
    assert_eq!(code, ExitCode::FAILURE);
    assert!(out.contains("/does/not/exist"));
    // A data directory that cannot be made.
    let file = s.node_rig.dir.path().join("plainfile");
    std::fs::write(&file, "x").unwrap();
    let under_file = vec![(
        "LNADDR_GATEWAY_DATA_DIR".to_string(),
        file.join("d").display().to_string(),
    )];
    for cmd in ["pubkey", "admin-pubkey", "admin-token"] {
        assert_eq!(run(&under_file, &[cmd]).await.0, ExitCode::FAILURE, "{cmd}");
    }
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_runs_until_shutdown_and_start_failures_are_reported() {
    let s = stack().await;
    let env = env_for(&s);
    assert_eq!(run(&env, &["serve"]).await.0, ExitCode::SUCCESS);
    // The admin listener taken: start fails, naming it.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut env2 = env.clone();
    env2.push((
        "LNADDR_GATEWAY_ADMIN_LISTEN".into(),
        taken.local_addr().unwrap().to_string(),
    ));
    let (code, out) = run(&env2, &[]).await;
    assert_eq!(code, ExitCode::FAILURE);
    assert!(out.contains("cannot listen on"), "{out}");
    let mut env3 = env.clone();
    env3.retain(|(k, _)| k != "LNADDR_GATEWAY_LISTEN");
    env3.push(("LNADDR_GATEWAY_LISTEN".into(), taken.local_addr().unwrap().to_string()));
    assert!(run(&env3, &[]).await.1.contains("cannot listen on"));
    // A data directory under a file.
    let file = s.node_rig.dir.path().join("plain");
    std::fs::write(&file, "x").unwrap();
    let mut env4 = env.clone();
    env4.push(("LNADDR_GATEWAY_DATA_DIR".into(), file.join("d").display().to_string()));
    env4.retain(|(k, v)| k != "LNADDR_GATEWAY_DATA_DIR" || v.ends_with("/d"));
    assert_eq!(run(&env4, &[]).await.0, ExitCode::FAILURE);
    // An unreadable admin token or key stops the start.
    let mut cfg = s.cfg.clone();
    cfg.data_dir = s.node_rig.dir.path().join("perm");
    seed_keys(&cfg.data_dir);
    crate::files::write_private(&cfg.data_dir.join(crate::gateway::config::TOKEN_FILE), "t").unwrap();
    std::fs::set_permissions(
        cfg.data_dir.join(crate::gateway::config::TOKEN_FILE),
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    assert!(app::start(cfg.clone()).await.err().unwrap().contains("chmod 600"));
    std::fs::set_permissions(
        cfg.data_dir.join(crate::gateway::config::TOKEN_FILE),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(
        cfg.data_dir.join(crate::gateway::config::ADMIN_KEY_FILE),
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    assert!(app::start(cfg.clone()).await.err().unwrap().contains("chmod 600"));
    // An empty token file gets a token.
    crate::files::write_private(&cfg.data_dir.join(crate::gateway::config::TOKEN_FILE), "\n").unwrap();
    assert_eq!(app::admin_token(&cfg.data_dir).unwrap().len(), 64);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_the_gateway_could_not_foresee_come_from_the_node() {
    // A long cache: the gateway keeps the old values while the node changes.
    let s = stack_with(Kind::Lnd, |c| c.limits.cache = Duration::from_secs(3600)).await;
    let admin = crate::node::app::tests::client(&s.node_rig, admin_keys(), &s.node_keys, Duration::from_secs(10)).await;
    let call = |tool: &'static str, args: Value| {
        let admin = &admin;
        async move { admin.call::<crate::proto::ConfigView>(tool, args).await.unwrap() }
    };
    call(
        crate::proto::SET_LIMITS,
        serde_json::json!({ "per_caller_per_minute": 1 }),
    )
    .await;
    assert_eq!(s.get("/.well-known/lnurlp/alice/callback?amount=1000").await.0, 200);
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=1000").await;
    assert_eq!(status, 429, "the node's own rate limit: {body}");
    call(
        crate::proto::SET_LIMITS,
        serde_json::json!({ "per_caller_per_minute": 60 }),
    )
    .await;
    call(crate::proto::SET_ADDRESS, serde_json::json!({ "name": "alice", "min_sendable": 5_000_000, "max_sendable": 9_000_000, "description": "Pay alice" })).await;
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=2000").await;
    assert_eq!(status, 400, "the node's own bounds: {body}");
    assert!(body["reason"].as_str().unwrap().contains("5000000"));
    call(crate::proto::REMOVE_ADDRESS, serde_json::json!({ "name": "alice" })).await;
    let (status, body) = s.get("/.well-known/lnurlp/alice/callback?amount=6000000").await;
    assert_eq!(status, 404, "removed on the node: {body}");
    admin.close().await;
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cache_is_refreshed_on_its_period() {
    let s = stack_with(Kind::Lnd, |c| c.limits.cache = Duration::from_millis(300)).await;
    let admin = crate::node::app::tests::client(&s.node_rig, admin_keys(), &s.node_keys, Duration::from_secs(10)).await;
    let _: crate::proto::ConfigView = admin
        .call(
            crate::proto::SET_ADDRESS,
            serde_json::json!({ "name": "gus", "min_sendable": 1000, "max_sendable": 2000, "description": "Gus" }),
        )
        .await
        .unwrap();
    let mut seen = false;
    for _ in 0..50 {
        if s.gw().dir.nodes[0].addresses().iter().any(|a| a.name == "gus") {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "the periodic refresh picked up the new address");
    admin.close().await;
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invoices_resume_after_the_only_relay_drops_and_returns() {
    use nostr_relay_builder::prelude::{LocalRelay, RelayBuilder};
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let relay = LocalRelay::new(RelayBuilder::default().port(port));
    relay.run().await.unwrap();
    let url = format!("ws://127.0.0.1:{port}");
    let s = stack_on_relay(&url, |c| c.limits.timeout = Duration::from_secs(4)).await;
    let cb = "/.well-known/lnurlp/alice/callback?amount=1000";
    let mut ok = false;
    for _ in 0..30 {
        if s.get(cb).await.0 == 200 {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(ok, "invoices flow over the relay");
    relay.shutdown();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.get(cb).await.0, 503, "no relay: a clear failure");
    let back = LocalRelay::new(RelayBuilder::default().port(port));
    back.run().await.unwrap();
    // Neither service is restarted: both reconnect by themselves.
    let mut resumed = false;
    for _ in 0..60 {
        if s.get(cb).await.0 == 200 {
            resumed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(resumed, "invoices resume once the relay is back");
    back.shutdown();
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_that_never_reached_its_node_says_unavailable_not_unknown() {
    let rig = node_rig(Kind::Lnd).await;
    let data = rig.dir.path().join("gw-cold");
    seed_keys(&data);
    let mut cfg = gateway_config(&rig, &Keys::generate(), &data);
    cfg.limits.timeout = Duration::from_secs(2);
    let gw = app::start(cfg).await.unwrap();
    let http = crate::tls::http_client(Duration::from_secs(10));
    let r = http
        .get(format!("http://{}/.well-known/lnurlp/alice", gw.public))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 503);
    gw.until(Box::pin(async {})).await;
}

/// The whole path, with the node and the gateway each reaching the relay
/// through a proxy: SOCKS5, then HTTP CONNECT.
#[tokio::test(flavor = "multi_thread")]
async fn a_lightning_address_works_through_a_socks5_or_an_http_connect_proxy() {
    let (socks, _s) = deadhop_net::testing::socks5_proxy(None).await;
    let (connect, _c) = deadhop_net::testing::connect_proxy(false, None).await;
    for url in [
        format!("socks5://127.0.0.1:{socks}"),
        format!("http://127.0.0.1:{connect}"),
    ] {
        let proxy = crate::settings::socks5(&url).unwrap();
        let mut rig = crate::node::app::tests::node_rig(Kind::Lnd).await;
        rig.cfg.socks5 = Some(url.clone());
        let s = stack_on(rig, |c| c.socks5 = Some(proxy)).await;
        let (status, params) = s.get("/.well-known/lnurlp/alice").await;
        assert_eq!(status, 200, "{url}: {params}");
        let path = params["callback"]
            .as_str()
            .unwrap()
            .trim_start_matches("http://pay.example")
            .to_string();
        let (status, inv) = s.get(&format!("{path}?amount=21000")).await;
        assert_eq!(status, 200, "{url}: {inv}");
        assert!(inv["pr"].as_str().unwrap().starts_with("lnbc"), "{url}: {inv}");
        s.stop().await;
    }
}
