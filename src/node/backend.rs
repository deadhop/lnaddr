//! Lightning backends. Each one only ever creates invoices, and each is
//! meant to run with its invoice-only credential: LND's invoice.macaroon, a
//! Core Lightning rune restricted to `method=invoice`, phoenixd's limited
//! password, or an LNbits invoice key. Nothing here can spend.

use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};

use crate::lnurl::description_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Lnd,
    Cln,
    Phoenixd,
    Lnbits,
}

impl FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "lnd" => Ok(Kind::Lnd),
            "cln" | "clnrest" => Ok(Kind::Cln),
            "phoenixd" => Ok(Kind::Phoenixd),
            "lnbits" => Ok(Kind::Lnbits),
            other => Err(format!("unknown backend {other:?} (lnd, cln, phoenixd or lnbits)")),
        }
    }
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Lnd => "lnd",
            Kind::Cln => "cln",
            Kind::Phoenixd => "phoenixd",
            Kind::Lnbits => "lnbits",
        }
    }

    /// Whether the backend takes whole satoshis only.
    pub fn whole_sats(self) -> bool {
        matches!(self, Kind::Phoenixd | Kind::Lnbits)
    }

    /// The default address of a backend running on the same host.
    pub fn default_url(self) -> &'static str {
        match self {
            Kind::Lnd => "https://127.0.0.1:8080",
            Kind::Cln => "https://127.0.0.1:3010",
            Kind::Phoenixd => "http://127.0.0.1:9740",
            Kind::Lnbits => "http://127.0.0.1:5000",
        }
    }
}

/// One invoice to create.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub amount_msat: u64,
    /// The LUD-06 metadata string; the invoice commits to its SHA-256.
    pub metadata: &'a str,
    pub expiry_secs: u32,
    /// A unique label (Core Lightning requires one; others store it).
    pub label: &'a str,
}

pub struct Backend {
    kind: Kind,
    base: String,
    secret: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend").field("kind", &self.kind).field("base", &self.base).finish_non_exhaustive()
    }
}

/// One printable line of at most 200 characters from a backend's reply.
fn excerpt(body: &str) -> String {
    let line: String = body.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    line.trim().to_string()
}

impl Backend {
    pub fn new(kind: Kind, base: &str, secret: String, pin: Option<[u8; 32]>, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(crate::tls::client_config(pin))
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .timeout(timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("a client with a rustls configuration always builds");
        Backend { kind, base: base.trim_end_matches('/').to_string(), secret, http }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Ask the backend for an invoice and return its BOLT11 string. The
    /// caller checks the invoice before using it.
    pub async fn create_invoice(&self, r: &Request<'_>) -> Result<String, String> {
        let hash = description_hash(r.metadata);
        let sats = r.amount_msat / 1000;
        let req = match self.kind {
            Kind::Lnd => self
                .http
                .post(format!("{}/v1/invoices", self.base))
                .header("Grpc-Metadata-macaroon", &self.secret)
                .json(&json!({
                    "value_msat": r.amount_msat.to_string(),
                    "description_hash": base64::engine::general_purpose::STANDARD.encode(hash),
                    "expiry": r.expiry_secs.to_string(),
                    "memo": "",
                })),
            Kind::Cln => self.http.post(format!("{}/v1/invoice", self.base)).header("Rune", &self.secret).json(&json!({
                "amount_msat": r.amount_msat,
                "label": r.label,
                "description": r.metadata,
                "deschashonly": true,
                "expiry": r.expiry_secs,
            })),
            Kind::Phoenixd => self
                .http
                .post(format!("{}/createinvoice", self.base))
                .basic_auth("", Some(&self.secret))
                .form(&[
                    ("amountSat", sats.to_string()),
                    ("descriptionHash", hex::encode(hash)),
                    ("expirySeconds", r.expiry_secs.to_string()),
                    ("externalId", r.label.to_string()),
                ]),
            Kind::Lnbits => {
                self.http.post(format!("{}/api/v1/payments", self.base)).header("X-Api-Key", &self.secret).json(&json!({
                    "out": false,
                    "amount": sats,
                    "unit": "sat",
                    "memo": "",
                    "description_hash": hex::encode(hash),
                    "expiry": r.expiry_secs,
                    "extra": { "tag": "lnaddr", "label": r.label },
                }))
            }
        };
        let resp = req.send().await.map_err(|e| format!("the {} backend is unreachable: {e}", self.kind.name()))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("the {} backend's reply broke off: {e}", self.kind.name()))?;
        if !status.is_success() {
            return Err(format!("the {} backend answered {}: {}", self.kind.name(), status.as_u16(), excerpt(&body)));
        }
        let v: Value = serde_json::from_str(&body)
            .map_err(|_| format!("the {} backend did not answer with JSON: {}", self.kind.name(), excerpt(&body)))?;
        let field = match self.kind {
            Kind::Lnd => "payment_request",
            Kind::Cln => "bolt11",
            Kind::Phoenixd => "serialized",
            Kind::Lnbits => "bolt11",
        };
        v.get(field)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("the {} backend's reply has no {field}", self.kind.name()))
    }
}

#[cfg(test)]
pub mod testutil {
    //! A fake of all four backend APIs that issues real, signed invoices.
    use super::*;
    use axum::extract::{Form, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct Fake {
        /// Answer every request with this status and body instead.
        pub fail: Mutex<Option<(u16, String)>>,
        /// Sign invoices for this amount instead of the one asked for.
        pub wrong_amount: Mutex<Option<u64>>,
        /// Delay each answer.
        pub delay: Mutex<Option<Duration>>,
        pub calls: AtomicU32,
        pub last: Mutex<Option<(HeaderMap, Value)>>,
    }

    pub const SECRET: &str = "s3cret";

    async fn answer(fake: &Fake, headers: HeaderMap, body: Value, kind: Kind) -> (StatusCode, String) {
        fake.calls.fetch_add(1, Ordering::SeqCst);
        let delay = *fake.delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        *fake.last.lock().unwrap() = Some((headers.clone(), body.clone()));
        if let Some((status, body)) = fake.fail.lock().unwrap().clone() {
            return (StatusCode::from_u16(status).unwrap(), body);
        }
        let authed = match kind {
            Kind::Lnd => headers.get("grpc-metadata-macaroon").is_some_and(|v| v == SECRET),
            Kind::Cln => headers.get("rune").is_some_and(|v| v == SECRET),
            Kind::Phoenixd => headers.get("authorization").is_some_and(|v| {
                v.to_str().unwrap() == format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!(":{SECRET}")))
            }),
            Kind::Lnbits => headers.get("x-api-key").is_some_and(|v| v == SECRET),
        };
        if !authed {
            return (StatusCode::UNAUTHORIZED, "{\"error\":\"bad credential\"}".into());
        }
        let num = |v: &Value| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap();
        let (msat, hash) = match kind {
            Kind::Lnd => {
                let h = base64::engine::general_purpose::STANDARD.decode(body["description_hash"].as_str().unwrap()).unwrap();
                (num(&body["value_msat"]), h)
            }
            Kind::Cln => {
                assert_eq!(body["deschashonly"], true);
                (num(&body["amount_msat"]), description_hash(body["description"].as_str().unwrap()).to_vec())
            }
            Kind::Phoenixd => (num(&body["amountSat"]) * 1000, hex::decode(body["descriptionHash"].as_str().unwrap()).unwrap()),
            Kind::Lnbits => {
                assert_eq!(body["out"], false);
                (num(&body["amount"]) * 1000, hex::decode(body["description_hash"].as_str().unwrap()).unwrap())
            }
        };
        let msat = fake.wrong_amount.lock().unwrap().unwrap_or(msat);
        let pr = crate::bolt11::testutil::invoice(msat, hash.try_into().unwrap());
        let field = match kind {
            Kind::Lnd => "payment_request",
            Kind::Cln | Kind::Lnbits => "bolt11",
            Kind::Phoenixd => "serialized",
        };
        (StatusCode::OK, json!({ field: pr, "payment_hash": "00" }).to_string())
    }

    pub fn router(fake: Arc<Fake>) -> Router {
        Router::new()
            .route(
                "/v1/invoices",
                post(|State(f): State<Arc<Fake>>, h: HeaderMap, Json(b): Json<Value>| async move { answer(&f, h, b, Kind::Lnd).await }),
            )
            .route(
                "/v1/invoice",
                post(|State(f): State<Arc<Fake>>, h: HeaderMap, Json(b): Json<Value>| async move { answer(&f, h, b, Kind::Cln).await }),
            )
            .route(
                "/createinvoice",
                post(|State(f): State<Arc<Fake>>, h: HeaderMap, Form(b): Form<HashMap<String, String>>| async move {
                    answer(&f, h, json!(b), Kind::Phoenixd).await
                }),
            )
            .route(
                "/api/v1/payments",
                post(|State(f): State<Arc<Fake>>, h: HeaderMap, Json(b): Json<Value>| async move { answer(&f, h, b, Kind::Lnbits).await }),
            )
            .with_state(fake)
    }

    /// Serve the fake over plain HTTP; returns its base URL.
    pub async fn serve(fake: Arc<Fake>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, router(fake)).await.unwrap() });
        url
    }

    /// Serve the fake over TLS with a fresh self-signed certificate; returns
    /// its base URL and the certificate (DER and PEM).
    pub async fn serve_tls(fake: Arc<Fake>) -> (String, crate::tls::testutil::SelfSigned) {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::service::TowerToHyperService;
        let cert = crate::tls::testutil::self_signed();
        let acceptor = cert.acceptor.clone();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://localhost:{}", l.local_addr().unwrap().port());
        let app = router(fake);
        tokio::spawn(async move {
            loop {
                let (tcp, _) = l.accept().await.unwrap();
                let (acceptor, app) = (acceptor.clone(), app.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                            .await;
                    }
                });
            }
        });
        (url, cert)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    const META: &str = "[[\"text/plain\",\"hi\"]]";

    fn req(amount_msat: u64) -> Request<'static> {
        Request { amount_msat, metadata: META, expiry_secs: 600, label: "lnaddr-1" }
    }

    fn check(pr: &str, msat: u64) {
        let want = crate::bolt11::Expect {
            amount_msat: msat,
            description_hash: description_hash(META),
            network: None,
            payee: None,
            now: crate::unix_now(),
            min_expiry: Duration::from_secs(1),
        };
        crate::bolt11::check(pr, &want).unwrap();
    }

    #[test]
    fn kinds_parse_and_describe_themselves() {
        for (s, k) in [("lnd", Kind::Lnd), ("cln", Kind::Cln), ("clnrest", Kind::Cln), ("phoenixd", Kind::Phoenixd), ("lnbits", Kind::Lnbits)] {
            assert_eq!(s.parse::<Kind>().unwrap(), k);
            assert!(k.default_url().contains("127.0.0.1"));
            assert!(s.starts_with(k.name()));
        }
        assert!("eclair".parse::<Kind>().unwrap_err().contains("unknown backend"));
        assert!(Kind::Phoenixd.whole_sats() && Kind::Lnbits.whole_sats());
        assert!(!Kind::Lnd.whole_sats() && !Kind::Cln.whole_sats());
    }

    #[tokio::test]
    async fn every_backend_makes_an_invoice_that_commits_to_the_metadata() {
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        for kind in [Kind::Lnd, Kind::Cln, Kind::Phoenixd, Kind::Lnbits] {
            let b = Backend::new(kind, &format!("{url}/"), SECRET.into(), None, Duration::from_secs(5));
            assert_eq!(b.kind(), kind);
            let pr = b.create_invoice(&req(21_000)).await.unwrap();
            check(&pr, 21_000);
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
        assert!(format!("{:?}", Backend::new(Kind::Lnd, &url, SECRET.into(), None, Duration::from_secs(1))).contains("Lnd"));
        assert!(!format!("{:?}", Backend::new(Kind::Lnd, &url, SECRET.into(), None, Duration::from_secs(1))).contains(SECRET));
    }

    #[tokio::test]
    async fn a_pinned_self_signed_backend_is_trusted_and_nothing_else() {
        let fake = Arc::new(Fake::default());
        let (url, cert) = serve_tls(fake).await;
        let pinned = Backend::new(Kind::Lnd, &url, SECRET.into(), Some(crate::tls::fingerprint(&cert.der)), Duration::from_secs(5));
        check(&pinned.create_invoice(&req(5_000)).await.unwrap(), 5_000);
        let wrong = Backend::new(Kind::Lnd, &url, SECRET.into(), Some([0; 32]), Duration::from_secs(5));
        assert!(wrong.create_invoice(&req(5_000)).await.unwrap_err().contains("unreachable"));
        let roots = Backend::new(Kind::Lnd, &url, SECRET.into(), None, Duration::from_secs(5));
        assert!(roots.create_invoice(&req(5_000)).await.is_err());
    }

    #[tokio::test]
    async fn backend_failures_are_explained_in_one_short_line() {
        let fake = Arc::new(Fake::default());
        let url = serve(fake.clone()).await;
        let bad_key = Backend::new(Kind::Cln, &url, "nope".into(), None, Duration::from_secs(5));
        assert!(bad_key.create_invoice(&req(1_000)).await.unwrap_err().contains("answered 401"));
        *fake.fail.lock().unwrap() = Some((500, format!("boom\n{}", "x".repeat(500))));
        let b = Backend::new(Kind::Lnd, &url, SECRET.into(), None, Duration::from_secs(5));
        let e = b.create_invoice(&req(1_000)).await.unwrap_err();
        assert!(e.contains("answered 500: boom x") && e.len() < 260, "{e}");
        *fake.fail.lock().unwrap() = Some((200, "<html>".into()));
        assert!(b.create_invoice(&req(1_000)).await.unwrap_err().contains("did not answer with JSON"));
        *fake.fail.lock().unwrap() = Some((200, "{}".into()));
        assert!(b.create_invoice(&req(1_000)).await.unwrap_err().contains("has no payment_request"));
        *fake.fail.lock().unwrap() = None;
        *fake.delay.lock().unwrap() = Some(Duration::from_secs(3));
        let quick = Backend::new(Kind::Lnd, &url, SECRET.into(), None, Duration::from_millis(300));
        assert!(quick.create_invoice(&req(1_000)).await.unwrap_err().contains("unreachable"));
        let gone = Backend::new(Kind::Lnd, "http://127.0.0.1:9", SECRET.into(), None, Duration::from_secs(1));
        assert!(gone.create_invoice(&req(1_000)).await.unwrap_err().contains("unreachable"));
    }

    #[tokio::test]
    async fn a_reply_that_breaks_off_is_reported() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{\"a\"").await.unwrap();
        });
        let b = Backend::new(Kind::Lnd, &url, SECRET.into(), None, Duration::from_secs(5));
        assert!(b.create_invoice(&req(1_000)).await.unwrap_err().contains("broke off"));
    }
}
