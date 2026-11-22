//! The public HTTP side: LUD-16 paths only.
//!
//!   GET /.well-known/lnurlp/<name>            LUD-06 pay parameters (from the cache)
//!   GET /.well-known/lnurlp/<name>/callback   an invoice (asks the node over ContextVM)
//!   GET /healthz                              ok / degraded, nothing else
//!
//! Both LNURL paths share one prefix, so a reverse proxy forwards a single
//! location. Nothing else is mounted here: the admin interface has its own
//! listener and is unreachable from this one.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde_json::json;

use crate::gateway::config::Config;
use crate::gateway::nodes::{Directory, Fail};
use crate::gateway::server::Peer;
use crate::lnurl::{self, ErrorResponse, InvoiceResponse, PayRequest};
use crate::ratelimit::RateLimiter;

pub struct Public {
    pub cfg: Config,
    pub dir: Arc<Directory>,
    params_limit: RateLimiter,
    invoice_limit: RateLimiter,
}

impl Public {
    pub fn new(cfg: Config, dir: Arc<Directory>) -> Self {
        let l = &cfg.limits;
        Public {
            // Parameters come from the cache, so they get a larger budget.
            params_limit: RateLimiter::new(l.global_per_minute.saturating_mul(4), l.per_ip_per_minute.saturating_mul(4)),
            invoice_limit: RateLimiter::new(l.global_per_minute, l.per_ip_per_minute),
            cfg,
            dir,
        }
    }

    /// The domain a request is for: the only configured domain, or the
    /// request's host when it is one of the configured ones. A forwarded host
    /// counts only from a trusted proxy.
    fn domain(&self, headers: &HeaderMap, trusted: bool) -> Option<String> {
        if let [only] = self.cfg.domains.as_slice() {
            return Some(only.clone());
        }
        let forwarded = trusted.then(|| headers.get("x-forwarded-host")).flatten();
        let host = forwarded.or_else(|| headers.get(header::HOST))?.to_str().ok()?;
        let host = host.split(',').next()?.trim().to_ascii_lowercase();
        let host = host.strip_suffix(".").unwrap_or(&host).to_string();
        self.cfg.domains.iter().find(|d| **d == host || d.split(':').next() == Some(host.as_str())).cloned()
    }

    fn trusted(&self, peer: Peer) -> bool {
        match peer.0 {
            None => true,
            Some(ip) => self.cfg.trusted_proxies.iter().any(|n| n.contains(ip)),
        }
    }

    /// The client's address: the peer, or for a trusted proxy the last
    /// address in X-Forwarded-For that is not itself a trusted proxy.
    fn client_ip(&self, peer: Peer, headers: &HeaderMap) -> String {
        if !self.trusted(peer) {
            return peer.0.map(|ip| ip.to_string()).unwrap_or_default();
        }
        let forwarded: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let client = forwarded.iter().rev().find(|ip| !self.cfg.trusted_proxies.iter().any(|n| n.contains(**ip)));
        match (client, peer.0) {
            (Some(ip), _) => ip.to_string(),
            (None, Some(ip)) => ip.to_string(),
            (None, None) => "local".into(),
        }
    }
}

fn reply(status: u16, body: String, cache: &'static str) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

fn error(f: Fail) -> Response {
    let body = serde_json::to_string(&ErrorResponse::new(f.reason())).expect("an error always serialises");
    reply(f.status(), body, "no-store")
}

/// `Alice+tips` → `alice`: names are case-insensitive in practice, and a
/// `+tag` is stripped (LUD-16).
pub fn normalise(raw: &str) -> Option<String> {
    let name = raw.split('+').next().unwrap_or_default().to_ascii_lowercase();
    lnurl::valid_name(&name).then_some(name)
}

async fn pay_params(State(p): State<Arc<Public>>, Path(raw): Path<String>, Extension(peer): Extension<Peer>, headers: HeaderMap) -> Response {
    let Some(name) = normalise(&raw) else { return error(Fail::NotFound) };
    let Some(domain) = p.domain(&headers, p.trusted(peer)) else { return error(Fail::NotFound) };
    if !p.params_limit.allow(&p.client_ip(peer, &headers), crate::unix_now()) {
        return error(Fail::RateLimited);
    }
    match p.dir.pay_params(&name, &domain).await {
        Ok(a) => {
            let body = PayRequest {
                tag: "payRequest".into(),
                callback: format!("{}/.well-known/lnurlp/{name}/callback", p.cfg.origin(&domain)),
                min_sendable: a.min_sendable,
                max_sendable: a.max_sendable,
                metadata: lnurl::metadata(&name, &domain, &a.description),
                comment_allowed: (a.comment_allowed > 0).then_some(a.comment_allowed),
            };
            reply(200, serde_json::to_string(&body).expect("pay parameters always serialise"), "public, max-age=60")
        }
        Err(f) => error(f),
    }
}

async fn callback(
    State(p): State<Arc<Public>>,
    Path(raw): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(name) = normalise(&raw) else { return error(Fail::NotFound) };
    let Some(domain) = p.domain(&headers, p.trusted(peer)) else { return error(Fail::NotFound) };
    if uri.query().is_some_and(|q| q.len() > 4096) {
        return error(Fail::Invalid("the request is too long".into()));
    }
    let Some(amount) = q.get("amount").and_then(|a| a.parse::<u64>().ok()) else {
        return error(Fail::Invalid("amount (millisatoshis) is required".into()));
    };
    if !p.invoice_limit.allow(&p.client_ip(peer, &headers), crate::unix_now()) {
        return error(Fail::RateLimited);
    }
    let comment = q.get("comment").filter(|c| !c.is_empty()).cloned();
    match p.dir.invoice(&name, &domain, amount, comment).await {
        Ok(pr) => {
            let body = InvoiceResponse { pr, routes: vec![] };
            reply(200, serde_json::to_string(&body).expect("an invoice always serialises"), "no-store")
        }
        Err(f) => error(f),
    }
}

async fn healthz(State(p): State<Arc<Public>>) -> Response {
    let mut up = false;
    for n in &p.dir.nodes {
        up |= n.health().await.reachable;
    }
    let (status, word) = if up { (200, "ok") } else { (503, "degraded") };
    reply(status, json!({ "status": word }).to_string(), "no-store")
}

async fn preflight() -> Response {
    let mut r = reply(204, String::new(), "no-store");
    r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET"));
    r
}

async fn not_found() -> Response {
    error(Fail::NotFound)
}

pub fn router(p: Arc<Public>) -> Router {
    Router::new()
        .route("/.well-known/lnurlp/{name}", get(pay_params).options(preflight))
        .route("/.well-known/lnurlp/{name}/callback", get(callback).options(preflight))
        .route("/healthz", get(healthz))
        .fallback(not_found)
        .with_state(p)
}
