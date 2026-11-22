//! The optional admin web interface, on its own listener (loopback by
//! default). Pages are rendered on the server and use no JavaScript, under a
//! strict Content-Security-Policy.
//!
//! Sign-in is a token kept in the gateway's data directory. A session is a
//! random cookie (HttpOnly, SameSite=Strict, Secure unless on loopback) held
//! in memory; every form carries the session's CSRF token, and a request
//! whose Origin is another site is refused. Changing a node needs the
//! gateway's admin key to be listed among that node's admins.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::json;

use crate::cvm::CallError;
use crate::gateway::config::Config;
use crate::gateway::nodes::{Directory, NodeLink};
use crate::gateway::server::Peer;
use crate::proto::{self, ConfigView, Status};
use crate::ratelimit::RateLimiter;

const COOKIE: &str = "lnaddr_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_SESSIONS: usize = 32;

const CSS: &str = include_str!("../../assets/admin.css");
const MARK: &str = include_str!("../../../brand/logo/mark-currentcolor.svg");
const FAVICON: &str = include_str!("../../../brand/icons/favicon.svg");
const FONTS: [(&str, &[u8]); 3] = [
    ("geist.woff2", include_bytes!("../../../brand/fonts/geist.woff2")),
    (
        "martian-mono.woff2",
        include_bytes!("../../../brand/fonts/martian-mono.woff2"),
    ),
    (
        "schibsted-grotesk.woff2",
        include_bytes!("../../../brand/fonts/schibsted-grotesk.woff2"),
    ),
];

struct Session {
    csrf: String,
    expires: Instant,
}

pub struct Admin {
    pub cfg: Config,
    pub dir: Arc<Directory>,
    /// Links to each node signed with the admin key, in the same order as `dir.nodes`.
    links: Option<Vec<NodeLink>>,
    admin_npub: Option<String>,
    token: String,
    sessions: Mutex<HashMap<String, Session>>,
    login_limit: RateLimiter,
}

/// Escape text for HTML.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn random_hex() -> String {
    let k = nostr_sdk::Keys::generate();
    k.secret_key().to_secret_hex()
}

/// Compare without stopping at the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn short(npub: &str) -> String {
    if npub.len() > 20 {
        format!("{}…{}", &npub[..12], &npub[npub.len() - 6..])
    } else {
        npub.to_string()
    }
}

fn sats(msat: u64) -> String {
    let s = msat / 1000;
    let digits = s.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if !msat.is_multiple_of(1000) {
        out.push_str(&format!(".{:03}", msat % 1000));
    }
    out
}

fn ago(secs: Option<u64>) -> String {
    match secs {
        None => "never".into(),
        Some(s) if s < 60 => format!("{s}s ago"),
        Some(s) if s < 3600 => format!("{}m ago", s / 60),
        Some(s) => format!("{}h ago", s / 3600),
    }
}

fn secure_headers(r: &mut Response) {
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
}

fn html(status: StatusCode, body: String) -> Response {
    let mut r = (status, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    secure_headers(&mut r);
    r
}

fn redirect(to: &str) -> Response {
    let mut r = (StatusCode::SEE_OTHER, "").into_response();
    r.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(to).expect("redirect targets are plain paths"),
    );
    secure_headers(&mut r);
    r
}

fn layout(title: &str, nav: Option<&str>, body: &str) -> String {
    let links = match nav {
        Some(on) => {
            let a = |href: &str, label: &str| {
                let class = if on == href { " class=\"on\"" } else { "" };
                format!("<a href=\"{href}\"{class}>{label}</a>")
            };
            format!(
                "<nav>{}<form class=\"inline\" method=\"post\" action=\"/logout\"><button class=\"quiet\">Sign out</button></form></nav>",
                a("/", "OVERVIEW")
            )
        }
        None => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\"><title>{t} · deadhop lnaddr</title><link rel=\"icon\" href=\"/assets/favicon.svg\" type=\"image/svg+xml\">\
<link rel=\"stylesheet\" href=\"/assets/app.css\"></head><body><header class=\"top\"><span class=\"mark\">{MARK}</span><span class=\"word\">deadhop</span>\
<span class=\"tag\">lnaddr</span>{links}</header><main>{body}</main></body></html>",
        t = esc(title)
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    token: String,
}

#[derive(Deserialize)]
pub struct AddressForm {
    csrf: String,
    name: String,
    min_sats: String,
    max_sats: String,
    description: String,
    #[serde(default)]
    comment_allowed: String,
    #[serde(default)]
    domains: String,
}

#[derive(Deserialize)]
pub struct RemoveForm {
    csrf: String,
    name: String,
}

#[derive(Deserialize)]
pub struct LimitsForm {
    csrf: String,
    invoices_per_minute: String,
    per_caller_per_minute: String,
    invoice_expiry_secs: String,
}

#[derive(Deserialize, Default)]
pub struct NodeQuery {
    saved: Option<String>,
    edit: Option<String>,
}

impl Admin {
    pub fn new(cfg: Config, dir: Arc<Directory>, token: String, admin_keys: Option<nostr_sdk::Keys>) -> Self {
        use nostr_sdk::ToBech32;
        let admin_npub = admin_keys
            .as_ref()
            .map(|k| k.public_key().to_bech32().expect("keys encode"));
        let links = admin_keys.map(|k| {
            cfg.nodes
                .iter()
                .map(|n| NodeLink::new(n.clone(), k.clone(), cfg.socks5, cfg.limits.timeout))
                .collect()
        });
        Admin {
            cfg,
            dir,
            links,
            admin_npub,
            token,
            sessions: Mutex::new(HashMap::new()),
            login_limit: RateLimiter::new(30, 5),
        }
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The session's CSRF token, if the request carries a live session.
    fn session(&self, headers: &HeaderMap) -> Option<String> {
        let cookie = session_cookie(headers)?;
        let mut s = self.sessions();
        match s.get(&cookie) {
            Some(sess) if sess.expires > Instant::now() => Some(sess.csrf.clone()),
            Some(_) => {
                s.remove(&cookie);
                None
            }
            None => None,
        }
    }

    /// A form post must come from this site and carry the session's token.
    fn check_post(&self, headers: &HeaderMap, csrf: &str) -> Result<(), Box<Response>> {
        let Some(expected) = self.session(headers) else {
            return Err(Box::new(redirect("/login")));
        };
        let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
        let cross = headers
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
            .is_some_and(|o| o.split("://").nth(1) != Some(host));
        if cross || !same(csrf, &expected) {
            return Err(Box::new(html(StatusCode::FORBIDDEN, layout("Refused", None, "<h1>Refused.</h1><p class=\"lead\">The form did not come from this page. Reload and try again.</p>"))));
        }
        Ok(())
    }

    fn login_page(&self, message: Option<&str>) -> Response {
        let note = message
            .map(|m| format!("<div class=\"note bad\">{}</div>", esc(m)))
            .unwrap_or_default();
        let body = format!(
            "<div class=\"login\"><h1>Sign in.</h1><p class=\"lead\">The token is in <code>{TOKEN_FILE}</code> in the gateway's data directory, or run <code>lnaddr-gateway admin-token</code>.</p>{note}\
<div class=\"card\"><form method=\"post\" action=\"/login\"><label class=\"lbl\">Admin token<input name=\"token\" type=\"password\" autocomplete=\"current-password\" required></label>\
<p><button>Sign in</button></p></form></div></div>",
            TOKEN_FILE = crate::gateway::config::TOKEN_FILE
        );
        html(
            if message.is_some() {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            },
            layout("Sign in", None, &body),
        )
    }

    async fn overview(&self) -> String {
        let m = self.dir.metrics.view();
        let ms = |v: Option<u64>| v.map(|v| format!("{v} ms")).unwrap_or_else(|| "–".into());
        let mut nodes = String::new();
        let mut addrs = String::new();
        for (i, n) in self.dir.nodes.iter().enumerate() {
            let h = n.health().await;
            let dot = match (h.reachable, h.last_ok) {
                (true, _) => "ok",
                (false, Some(_)) => "bad",
                (false, None) => "wait",
            };
            nodes.push_str(&format!(
                "<tr><td><span class=\"dot {dot}\"></span><a class=\"mono\" href=\"/nodes/{i}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"muted\">{}</td></tr>",
                esc(&short(&h.npub)),
                h.relays_connected,
                h.addresses,
                ms(h.latency_ms),
                ago(h.cache_age_secs),
                esc(h.last_error.as_deref().filter(|_| !h.reachable).unwrap_or(""))
            ));
            for a in n.addresses() {
                let domains: Vec<&String> = self.cfg.domains.iter().filter(|d| a.serves(d)).collect();
                for d in domains {
                    addrs.push_str(&format!(
                        "<tr><td class=\"mono\">{}@{}</td><td>{} – {} sat</td><td>{}</td><td class=\"muted\">{}</td></tr>",
                        esc(&a.name),
                        esc(d),
                        sats(a.min_sendable),
                        sats(a.max_sendable),
                        if a.comment_allowed > 0 { format!("{} chars", a.comment_allowed) } else { "off".into() },
                        esc(&a.description)
                    ));
                }
            }
        }
        if addrs.is_empty() {
            addrs = "<tr><td colspan=\"4\" class=\"muted\">No addresses yet: the nodes have not answered, or serve none.</td></tr>".into();
        }
        let failures: String = if m.recent_failures.is_empty() {
            "<p class=\"muted\">None.</p>".into()
        } else {
            let rows: String = m
                .recent_failures
                .iter()
                .map(|(t, w)| {
                    format!(
                        "<tr><td class=\"mono\">{}</td><td>{}</td></tr>",
                        ago(Some(crate::unix_now().saturating_sub(*t))),
                        esc(w)
                    )
                })
                .collect();
            format!("<table><tr><th>When</th><th>What</th></tr>{rows}</table>")
        };
        format!(
            "<h1>Serving.</h1><p class=\"lead\">Public endpoint {listen} for {domains}. Invoices come from your nodes over ContextVM.</p>\
<div class=\"tiles\"><div class=\"tile\"><div class=\"lbl\">Invoices</div><div class=\"v\">{inv}</div></div>\
<div class=\"tile\"><div class=\"lbl\">Lookups</div><div class=\"v\">{meta}</div></div>\
<div class=\"tile\"><div class=\"lbl\">Failures</div><div class=\"v\">{fail}</div></div>\
<div class=\"tile\"><div class=\"lbl\">Invoice p50 / p95</div><div class=\"v\">{p50}</div><div class=\"muted\">{p95}</div></div></div>\
<h2>Nodes</h2><div class=\"card\"><table><tr><th>Node</th><th>Relays</th><th>Addresses</th><th>Latency</th><th>Refreshed</th><th></th></tr>{nodes}</table></div>\
<h2>Addresses</h2><div class=\"card\"><table><tr><th>Address</th><th>Range</th><th>Comments</th><th>Description</th></tr>{addrs}</table></div>\
<h2>Recent failures</h2><div class=\"card\">{failures}</div>",
            listen = esc(&self.cfg.listen.to_string()),
            domains = esc(&self.cfg.domains.join(", ")),
            inv = m.invoices,
            meta = m.metadata,
            fail = m.failures,
            p50 = ms(m.p50_ms),
            p95 = ms(m.p95_ms),
        )
    }

    async fn node_page(&self, i: usize, csrf: &str, q: &NodeQuery, message: Option<(&str, String)>) -> Response {
        let Some(n) = self.dir.nodes.get(i) else {
            return html(
                StatusCode::NOT_FOUND,
                layout("Not found", Some("/"), "<h1>No such node.</h1>"),
            );
        };
        let h = n.health().await;
        let mut body = format!(
            "<h1>Node</h1><p class=\"lead mono\">{}</p><div class=\"tiles\"><div class=\"tile\"><div class=\"lbl\">Reachable</div><div class=\"v\">{}</div></div>\
<div class=\"tile\"><div class=\"lbl\">Relays connected</div><div class=\"v\">{}</div></div><div class=\"tile\"><div class=\"lbl\">Addresses</div><div class=\"v\">{}</div></div></div>",
            esc(&h.npub),
            if h.reachable { "yes" } else { "no" },
            h.relays_connected,
            h.addresses
        );
        if let Some((kind, text)) = message {
            body.push_str(&format!("<div class=\"note {kind}\">{}</div>", esc(&text)));
        } else if q.saved.is_some() {
            body.push_str("<div class=\"note ok\">Saved on the node.</div>");
        }
        let Some(links) = &self.links else {
            body.push_str(&format!(
                "<div class=\"card dashed\"><p>Read only: this gateway has no admin key. Run <code>lnaddr-gateway admin-pubkey</code>, add the key it prints to the node's <code>admins</code>, and restart the gateway.</p></div>{}",
                self.address_table(n.addresses(), None, i)
            ));
            return html(StatusCode::OK, layout("Node", Some("/nodes"), &body));
        };
        let link = &links[i];
        let (status, view) = tokio::join!(
            link.call::<Status>(proto::GET_STATUS, json!({})),
            link.call::<ConfigView>(proto::GET_CONFIG, json!({}))
        );
        match (status, view) {
            (Ok(st), Ok(view)) => {
                body.push_str(&format!(
                    "<h2>Status</h2><div class=\"card\"><table><tr><th>Backend</th><th>Network</th><th>Invoices</th><th>Failed</th><th>Up</th><th>Remote settings</th></tr>\
<tr><td>{} <span class=\"muted\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr></table>{}</div>",
                    esc(&st.backend),
                    esc(&view.backend.url),
                    esc(&st.network),
                    st.invoices_made,
                    st.invoices_failed,
                    ago(Some(st.uptime_secs)).replace(" ago", ""),
                    if st.remote_settings { "on" } else { "off" },
                    st.last_error.map(|e| format!("<p class=\"muted\">Last error: {}</p>", esc(&e))).unwrap_or_default()
                ));
                let editable = view.sources.remote.then_some(csrf);
                body.push_str(&self.address_table(view.addresses.clone(), editable, i));
                if let Some(csrf) = editable {
                    let edit = q
                        .edit
                        .as_deref()
                        .and_then(|name| view.addresses.iter().find(|a| a.name == name));
                    body.push_str(&address_form(i, csrf, edit));
                    body.push_str(&limits_form(i, csrf, &view));
                } else {
                    body.push_str(
                        "<div class=\"card dashed\"><p>Remote settings are switched off on this node. Turn them on with <code>LNADDR_NODE_REMOTE=on</code> (or <code>sources.remote = true</code>) to change addresses from here.</p></div>",
                    );
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                let why = match &e {
                    CallError::Refused { code, .. } if code == proto::code::UNAUTHORIZED => format!(
                        "The node does not list this gateway's admin key. Add {} to the node's admins.",
                        self.admin_npub.clone().unwrap_or_default()
                    ),
                    other => format!("The node did not answer: {other}"),
                };
                body.push_str(&format!(
                    "<div class=\"note bad\">{}</div>{}",
                    esc(&why),
                    self.address_table(n.addresses(), None, i)
                ));
            }
        }
        html(StatusCode::OK, layout("Node", Some("/nodes"), &body))
    }

    fn address_table(&self, addrs: Vec<proto::AddressInfo>, csrf: Option<&str>, i: usize) -> String {
        let mut rows = String::new();
        for a in &addrs {
            let actions = match csrf {
                Some(c) => format!(
                    "<a href=\"/nodes/{i}?edit={n}\">Edit</a> <form class=\"inline\" method=\"post\" action=\"/nodes/{i}/remove\"><input type=\"hidden\" name=\"csrf\" value=\"{c}\"><input type=\"hidden\" name=\"name\" value=\"{n}\"><button class=\"danger\">Remove</button></form>",
                    n = esc(&a.name)
                ),
                None => String::new(),
            };
            rows.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{} – {} sat</td><td>{}</td><td>{}</td><td class=\"muted\">{}</td><td>{actions}</td></tr>",
                esc(&a.name),
                sats(a.min_sendable),
                sats(a.max_sendable),
                a.comment_allowed,
                esc(&if a.domains.is_empty() { "any".to_string() } else { a.domains.join(", ") }),
                esc(&a.description)
            ));
        }
        if rows.is_empty() {
            rows = "<tr><td colspan=\"6\" class=\"muted\">None.</td></tr>".into();
        }
        format!("<h2>Addresses</h2><div class=\"card\"><table><tr><th>Name</th><th>Range</th><th>Comment chars</th><th>Domains</th><th>Description</th><th></th></tr>{rows}</table></div>")
    }

    /// Call an admin tool on node `i`, then refresh the public cache.
    async fn change(&self, i: usize, tool: &'static str, args: serde_json::Value) -> Result<(), String> {
        let Some(link) = self.links.as_ref().and_then(|l| l.get(i)) else {
            return Err("this gateway has no admin key".into());
        };
        link.call::<ConfigView>(tool, args).await.map_err(|e| e.to_string())?;
        let _ = self.dir.nodes[i].refresh().await;
        Ok(())
    }

    pub async fn close(&self) {
        for l in self.links.iter().flatten() {
            l.close().await;
        }
    }
}

fn address_form(i: usize, csrf: &str, edit: Option<&proto::AddressInfo>) -> String {
    let (name, min, max, desc, comments, domains, title) = match edit {
        Some(a) => (
            a.name.clone(),
            (a.min_sendable / 1000).to_string(),
            (a.max_sendable / 1000).to_string(),
            a.description.clone(),
            a.comment_allowed.to_string(),
            a.domains.join(", "),
            format!("Edit {}", a.name),
        ),
        None => (
            String::new(),
            "1".into(),
            "1000000".into(),
            String::new(),
            "0".into(),
            String::new(),
            "Add an address".into(),
        ),
    };
    format!(
        "<h2>{title}</h2><div class=\"card\"><form class=\"grid\" method=\"post\" action=\"/nodes/{i}/address\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<label class=\"lbl\">Name<input name=\"name\" value=\"{}\" pattern=\"[a-z0-9_.\\-]{{1,64}}\" required></label>\
<label class=\"lbl\">Min sats<input name=\"min_sats\" value=\"{}\" inputmode=\"numeric\" required></label>\
<label class=\"lbl\">Max sats<input name=\"max_sats\" value=\"{}\" inputmode=\"numeric\" required></label>\
<label class=\"lbl\">Comment chars<input name=\"comment_allowed\" value=\"{}\" inputmode=\"numeric\"></label>\
<label class=\"lbl\">Description<input name=\"description\" value=\"{}\" required></label>\
<label class=\"lbl\">Domains (blank = any)<input name=\"domains\" value=\"{}\"></label>\
<div><button>Save on the node</button></div></form></div>",
        esc(&name),
        esc(&min),
        esc(&max),
        esc(&comments),
        esc(&desc),
        esc(&domains),
        title = esc(&title)
    )
}

fn limits_form(i: usize, csrf: &str, v: &ConfigView) -> String {
    format!(
        "<h2>Limits</h2><div class=\"card\"><form class=\"grid\" method=\"post\" action=\"/nodes/{i}/limits\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<label class=\"lbl\">Invoices / minute<input name=\"invoices_per_minute\" value=\"{}\" inputmode=\"numeric\"></label>\
<label class=\"lbl\">Per caller / minute<input name=\"per_caller_per_minute\" value=\"{}\" inputmode=\"numeric\"></label>\
<label class=\"lbl\">Invoice expiry (s)<input name=\"invoice_expiry_secs\" value=\"{}\" inputmode=\"numeric\"></label>\
<div><button>Save limits</button></div></form></div>",
        v.limits.invoices_per_minute, v.limits.per_caller_per_minute, v.limits.invoice_expiry_secs
    )
}

fn number(field: &str, s: &str) -> Result<u64, String> {
    s.trim()
        .replace([',', '_'], "")
        .parse()
        .map_err(|_| format!("{field}: {s:?} is not a whole number"))
}

impl AddressForm {
    fn args(&self) -> Result<serde_json::Value, String> {
        let min = number("Min sats", &self.min_sats)?;
        let max = number("Max sats", &self.max_sats)?;
        let comments = if self.comment_allowed.trim().is_empty() {
            0
        } else {
            number("Comment chars", &self.comment_allowed)?
        };
        let domains = crate::settings::list(&self.domains);
        Ok(json!({
            "name": self.name.trim(),
            "min_sendable": min.saturating_mul(1000),
            "max_sendable": max.saturating_mul(1000),
            "description": self.description.trim(),
            "comment_allowed": comments.min(u16::MAX as u64),
            "domains": domains,
        }))
    }
}

impl LimitsForm {
    fn args(&self) -> Result<serde_json::Value, String> {
        Ok(json!({
            "invoices_per_minute": number("Invoices / minute", &self.invoices_per_minute)?,
            "per_caller_per_minute": number("Per caller / minute", &self.per_caller_per_minute)?,
            "invoice_expiry_secs": number("Invoice expiry", &self.invoice_expiry_secs)?,
        }))
    }
}

type St = State<Arc<Admin>>;

async fn get_login(State(a): St, headers: HeaderMap) -> Response {
    if a.session(&headers).is_some() {
        return redirect("/");
    }
    a.login_page(None)
}

async fn post_login(State(a): St, Extension(peer): Extension<Peer>, Form(f): Form<LoginForm>) -> Response {
    let who = peer.0.map(|ip| ip.to_string()).unwrap_or_else(|| "local".into());
    if !a.login_limit.allow(&who, crate::unix_now()) {
        return a.login_page(Some("Too many attempts. Wait a minute."));
    }
    if !same(f.token.trim(), &a.token) {
        tracing::warn!(from = %who, "admin sign-in refused");
        return a.login_page(Some("That token is not right."));
    }
    let id = random_hex();
    {
        let mut s = a.sessions();
        let now = Instant::now();
        s.retain(|_, v| v.expires > now);
        if s.len() >= MAX_SESSIONS {
            let oldest = s
                .iter()
                .min_by_key(|(_, v)| v.expires)
                .map(|(k, _)| k.clone())
                .expect("the map is full");
            s.remove(&oldest);
        }
        s.insert(
            id.clone(),
            Session {
                csrf: random_hex(),
                expires: now + SESSION_TTL,
            },
        );
    }
    let secure = if a.cfg.secure_cookie { "; Secure" } else { "" };
    let mut r = redirect("/");
    let cookie = format!(
        "{COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{secure}",
        SESSION_TTL.as_secs()
    );
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie is ASCII"),
    );
    r
}

/// The session id in the request's cookies.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == COOKIE).then(|| v.to_string())
        })
}

async fn post_logout(State(a): St, headers: HeaderMap) -> Response {
    let id = session_cookie(&headers).unwrap_or_default();
    a.sessions().remove(&id);
    let mut r = redirect("/login");
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("lnaddr_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    r
}

async fn get_overview(State(a): St, headers: HeaderMap) -> Response {
    if a.session(&headers).is_none() {
        return redirect("/login");
    }
    let body = a.overview().await;
    html(StatusCode::OK, layout("Overview", Some("/"), &body))
}

async fn get_node(State(a): St, Path(i): Path<usize>, Query(q): Query<NodeQuery>, headers: HeaderMap) -> Response {
    let Some(csrf) = a.session(&headers) else {
        return redirect("/login");
    };
    a.node_page(i, &csrf, &q, None).await
}

async fn finish(a: &Admin, i: usize, csrf: &str, outcome: Result<(), String>) -> Response {
    match outcome {
        Ok(()) => redirect(&format!("/nodes/{i}?saved=1")),
        Err(e) => {
            a.node_page(i, csrf, &NodeQuery::default(), Some(("bad", format!("Not saved. {e}"))))
                .await
        }
    }
}

async fn post_address(State(a): St, Path(i): Path<usize>, headers: HeaderMap, Form(f): Form<AddressForm>) -> Response {
    if let Err(r) = a.check_post(&headers, &f.csrf) {
        return *r;
    }
    let outcome = match f.args() {
        Ok(args) => a.change(i, proto::SET_ADDRESS, args).await,
        Err(e) => Err(e),
    };
    finish(&a, i, &f.csrf, outcome).await
}

async fn post_remove(State(a): St, Path(i): Path<usize>, headers: HeaderMap, Form(f): Form<RemoveForm>) -> Response {
    if let Err(r) = a.check_post(&headers, &f.csrf) {
        return *r;
    }
    let outcome = a.change(i, proto::REMOVE_ADDRESS, json!({ "name": f.name })).await;
    finish(&a, i, &f.csrf, outcome).await
}

async fn post_limits(State(a): St, Path(i): Path<usize>, headers: HeaderMap, Form(f): Form<LimitsForm>) -> Response {
    if let Err(r) = a.check_post(&headers, &f.csrf) {
        return *r;
    }
    let outcome = match f.args() {
        Ok(args) => a.change(i, proto::SET_LIMITS, args).await,
        Err(e) => Err(e),
    };
    finish(&a, i, &f.csrf, outcome).await
}

async fn asset(Path(file): Path<String>) -> Response {
    let (ctype, body): (&'static str, Vec<u8>) = match file.as_str() {
        "app.css" => ("text/css; charset=utf-8", CSS.as_bytes().to_vec()),
        "favicon.svg" => ("image/svg+xml", FAVICON.as_bytes().to_vec()),
        f => match FONTS.iter().find(|(n, _)| *n == f) {
            Some((_, bytes)) => ("font/woff2", bytes.to_vec()),
            None => return html(StatusCode::NOT_FOUND, String::new()),
        },
    };
    let mut r = (StatusCode::OK, body).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
    secure_headers(&mut r);
    r
}

async fn not_found() -> Response {
    html(
        StatusCode::NOT_FOUND,
        layout(
            "Not found",
            None,
            "<h1>Not found.</h1><p class=\"lead\"><a href=\"/\">Back to the overview</a></p>",
        ),
    )
}

pub fn router(a: Arc<Admin>) -> Router {
    Router::new()
        .route("/", get(get_overview))
        .route("/login", get(get_login).post(post_login))
        .route("/logout", post(post_logout))
        .route("/nodes/{i}", get(get_node))
        .route("/nodes/{i}/address", post(post_address))
        .route("/nodes/{i}/remove", post(post_remove))
        .route("/nodes/{i}/limits", post(post_limits))
        .route("/assets/{file}", get(asset))
        .fallback(not_found)
        .with_state(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::config::NodeConfig;

    fn admin() -> Admin {
        let node = NodeConfig {
            pubkey: nostr_sdk::Keys::generate().public_key(),
            names: None,
            relays: vec!["ws://127.0.0.1:9".into()],
            payee: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::gateway::tests::gateway_config_for(vec![node], dir.path());
        cfg.limits.timeout = Duration::from_secs(1);
        let d = Arc::new(Directory::new(
            cfg.nodes.clone(),
            nostr_sdk::Keys::generate(),
            None,
            cfg.limits.timeout,
        ));
        Admin::new(cfg, d, "t".into(), None)
    }

    fn with_cookie(id: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE}={id}")).unwrap(),
        );
        h
    }

    #[test]
    fn text_is_escaped_and_numbers_read_well() {
        assert_eq!(
            esc("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(short("npub1abc"), "npub1abc");
        assert_eq!(
            short(&format!("npub1{}", "q".repeat(58))),
            format!("npub1qqqqqqq…{}", "q".repeat(6))
        );
        assert_eq!(sats(1_234_567_000), "1,234,567");
        assert_eq!(sats(1_500), "1.500");
        assert_eq!(ago(None), "never");
        assert_eq!(ago(Some(5)), "5s ago");
        assert_eq!(ago(Some(125)), "2m ago");
        assert_eq!(ago(Some(7300)), "2h ago");
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "ab"));
    }

    #[test]
    fn sessions_expire_and_the_oldest_gives_way() {
        let a = admin();
        a.sessions().insert(
            "old".into(),
            Session {
                csrf: "c".into(),
                expires: Instant::now() - Duration::from_secs(1),
            },
        );
        assert_eq!(a.session(&with_cookie("old")), None);
        assert!(a.sessions().is_empty(), "an expired session is forgotten");
        assert_eq!(a.session(&with_cookie("unknown")), None);
        assert_eq!(a.session(&HeaderMap::new()), None);
        let now = Instant::now() + Duration::from_secs(60);
        for i in 0..MAX_SESSIONS {
            a.sessions().insert(
                format!("s{i}"),
                Session {
                    csrf: "c".into(),
                    expires: now + Duration::from_secs(i as u64),
                },
            );
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = Arc::new(a);
        let r = rt.block_on(post_login(
            State(a.clone()),
            Extension(Peer(None)),
            Form(LoginForm { token: "t".into() }),
        ));
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let s = a.sessions();
        assert_eq!(s.len(), MAX_SESSIONS);
        assert!(!s.contains_key("s0"), "the session closest to expiry was dropped");
    }

    #[tokio::test]
    async fn a_node_never_heard_from_waits_and_shows_no_addresses() {
        let a = admin();
        let page = a.overview().await;
        assert!(page.contains("dot wait") && page.contains("No addresses yet"), "{page}");
        assert!(a.address_table(vec![], None, 0).contains("None."));
        assert!(a
            .change(0, proto::SET_LIMITS, json!({}))
            .await
            .unwrap_err()
            .contains("no admin key"));
    }
}
