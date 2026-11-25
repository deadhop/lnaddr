//! Running the gateway and the `lnaddr-gateway` command line.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Keys, ToBech32};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::gateway::admin::{self, Admin};
use crate::gateway::config::{self, Config, Listen, ADMIN_KEY_FILE, KEY_FILE, TOKEN_FILE};
use crate::gateway::http::{self, Public};
use crate::gateway::network::{Network, ADMIN_LANE, GATEWAY_LANE};
use crate::gateway::nodes::{Directory, NodeLink};
use crate::gateway::server;
use crate::gateway::supervise::{close, connect, dead, fall_back, or_log, relay_setup, supervise, Ident, Supervised};
use crate::gateway::supervise::{DEAD_AT_START, RELAY_CHECK, RELAY_HEALTH_EVERY};
use crate::proto::{self, ConfigView, Status};

pub struct Gateway {
    pub keys: Keys,
    pub dir: Arc<Directory>,
    pub net: Arc<Network>,
    pub public: Listen,
    pub admin: Option<Listen>,
    /// The key the network console signs in to (`admin.key`), when `admins` are set.
    pub console: Option<Keys>,
    admin_state: Option<Arc<Admin>>,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    supervisor: JoinHandle<()>,
    /// The proxy probe loop (tests stop it to plan routes by hand).
    pub(crate) probe: JoinHandle<()>,
    /// Cancels the console's current request loop (tests use it to simulate a crash).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) current: Arc<std::sync::Mutex<CancellationToken>>,
}

/// The admin token, created on first use.
pub fn admin_token(data_dir: &std::path::Path) -> Result<String, String> {
    let path = data_dir.join(TOKEN_FILE);
    match crate::files::read_private(&path)? {
        Some(t) if !t.trim().is_empty() => Ok(t.trim().to_string()),
        _ => {
            let token = Keys::generate().secret_key().to_secret_hex();
            crate::files::write_private(&path, &format!("{token}\n"))?;
            Ok(token)
        }
    }
}

/// The admin key, if one was made (`lnaddr-gateway admin-pubkey`).
pub fn admin_keys(data_dir: &std::path::Path) -> Result<Option<Keys>, String> {
    let path = data_dir.join(ADMIN_KEY_FILE);
    if path.exists() {
        crate::files::load_or_create_keys(&path).map(Some)
    } else {
        Ok(None)
    }
}

pub async fn start(cfg: Config) -> Result<Gateway, String> {
    crate::files::open_dir(&cfg.data_dir)?;
    let keys = crate::files::load_or_create_keys(&cfg.data_dir.join(KEY_FILE))?;
    // With admins listed, the admin key is also the console's way in: made now.
    let admin_key = if cfg.admins.is_empty() {
        admin_keys(&cfg.data_dir)?
    } else {
        Some(crate::files::load_or_create_keys(&cfg.data_dir.join(ADMIN_KEY_FILE))?)
    };
    let net = Arc::new(Network::new(cfg.clone()));
    net.load_network();
    net.set_pubkey(GATEWAY_LANE, &keys.public_key().to_hex());
    if let Some(k) = &admin_key {
        net.set_pubkey(ADMIN_LANE, &k.public_key().to_hex());
    }
    // Look at the proxies before connecting anything, so that no relay is
    // ever reached the wrong way round.
    net.runtime.refresh_pool(&*net).await;
    let dir = Arc::new(Directory::new(
        cfg.nodes.clone(),
        keys.clone(),
        net.clone(),
        cfg.limits.timeout,
    ));
    let stop = CancellationToken::new();
    let mut tasks = Vec::new();
    let public_bound = server::bind(&cfg.listen).await?;
    let public = public_bound.local();
    let admin_bound = match &cfg.admin_listen {
        Some(l) => Some(server::bind(l).await?),
        None => None,
    };
    let admin = admin_bound.as_ref().map(server::Bound::local);
    let console = admin_key.clone().filter(|_| !cfg.admins.is_empty());
    let id = console.clone().map(|keys| Ident {
        keys,
        allowed: cfg.admins.iter().map(|k| k.to_hex()).collect(),
    });
    let saved = relay_setup(&net) != (net.baseline().relays.clone(), BTreeMap::new());
    // A console server that cannot start leaves the LNURL side serving; the
    // supervisor tries it again.
    let mut link = or_log(
        &net,
        connect(&id, &net, &dir).await,
        "could not start the console server",
    );
    // Saved relays the console or the gateway key reaches nothing on would
    // leave it unmanageable or without invoices, and a restart would not
    // help: back to the configured ones.
    if saved && (dead(&link, RELAY_CHECK).await || !dir.any_connects_within(RELAY_CHECK).await) {
        tracing::warn!("no saved relay connected; using the configured relays");
        close(&mut link).await;
        link = or_log(
            &net,
            fall_back(&id, &net, &dir, DEAD_AT_START).await,
            "could not go back to the configured relays",
        );
    }
    // Keep the cache warm: refresh now, then every cache period.
    tasks.push(tokio::spawn({
        let (dir, stop, every) = (dir.clone(), stop.clone(), cfg.limits.cache);
        async move {
            loop {
                dir.refresh_all().await;
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(every) => {}
                }
            }
        }
    }));
    let app = http::router(Arc::new(Public::new(cfg.clone(), dir.clone())));
    tasks.push(tokio::spawn(server::serve(
        public_bound,
        app,
        cfg.limits.max_connections,
        stop.clone(),
    )));
    let mut admin_state = None;
    if let Some(bound) = admin_bound {
        let state = Arc::new(Admin::new(
            cfg.clone(),
            dir.clone(),
            net.clone(),
            admin_token(&cfg.data_dir)?,
            admin_key,
        ));
        tasks.push(tokio::spawn(server::serve(
            bound,
            admin::router(state.clone()),
            64,
            stop.clone(),
        )));
        admin_state = Some(state);
    }
    let current = Arc::new(std::sync::Mutex::new(CancellationToken::new()));
    let supervisor = tokio::spawn(supervise(
        Supervised {
            net: net.clone(),
            dir: dir.clone(),
            id,
            current: current.clone(),
        },
        link,
        stop.clone(),
    ));
    let probe = tokio::spawn({
        let (net, stop) = (net.clone(), stop.clone());
        async move { deadhop_netengine::proxypool::run_probe_loop(&net.runtime, &*net, stop).await }
    });
    tasks.push(tokio::spawn({
        let (net, stop) = (net.clone(), stop.clone());
        async move {
            loop {
                net.runtime.refresh_relay_health(&*net).await;
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(RELAY_HEALTH_EVERY) => {}
                }
            }
        }
    }));
    Ok(Gateway {
        keys,
        dir,
        net,
        public,
        admin,
        console,
        admin_state,
        stop,
        tasks,
        supervisor,
        probe,
        current,
    })
}

impl Gateway {
    pub async fn until(self, shutdown: crate::Shutdown) {
        shutdown.await;
        self.stop.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.supervisor).await;
        let _ = self.probe.await;
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
        if let Some(a) = &self.admin_state {
            a.close().await;
        }
        self.dir.close().await;
    }
}

pub const USAGE: &str = "usage:
  lnaddr-gateway [serve]                      run the gateway
  lnaddr-gateway pubkey                       print the gateway's public key (npub) for the node's gateways
  lnaddr-gateway admin-pubkey                 print the admin key (npub) for the node's admins, creating it
  lnaddr-gateway admin-token                  print the web admin sign-in token, creating it
  lnaddr-gateway status                       ask every node how it is and what it serves
  lnaddr-gateway test NAME[@DOMAIN] [SATS]    get and check a real invoice, as a wallet would
  lnaddr-gateway node status [N]              admin: the node's backend, counters and last error
  lnaddr-gateway node config [N]              admin: the node's configuration (no secrets)
  lnaddr-gateway node set-address N NAME MIN_SATS MAX_SATS DESCRIPTION [COMMENT_CHARS]
  lnaddr-gateway node remove-address N NAME
  lnaddr-gateway node set-limits N PER_MINUTE PER_CALLER EXPIRY_SECS
  lnaddr-gateway version

N is the node's number in the configuration (1 is the first; the default).
options:
  --config FILE                               read FILE (TOML) before the LNADDR_GATEWAY_* variables";

pub const DEFAULT_LOG: &str = "warn,deadhop_lnaddr=info,contextvm_sdk=off,rmcp=off";

fn fail(out: &mut dyn Write, e: &str) -> ExitCode {
    let _ = writeln!(out, "lnaddr-gateway: {e}");
    ExitCode::FAILURE
}

fn usage(out: &mut dyn Write) -> ExitCode {
    let _ = writeln!(out, "{USAGE}");
    ExitCode::from(2)
}

fn npub(k: &Keys) -> String {
    k.public_key().to_bech32().expect("keys encode")
}

fn node_index(cfg: &Config, arg: Option<&String>) -> Result<usize, String> {
    let n: usize = match arg {
        Some(a) => a.parse().map_err(|_| format!("{a:?} is not a node number"))?,
        None => 1,
    };
    if n == 0 || n > cfg.nodes.len() {
        return Err(format!(
            "there is no node {n} (the configuration lists {})",
            cfg.nodes.len()
        ));
    }
    Ok(n - 1)
}

async fn admin_link(cfg: &Config, i: usize) -> Result<NodeLink, String> {
    let keys = admin_keys(&cfg.data_dir)?
        .ok_or("no admin key yet: run `lnaddr-gateway admin-pubkey` and add the key to the node's admins")?;
    Ok(NodeLink::new(
        cfg.nodes[i].clone(),
        keys,
        ADMIN_LANE,
        Network::for_command(cfg).await,
        cfg.limits.timeout,
    ))
}

fn print_view(out: &mut dyn Write, v: &ConfigView) {
    let _ = writeln!(
        out,
        "backend   {} at {} (credential {}, pin {})",
        v.backend.kind,
        v.backend.url,
        v.backend.secret,
        v.backend.tls_pin.as_deref().unwrap_or("none")
    );
    let _ = writeln!(out, "network   {}", v.network);
    let _ = writeln!(out, "relays    {}", v.relays.join(", "));
    let _ = writeln!(
        out,
        "sources   file={} env={} remote={}",
        v.sources.file, v.sources.env, v.sources.remote
    );
    let l = &v.limits;
    let _ = writeln!(
        out,
        "limits    {}/min, {}/min per caller, {} at once, invoices live {}s",
        l.invoices_per_minute, l.per_caller_per_minute, l.concurrent, l.invoice_expiry_secs
    );
    for a in &v.addresses {
        let _ = writeln!(
            out,
            "address   {:<16} {}–{} sat  comments {}  {}",
            a.name,
            a.min_sendable / 1000,
            a.max_sendable / 1000,
            a.comment_allowed,
            a.description
        );
    }
}

async fn node_command(cfg: &Config, args: &[String], out: &mut dyn Write) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    let i = node_index(cfg, args.get(1))?;
    let link = admin_link(cfg, i).await?;
    let num = |s: &String| {
        s.replace([',', '_'], "")
            .parse::<u64>()
            .map_err(|_| format!("{s:?} is not a whole number"))
    };
    let outcome = match (sub, &args[2.min(args.len())..]) {
        ("status", []) => link.call::<Status>(proto::GET_STATUS, json!({})).await.map(|st| {
            let _ = writeln!(out, "backend   {} ({})", st.backend, st.network);
            let _ = writeln!(
                out,
                "invoices  {} made, {} failed",
                st.invoices_made, st.invoices_failed
            );
            let _ = writeln!(out, "up        {}s", st.uptime_secs);
            let _ = writeln!(out, "remote    {}", if st.remote_settings { "on" } else { "off" });
            let _ = writeln!(out, "payee     {}", st.payee.as_deref().unwrap_or("(no invoice yet)"));
            let _ = writeln!(out, "error     {}", st.last_error.as_deref().unwrap_or("none"));
        }),
        ("config", []) => link
            .call::<ConfigView>(proto::GET_CONFIG, json!({}))
            .await
            .map(|v| print_view(out, &v)),
        ("set-address", [name, min, max, desc, rest @ ..]) if rest.len() <= 1 => {
            let comments = rest.first().map(num).transpose()?.unwrap_or(0);
            let args = json!({
                "name": name, "min_sendable": num(min)?.saturating_mul(1000), "max_sendable": num(max)?.saturating_mul(1000),
                "description": desc, "comment_allowed": comments.min(u16::MAX as u64),
            });
            link.call::<ConfigView>(proto::SET_ADDRESS, args)
                .await
                .map(|v| print_view(out, &v))
        }
        ("remove-address", [name]) => link
            .call::<ConfigView>(proto::REMOVE_ADDRESS, json!({ "name": name }))
            .await
            .map(|v| print_view(out, &v)),
        ("set-limits", [per_min, per_caller, expiry]) => {
            let args = json!({ "invoices_per_minute": num(per_min)?, "per_caller_per_minute": num(per_caller)?, "invoice_expiry_secs": num(expiry)? });
            link.call::<ConfigView>(proto::SET_LIMITS, args)
                .await
                .map(|v| print_view(out, &v))
        }
        _ => {
            link.close().await;
            return Err(format!("unknown node command\n\n{USAGE}"));
        }
    };
    link.close().await;
    outcome.map_err(|e| e.to_string())
}

/// The gateway's own key, creating the data directory and key if needed.
fn own_keys(cfg: &Config) -> Result<Keys, String> {
    crate::files::open_dir(&cfg.data_dir)?;
    crate::files::load_or_create_keys(&cfg.data_dir.join(KEY_FILE))
}

async fn status_command(cfg: &Config, out: &mut dyn Write) -> Result<(), String> {
    let dir = Directory::new(
        cfg.nodes.clone(),
        own_keys(cfg)?,
        Network::for_command(cfg).await,
        cfg.limits.timeout,
    );
    let started = Instant::now();
    dir.refresh_all().await;
    let mut any = false;
    for (i, n) in dir.nodes.iter().enumerate() {
        let h = n.health().await;
        any |= h.reachable;
        let state = if h.reachable {
            format!("ok in {} ms", h.latency_ms.unwrap_or(0))
        } else {
            format!("NOT REACHABLE: {}", h.last_error.unwrap_or_default())
        };
        let _ = writeln!(out, "node {}  {}  {state}", i + 1, h.npub);
        for a in n.addresses() {
            for d in cfg.domains.iter().filter(|d| a.serves(d)) {
                let _ = writeln!(
                    out,
                    "  {}@{}  {}–{} sat",
                    a.name,
                    d,
                    a.min_sendable / 1000,
                    a.max_sendable / 1000
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "checked {} node(s) in {} ms",
        dir.nodes.len(),
        started.elapsed().as_millis()
    );
    dir.close().await;
    if any {
        Ok(())
    } else {
        Err("no node answered".into())
    }
}

async fn test_command(cfg: &Config, args: &[String], out: &mut dyn Write) -> Result<(), String> {
    let (target, amount) = match args {
        [t] => (t, 1u64),
        [t, sats] => (
            t,
            sats.parse::<u64>()
                .map_err(|_| format!("{sats:?} is not a number of sats"))?,
        ),
        _ => return Err(format!("test needs NAME[@DOMAIN] [SATS]\n\n{USAGE}")),
    };
    let (name, domain) = match target.split_once('@') {
        Some((n, d)) => (n.to_string(), d.to_string()),
        None => (target.clone(), cfg.domains[0].clone()),
    };
    let name = http::normalise(&name).ok_or_else(|| format!("{name:?} is not a valid name"))?;
    if !cfg.domains.contains(&domain) {
        return Err(format!(
            "{domain} is not one of this gateway's domains ({})",
            cfg.domains.join(", ")
        ));
    }
    let dir = Directory::new(
        cfg.nodes.clone(),
        own_keys(cfg)?,
        Network::for_command(cfg).await,
        cfg.limits.timeout,
    );
    let started = Instant::now();
    let outcome = async {
        let a = dir.pay_params(&name, &domain).await.map_err(|f| f.reason())?;
        let _ = writeln!(out, "{name}@{domain}");
        let _ = writeln!(
            out,
            "  callback   {}/.well-known/lnurlp/{name}/callback",
            cfg.origin(&domain)
        );
        let _ = writeln!(
            out,
            "  range      {}–{} sat, comments {}",
            a.min_sendable / 1000,
            a.max_sendable / 1000,
            a.comment_allowed
        );
        let lookup = started.elapsed().as_millis();
        let pr = dir
            .invoice(&name, &domain, amount * 1000, None)
            .await
            .map_err(|f| f.reason())?;
        let _ = writeln!(out, "  invoice    {pr}");
        let _ = writeln!(
            out,
            "  checked    amount {amount} sat, description hash, network, expiry"
        );
        let _ = writeln!(
            out,
            "  timing     lookup {lookup} ms, invoice {} ms over ContextVM",
            started.elapsed().as_millis() - lookup
        );
        Ok::<(), String>(())
    }
    .await;
    dir.close().await;
    outcome
}

/// Start with `cfg` and serve until `shutdown`.
pub async fn serve(cfg: Result<Config, String>, shutdown: crate::Shutdown) -> Result<(), String> {
    let g = start(cfg?).await?;
    tracing::info!(npub = %npub(&g.keys), public = %g.public, admin = ?g.admin.as_ref().map(ToString::to_string), "lnaddr gateway is serving");
    g.until(shutdown).await;
    Ok(())
}

pub async fn command(
    args: &[String],
    lookup: crate::Lookup,
    shutdown: crate::Shutdown,
    out: &mut dyn Write,
) -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(crate::node::app::log_filter_or(
            lookup("LNADDR_GATEWAY_LOG"),
            DEFAULT_LOG,
        )))
        .with_writer(std::io::stderr)
        .try_init();
    let (args, file) = match crate::node::app::split_config(args) {
        Ok(v) => v,
        Err(e) => return fail(out, &e),
    };
    let lookup = move |k: &str| match (k, &file) {
        ("LNADDR_GATEWAY_CONFIG", Some(f)) => Some(f.clone()),
        _ => lookup(k),
    };
    let cmd = args.first().map(String::as_str).unwrap_or("serve");
    let rest = args.get(1..).unwrap_or_default();
    let load = || config::load(config::BUILTIN, &lookup);
    let key_dir = || {
        let d = config::data_dir_only(config::BUILTIN, &lookup);
        crate::files::open_dir(&d).map(|()| d)
    };
    let result: Result<(), String> = match (cmd, rest.len()) {
        ("version" | "--version", 0) => {
            let _ = writeln!(out, "lnaddr-gateway {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ("help" | "--help" | "-h", 0) => {
            let _ = writeln!(out, "{USAGE}");
            Ok(())
        }
        ("pubkey", 0) => key_dir()
            .and_then(|d| crate::files::load_or_create_keys(&d.join(KEY_FILE)))
            .map(|k| {
                let _ = writeln!(out, "{}", npub(&k));
            }),
        ("admin-pubkey", 0) => key_dir()
            .and_then(|d| crate::files::load_or_create_keys(&d.join(ADMIN_KEY_FILE)))
            .map(|k| {
                let _ = writeln!(out, "{}", npub(&k));
            }),
        ("admin-token", 0) => key_dir().and_then(|d| admin_token(&d)).map(|t| {
            let _ = writeln!(out, "{t}");
        }),
        ("status", 0) => match load() {
            Ok(cfg) => status_command(&cfg, out).await,
            Err(e) => Err(e),
        },
        ("test", _) => match load() {
            Ok(cfg) => test_command(&cfg, rest, out).await,
            Err(e) => Err(e),
        },
        ("node", _) => match load() {
            Ok(cfg) => node_command(&cfg, rest, out).await,
            Err(e) => Err(e),
        },
        ("serve", 0) => serve(load(), shutdown).await,
        _ => return usage(out),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(out, &e),
    }
}
