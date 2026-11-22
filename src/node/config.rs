//! Node configuration: built-in values, a TOML file, environment variables
//! and, when switched on, address and limit settings saved by an admin over
//! ContextVM. See [`crate::settings`] for how the layers combine.
//!
//! Remote settings can only ever change the address table and the invoice
//! limits. The backend (address, credential, certificate pin), the keys
//! allowed to call, the relays and the data directory are host-only: a
//! stolen admin key must not be able to point the node at another backend
//! or let itself in.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nostr_sdk::prelude::PublicKey;
use serde::{Deserialize, Serialize};

use crate::bolt11::Network;
use crate::lnurl;
use crate::node::backend::Kind;
use crate::settings::{self, Sources, SourcesLayer};

/// The relays used when none are configured.
pub const DEFAULT_RELAYS: [&str; 2] = ["wss://relay.contextvm.org", "wss://relay2.contextvm.org"];
/// Saved remote settings, inside the data directory.
pub const REMOTE_FILE: &str = "remote.toml";
pub const KEY_FILE: &str = "node.key";

/// Built-in configuration, compiled in from `LNADDR_NODE_BUILTIN` (TOML text)
/// at build time. Never put secrets here: point at files instead.
pub const BUILTIN: Option<&str> = option_env!("LNADDR_NODE_BUILTIN");

/// One Lightning address served by this node.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    /// Smallest payment, in millisatoshis.
    pub min_sendable: u64,
    /// Largest payment, in millisatoshis.
    pub max_sendable: u64,
    /// What the payer's wallet shows.
    pub description: String,
    /// Longest comment a payer may attach (LUD-12); 0 for none.
    #[serde(default)]
    pub comment_allowed: u16,
    /// Domains this address may be served under; empty for any.
    #[serde(default)]
    pub domains: Vec<String>,
}

impl Address {
    /// The address used when only names are configured: 1 sat to 1M sat.
    pub fn default_for(name: &str) -> Self {
        Address {
            min_sendable: 1_000,
            max_sendable: 1_000_000_000,
            description: format!("Pay {name}"),
            comment_allowed: 0,
            domains: Vec::new(),
        }
    }

    pub fn validate(&self, name: &str, kind: Kind) -> Result<(), String> {
        let e = |m: String| Err(format!("address {name:?}: {m}"));
        if !lnurl::valid_name(name) {
            return e("names are 1 to 64 of a-z 0-9 - _ .".into());
        }
        if self.min_sendable < lnurl::MIN_MSAT
            || self.min_sendable > self.max_sendable
            || self.max_sendable > lnurl::MAX_MSAT
        {
            return e(format!(
                "need 1 <= min_sendable <= max_sendable <= {} msat",
                lnurl::MAX_MSAT
            ));
        }
        if kind.whole_sats() && self.min_sendable.div_ceil(1000) * 1000 > self.max_sendable {
            return e(format!(
                "{} takes whole satoshis, and no whole satoshi amount fits the range",
                kind.name()
            ));
        }
        let len = self.description.chars().count();
        if len == 0 || len > lnurl::MAX_DESCRIPTION_LEN || self.description.chars().any(char::is_control) {
            return e(format!(
                "description must be 1 to {} printable characters",
                lnurl::MAX_DESCRIPTION_LEN
            ));
        }
        if self.comment_allowed > lnurl::MAX_COMMENT_LEN {
            return e(format!("comment_allowed is at most {}", lnurl::MAX_COMMENT_LEN));
        }
        if let Some(d) = self.domains.iter().find(|d| !lnurl::valid_domain(d)) {
            return e(format!("{d:?} is not a lower-case domain name"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLayer {
    pub kind: Option<String>,
    pub url: Option<String>,
    /// The credential itself. Prefer `secret_file`.
    pub secret: Option<String>,
    /// A file holding the credential (a binary LND macaroon is read as hex).
    pub secret_file: Option<PathBuf>,
    /// SHA-256 of the backend's TLS certificate.
    pub tls_cert_sha256: Option<String>,
    /// The backend's own certificate (LND's tls.cert): pinned exactly.
    pub tls_cert_file: Option<PathBuf>,
    pub timeout_secs: Option<u64>,
    /// Allow plain http to a host that is not local.
    pub insecure_http: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsLayer {
    pub invoices_per_minute: Option<u32>,
    pub per_caller_per_minute: Option<u32>,
    pub concurrent: Option<u32>,
    pub invoice_expiry_secs: Option<u32>,
}

/// One layer of configuration as written in TOML.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub data_dir: Option<PathBuf>,
    pub relays: Option<Vec<String>>,
    pub gateways: Option<Vec<String>>,
    pub admins: Option<Vec<String>>,
    pub socks5: Option<String>,
    pub network: Option<String>,
    pub backend: Option<BackendLayer>,
    pub limits: Option<LimitsLayer>,
    pub addresses: Option<BTreeMap<String, Address>>,
    pub sources: Option<SourcesLayer>,
}

/// What an admin may save over ContextVM: addresses and limits, nothing else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<BTreeMap<String, Address>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Limits {
    /// Invoices per minute, for all callers together.
    pub invoices_per_minute: u32,
    /// Invoices per minute for one calling key.
    pub per_caller_per_minute: u32,
    /// Backend requests in flight at once.
    pub concurrent: u32,
    /// How long each invoice stays payable.
    pub invoice_expiry_secs: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            invoices_per_minute: 120,
            per_caller_per_minute: 60,
            concurrent: 8,
            invoice_expiry_secs: 600,
        }
    }
}

impl Limits {
    fn apply(&mut self, l: &LimitsLayer) {
        self.invoices_per_minute = l.invoices_per_minute.unwrap_or(self.invoices_per_minute);
        self.per_caller_per_minute = l.per_caller_per_minute.unwrap_or(self.per_caller_per_minute);
        self.concurrent = l.concurrent.unwrap_or(self.concurrent);
        self.invoice_expiry_secs = l.invoice_expiry_secs.unwrap_or(self.invoice_expiry_secs);
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.invoices_per_minute == 0
            || self.per_caller_per_minute == 0
            || self.concurrent == 0
            || self.concurrent > 256
        {
            return Err("limits: rates must be at least 1 and concurrent 1 to 256".into());
        }
        if !(60..=86_400).contains(&self.invoice_expiry_secs) {
            return Err("limits: invoice_expiry_secs must be 60 to 86400".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct BackendConfig {
    pub kind: Kind,
    pub url: String,
    pub secret: String,
    pub pin: Option<[u8; 32]>,
    pub timeout: Duration,
}

impl std::fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendConfig")
            .field("kind", &self.kind)
            .field("url", &self.url)
            .field("secret", &settings::redact(true))
            .field("pin", &self.pin.map(hex::encode))
            .finish()
    }
}

/// The configuration in effect.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub relays: Vec<String>,
    pub gateways: Vec<PublicKey>,
    pub admins: Vec<PublicKey>,
    pub socks5: Option<SocketAddr>,
    pub network: Network,
    pub backend: BackendConfig,
    pub limits: Limits,
    pub addresses: BTreeMap<String, Address>,
    pub sources: Sources,
}

/// Merge `b` over `a`, field by field.
fn merge(a: &mut Layer, b: Layer) {
    macro_rules! take {
        ($($f:ident),*) => { $( if b.$f.is_some() { a.$f = b.$f; } )* };
    }
    take!(data_dir, relays, gateways, admins, socks5, network);
    if let Some(bb) = b.backend {
        let ab = a.backend.get_or_insert_with(Default::default);
        macro_rules! takeb {
            ($($f:ident),*) => { $( if bb.$f.is_some() { ab.$f = bb.$f; } )* };
        }
        takeb!(
            kind,
            url,
            secret,
            secret_file,
            tls_cert_sha256,
            tls_cert_file,
            timeout_secs,
            insecure_http
        );
    }
    if let Some(bl) = b.limits {
        let al = a.limits.get_or_insert_with(Default::default);
        macro_rules! takel {
            ($($f:ident),*) => { $( if bl.$f.is_some() { al.$f = bl.$f; } )* };
        }
        takel!(
            invoices_per_minute,
            per_caller_per_minute,
            concurrent,
            invoice_expiry_secs
        );
    }
    if let Some(addrs) = b.addresses {
        a.addresses.get_or_insert_with(Default::default).extend(addrs);
    }
}

pub fn parse_layer(what: &str, text: &str) -> Result<Layer, String> {
    toml::from_str(text).map_err(|e| format!("{what}: {}", e.message()))
}

/// The environment as a layer. `LNADDR_NODE_ADDRESSES=alice,bob` serves those
/// names with [`Address::default_for`] values.
fn env_layer(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Layer, String> {
    let get = |k: &str| lookup(&format!("LNADDR_NODE_{k}")).filter(|v| !v.trim().is_empty());
    let mut backend = BackendLayer {
        kind: get("BACKEND"),
        url: get("BACKEND_URL"),
        secret: get("BACKEND_SECRET"),
        secret_file: get("BACKEND_SECRET_FILE").map(PathBuf::from),
        tls_cert_sha256: get("BACKEND_TLS_CERT_SHA256"),
        tls_cert_file: get("BACKEND_TLS_CERT_FILE").map(PathBuf::from),
        timeout_secs: None,
        insecure_http: None,
    };
    if let Some(v) = get("BACKEND_TIMEOUT_SECS") {
        backend.timeout_secs = Some(settings::number("LNADDR_NODE_BACKEND_TIMEOUT_SECS", &v)?);
    }
    if let Some(v) = get("BACKEND_INSECURE_HTTP") {
        backend.insecure_http = Some(settings::flag("LNADDR_NODE_BACKEND_INSECURE_HTTP", &v)?);
    }
    let remote = match get("REMOTE") {
        Some(v) => Some(settings::flag("LNADDR_NODE_REMOTE", &v)?),
        None => None,
    };
    Ok(Layer {
        data_dir: get("DATA_DIR").map(PathBuf::from),
        relays: get("RELAYS").map(|v| settings::list(&v)),
        gateways: get("GATEWAYS").map(|v| settings::list(&v)),
        admins: get("ADMINS").map(|v| settings::list(&v)),
        socks5: get("SOCKS5"),
        network: get("NETWORK"),
        backend: Some(backend),
        limits: None,
        addresses: get("ADDRESSES").map(|v| {
            settings::list(&v)
                .into_iter()
                .map(|n| (n.clone(), Address::default_for(&n)))
                .collect()
        }),
        sources: Some(SourcesLayer {
            file: None,
            env: None,
            remote,
        }),
    })
}

fn default_data_dir(lookup: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    match lookup("HOME") {
        Some(home) => Path::new(&home).join(".local/share/deadhop-lnaddr/node"),
        None => PathBuf::from("lnaddr-node-data"),
    }
}

/// The built-in, file and environment layers combined, and the sources in effect.
fn layers(builtin: Option<&str>, lookup: &dyn Fn(&str) -> Option<String>) -> Result<(Layer, Sources), String> {
    let mut sources = Sources::default();
    let mut layer = Layer::default();
    let mut add = |l: Layer, sources: &mut Sources| {
        if let Some(s) = &l.sources {
            sources.apply(s);
        }
        merge(&mut layer, l);
    };
    if let Some(text) = builtin {
        add(parse_layer("built-in configuration", text)?, &mut sources);
    }
    if sources.file {
        if let Some(path) = lookup("LNADDR_NODE_CONFIG").filter(|p| !p.is_empty()) {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
            add(parse_layer(&path, &text)?, &mut sources);
        }
    }
    if sources.env {
        add(env_layer(lookup)?, &mut sources);
    }
    Ok((layer, sources))
}

/// Just the data directory, for commands that need nothing else. Falls back
/// to the default when the configuration cannot be read.
pub fn data_dir_only(builtin: Option<&str>, lookup: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    layers(builtin, lookup)
        .ok()
        .and_then(|(l, _)| l.data_dir)
        .unwrap_or_else(|| default_data_dir(lookup))
}

/// Load and check the configuration. `builtin` is the compiled-in layer;
/// the file comes from `LNADDR_NODE_CONFIG`.
pub fn load(builtin: Option<&str>, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Config, String> {
    let (mut layer, sources) = layers(builtin, lookup)?;
    let data_dir = layer.data_dir.clone().unwrap_or_else(|| default_data_dir(lookup));
    if sources.remote {
        if let Some(remote) = read_remote(&data_dir)? {
            if let Some(a) = remote.addresses {
                layer.addresses = Some(a);
            }
            if let Some(l) = remote.limits {
                merge(
                    &mut layer,
                    Layer {
                        limits: Some(l),
                        ..Default::default()
                    },
                );
            }
        }
    }
    finish(layer, data_dir, sources)
}

/// Saved remote settings, if any.
pub fn read_remote(data_dir: &Path) -> Result<Option<Remote>, String> {
    let path = data_dir.join(REMOTE_FILE);
    match crate::files::read_private(&path)? {
        Some(text) => toml::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {}", path.display(), e.message())),
        None => Ok(None),
    }
}

pub fn write_remote(data_dir: &Path, remote: &Remote) -> Result<(), String> {
    let text = toml::to_string(remote).expect("remote settings always serialise to TOML");
    crate::files::write_private(&data_dir.join(REMOTE_FILE), &text)
}

fn keys(what: &str, list: Option<Vec<String>>) -> Result<Vec<PublicKey>, String> {
    list.unwrap_or_default()
        .iter()
        .map(|k| settings::pubkey(k).map_err(|e| format!("{what}: {e}")))
        .collect()
}

/// Whether plain http to `host` keeps the credential on this machine or
/// its private network (loopback, private ranges, container names, .local,
/// overlays).
pub fn local_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }
    !bare.contains('.') || bare.ends_with(".local") || bare.ends_with(".internal") || settings::is_overlay_host(bare)
}

fn backend(b: BackendLayer) -> Result<BackendConfig, String> {
    let kind: Kind = b
        .kind
        .as_deref()
        .ok_or("backend: set backend.kind (lnd, cln, phoenixd or lnbits)")?
        .parse()?;
    let url = b.url.unwrap_or_else(|| kind.default_url().to_string());
    let parsed = reqwest::Url::parse(&url).map_err(|_| format!("backend: {url:?} is not a URL"))?;
    let host = parsed.host_str().unwrap_or("").to_string();
    match parsed.scheme() {
        "https" => {}
        "http" if local_host(&host) || b.insecure_http == Some(true) => {}
        "http" => {
            return Err(format!(
            "backend: {url} sends the credential in the clear to a public host; use https or set backend.insecure_http"
        ))
        }
        other => return Err(format!("backend: {other}:// is not supported (http or https)")),
    }
    let secret = match (b.secret, b.secret_file) {
        (Some(s), _) => s,
        (None, Some(path)) => crate::files::read_secret_text(&path).map_err(|e| format!("backend: {e}"))?,
        (None, None) => return Err("backend: set backend.secret_file (or backend.secret)".into()),
    };
    let pin = match (b.tls_cert_sha256, b.tls_cert_file) {
        (Some(p), _) => Some(crate::tls::parse_pin(&p).map_err(|e| format!("backend: {e}"))?),
        (None, Some(path)) => {
            let pem = std::fs::read_to_string(&path).map_err(|e| format!("backend: {}: {e}", path.display()))?;
            Some(crate::tls::fingerprint(
                &crate::tls::first_pem_cert(&pem).map_err(|e| format!("backend: {e}"))?,
            ))
        }
        (None, None) => None,
    };
    let timeout = Duration::from_secs(b.timeout_secs.unwrap_or(10).clamp(1, 60));
    Ok(BackendConfig {
        kind,
        url,
        secret,
        pin,
        timeout,
    })
}

fn finish(layer: Layer, data_dir: PathBuf, sources: Sources) -> Result<Config, String> {
    let relays = layer
        .relays
        .unwrap_or_else(|| DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect());
    if relays.is_empty() {
        return Err("relays: at least one relay is needed".into());
    }
    for r in &relays {
        settings::relay(r)?;
    }
    let gateways = keys("gateways", layer.gateways)?;
    let admins = keys("admins", layer.admins)?;
    if gateways.is_empty() && admins.is_empty() {
        return Err("gateways: set the gateway's public key (run `lnaddr-gateway pubkey` on the gateway)".into());
    }
    let socks5 = layer.socks5.as_deref().map(settings::socks5).transpose()?;
    let network: Network = layer.network.as_deref().unwrap_or("bitcoin").parse()?;
    let backend = backend(layer.backend.unwrap_or_default())?;
    let mut limits = Limits::default();
    if let Some(l) = &layer.limits {
        limits.apply(l);
    }
    limits.validate()?;
    let addresses = layer.addresses.unwrap_or_default();
    for (name, a) in &addresses {
        a.validate(name, backend.kind)?;
    }
    Ok(Config {
        data_dir,
        relays,
        gateways,
        admins,
        socks5,
        network,
        backend,
        limits,
        addresses,
        sources,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;

    pub fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    pub fn gateway_hex() -> String {
        nostr_sdk::Keys::parse(&"11".repeat(32)).unwrap().public_key().to_hex()
    }

    fn minimal() -> Vec<(&'static str, String)> {
        vec![
            ("LNADDR_NODE_GATEWAYS", gateway_hex()),
            ("LNADDR_NODE_BACKEND", "phoenixd".into()),
            ("LNADDR_NODE_BACKEND_SECRET", "pw".into()),
            ("LNADDR_NODE_ADDRESSES", "alice, bob".into()),
        ]
    }

    fn load_pairs(builtin: Option<&str>, pairs: &[(&str, String)]) -> Result<Config, String> {
        let p: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        load(builtin, &env(&p))
    }

    #[test]
    fn the_environment_alone_is_enough() {
        let c = load_pairs(None, &minimal()).unwrap();
        assert_eq!(c.backend.kind, Kind::Phoenixd);
        assert_eq!(c.backend.url, "http://127.0.0.1:9740");
        assert_eq!(c.relays.len(), 2);
        assert_eq!(c.network, Network::Bitcoin);
        assert_eq!(c.addresses["alice"], Address::default_for("alice"));
        assert_eq!(c.limits, Limits::default());
        assert!(c.data_dir.ends_with("lnaddr-node-data"));
        assert!(!c.sources.remote);
        assert!(!format!("{:?}", c.backend).contains("pw"));
        let mut with_home = minimal();
        with_home.push(("HOME", "/home/u".into()));
        assert_eq!(
            load_pairs(None, &with_home).unwrap().data_dir,
            Path::new("/home/u/.local/share/deadhop-lnaddr/node")
        );
    }

    #[test]
    fn files_layer_over_builtin_and_env_over_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("node.toml");
        std::fs::write(
            &file,
            format!(
                r#"
relays = ["ws://127.0.0.1:7777"]
network = "regtest"
socks5 = "127.0.0.1:9050"
admins = ["{}"]
[backend]
kind = "lnd"
url = "https://10.0.0.5:8080"
tls_cert_sha256 = "{}"
timeout_secs = 99
[limits]
concurrent = 2
[addresses.carol]
min_sendable = 1000
max_sendable = 5000
description = "Carol"
comment_allowed = 100
domains = ["example.com"]
"#,
                gateway_hex(),
                "ab".repeat(32)
            ),
        )
        .unwrap();
        let builtin = r#"
data_dir = "/builtin"
[backend]
kind = "cln"
secret = "from-builtin"
[limits]
invoices_per_minute = 5
"#;
        let mut pairs = minimal();
        pairs.retain(|(k, _)| *k != "LNADDR_NODE_BACKEND" && *k != "LNADDR_NODE_BACKEND_SECRET");
        pairs.push(("LNADDR_NODE_CONFIG", file.display().to_string()));
        pairs.push(("LNADDR_NODE_BACKEND_TIMEOUT_SECS", "3".into()));
        let c = load_pairs(Some(builtin), &pairs).unwrap();
        assert_eq!(c.data_dir, Path::new("/builtin"));
        assert_eq!(c.backend.kind, Kind::Lnd);
        assert_eq!(c.backend.secret, "from-builtin");
        assert_eq!(c.backend.pin, Some([0xab; 32]));
        assert_eq!(c.backend.timeout, Duration::from_secs(3));
        assert_eq!(c.limits.invoices_per_minute, 5);
        assert_eq!(c.limits.concurrent, 2);
        assert_eq!(c.network, Network::Regtest);
        assert_eq!(c.socks5.unwrap().port(), 9050);
        assert_eq!(c.admins.len(), 1);
        // File and environment addresses add up, per name.
        assert_eq!(c.addresses.keys().collect::<Vec<_>>(), ["alice", "bob", "carol"]);
        assert_eq!(c.addresses["carol"].domains, ["example.com"]);
    }

    #[test]
    fn builtin_values_can_shut_out_every_other_source() {
        let builtin = format!(
            r#"
gateways = ["{}"]
sources = {{ file = false, env = false, remote = false }}
[backend]
kind = "phoenixd"
secret = "x"
[addresses.only]
min_sendable = 1000
max_sendable = 2000
description = "Only"
"#,
            gateway_hex()
        );
        let pairs = [
            ("LNADDR_NODE_CONFIG", "/does/not/exist".to_string()),
            ("LNADDR_NODE_BACKEND", "bogus".to_string()),
            ("LNADDR_NODE_REMOTE", "on".to_string()),
        ];
        let c = load_pairs(Some(&builtin), &pairs).unwrap();
        assert_eq!(c.addresses.keys().collect::<Vec<_>>(), ["only"]);
        assert!(!c.sources.file && !c.sources.env && !c.sources.remote);
    }

    #[test]
    fn remote_settings_replace_addresses_and_limits_only_when_switched_on() {
        let dir = tempfile::tempdir().unwrap();
        let mut pairs = minimal();
        pairs.push(("LNADDR_NODE_DATA_DIR", dir.path().display().to_string()));
        let mut addrs = BTreeMap::new();
        addrs.insert("zed".to_string(), Address::default_for("zed"));
        let remote = Remote {
            addresses: Some(addrs),
            limits: Some(LimitsLayer {
                invoices_per_minute: Some(7),
                ..Default::default()
            }),
        };
        write_remote(dir.path(), &remote).unwrap();
        assert_eq!(read_remote(dir.path()).unwrap().unwrap(), remote);
        let off = load_pairs(None, &pairs).unwrap();
        assert!(off.addresses.contains_key("alice"));
        pairs.push(("LNADDR_NODE_REMOTE", "on".into()));
        let on = load_pairs(None, &pairs).unwrap();
        assert!(on.sources.remote);
        assert_eq!(on.addresses.keys().collect::<Vec<_>>(), ["zed"]);
        assert_eq!(on.limits.invoices_per_minute, 7);
        // Nothing saved yet: the configured values stand.
        let empty = tempfile::tempdir().unwrap();
        let mut fresh = pairs.clone();
        fresh.retain(|(k, _)| *k != "LNADDR_NODE_DATA_DIR");
        fresh.push(("LNADDR_NODE_DATA_DIR", empty.path().display().to_string()));
        assert!(load_pairs(None, &fresh).unwrap().addresses.contains_key("alice"));
        assert_eq!(read_remote(empty.path()).unwrap(), None);
        // Only limits saved: addresses stay as configured.
        write_remote(
            dir.path(),
            &Remote {
                addresses: None,
                limits: None,
            },
        )
        .unwrap();
        assert!(load_pairs(None, &pairs).unwrap().addresses.contains_key("alice"));
        // A remote file that tries to change anything else is refused.
        std::fs::write(dir.path().join(REMOTE_FILE), "[backend]\nurl = \"https://evil\"\n").unwrap();
        assert!(load_pairs(None, &pairs).unwrap_err().contains("unknown field"));
    }

    #[test]
    fn mistakes_are_named() {
        let cases: Vec<(&str, &str, &str)> = vec![
            ("LNADDR_NODE_RELAYS", "ws://relay.example.com", "must use wss://"),
            ("LNADDR_NODE_RELAYS", " , ", "at least one relay"),
            ("LNADDR_NODE_GATEWAYS", "nope", "gateways: \"nope\""),
            ("LNADDR_NODE_GATEWAYS", "", "set the gateway's public key"),
            ("LNADDR_NODE_ADMINS", "nope", "admins: \"nope\""),
            ("LNADDR_NODE_SOCKS5", "tor", "IP address and port"),
            ("LNADDR_NODE_NETWORK", "doge", "unknown network"),
            ("LNADDR_NODE_BACKEND", "eclair", "unknown backend"),
            ("LNADDR_NODE_BACKEND_URL", "nope", "is not a URL"),
            ("LNADDR_NODE_BACKEND_URL", "http://lnbits.example.com", "in the clear"),
            ("LNADDR_NODE_BACKEND_URL", "ftp://10.0.0.1", "ftp:// is not supported"),
            ("LNADDR_NODE_BACKEND_TLS_CERT_SHA256", "zz", "not a hex"),
            (
                "LNADDR_NODE_BACKEND_TLS_CERT_FILE",
                "/does/not/exist",
                "/does/not/exist",
            ),
            ("LNADDR_NODE_BACKEND_TIMEOUT_SECS", "soon", "not a valid number"),
            ("LNADDR_NODE_BACKEND_INSECURE_HTTP", "maybe", "not on or off"),
            ("LNADDR_NODE_REMOTE", "maybe", "not on or off"),
            ("LNADDR_NODE_ADDRESSES", "Alice", "names are 1 to 64"),
            ("LNADDR_NODE_CONFIG", "/does/not/exist", "/does/not/exist"),
        ];
        for (k, v, want) in cases {
            let mut pairs = minimal();
            pairs.retain(|(key, _)| *key != k);
            pairs.push((k, v.to_string()));
            let e = load_pairs(None, &pairs).unwrap_err();
            assert!(e.contains(want), "{k}={v}: {e}");
        }
        let mut no_kind = minimal();
        no_kind.retain(|(k, _)| *k != "LNADDR_NODE_BACKEND");
        assert!(load_pairs(None, &no_kind).unwrap_err().contains("set backend.kind"));
        let mut no_secret = minimal();
        no_secret.retain(|(k, _)| *k != "LNADDR_NODE_BACKEND_SECRET");
        assert!(load_pairs(None, &no_secret)
            .unwrap_err()
            .contains("set backend.secret_file"));
        no_secret.push(("LNADDR_NODE_BACKEND_SECRET_FILE", "/does/not/exist".into()));
        assert!(load_pairs(None, &no_secret).unwrap_err().contains("does not exist"));
        assert!(load_pairs(Some("nonsense = 1"), &minimal())
            .unwrap_err()
            .contains("built-in configuration: unknown field"));
        assert!(load_pairs(Some("[limits]\nconcurrent = 0"), &minimal())
            .unwrap_err()
            .contains("concurrent 1 to 256"));
        let dir = tempfile::tempdir().unwrap();
        let bad_pem = dir.path().join("tls.cert");
        std::fs::write(&bad_pem, "junk").unwrap();
        let mut pem = minimal();
        pem.push(("LNADDR_NODE_BACKEND_TLS_CERT_FILE", bad_pem.display().to_string()));
        assert!(load_pairs(None, &pem).unwrap_err().contains("no certificate"));
        let mut insecure = minimal();
        insecure.push(("LNADDR_NODE_BACKEND_URL", "http://lnbits.example.com".into()));
        insecure.push(("LNADDR_NODE_BACKEND_INSECURE_HTTP", "yes".into()));
        assert!(load_pairs(None, &insecure).is_ok());
    }

    #[test]
    fn a_certificate_file_is_pinned_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let cert = crate::tls::testutil::self_signed();
        let path = dir.path().join("tls.cert");
        std::fs::write(&path, &cert.pem).unwrap();
        let mut pairs = minimal();
        pairs.push(("LNADDR_NODE_BACKEND_TLS_CERT_FILE", path.display().to_string()));
        let c = load_pairs(None, &pairs).unwrap();
        assert_eq!(c.backend.pin, Some(crate::tls::fingerprint(&cert.der)));
        let secret = dir.path().join("pw");
        crate::files::write_private(&secret, "filepw\n").unwrap();
        let mut file_secret = minimal();
        file_secret.retain(|(k, _)| *k != "LNADDR_NODE_BACKEND_SECRET");
        file_secret.push(("LNADDR_NODE_BACKEND_SECRET_FILE", secret.display().to_string()));
        assert_eq!(load_pairs(None, &file_secret).unwrap().backend.secret, "filepw");
    }

    #[test]
    fn the_data_directory_is_found_without_a_full_configuration() {
        assert_eq!(data_dir_only(Some("data_dir = \"/x\""), &env(&[])), Path::new("/x"));
        assert_eq!(
            data_dir_only(Some("junk"), &env(&[("HOME", "/h")])),
            Path::new("/h/.local/share/deadhop-lnaddr/node")
        );
    }

    #[test]
    fn addresses_are_checked() {
        let ok = Address::default_for("a");
        assert!(ok.validate("a", Kind::Lnd).is_ok());
        let bad = |f: &dyn Fn(&mut Address), kind: Kind, want: &str| {
            let mut a = Address::default_for("a");
            f(&mut a);
            let e = a.validate("a", kind).unwrap_err();
            assert!(e.contains(want), "{e}");
        };
        bad(&|a| a.min_sendable = 0, Kind::Lnd, "min_sendable");
        bad(&|a| a.min_sendable = a.max_sendable + 1, Kind::Lnd, "min_sendable");
        bad(&|a| a.max_sendable = lnurl::MAX_MSAT + 1, Kind::Lnd, "min_sendable");
        bad(
            &|a| {
                a.min_sendable = 1500;
                a.max_sendable = 1900
            },
            Kind::Phoenixd,
            "whole satoshis",
        );
        bad(&|a| a.description.clear(), Kind::Lnd, "description");
        bad(&|a| a.description = "x".repeat(641), Kind::Lnd, "description");
        bad(&|a| a.description = "tab\there".into(), Kind::Lnd, "description");
        bad(&|a| a.comment_allowed = 2001, Kind::Lnd, "comment_allowed");
        bad(
            &|a| a.domains = vec!["Example.com".into()],
            Kind::Lnd,
            "not a lower-case domain",
        );
        let mut sub_sat = Address::default_for("a");
        sub_sat.min_sendable = 1500;
        sub_sat.max_sendable = 1900;
        assert!(sub_sat.validate("a", Kind::Lnd).is_ok());
        let e = Limits {
            invoice_expiry_secs: 10,
            ..Limits::default()
        }
        .validate()
        .unwrap_err();
        assert!(e.contains("60 to 86400"));
    }

    #[test]
    fn only_local_hosts_may_get_the_credential_in_the_clear() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "[::1]",
            "[fd00::1]",
            "phoenixd",
            "node.local",
            "lnd.internal",
            "abc.onion",
        ] {
            assert!(local_host(local), "{local}");
        }
        for public in ["8.8.8.8", "[2001:db8::1]", "lnbits.example.com"] {
            assert!(!local_host(public), "{public}");
        }
    }
}
