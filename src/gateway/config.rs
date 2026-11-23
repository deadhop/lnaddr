//! Gateway configuration: built-in values, a TOML file, then environment
//! variables (see [`crate::settings`]). The gateway has no remote settings.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nostr_sdk::prelude::PublicKey;
use serde::Deserialize;

use crate::lnurl;
use crate::settings::{self, Sources, SourcesLayer};

pub const BUILTIN: Option<&str> = option_env!("LNADDR_GATEWAY_BUILTIN");
pub const KEY_FILE: &str = "gateway.key";
pub const ADMIN_KEY_FILE: &str = "admin.key";
pub const TOKEN_FILE: &str = "admin.token";

/// Where to listen: a TCP address, or a Unix socket for a reverse proxy on
/// the same host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Listen {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.strip_prefix("unix:") {
            Some(path) if !path.is_empty() => Ok(Listen::Unix(PathBuf::from(path))),
            Some(_) => Err("listen: unix: needs a socket path".into()),
            None => s
                .parse()
                .map(Listen::Tcp)
                .map_err(|_| format!("listen: {s:?} is not an address and port, e.g. 127.0.0.1:8080")),
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            Listen::Tcp(a) => a.ip().is_loopback(),
            Listen::Unix(_) => true,
        }
    }
}

impl std::fmt::Display for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listen::Tcp(a) => write!(f, "{a}"),
            Listen::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

/// An IP network such as `10.0.0.0/8`, or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    bits: u8,
}

impl Net {
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = || format!("trusted_proxies: {s:?} is not an address or network (e.g. 10.0.0.0/8)");
        let (a, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b.parse::<u8>().map_err(|_| bad())?)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        if bits > max {
            return Err(bad());
        }
        Ok(Net { addr, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        fn prefix(bytes: &[u8], bits: u8) -> Vec<u8> {
            let mut out = bytes.to_vec();
            for (i, b) in out.iter_mut().enumerate() {
                let keep = (bits as usize).saturating_sub(i * 8).min(8);
                *b &= (0xffu16 << (8 - keep)) as u8;
            }
            out
        }
        let ip = match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => prefix(&a.octets(), self.bits) == prefix(&b.octets(), self.bits),
            (IpAddr::V6(a), IpAddr::V6(b)) => prefix(&a.octets(), self.bits) == prefix(&b.octets(), self.bits),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeLayer {
    pub pubkey: String,
    /// Names this node serves; `*` (the default) for whatever it lists.
    pub names: Option<Vec<String>>,
    pub relays: Option<Vec<String>>,
    /// The Lightning node key every invoice must be signed by.
    pub payee: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsLayer {
    pub per_ip_per_minute: Option<u32>,
    pub global_per_minute: Option<u32>,
    pub timeout_secs: Option<u64>,
    pub cache_secs: Option<u64>,
    pub max_connections: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminLayer {
    pub listen: Option<String>,
    pub secure_cookie: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub data_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub domains: Option<Vec<String>>,
    /// `http` for local testing; otherwise https (http for .onion).
    pub scheme: Option<String>,
    pub trusted_proxies: Option<Vec<String>>,
    pub relays: Option<Vec<String>>,
    pub socks5: Option<String>,
    pub nodes: Option<Vec<NodeLayer>>,
    pub limits: Option<LimitsLayer>,
    pub admin: Option<AdminLayer>,
    pub sources: Option<SourcesLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub pubkey: PublicKey,
    pub names: Option<Vec<String>>,
    pub relays: Vec<String>,
    pub payee: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub per_ip_per_minute: u32,
    pub global_per_minute: u32,
    pub timeout: Duration,
    pub cache: Duration,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub listen: Listen,
    pub domains: Vec<String>,
    pub scheme_override: Option<String>,
    pub trusted_proxies: Vec<Net>,
    pub socks5: Option<crate::pool::ProxySpec>,
    pub nodes: Vec<NodeConfig>,
    pub limits: Limits,
    pub admin_listen: Option<Listen>,
    pub secure_cookie: bool,
    pub sources: Sources,
}

impl Config {
    /// `https://domain`, or `http://` for onion services and the http override.
    pub fn origin(&self, domain: &str) -> String {
        let scheme = match &self.scheme_override {
            Some(s) => s.as_str(),
            None if lnurl::is_onion(domain) => "http",
            None => "https",
        };
        format!("{scheme}://{domain}")
    }
}

fn merge(a: &mut Layer, b: Layer) {
    macro_rules! take {
        ($($f:ident),*) => { $( if b.$f.is_some() { a.$f = b.$f; } )* };
    }
    take!(
        data_dir,
        listen,
        domains,
        scheme,
        trusted_proxies,
        relays,
        socks5,
        nodes
    );
    if let Some(bl) = b.limits {
        let al = a.limits.get_or_insert_with(Default::default);
        macro_rules! takel {
            ($($f:ident),*) => { $( if bl.$f.is_some() { al.$f = bl.$f; } )* };
        }
        takel!(
            per_ip_per_minute,
            global_per_minute,
            timeout_secs,
            cache_secs,
            max_connections
        );
    }
    if let Some(ba) = b.admin {
        let aa = a.admin.get_or_insert_with(Default::default);
        if ba.listen.is_some() {
            aa.listen = ba.listen;
        }
        if ba.secure_cookie.is_some() {
            aa.secure_cookie = ba.secure_cookie;
        }
    }
}

/// The environment as a layer. `LNADDR_GATEWAY_NODE=npub…` adds one node
/// serving every name it lists, so a single variable is enough to start.
fn env_layer(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Layer, String> {
    let get = |k: &str| lookup(&format!("LNADDR_GATEWAY_{k}")).filter(|v| !v.trim().is_empty());
    let num = |k: &str| -> Result<Option<u64>, String> {
        get(k)
            .map(|v| settings::number::<u64>(&format!("LNADDR_GATEWAY_{k}"), &v))
            .transpose()
    };
    let n32 = |k: &str| -> Result<Option<u32>, String> {
        get(k)
            .map(|v| settings::number::<u32>(&format!("LNADDR_GATEWAY_{k}"), &v))
            .transpose()
    };
    let limits = LimitsLayer {
        per_ip_per_minute: n32("PER_IP_PER_MINUTE")?,
        global_per_minute: n32("GLOBAL_PER_MINUTE")?,
        timeout_secs: num("TIMEOUT_SECS")?,
        cache_secs: num("CACHE_SECS")?,
        max_connections: n32("MAX_CONNECTIONS")?,
    };
    let secure_cookie = get("ADMIN_SECURE_COOKIE")
        .map(|v| settings::flag("LNADDR_GATEWAY_ADMIN_SECURE_COOKIE", &v))
        .transpose()?;
    let nodes = get("NODES").or(get("NODE")).map(|v| {
        settings::list(&v)
            .into_iter()
            .map(|pubkey| NodeLayer {
                pubkey,
                ..Default::default()
            })
            .collect()
    });
    Ok(Layer {
        data_dir: get("DATA_DIR").map(PathBuf::from),
        listen: get("LISTEN"),
        domains: get("DOMAINS").or(get("DOMAIN")).map(|v| settings::list(&v)),
        scheme: get("SCHEME"),
        trusted_proxies: get("TRUSTED_PROXIES").map(|v| settings::list(&v)),
        relays: get("RELAYS").map(|v| settings::list(&v)),
        socks5: get("SOCKS5"),
        nodes,
        limits: Some(limits),
        admin: Some(AdminLayer {
            listen: get("ADMIN_LISTEN"),
            secure_cookie,
        }),
        sources: None,
    })
}

fn parse_layer(what: &str, text: &str) -> Result<Layer, String> {
    toml::from_str(text).map_err(|e| format!("{what}: {}", e.message()))
}

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
        if let Some(path) = lookup("LNADDR_GATEWAY_CONFIG").filter(|p| !p.is_empty()) {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
            add(parse_layer(&path, &text)?, &mut sources);
        }
    }
    if sources.env {
        add(env_layer(lookup)?, &mut sources);
    }
    Ok((layer, sources))
}

fn default_data_dir(lookup: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    match lookup("HOME") {
        Some(home) => Path::new(&home).join(".local/share/deadhop-lnaddr/gateway"),
        None => PathBuf::from("lnaddr-gateway-data"),
    }
}

/// Just the data directory, for commands that need nothing else.
pub fn data_dir_only(builtin: Option<&str>, lookup: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    layers(builtin, lookup)
        .ok()
        .and_then(|(l, _)| l.data_dir)
        .unwrap_or_else(|| default_data_dir(lookup))
}

pub fn load(builtin: Option<&str>, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Config, String> {
    let (l, sources) = layers(builtin, lookup)?;
    let data_dir = l.data_dir.clone().unwrap_or_else(|| default_data_dir(lookup));
    let listen = Listen::parse(l.listen.as_deref().unwrap_or("127.0.0.1:8080"))?;
    let domains = l.domains.unwrap_or_default();
    if domains.is_empty() {
        return Err("domains: set the domain your Lightning addresses are under (LNADDR_GATEWAY_DOMAIN)".into());
    }
    if let Some(d) = domains.iter().find(|d| !lnurl::valid_domain(d)) {
        return Err(format!("domains: {d:?} is not a lower-case domain name"));
    }
    let scheme_override = match l.scheme.as_deref() {
        None | Some("https") => None,
        Some("http") => Some("http".to_string()),
        Some(other) => return Err(format!("scheme: {other:?} is not http or https")),
    };
    let trusted_proxies = l
        .trusted_proxies
        .unwrap_or_default()
        .iter()
        .map(|s| Net::parse(s))
        .collect::<Result<_, _>>()?;
    let relays = l.relays.unwrap_or_else(|| {
        crate::node::config::DEFAULT_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    let check_relays = |rs: &[String]| -> Result<(), String> {
        if rs.is_empty() {
            return Err("relays: at least one relay is needed".into());
        }
        rs.iter().try_for_each(|r| settings::relay(r).map(|_| ()))
    };
    check_relays(&relays)?;
    let socks5 = l.socks5.as_deref().map(settings::socks5).transpose()?;
    let node_layers = l.nodes.unwrap_or_default();
    if node_layers.is_empty() {
        return Err("nodes: set the node's public key (run `lnaddr-node pubkey` next to your Lightning node)".into());
    }
    let mut nodes = Vec::new();
    for n in node_layers {
        let pubkey = settings::pubkey(&n.pubkey).map_err(|e| format!("nodes: {e}"))?;
        let names = n.names.filter(|ns| !ns.iter().any(|x| x == "*"));
        if let Some(bad) = names.iter().flatten().find(|x| !lnurl::valid_name(x)) {
            return Err(format!("nodes: {bad:?} is not a valid name (a-z 0-9 - _ .)"));
        }
        let node_relays = n.relays.unwrap_or_else(|| relays.clone());
        check_relays(&node_relays)?;
        if let Some(p) = &n.payee {
            if p.len() != 66 || hex::decode(p).is_err() {
                return Err(format!("nodes: payee {p:?} is not a 33-byte hex node key"));
            }
        }
        nodes.push(NodeConfig {
            pubkey,
            names,
            relays: node_relays,
            payee: n.payee.map(|p| p.to_lowercase()),
        });
    }
    let ll = l.limits.unwrap_or_default();
    let limits = Limits {
        per_ip_per_minute: ll.per_ip_per_minute.unwrap_or(30).max(1),
        global_per_minute: ll.global_per_minute.unwrap_or(600).max(1),
        timeout: Duration::from_secs(ll.timeout_secs.unwrap_or(15).clamp(2, 60)),
        cache: Duration::from_secs(ll.cache_secs.unwrap_or(60).clamp(5, 3600)),
        max_connections: ll.max_connections.unwrap_or(1024).clamp(16, 65_536),
    };
    let admin = l.admin.unwrap_or_default();
    let admin_listen = admin.listen.as_deref().map(Listen::parse).transpose()?;
    if admin_listen.as_ref().is_some_and(|a| *a == listen) {
        return Err(
            "admin.listen must differ from listen: the admin interface never shares the public listener".into(),
        );
    }
    let secure_cookie = admin
        .secure_cookie
        .unwrap_or_else(|| !admin_listen.as_ref().is_some_and(Listen::is_loopback));
    Ok(Config {
        data_dir,
        listen,
        domains,
        scheme_override,
        trusted_proxies,
        socks5,
        nodes,
        limits,
        admin_listen,
        secure_cookie,
        sources,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::node::config::tests::env;

    pub fn node_hex() -> String {
        nostr_sdk::Keys::parse(&"33".repeat(32)).unwrap().public_key().to_hex()
    }

    fn minimal() -> Vec<(&'static str, String)> {
        vec![
            ("LNADDR_GATEWAY_DOMAIN", "pay.example".into()),
            ("LNADDR_GATEWAY_NODE", node_hex()),
        ]
    }

    fn load_pairs(builtin: Option<&str>, pairs: &[(&str, String)]) -> Result<Config, String> {
        let p: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        load(builtin, &env(&p))
    }

    #[test]
    fn two_variables_are_enough() {
        let c = load_pairs(None, &minimal()).unwrap();
        assert_eq!(c.listen, Listen::Tcp("127.0.0.1:8080".parse().unwrap()));
        assert_eq!(c.domains, ["pay.example"]);
        assert_eq!(c.nodes.len(), 1);
        assert_eq!(c.nodes[0].names, None);
        assert_eq!(c.nodes[0].relays.len(), 2);
        assert_eq!(c.limits.per_ip_per_minute, 30);
        assert_eq!(c.admin_listen, None);
        assert_eq!(c.origin("pay.example"), "https://pay.example");
        assert_eq!(c.origin("abc.onion"), "http://abc.onion");
        assert!(c.data_dir.ends_with("lnaddr-gateway-data"));
        assert_eq!(
            data_dir_only(None, &env(&[("HOME", "/h")])),
            Path::new("/h/.local/share/deadhop-lnaddr/gateway")
        );
    }

    #[test]
    fn a_file_describes_several_nodes_and_the_environment_wins() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gateway.toml");
        std::fs::write(
            &file,
            format!(
                r#"
listen = "unix:/run/lnaddr.sock"
domains = ["a.example", "b.example"]
trusted_proxies = ["10.0.0.0/8", "::1"]
socks5 = "127.0.0.1:9050"
[limits]
per_ip_per_minute = 5
timeout_secs = 1
cache_secs = 99999
[admin]
listen = "127.0.0.1:8081"
[[nodes]]
pubkey = "{n}"
names = ["alice", "bob"]
relays = ["ws://127.0.0.1:7000"]
payee = "{p}"
[[nodes]]
pubkey = "{n}"
names = ["*"]
"#,
                n = node_hex(),
                p = "02".repeat(33).to_uppercase()
            ),
        )
        .unwrap();
        let pairs = vec![
            ("LNADDR_GATEWAY_CONFIG", file.display().to_string()),
            ("LNADDR_GATEWAY_GLOBAL_PER_MINUTE", "7".to_string()),
            ("LNADDR_GATEWAY_SCHEME", "http".to_string()),
        ];
        let c = load_pairs(Some("data_dir = \"/b\""), &pairs).unwrap();
        assert_eq!(c.data_dir, Path::new("/b"));
        assert_eq!(c.listen, Listen::Unix("/run/lnaddr.sock".into()));
        assert_eq!(c.listen.to_string(), "unix:/run/lnaddr.sock");
        assert!(c.listen.is_loopback());
        assert_eq!(
            c.nodes[0].names.as_deref(),
            Some(&["alice".to_string(), "bob".to_string()][..])
        );
        assert_eq!(c.nodes[0].payee.as_deref(), Some("02".repeat(33).as_str()));
        assert_eq!(c.nodes[1].names, None);
        assert_eq!((c.limits.per_ip_per_minute, c.limits.global_per_minute), (5, 7));
        assert_eq!(c.limits.timeout, Duration::from_secs(2));
        assert_eq!(c.limits.cache, Duration::from_secs(3600));
        assert_eq!(c.trusted_proxies.len(), 2);
        assert_eq!(c.admin_listen.as_ref().unwrap().to_string(), "127.0.0.1:8081");
        assert!(!c.secure_cookie);
        assert_eq!(c.origin("a.example"), "http://a.example");
        assert!(c.socks5.is_some());
    }

    #[test]
    fn builtin_values_can_be_the_only_source() {
        let builtin = format!("domains = [\"only.example\"]\nnodes = [{{ pubkey = \"{}\" }}]\nsources = {{ file = false, env = false }}\n", node_hex());
        let pairs = [
            ("LNADDR_GATEWAY_DOMAIN", "other.example".to_string()),
            ("LNADDR_GATEWAY_CONFIG", "/nope".to_string()),
        ];
        let c = load_pairs(Some(&builtin), &pairs).unwrap();
        assert_eq!(c.domains, ["only.example"]);
        assert!(!c.sources.env && !c.sources.file);
    }

    #[test]
    fn mistakes_are_named() {
        let cases: Vec<(&str, &str, &str)> = vec![
            ("LNADDR_GATEWAY_LISTEN", "8080", "not an address and port"),
            ("LNADDR_GATEWAY_LISTEN", "unix:", "needs a socket path"),
            ("LNADDR_GATEWAY_DOMAIN", "", "set the domain"),
            ("LNADDR_GATEWAY_DOMAIN", "https://x.io", "not a lower-case domain"),
            ("LNADDR_GATEWAY_SCHEME", "gopher", "not http or https"),
            (
                "LNADDR_GATEWAY_TRUSTED_PROXIES",
                "10.0.0.0/99",
                "not an address or network",
            ),
            (
                "LNADDR_GATEWAY_TRUSTED_PROXIES",
                "10.0.0.0/x",
                "not an address or network",
            ),
            ("LNADDR_GATEWAY_TRUSTED_PROXIES", "proxy", "not an address or network"),
            ("LNADDR_GATEWAY_RELAYS", "ws://relay.example.com", "must use wss://"),
            ("LNADDR_GATEWAY_RELAYS", ",", "at least one relay"),
            ("LNADDR_GATEWAY_SOCKS5", "tor", "a port is required"),
            ("LNADDR_GATEWAY_NODE", "", "set the node's public key"),
            ("LNADDR_GATEWAY_NODE", "nope", "nodes: \"nope\""),
            ("LNADDR_GATEWAY_PER_IP_PER_MINUTE", "many", "not a valid number"),
            ("LNADDR_GATEWAY_TIMEOUT_SECS", "soon", "not a valid number"),
            ("LNADDR_GATEWAY_ADMIN_SECURE_COOKIE", "maybe", "not on or off"),
            (
                "LNADDR_GATEWAY_ADMIN_LISTEN",
                "127.0.0.1:8080",
                "must differ from listen",
            ),
            ("LNADDR_GATEWAY_ADMIN_LISTEN", "nope", "not an address"),
            ("LNADDR_GATEWAY_CONFIG", "/does/not/exist", "/does/not/exist"),
        ];
        for (k, v, want) in cases {
            let mut pairs = minimal();
            pairs.retain(|(key, _)| *key != k);
            pairs.push((k, v.to_string()));
            let e = load_pairs(None, &pairs).unwrap_err();
            assert!(e.contains(want), "{k}={v}: {e}");
        }
        let node = |extra: &str| format!("domains = [\"x.io\"]\n[[nodes]]\npubkey = \"{}\"\n{extra}", node_hex());
        assert!(load_pairs(Some(&node("names = [\"Bad\"]")), &[])
            .unwrap_err()
            .contains("not a valid name"));
        assert!(load_pairs(Some(&node("payee = \"02\"")), &[])
            .unwrap_err()
            .contains("33-byte hex"));
        assert!(load_pairs(Some(&node("relays = []")), &[])
            .unwrap_err()
            .contains("at least one relay"));
        assert!(load_pairs(Some("bogus = 1"), &minimal())
            .unwrap_err()
            .contains("unknown field"));
        let public_admin = [("LNADDR_GATEWAY_ADMIN_LISTEN", "0.0.0.0:8081".to_string())];
        let mut pairs = minimal();
        pairs.extend(public_admin);
        assert!(load_pairs(None, &pairs).unwrap().secure_cookie);
        let mut pairs = minimal();
        pairs.push(("LNADDR_GATEWAY_ADMIN_SECURE_COOKIE", "off".into()));
        pairs.push(("LNADDR_GATEWAY_MAX_CONNECTIONS", "1".into()));
        pairs.push(("LNADDR_GATEWAY_CACHE_SECS", "1".into()));
        let c = load_pairs(None, &pairs).unwrap();
        assert!(!c.secure_cookie);
        assert_eq!(c.limits.max_connections, 16);
    }

    #[test]
    fn networks_contain_what_they_should() {
        let n = Net::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.9.8.7".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert!(n.contains("::ffff:10.1.1.1".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
        let one = Net::parse("192.168.1.5").unwrap();
        assert!(one.contains("192.168.1.5".parse().unwrap()));
        assert!(!one.contains("192.168.1.6".parse().unwrap()));
        let odd = Net::parse("172.16.0.0/12").unwrap();
        assert!(odd.contains("172.31.255.255".parse().unwrap()));
        assert!(!odd.contains("172.32.0.0".parse().unwrap()));
        let v6 = Net::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(Net::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
    }
}
