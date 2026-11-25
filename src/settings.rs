//! Shared pieces of configuration: where values come from, and parsers for
//! the values both services take.
//!
//! Values come in layers, later ones winning: built-in (compiled into the
//! binary), then a TOML file, then environment variables, then (node only)
//! settings saved over ContextVM by an admin. Any layer can switch a later
//! source off for good; none can switch back on one an earlier layer
//! switched off. A binary built with `sources = { file = false, env = false }`
//! therefore runs only on its built-in values.

use crate::pool::ProxySpec;

use nostr_sdk::prelude::{FromBech32, PublicKey};
use serde::{Deserialize, Serialize};

/// Which layers may add to the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesLayer {
    pub file: Option<bool>,
    pub env: Option<bool>,
    pub remote: Option<bool>,
}

/// The sources in effect, and whether each was switched off for good.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sources {
    pub file: bool,
    pub env: bool,
    pub remote: bool,
    #[serde(skip)]
    locked: [bool; 3],
}

impl Default for Sources {
    /// Files and the environment are read; remote settings are off until
    /// some layer switches them on.
    fn default() -> Self {
        Sources {
            file: true,
            env: true,
            remote: false,
            locked: [false; 3],
        }
    }
}

impl Sources {
    /// Apply one layer's switches.
    pub fn apply(&mut self, layer: &SourcesLayer) {
        let slots = [
            (&mut self.file, layer.file),
            (&mut self.env, layer.env),
            (&mut self.remote, layer.remote),
        ];
        for (i, (value, wanted)) in slots.into_iter().enumerate() {
            match wanted {
                Some(false) => {
                    *value = false;
                    self.locked[i] = true;
                }
                Some(true) if !self.locked[i] => *value = true,
                _ => {}
            }
        }
    }
}

/// `a, b ,c` as a list, skipping blanks.
pub fn list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// A yes/no environment value.
pub fn flag(name: &str, s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(format!("{name}: {other:?} is not on or off")),
    }
}

/// A number from the environment.
pub fn number<T: std::str::FromStr>(name: &str, s: &str) -> Result<T, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("{name}: {s:?} is not a valid number"))
}

/// A Nostr public key given as npub or hex.
pub fn pubkey(s: &str) -> Result<PublicKey, String> {
    let s = s.trim();
    PublicKey::from_bech32(s)
        .or_else(|_| PublicKey::from_hex(s))
        .map_err(|_| format!("{s:?} is not a nostr public key (npub or hex)"))
}

/// A relay address: `wss://`, or `ws://` for loopback and overlay hosts.
pub fn relay(s: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(s).map_err(|_| format!("relay {s:?} is not a URL"))?;
    let host = url.host_str().unwrap_or("");
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("relay {s:?} must not carry a user name or password"));
    }
    match url.scheme() {
        "wss" if !host.is_empty() => Ok(s.to_string()),
        "ws" if is_loopback_host(host) || is_overlay_host(host) => Ok(s.to_string()),
        "ws" => Err(format!(
            "relay {s:?} must use wss:// (ws:// is for loopback, .onion and .i2p only)"
        )),
        _ => Err(format!("relay {s:?} must be a wss:// address")),
    }
}

// The host classifiers are the shared net crate's (overlay hosts include
// `.fips`, any case and a trailing dot).
pub use deadhop_net::hosts::{is_loopback_host, is_overlay_host};

/// The proxy for relay connections: `host:port` (SOCKS5), or a
/// `socks5://`, `http://` or `https://` url (HTTP CONNECT for the last two).
pub fn socks5(s: &str) -> Result<ProxySpec, String> {
    let url = proxy_url(s)?;
    Ok(deadhop_net::relay::parse_proxy(&url)
        .ok()
        .flatten()
        .expect("a checked proxy url parses"))
}

/// The same proxy as a url (a bare `host:port` becomes `socks5://host:port`),
/// once it has been checked.
pub fn proxy_url(s: &str) -> Result<String, String> {
    let s = s.trim();
    let url = if s.contains("://") {
        s.to_string()
    } else {
        format!("socks5://{s}")
    };
    deadhop_net::relay::parse_proxy(&url).map_err(|e| format!("proxy {s:?}: {e}"))?;
    Ok(url)
}

/// A secret is never printed: only whether it is set.
pub fn redact(set: bool) -> &'static str {
    if set {
        "(set)"
    } else {
        "(not set)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_switched_off_stays_off() {
        let mut s = Sources::default();
        assert!(s.file && s.env && !s.remote);
        s.apply(&SourcesLayer {
            remote: Some(true),
            ..Default::default()
        });
        assert!(s.remote);
        s.apply(&SourcesLayer {
            env: Some(false),
            remote: Some(false),
            file: None,
        });
        assert!(!s.env && !s.remote);
        s.apply(&SourcesLayer {
            env: Some(true),
            remote: Some(true),
            file: Some(true),
        });
        assert!(!s.env && !s.remote && s.file);
    }

    #[test]
    fn plain_values_parse() {
        assert_eq!(list(" a, ,b,"), vec!["a", "b"]);
        for on in ["1", "true", "YES", " on "] {
            assert!(flag("X", on).unwrap());
        }
        for off in ["0", "false", "no", "off", ""] {
            assert!(!flag("X", off).unwrap());
        }
        assert!(flag("X", "maybe").unwrap_err().contains("X: \"maybe\""));
        assert_eq!(number::<u32>("N", " 7 ").unwrap(), 7);
        assert!(number::<u32>("N", "-1").unwrap_err().contains("not a valid number"));
        assert_eq!(redact(true), "(set)");
        assert_eq!(redact(false), "(not set)");
    }

    #[test]
    fn keys_are_npub_or_hex() {
        let k = nostr_sdk::Keys::generate().public_key();
        use nostr_sdk::ToBech32;
        assert_eq!(pubkey(&k.to_bech32().unwrap()).unwrap(), k);
        assert_eq!(pubkey(&format!(" {} ", k.to_hex())).unwrap(), k);
        assert!(pubkey("nope").unwrap_err().contains("not a nostr public key"));
    }

    #[test]
    fn relays_need_tls_unless_local_or_overlay() {
        assert!(relay("wss://relay.example.com").is_ok());
        assert!(relay("ws://127.0.0.1:7777").is_ok());
        assert!(relay("ws://localhost:7777").is_ok());
        assert!(relay("ws://[::1]:7777").is_ok());
        assert!(relay("ws://abc.onion").is_ok());
        assert!(relay("ws://abc.i2p").is_ok());
        assert!(relay("ws://relay.example.com").unwrap_err().contains("must use wss://"));
        assert!(relay("https://relay.example.com")
            .unwrap_err()
            .contains("must be a wss://"));
        assert!(relay("wss://u:p@relay.example.com").unwrap_err().contains("user name"));
        assert!(relay("relay").unwrap_err().contains("not a URL"));
    }

    #[test]
    fn proxies_are_socks5_or_http_connect_urls() {
        use deadhop_net::relay::ProxyKind;
        let p = socks5("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port),
            (ProxyKind::Socks5, "127.0.0.1", 9050)
        );
        assert_eq!(socks5("socks5h://127.0.0.1:9050").unwrap().port, 9050);
        // A bare address is SOCKS5; a name is fine too (Tor resolves .onion at the proxy).
        assert_eq!(
            (socks5("10.0.0.1:1080").unwrap().kind, socks5("tor:9050").unwrap().host),
            (ProxyKind::Socks5, "tor".into())
        );
        assert_eq!(socks5("http://127.0.0.1:3128").unwrap().kind, ProxyKind::Http);
        assert_eq!(socks5("https://proxy.example:443").unwrap().kind, ProxyKind::Https);
        assert!(socks5("ftp://h:1").unwrap_err().contains("scheme must be"));
        assert!(socks5("socks5://h").unwrap_err().contains("port"));
        assert_eq!(proxy_url(" 10.0.0.1:1080 ").unwrap(), "socks5://10.0.0.1:1080");
        assert_eq!(proxy_url("socks5h://tor:9050").unwrap(), "socks5h://tor:9050");
        assert!(proxy_url("").unwrap_err().contains("host"));
    }
}
