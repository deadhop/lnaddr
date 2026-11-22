//! Shared pieces of configuration: where values come from, and parsers for
//! the values both services take.
//!
//! Values come in layers, later ones winning: built-in (compiled into the
//! binary), then a TOML file, then environment variables, then (node only)
//! settings saved over ContextVM by an admin. Any layer can switch a later
//! source off for good; none can switch back on one an earlier layer
//! switched off. A binary built with `sources = { file = false, env = false }`
//! therefore runs only on its built-in values.

use std::net::{IpAddr, SocketAddr};

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

pub fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare == "localhost" || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub fn is_overlay_host(host: &str) -> bool {
    host.ends_with(".onion") || host.ends_with(".i2p")
}

/// A SOCKS5 proxy for relay connections, as `host:port` or `socks5://host:port`.
pub fn socks5(s: &str) -> Result<SocketAddr, String> {
    let bare = s
        .trim()
        .trim_start_matches("socks5h://")
        .trim_start_matches("socks5://");
    bare.parse()
        .map_err(|_| format!("proxy {s:?} must be an IP address and port, e.g. 127.0.0.1:9050"))
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
    fn proxies_are_socket_addresses() {
        assert_eq!(socks5("socks5://127.0.0.1:9050").unwrap().port(), 9050);
        assert_eq!(socks5("socks5h://127.0.0.1:9050").unwrap().port(), 9050);
        assert_eq!(socks5("10.0.0.1:1080").unwrap().port(), 1080);
        assert!(socks5("tor:9050").unwrap_err().contains("IP address and port"));
    }
}
