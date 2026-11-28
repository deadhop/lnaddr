//! LNURL-pay (LUD-06) as used by Lightning addresses (LUD-16), with comments
//! (LUD-12). Both services build the metadata string with [`metadata`], so
//! the string the gateway serves and the string the node hashes into the
//! invoice are the same bytes.

use nostr_sdk::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

/// Longest user name accepted. LUD-16 sets no limit; this keeps paths short.
pub const MAX_NAME_LEN: usize = 64;
/// Longest comment any address may allow (LUD-12 leaves it to the server).
pub const MAX_COMMENT_LEN: u16 = 2000;
/// Longest description, so the metadata stays a small, cacheable string.
pub const MAX_DESCRIPTION_LEN: usize = 640;
/// Smallest amount LNURL can express: one millisatoshi.
pub const MIN_MSAT: u64 = 1;
/// Largest amount accepted anywhere: 0.1 BTC. Larger payments are not what a
/// Lightning address is for, and capping it bounds every amount check.
pub const MAX_MSAT: u64 = 10_000_000_000_000;

/// Whether `name` is a valid LUD-16 user name: `a-z0-9-_.`, 1 to 64 long.
/// Upper case is refused rather than folded, so one address has one spelling.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
}

/// Whether `domain` is a plain lower-case DNS name (optionally with a port):
/// no scheme, no path, no user info. Used for configured domains only.
pub fn valid_domain(domain: &str) -> bool {
    let (host, port) = match domain.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (domain, None),
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    port_ok
        && !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Whether the domain is an onion service, which LUD-16 serves over http.
pub fn is_onion(domain: &str) -> bool {
    domain.split(':').next().is_some_and(|h| h.ends_with(".onion"))
}

/// The LUD-06 metadata string for `name@domain`: a JSON array holding the
/// description and the identifier, always serialised the same way.
pub fn metadata(name: &str, domain: &str, description: &str) -> String {
    let entries = [
        ["text/plain", description],
        ["text/identifier", &format!("{name}@{domain}")],
    ];
    serde_json::to_string(&entries).expect("an array of strings always serialises")
}

/// SHA-256 of the metadata string: the invoice's description hash.
pub fn description_hash(metadata: &str) -> [u8; 32] {
    sha256(metadata.as_bytes())
}

/// SHA-256, as a payment hash is of its preimage.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(bytes).to_byte_array()
}

/// First LUD-06 response: what the wallet shows before asking for an amount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayRequest {
    pub tag: String,
    pub callback: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub metadata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_allowed: Option<u16>,
}

/// Second LUD-06 response: the invoice, and where to ask whether it was
/// paid (LUD-21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceResponse {
    pub pr: String,
    pub routes: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
}

/// LUD-21 answer: whether the invoice was paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub status: String,
    pub settled: bool,
    pub preimage: Option<String>,
    pub pr: String,
}

/// LUD-06 error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub reason: String,
}

impl ErrorResponse {
    pub fn new(reason: impl Into<String>) -> Self {
        ErrorResponse {
            status: "ERROR".into(),
            reason: reason.into(),
        }
    }
}

/// Whether a comment fits what the address allows. LUD-12 counts characters.
pub fn comment_fits(comment: &str, allowed: u16) -> bool {
    comment.chars().count() <= allowed as usize && !comment.chars().any(|c| c.is_control() && c != '\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_lud16() {
        for ok in ["alice", "a", "bob-1", "x_y", "first.last", &"a".repeat(64)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "Alice", "al ice", "a/b", "ä", "a@b", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn domains_are_plain_dns_names() {
        for ok in [
            "example.com",
            "pay.example.com",
            "localhost:8080",
            "abc.onion",
            "a-b.io",
        ] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "Example.com",
            "https://x.io",
            "x.io/a",
            "u@x.io",
            "-x.io",
            "x-.io",
            "x..io",
            "x.io:",
            "x.io:123456",
            "x.io:8a",
            &format!("{}.io", "a".repeat(64)),
            &"a.".repeat(130),
        ] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn onion_domains_are_recognised() {
        assert!(is_onion("abc.onion"));
        assert!(is_onion("abc.onion:80"));
        assert!(!is_onion("onion.example.com"));
    }

    #[test]
    fn metadata_is_stable_and_escaped() {
        let m = metadata("alice", "example.com", "Pay \"alice\"");
        assert_eq!(
            m,
            r#"[["text/plain","Pay \"alice\""],["text/identifier","alice@example.com"]]"#
        );
        assert_eq!(metadata("alice", "example.com", "Pay \"alice\""), m);
        assert_eq!(
            hex::encode(description_hash("")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn pay_request_uses_lud06_keys() {
        let p = PayRequest {
            tag: "payRequest".into(),
            callback: "https://x.io/cb".into(),
            min_sendable: 1000,
            max_sendable: 2000,
            metadata: "[]".into(),
            comment_allowed: Some(10),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["minSendable"], 1000);
        assert_eq!(v["commentAllowed"], 10);
        let none = PayRequest {
            comment_allowed: None,
            ..p
        };
        assert!(serde_json::to_value(&none).unwrap().get("commentAllowed").is_none());
        let e = serde_json::to_value(ErrorResponse::new("no")).unwrap();
        assert_eq!(e, serde_json::json!({"status": "ERROR", "reason": "no"}));
        let i = serde_json::to_value(InvoiceResponse {
            pr: "lnbc1".into(),
            routes: vec![],
            verify: None,
        })
        .unwrap();
        assert_eq!(i, serde_json::json!({"pr": "lnbc1", "routes": []}));
        let v = serde_json::to_value(VerifyResponse {
            status: "OK".into(),
            settled: false,
            preimage: None,
            pr: "lnbc1".into(),
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"status": "OK", "settled": false, "preimage": null, "pr": "lnbc1"})
        );
    }

    #[test]
    fn comments_are_counted_in_characters() {
        assert!(comment_fits("", 0));
        assert!(comment_fits("ääää", 4));
        assert!(!comment_fits("ääää", 3));
        assert!(comment_fits("line\nbreak", 20));
        assert!(!comment_fits("bell\u{7}", 20));
    }
}
