//! What crosses ContextVM between the gateway (and admins) and the node.
//! Inputs refuse unknown fields; nothing free-form crosses in either direction.

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::node::config::{Address, LimitsLayer};

/// Tool names, shared by both sides.
pub const LIST_ADDRESSES: &str = "list_addresses";
pub const MAKE_INVOICE: &str = "make_invoice";
pub const GET_STATUS: &str = "get_status";
pub const GET_CONFIG: &str = "get_config";
pub const SET_ADDRESS: &str = "set_address";
pub const REMOVE_ADDRESS: &str = "remove_address";
pub const SET_LIMITS: &str = "set_limits";
pub const LIST_INVOICES: &str = "list_invoices";
pub const LOOKUP_INVOICE: &str = "lookup_invoice";
pub const VERIFY_INVOICE: &str = "verify_invoice";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressInfo {
    pub name: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub description: String,
    pub comment_allowed: u16,
    pub domains: Vec<String>,
}

impl AddressInfo {
    pub fn new(name: &str, a: &Address) -> Self {
        AddressInfo {
            name: name.to_string(),
            min_sendable: a.min_sendable,
            max_sendable: a.max_sendable,
            description: a.description.clone(),
            comment_allowed: a.comment_allowed,
            domains: a.domains.clone(),
        }
    }

    /// Whether this address may be served under `domain`.
    pub fn serves(&self, domain: &str) -> bool {
        self.domains.is_empty() || self.domains.iter().any(|d| d == domain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AddressList {
    pub addresses: Vec<AddressInfo>,
    /// The Lightning node key that signed this node's last invoice, if any.
    pub payee: Option<String>,
    pub network: String,
    /// Whether the node answers `verify_invoice` (older nodes do not).
    #[serde(default)]
    pub verifies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MakeInvoiceParams {
    pub name: String,
    pub domain: String,
    pub amount_msat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MadeInvoice {
    pub pr: String,
    pub payment_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Status {
    pub version: String,
    pub backend: String,
    pub network: String,
    pub addresses: usize,
    pub remote_settings: bool,
    pub invoices_made: u64,
    pub invoices_failed: u64,
    pub last_error: Option<String>,
    pub uptime_secs: u64,
    pub payee: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackendView {
    pub kind: String,
    pub url: String,
    pub secret: String,
    pub tls_pin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LimitsView {
    pub invoices_per_minute: u32,
    pub per_caller_per_minute: u32,
    pub concurrent: u32,
    pub invoice_expiry_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourcesView {
    pub file: bool,
    pub env: bool,
    pub remote: bool,
}

/// The node's configuration as an admin sees it: never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigView {
    pub relays: Vec<String>,
    pub gateways: Vec<String>,
    pub admins: Vec<String>,
    pub network: String,
    pub backend: BackendView,
    pub limits: LimitsView,
    pub addresses: Vec<AddressInfo>,
    pub sources: SourcesView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetAddressParams {
    pub name: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub description: String,
    #[serde(default)]
    pub comment_allowed: u16,
    #[serde(default)]
    pub domains: Vec<String>,
}

impl SetAddressParams {
    pub fn address(&self) -> Address {
        Address {
            min_sendable: self.min_sendable,
            max_sendable: self.max_sendable,
            description: self.description.clone(),
            comment_allowed: self.comment_allowed,
            domains: self.domains.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoveAddressParams {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetLimitsParams {
    pub invoices_per_minute: Option<u32>,
    pub per_caller_per_minute: Option<u32>,
    pub invoice_expiry_secs: Option<u32>,
}

impl SetLimitsParams {
    pub fn layer(&self) -> LimitsLayer {
        LimitsLayer {
            invoices_per_minute: self.invoices_per_minute,
            per_caller_per_minute: self.per_caller_per_minute,
            concurrent: None,
            invoice_expiry_secs: self.invoice_expiry_secs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListInvoicesParams {
    /// `settled` (the default), `pending`, `expired` or `all`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Only invoices settled (or, for the other statuses, made) at or after
    /// this time, in seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// The `next_cursor` of the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// At most this many (default 100, at most 1000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One invoice the node made, as an admin sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InvoiceView {
    pub payment_hash: String,
    pub name: String,
    pub domain: String,
    pub amount_msat: u64,
    /// The payer's LUD-12 comment.
    pub comment: Option<String>,
    pub pr: String,
    /// `settled`, `pending` or `expired`.
    pub state: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub settled_at: Option<u64>,
    pub preimage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InvoiceList {
    /// Oldest first: by when they were settled, or made.
    pub invoices: Vec<InvoiceView>,
    /// Pass as `cursor` for the next page; none on the last one.
    pub next_cursor: Option<String>,
    /// Why invoices are not being recorded, if they are not.
    pub record_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupInvoiceParams {
    pub payment_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyInvoiceParams {
    /// The address the invoice was made for.
    pub name: String,
    pub payment_hash: String,
}

/// What LUD-21 tells a payer: nothing about the address or the comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Verified {
    pub settled: bool,
    /// Only once settled.
    pub preimage: Option<String>,
    pub pr: String,
}

/// Whether `s` is a payment hash: 64 lower-case hex digits.
pub fn valid_payment_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Error codes in `error.data.code`, the same on both sides.
pub mod code {
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const INVALID: &str = "invalid_params";
    pub const NOT_FOUND: &str = "not_found";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const BUSY: &str = "busy";
    pub const BACKEND: &str = "backend_failed";
    pub const LOCKED: &str = "locked";
    /// The node serves only admins now (no proxy is reachable).
    pub const UNAVAILABLE: &str = "unavailable";
    pub const INTERNAL: &str = "internal";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_hashes_are_lower_case_hex() {
        assert!(valid_payment_hash(&"ab".repeat(32)));
        for bad in [
            "".to_string(),
            "ab".repeat(31),
            "AB".repeat(32),
            "zz".repeat(32),
            "ab".repeat(33),
        ] {
            assert!(!valid_payment_hash(&bad), "{bad}");
        }
        // An older node's list says nothing about verifying.
        let old: AddressList = serde_json::from_value(serde_json::json!({
            "addresses": [], "payee": null, "network": "regtest"
        }))
        .unwrap();
        assert!(!old.verifies);
    }

    #[test]
    fn addresses_know_their_domains() {
        let mut a = AddressInfo::new("alice", &Address::default_for("alice"));
        assert!(a.serves("any.example"));
        a.domains = vec!["x.io".into()];
        assert!(a.serves("x.io") && !a.serves("y.io"));
    }

    #[test]
    fn params_refuse_unknown_fields_and_convert() {
        let bad = serde_json::from_value::<MakeInvoiceParams>(serde_json::json!({
            "name": "a", "domain": "b", "amount_msat": 1, "extra": 1
        }));
        assert!(bad.is_err());
        let p = SetAddressParams {
            name: "a".into(),
            min_sendable: 1000,
            max_sendable: 2000,
            description: "d".into(),
            comment_allowed: 5,
            domains: vec![],
        };
        assert_eq!(p.address().comment_allowed, 5);
        let l = SetLimitsParams {
            invoices_per_minute: Some(3),
            per_caller_per_minute: None,
            invoice_expiry_secs: Some(90),
        }
        .layer();
        assert_eq!(
            (l.invoices_per_minute, l.concurrent, l.invoice_expiry_secs),
            (Some(3), None, Some(90))
        );
    }
}
