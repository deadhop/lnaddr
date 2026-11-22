//! deadhop lnaddr: Lightning addresses (LUD-16) for a node with no public
//! address. The node service sits next to the Lightning node and answers
//! invoice requests over ContextVM (MCP over Nostr); the gateway serves the
//! public LNURL paths and asks the node for each invoice.

pub mod bolt11;
pub mod cvm;
pub mod files;
pub mod handshake;
pub mod lnurl;
pub mod node;
pub mod pool;
pub mod proto;
pub mod ratelimit;
pub mod settings;
pub mod tls;

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
