//! The relay pool: the shared net crate's (`deadhop_net::relay::Pool`). It
//! connects through a SOCKS5, HTTP or HTTPS CONNECT proxy, and returns as soon
//! as one relay accepts an event.

use nostr_sdk::RelayStatus;

pub use deadhop_net::relay::{Pool, ProxySpec};

/// How many of the pool's relays are connected now.
pub async fn connected(pool: &Pool) -> usize {
    let relays = pool.client().relays().await;
    relays.values().filter(|r| r.status() == RelayStatus::Connected).count()
}
