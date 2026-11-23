//! Completes the MCP handshake locally, before any network message is read
//! (see `deadhop_cvm::handshake`); lnaddr's own identity in it is set here.

pub use deadhop_cvm::handshake::LocalHandshake;

/// Request id of the synthetic `initialize`. Real requests can never carry
/// it: the Nostr transport replaces every inbound id with a 64-hex event id.
pub const LOCAL_INIT_ID: &str = "lnaddr-local-init";

/// The handshake as lnaddr performs it: its own request id, client name and version.
pub fn local<T>(inner: T) -> LocalHandshake<T> {
    LocalHandshake::new(inner, LOCAL_INIT_ID, "lnaddr-local", env!("CARGO_PKG_VERSION"))
}
