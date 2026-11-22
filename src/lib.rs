//! deadhop lnaddr: Lightning addresses (LUD-16) for a node with no public
//! address. The node service sits next to the Lightning node and answers
//! invoice requests over ContextVM (MCP over Nostr); the gateway serves the
//! public LNURL paths and asks the node for each invoice.

pub mod bolt11;
pub mod cvm;
pub mod files;
pub mod gateway;
pub mod handshake;
pub mod lnurl;
pub mod node;
pub mod pool;
pub mod proto;
pub mod ratelimit;
pub mod settings;
pub mod tls;

/// Resolves when the service should stop. Boxed, so the functions taking it
/// are compiled once rather than once per kind of future.
pub type Shutdown = std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;

/// Reads a configuration variable by name.
pub type Lookup = Box<dyn Fn(&str) -> Option<String>>;

/// An error as text, for errors that are passed on rather than handled.
pub fn why(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolves on SIGINT or SIGTERM. The handlers are installed when this is
/// called, not when it is first awaited, so a signal during start-up is not
/// lost. Must be called inside a Tokio runtime.
pub fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler can be installed");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler can be installed");
    async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn errors_become_text() {
        assert_eq!(super::why(std::io::Error::other("boom")), "boom");
        assert!(super::unix_now() > 1_700_000_000);
    }
}
