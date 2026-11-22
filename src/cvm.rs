//! A ContextVM client for calling a node: used by the gateway, its CLI and
//! its web interface.
//!
//! It runs stateless: the MCP handshake is answered locally and every call is
//! one request event and one reply event. Nothing is kept per session on
//! either side, so a node restart never strands the gateway on a dead
//! session, and the first invoice after a restart costs no extra round trip.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use contextvm_sdk::transport::client::{NostrClientTransport, NostrClientTransportConfig};
use contextvm_sdk::{EncryptionMode, GiftWrapMode};
use nostr_sdk::prelude::{Keys, PublicKey};
use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService, ServiceError};
use rmcp::ServiceExt;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::pool::Pool;

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The node answered with a refusal; `code` is from [`crate::proto::code`].
    Refused { code: String, message: String },
    /// No answer in time.
    Timeout,
    /// The connection to the relays is gone; reconnect.
    Closed(String),
    /// The answer was not what the tool promises.
    Bad(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Refused { code, message } => write!(f, "{message} ({code})"),
            CallError::Timeout => write!(f, "the node did not answer in time"),
            CallError::Closed(e) => write!(f, "the relay connection is gone: {e}"),
            CallError::Bad(e) => write!(f, "the node's answer was not understood: {e}"),
        }
    }
}

/// Decode a tool's JSON result. Kept tiny: it is copied for every result type.
pub fn decode<T: DeserializeOwned>(v: Value) -> Result<T, CallError> {
    serde_json::from_value(v).map_err(bad)
}

fn bad(e: serde_json::Error) -> CallError {
    CallError::Bad(e.to_string())
}

pub struct NodeClient {
    service: RunningService<RoleClient, ()>,
    pool: Arc<Pool>,
    timeout: Duration,
}

impl NodeClient {
    pub async fn connect(
        keys: Keys,
        node: &PublicKey,
        relays: &[String],
        socks5: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let pool = Arc::new(Pool::new(keys, socks5));
        let config = NostrClientTransportConfig::default()
            .with_relay_urls(relays.to_vec())
            .with_server_pubkey(node.to_hex())
            .with_encryption_mode(EncryptionMode::Required)
            .with_gift_wrap_mode(GiftWrapMode::Ephemeral)
            .with_stateless(true)
            .with_timeout(timeout)
            .with_discovery_relay_urls(Vec::new())
            .with_oversized_enabled(false);
        let transport = NostrClientTransport::with_relay_pool(config, pool.clone())
            .await
            .map_err(crate::why)?;
        let service = ().serve(transport).await.map_err(crate::why)?;
        Ok(NodeClient { service, pool, timeout })
    }

    /// Cancelling this ends the client, as a dead relay connection would.
    #[cfg(test)]
    pub fn service_token(&self) -> rmcp::service::RunningServiceCancellationToken {
        self.service.cancellation_token()
    }

    /// How many relays are connected.
    pub async fn relays_connected(&self) -> usize {
        self.pool.connected().await
    }

    /// Call `tool` with `args` and decode its structured result.
    pub async fn call<T: DeserializeOwned>(&self, tool: &'static str, args: Value) -> Result<T, CallError> {
        self.call_value(tool, args).await.and_then(decode)
    }

    /// Call `tool` and return its structured result as JSON.
    pub async fn call_value(&self, tool: &'static str, args: Value) -> Result<Value, CallError> {
        let mut params = CallToolRequestParams::new(tool);
        if let Value::Object(map) = args {
            params = params.with_arguments(map);
        }
        let result = match tokio::time::timeout(self.timeout, self.service.call_tool(params)).await {
            Err(_) => return Err(CallError::Timeout),
            Ok(Err(ServiceError::McpError(e))) => {
                let code = e
                    .data
                    .as_ref()
                    .and_then(|d| d.get("code"))
                    .and_then(Value::as_str)
                    .unwrap_or("error");
                return Err(CallError::Refused {
                    code: code.to_string(),
                    message: e.message.to_string(),
                });
            }
            Ok(Err(e)) => return Err(CallError::Closed(e.to_string())),
            Ok(Ok(r)) => r,
        };
        if result.is_error == Some(true) {
            // Arguments the tool could not read come back as an error result.
            let message = result
                .content
                .iter()
                .find_map(|c| c.as_text().map(|t| t.text.clone()))
                .unwrap_or_default();
            return Err(CallError::Refused {
                code: crate::proto::code::INVALID.into(),
                message,
            });
        }
        result
            .structured_content
            .ok_or(CallError::Bad("no structured content".into()))
    }

    pub async fn close(self) {
        let _ = self.service.cancel().await;
        let _ = contextvm_sdk::relay::RelayPoolTrait::disconnect(&*self.pool).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_closed_client_says_so() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let c = NodeClient::connect(
            Keys::generate(),
            &Keys::generate().public_key(),
            &[url],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        c.service.cancellation_token().cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let e = c.call::<Value>("anything", Value::Null).await.unwrap_err();
        assert!(matches!(e, CallError::Closed(_)), "{e:?}");
    }

    #[test]
    fn errors_read_well() {
        let r = CallError::Refused {
            code: "not_found".into(),
            message: "no address".into(),
        };
        assert_eq!(r.to_string(), "no address (not_found)");
        assert!(CallError::Timeout.to_string().contains("in time"));
        assert!(CallError::Closed("x".into()).to_string().contains("gone: x"));
        assert!(CallError::Bad("y".into()).to_string().contains("understood: y"));
    }
}
