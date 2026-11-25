//! The gateway's ContextVM surface for the network console: its network
//! (relays, proxies, routing, relay health, the privacy audit) and what the
//! console reads when an admin signs in. It runs on the admin key
//! (`admin.key`) and answers only the keys in `admins`; every tool checks
//! that again, so no other key sees or calls any of them.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{Extensions, Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};

use crate::gateway::network::{GatewayHealth, Network};
use crate::gateway::nodes::Directory;
use crate::node::mcp::{caller_from, rpc_error};
use crate::node::network::NodeInfo;
use deadhop_netengine::tools::tool_page;
use deadhop_netengine::view::{NetworkView, UpdateNetworkParams};

/// How long the gateway takes an invoice to stay payable for the console:
/// the nodes decide (600 seconds unless set otherwise there).
pub const INVOICE_EXPIRY_SECS: u64 = 600;

#[derive(Clone)]
pub struct GatewayServer {
    net: Arc<Network>,
    dir: Arc<Directory>,
    #[allow(dead_code)] // read by the tool_handler macro
    router: ToolRouter<GatewayServer>,
}

impl GatewayServer {
    pub fn new(net: Arc<Network>, dir: Arc<Directory>) -> Self {
        GatewayServer {
            net,
            dir,
            router: Self::tool_router(),
        }
    }

    /// Every tool: the gateway's own and the network tools of its engine.
    pub fn tool_router() -> ToolRouter<Self> {
        Self::own_tools() + deadhop_netengine::tools::network_router::<GatewayServer>()
    }

    /// What the console reads when an admin signs in (admins only). The
    /// gateway makes no invoices itself: the payment fields describe what
    /// its nodes serve.
    pub fn info(&self, c: &crate::node::service::Caller) -> Result<NodeInfo, crate::node::service::Refusal> {
        self.net.admin(c)?;
        let (min, max) = self.dir.amounts();
        Ok(NodeInfo {
            name: "deadhop lnaddr gateway".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            network: self.dir.chain().unwrap_or_else(|| "bitcoin".into()),
            public_invoicing: false,
            pow_bits: 0,
            pow_window_secs: 60,
            min_confirmations: 1,
            default_expiry_secs: INVOICE_EXPIRY_SECS,
            max_expiry_secs: INVOICE_EXPIRY_SECS,
            min_amount_sat: min,
            max_amount_sat: max,
            is_admin: true,
        })
    }
}

#[tool_router(router = own_tools)]
impl GatewayServer {
    #[tool(
        name = "get_info",
        description = "Admins only: what the gateway is, in the shape the network console reads when an admin signs in."
    )]
    async fn tool_get_info(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NodeInfo>, ErrorData> {
        self.info(&caller_from(&ctx.extensions)).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "get_health",
        description = "Admins only: the gateway's keys and relays, the relay connections, the proxies and routes in use, the last relay checks, nodes it shares no relay with, and how each node answered."
    )]
    async fn tool_get_health(&self, ctx: RequestContext<RoleServer>) -> Result<Json<GatewayHealth>, ErrorData> {
        let nodes = self.dir.healths().await;
        self.net
            .health(&caller_from(&ctx.extensions), nodes)
            .await
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_network",
        description = "Admins only: the network settings (relays, relay names, proxies, groups, routing rules, I2P registries), live and as configured on the host."
    )]
    async fn tool_get_network(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NetworkView>, ErrorData> {
        self.net
            .get_network(&caller_from(&ctx.extensions), self.dir.chain())
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "update_network",
        description = "Admins only, when remote settings are on: change the network settings; anything left out stays as it is. Every node must keep a relay in common with the gateway key. Saved in network.json and recorded in the audit log."
    )]
    async fn tool_update_network(
        &self,
        Parameters(p): Parameters<UpdateNetworkParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<NetworkView>, ErrorData> {
        self.net
            .update_network(&caller_from(&ctx.extensions), p, self.dir.chain())
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "reset_network",
        description = "Admins only, when remote settings are on: drop every saved network change and go back to the relays and proxy configured on the host."
    )]
    async fn tool_reset_network(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NetworkView>, ErrorData> {
        self.net
            .reset_network(&caller_from(&ctx.extensions), self.dir.chain())
            .map(Json)
            .map_err(rpc_error)
    }
}

#[tool_handler(router = self.router)]
impl ServerHandler for GatewayServer {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        // Every tool is for admins: refused before it runs, whatever it checks itself.
        self.net.admin(&caller_from(&context.extensions)).map_err(rpc_error)?;
        self.router.call(ToolCallContext::new(self, request, context)).await
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, ErrorData> {
        self.net.admin(&caller_from(&context.extensions)).map_err(rpc_error)?;
        tool_page(self.router.list_all(), request.and_then(|r| r.cursor).as_deref()).map(|(tools, next_cursor)| {
            rmcp::model::ListToolsResult {
                tools,
                meta: None,
                next_cursor,
            }
        })
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("deadhop-lnaddr-gateway", env!("CARGO_PKG_VERSION")))
            .with_instructions("The network of a Lightning address gateway, for its admins.")
    }
}

impl deadhop_netengine::tools::NetworkServer for GatewayServer {
    fn network(&self) -> &deadhop_netengine::netruntime::NetworkRuntime {
        &self.net.runtime
    }

    fn host(&self) -> &dyn deadhop_netengine::netruntime::NetworkHost {
        &*self.net
    }

    fn caller(&self, ext: &Extensions) -> crate::node::service::Caller {
        caller_from(ext)
    }

    fn to_rpc(&self, e: deadhop_netengine::error::Error) -> ErrorData {
        rpc_error(crate::node::network::from_engine(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvm::{CallError, NodeClient};
    use crate::gateway::tests::{console_keys, stack};
    use crate::node::service::tests::admin_keys;
    use nostr_sdk::prelude::Keys;
    use serde_json::json;
    use std::time::Duration;

    /// The console's client to a gateway of the test stack.
    pub async fn console(s: &crate::gateway::tests::Stack, keys: Keys, timeout: Duration) -> NodeClient {
        let server = s.gw().console.as_ref().unwrap().public_key();
        NodeClient::connect(
            keys,
            &server,
            std::slice::from_ref(&s.node_rig.relay_url),
            None,
            timeout,
        )
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_console_signs_in_and_reads_everything_and_no_one_else_gets_an_answer() {
        let s = stack().await;
        assert_eq!(
            s.gw().console.as_ref().unwrap().public_key(),
            admin_keys().public_key(),
            "the console signs in to admin.key"
        );
        let c = console(&s, console_keys(), Duration::from_secs(20)).await;
        let all: Vec<String> = GatewayServer::tool_router()
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        let shown = c.tool_names().await.unwrap();
        assert!(all.iter().all(|t| shown.contains(t)), "{shown:?}");
        assert!(shown.iter().any(|t| t == "check_proxy"));
        let info = c.call_value("get_info", json!({})).await.unwrap();
        assert_eq!(info["network"], "regtest");
        assert_eq!(info["is_admin"], true);
        assert_eq!(
            (info["min_amount_sat"].as_u64(), info["max_amount_sat"].as_u64()),
            (Some(1), Some(1_000_000))
        );
        let health = c.call_value("get_health", json!({})).await.unwrap();
        assert_eq!(health["nodes"][0]["reachable"], true);
        assert_eq!(health["keys"].as_array().unwrap().len(), 2);
        let relay = s.node_rig.relay_url.clone();
        let v = c
            .call_value(
                "update_network",
                json!({ "patch": { "relay_names": { relay.clone(): "Local" } } }),
            )
            .await
            .unwrap();
        assert_eq!(v["settings"]["relay_names"][&relay], "Local");
        assert_eq!(
            c.call_value("get_network", json!({})).await.unwrap()["chain"],
            "regtest"
        );
        for (tool, args) in [
            ("check_proxy", json!({})),
            ("check_relays", json!({})),
            ("get_relay_history", json!({ "window": "1h" })),
            ("get_privacy_audit", json!({})),
            ("reset_network", json!({})),
        ] {
            let v = c.call_value(tool, args).await.unwrap();
            assert!(v.is_object(), "{tool}: {v}");
        }
        let e = c
            .call_value("resolve_i2p_name", json!({ "name": "example.i2p" }))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, CallError::Refused { message, .. } if message.contains("I2P router")),
            "{e:?}"
        );
        // A key not in `admins` (the node admin key the gateway itself uses
        // included) gets no answer at all.
        for k in [Keys::generate(), admin_keys()] {
            let other = console(&s, k, Duration::from_secs(2)).await;
            assert_eq!(
                other.call_value("get_info", json!({})).await.unwrap_err(),
                CallError::Timeout
            );
            other.close().await;
        }
        // The gateway still manages its node with the same key meanwhile.
        let (status, _) = s.get("/.well-known/lnurlp/alice").await;
        assert_eq!(status, 200);
        c.close().await;
        s.stop().await;
    }

    #[tokio::test]
    async fn before_any_node_answers_the_info_says_bitcoin_and_no_amounts() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::gateway::tests::gateway_config_for(Vec::new(), dir.path());
        let net = Arc::new(Network::new(cfg));
        let dir = Arc::new(Directory::new(
            Vec::new(),
            Keys::generate(),
            net.clone(),
            Duration::from_secs(1),
        ));
        let server = GatewayServer::new(net, dir);
        let i = server
            .info(&crate::node::service::tests::caller(&console_keys()))
            .unwrap();
        assert_eq!(
            (i.network.as_str(), i.min_amount_sat, i.max_amount_sat),
            ("bitcoin", 0, 0)
        );
        assert!(server
            .info(&crate::node::service::tests::caller(&admin_keys()))
            .is_err());
        assert_eq!(
            ServerHandler::get_info(&server).server_info.name,
            "deadhop-lnaddr-gateway"
        );
    }
}
