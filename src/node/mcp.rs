//! The node's ContextVM surface: two tools for gateways; those and the rest
//! (settings, health, and the network tools of the shared network engine)
//! for admins. The node has one key for both, so the tools are filtered by
//! who calls: a gateway never sees or calls an admin tool.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ErrorCode, Extensions, Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::json;

use crate::node::network::{NodeHealth, NodeInfo};
use crate::node::service::{Refusal, Role, Service};
use crate::proto::{
    self, code, AddressList, ConfigView, InvoiceList, InvoiceView, ListInvoicesParams, LookupInvoiceParams,
    MadeInvoice, MakeInvoiceParams, RemoveAddressParams, SetAddressParams, SetLimitsParams, Status, Verified,
    VerifyInvoiceParams,
};
use deadhop_netengine::tools::tool_page;
use deadhop_netengine::view::{NetworkView, UpdateNetworkParams};

// Reading the caller is the shared ContextVM crate's.
pub use deadhop_cvm::caller::caller_from;

/// A JSON-RPC error carrying the refusal's code in `data.code`.
pub fn rpc_error(r: Refusal) -> ErrorData {
    let n = match r.code {
        code::INVALID => -32602,
        code::UNAUTHORIZED => -32001,
        code::NOT_FOUND => -32002,
        code::RATE_LIMITED => -32004,
        code::BUSY => -32005,
        code::LOCKED => -32006,
        code::BACKEND => -32007,
        code::UNAVAILABLE => -32008,
        _ => -32603,
    };
    ErrorData::new(ErrorCode(n), r.message, Some(json!({ "code": r.code })))
}

#[derive(Clone)]
pub struct NodeServer {
    svc: Arc<Service>,
    #[allow(dead_code)] // read by the tool_handler macro
    router: ToolRouter<NodeServer>,
}

impl NodeServer {
    pub fn new(svc: Arc<Service>) -> Self {
        NodeServer {
            svc,
            router: Self::tool_router(),
        }
    }

    /// Every tool: the node's own and the network tools of its engine.
    pub fn tool_router() -> ToolRouter<Self> {
        Self::own_tools() + deadhop_netengine::tools::network_router::<NodeServer>()
    }
}

/// The tools a gateway may see and call; every other tool is for admins.
pub const GATEWAY_TOOLS: [&str; 3] = [proto::LIST_ADDRESSES, proto::MAKE_INVOICE, proto::VERIFY_INVOICE];

#[tool_router(router = own_tools)]
impl NodeServer {
    #[tool(
        name = "list_addresses",
        description = "The Lightning addresses this node serves, with their limits."
    )]
    async fn list_addresses(&self, ctx: RequestContext<RoleServer>) -> Result<Json<AddressList>, ErrorData> {
        self.svc
            .list_addresses(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "make_invoice",
        description = "Make an invoice for name@domain that commits to its LUD-06 metadata."
    )]
    async fn make_invoice(
        &self,
        Parameters(p): Parameters<MakeInvoiceParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<MadeInvoice>, ErrorData> {
        self.svc
            .make_invoice(&caller_from(&ctx.extensions), p)
            .await
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "verify_invoice",
        description = "Whether an invoice this node made for an address was paid (LUD-21): settled, the preimage once paid, and the invoice."
    )]
    async fn verify_invoice(
        &self,
        Parameters(p): Parameters<VerifyInvoiceParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Verified>, ErrorData> {
        self.svc
            .verify_invoice(&caller_from(&ctx.extensions), p)
            .await
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "list_invoices",
        description = "Admins only: the invoices this node made, oldest first, with each payer's comment. status is settled (the default), pending, expired or all; since is a Unix time; pass next_cursor back as cursor for the next page."
    )]
    async fn list_invoices(
        &self,
        Parameters(p): Parameters<ListInvoicesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<InvoiceList>, ErrorData> {
        self.svc
            .list_invoices(&caller_from(&ctx.extensions), p)
            .await
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "lookup_invoice",
        description = "Admins only: one invoice this node made, by payment hash, with the payer's comment and whether it was paid."
    )]
    async fn lookup_invoice(
        &self,
        Parameters(p): Parameters<LookupInvoiceParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<InvoiceView>, ErrorData> {
        self.svc
            .lookup_invoice(&caller_from(&ctx.extensions), p)
            .await
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_status",
        description = "Admins only: backend, counters, last error and uptime."
    )]
    async fn get_status(&self, ctx: RequestContext<RoleServer>) -> Result<Json<Status>, ErrorData> {
        self.svc
            .status(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_config",
        description = "Admins only: the configuration in effect, without secrets."
    )]
    async fn get_config(&self, ctx: RequestContext<RoleServer>) -> Result<Json<ConfigView>, ErrorData> {
        self.svc
            .config_view(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "set_address",
        description = "Admins only, when remote settings are on: add or change an address."
    )]
    async fn set_address(
        &self,
        Parameters(p): Parameters<SetAddressParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<ConfigView>, ErrorData> {
        self.svc
            .set_address(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "remove_address",
        description = "Admins only, when remote settings are on: stop serving an address."
    )]
    async fn remove_address(
        &self,
        Parameters(p): Parameters<RemoveAddressParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<ConfigView>, ErrorData> {
        self.svc
            .remove_address(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "set_limits",
        description = "Admins only, when remote settings are on: change invoice limits."
    )]
    async fn set_limits(
        &self,
        Parameters(p): Parameters<SetLimitsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<ConfigView>, ErrorData> {
        self.svc
            .set_limits(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_info",
        description = "Admins only: what the node is, in the shape the network console reads when an admin signs in."
    )]
    async fn tool_get_info(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NodeInfo>, ErrorData> {
        self.svc
            .info(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_health",
        description = "Admins only: the node's key and relays, the relay connections, the proxies and routes in use, and the last relay checks."
    )]
    async fn tool_get_health(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NodeHealth>, ErrorData> {
        self.svc
            .health(&caller_from(&ctx.extensions))
            .await
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_network",
        description = "Admins only: the network settings (relays, relay names, proxies, groups, routing rules, I2P registries), live and as configured on the host."
    )]
    async fn tool_get_network(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NetworkView>, ErrorData> {
        self.svc
            .get_network(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "update_network",
        description = "Admins only, when remote settings are on: change the network settings; anything left out stays as it is. Saved in network.json and recorded in the audit log."
    )]
    async fn tool_update_network(
        &self,
        Parameters(p): Parameters<UpdateNetworkParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<NetworkView>, ErrorData> {
        self.svc
            .update_network(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "reset_network",
        description = "Admins only, when remote settings are on: drop every saved network change and go back to the relays and proxy configured on the host."
    )]
    async fn tool_reset_network(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NetworkView>, ErrorData> {
        self.svc
            .reset_network(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }
}

#[tool_handler(router = self.router)]
impl ServerHandler for NodeServer {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        // A gateway is refused before any admin tool runs, whatever the tool
        // itself checks.
        if !GATEWAY_TOOLS.contains(&request.name.as_ref()) {
            self.svc.admin(&caller_from(&context.extensions)).map_err(rpc_error)?;
        }
        self.router.call(ToolCallContext::new(self, request, context)).await
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, ErrorData> {
        let role = self.svc.role(&caller_from(&context.extensions)).map_err(rpc_error)?;
        let tools = self
            .router
            .list_all()
            .into_iter()
            .filter(|t| role == Role::Admin || GATEWAY_TOOLS.contains(&t.name.as_ref()))
            .collect();
        tool_page(tools, request.and_then(|r| r.cursor).as_deref()).map(|(tools, next_cursor)| {
            rmcp::model::ListToolsResult {
                tools,
                meta: None,
                next_cursor,
            }
        })
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("deadhop-lnaddr-node", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Lightning invoices for Lightning addresses, for the gateways and admins this node lets in.",
            )
    }
}

impl deadhop_netengine::tools::NetworkServer for NodeServer {
    fn network(&self) -> &deadhop_netengine::netruntime::NetworkRuntime {
        &self.svc.net.runtime
    }

    fn host(&self) -> &dyn deadhop_netengine::netruntime::NetworkHost {
        &*self.svc
    }

    fn caller(&self, ext: &Extensions) -> crate::node::service::Caller {
        caller_from(ext)
    }

    fn to_rpc(&self, e: deadhop_netengine::error::Error) -> ErrorData {
        rpc_error(crate::node::network::from_engine(e))
    }
}

/// The node's own tool names, so both sides agree on them.
pub const TOOLS: [&str; 10] = [
    proto::LIST_ADDRESSES,
    proto::MAKE_INVOICE,
    proto::VERIFY_INVOICE,
    proto::LIST_INVOICES,
    proto::LOOKUP_INVOICE,
    proto::GET_STATUS,
    proto::GET_CONFIG,
    proto::SET_ADDRESS,
    proto::REMOVE_ADDRESS,
    proto::SET_LIMITS,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvm::CallError;
    use crate::node::app::start;
    use crate::node::app::tests::{client, node_rig};
    use crate::node::backend::Kind;
    use crate::node::service::tests::{admin_keys, gateway_keys};
    use std::time::Duration;

    fn names(r: ToolRouter<NodeServer>) -> Vec<String> {
        r.list_all().iter().map(|t| t.name.to_string()).collect()
    }

    /// `check_proxy` and the other network tools open connections from the
    /// node's machine, and the admin tools change it: the node's one key
    /// serves gateways too, so a gateway must never see or call any of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_gateway_sees_a_network_tool() {
        let network = names(deadhop_netengine::tools::network_router::<NodeServer>());
        assert!(network.len() >= 5, "{network:?}");
        assert!(network.iter().any(|n| n == "check_proxy"));
        let all = names(NodeServer::tool_router());
        let admin_only: Vec<&String> = all.iter().filter(|t| !GATEWAY_TOOLS.contains(&t.as_str())).collect();
        assert!(network.iter().all(|n| admin_only.contains(&n)));

        let r = node_rig(Kind::Lnd).await;
        let node = start(r.cfg.clone()).await.unwrap();
        let gw = client(&r, gateway_keys(), &node.keys, Duration::from_secs(10)).await;
        let mut shown = gw.tool_names().await.unwrap();
        shown.sort();
        assert_eq!(shown, GATEWAY_TOOLS);
        for tool in &admin_only {
            let name: &'static str = tool.to_string().leak();
            let refused = gw.call_value(name, serde_json::json!({})).await.unwrap_err();
            assert!(
                matches!(&refused, CallError::Refused { code, .. } if code == "unauthorized"),
                "{tool}: {refused:?}"
            );
        }

        let admin = client(&r, admin_keys(), &node.keys, Duration::from_secs(20)).await;
        let shown = admin.tool_names().await.unwrap();
        assert!(all.iter().all(|t| shown.contains(t)), "{shown:?}");
        for (tool, args) in [
            ("check_proxy", serde_json::json!({})),
            ("check_relays", serde_json::json!({})),
            ("get_relay_history", serde_json::json!({ "window": "1h" })),
            ("get_privacy_audit", serde_json::json!({})),
            ("get_info", serde_json::json!({})),
            ("get_health", serde_json::json!({})),
            ("get_network", serde_json::json!({})),
            ("update_network", serde_json::json!({ "patch": {} })),
            ("reset_network", serde_json::json!({})),
            ("list_invoices", serde_json::json!({ "status": "all" })),
        ] {
            let v = admin.call_value(tool, args).await.unwrap();
            assert!(v.is_object(), "{tool}: {v}");
        }
        // Served, and refused for its own reason: there is no I2P router.
        let e = admin
            .call_value("resolve_i2p_name", serde_json::json!({ "name": "example.i2p" }))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, CallError::Refused { code, message } if code == "invalid_params" && message.contains("I2P router")),
            "{e:?}"
        );
        let audit = admin
            .call_value("get_privacy_audit", serde_json::json!({}))
            .await
            .unwrap();
        let ports = audit["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "service_ports");
        assert!(audit["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["id"] != "electrum_network"));
        assert!(ports.is_some());
        for (who, tool, args) in [
            (
                &gw,
                "verify_invoice",
                serde_json::json!({ "name": "alice", "payment_hash": "00".repeat(32) }),
            ),
            (
                &admin,
                "lookup_invoice",
                serde_json::json!({ "payment_hash": "00".repeat(32) }),
            ),
        ] {
            let e = who.call_value(tool, args).await.unwrap_err();
            assert!(
                matches!(&e, CallError::Refused { code, .. } if code == "not_found"),
                "{tool}: {e:?}"
            );
        }
        gw.close().await;
        admin.close().await;
        node.until(Box::pin(async {})).await.unwrap();
    }

    #[test]
    fn refusals_map_to_stable_codes() {
        for (c, n) in [
            (code::INVALID, -32602),
            (code::UNAUTHORIZED, -32001),
            (code::NOT_FOUND, -32002),
            (code::RATE_LIMITED, -32004),
            (code::BUSY, -32005),
            (code::LOCKED, -32006),
            (code::BACKEND, -32007),
            (code::UNAVAILABLE, -32008),
            (code::INTERNAL, -32603),
        ] {
            let e = rpc_error(Refusal {
                code: c,
                message: "m".into(),
            });
            assert_eq!(e.code.0, n);
            assert_eq!(e.data.unwrap()["code"], c);
        }
        assert!(caller_from(&Extensions::new()).pubkey.is_none());
    }
}
