//! The node's ContextVM surface: two tools for gateways and five for admins.

use std::sync::Arc;

use contextvm_sdk::transport::server::{ClientPubkey, InboundEvent};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ErrorCode, Extensions, Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::json;

use crate::node::service::{Caller, Refusal, Service};
use crate::proto::{
    self, code, AddressList, ConfigView, MadeInvoice, MakeInvoiceParams, RemoveAddressParams, SetAddressParams,
    SetLimitsParams, Status,
};

/// The caller's key and request event, as the Nostr transport hands them over.
pub fn caller_from(ext: &Extensions) -> Caller {
    Caller {
        pubkey: ext.get::<ClientPubkey>().map(|p| p.0.clone()),
        event: ext.get::<InboundEvent>().map(|e| e.0.clone()),
    }
}

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
}

#[tool_router]
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
}

#[tool_handler]
impl ServerHandler for NodeServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("deadhop-lnaddr-node", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Lightning invoices for Lightning addresses, for the gateways and admins this node lets in.",
            )
    }
}

/// The tool names, so both sides agree on them.
pub const TOOLS: [&str; 7] = [
    proto::LIST_ADDRESSES,
    proto::MAKE_INVOICE,
    proto::GET_STATUS,
    proto::GET_CONFIG,
    proto::SET_ADDRESS,
    proto::REMOVE_ADDRESS,
    proto::SET_LIMITS,
];

#[cfg(test)]
mod tests {
    use super::*;

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
