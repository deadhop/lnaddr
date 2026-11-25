//! The gateway: serves the public LNURL paths and asks nodes for invoices over ContextVM.

pub mod admin;
pub mod app;
pub mod config;
pub mod http;
pub mod mcp;
pub mod network;
pub mod nodes;
pub mod server;
pub mod supervise;
#[cfg(test)]
mod tests;
