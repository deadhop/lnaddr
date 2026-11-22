//! The gateway: serves the public LNURL paths and asks nodes for invoices over ContextVM.

pub mod admin;
pub mod app;
pub mod config;
pub mod http;
pub mod nodes;
pub mod server;
#[cfg(test)]
mod tests;
