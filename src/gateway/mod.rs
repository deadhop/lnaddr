//! The gateway: serves the public LNURL paths and asks nodes for invoices over ContextVM.

pub mod config;
pub mod nodes;
pub mod server;
pub mod admin;
pub mod http;
pub mod app;
#[cfg(test)]
mod tests;
