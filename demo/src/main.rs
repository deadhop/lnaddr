//! lnaddr-demo: a relay on ws://127.0.0.1:7788 and a fake LND on
//! http://127.0.0.1:18080 (macaroon "demo"). Invoices are real regtest BOLT11
//! invoices signed by a fixed test key; nothing can pay them, so
//! `POST /demo/pay/<payment hash>` marks one paid instead.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use nostr_relay_builder::prelude::*;
use nostr_sdk::hashes::{sha256, Hash};
use nostr_sdk::secp256k1::{Secp256k1, SecretKey};
use serde_json::{json, Value};

/// Every invoice made: payment hash (hex) → (preimage, when it was paid).
type Invoices = Arc<Mutex<HashMap<String, ([u8; 32], Option<u64>)>>>;

fn unauthorized(headers: &HeaderMap) -> Option<(StatusCode, Json<Value>)> {
    headers
        .get("grpc-metadata-macaroon")
        .is_none_or(|m| m != "demo")
        .then(|| (StatusCode::UNAUTHORIZED, Json(json!({ "message": "verification failed" }))))
}

async fn invoice(State(invoices): State<Invoices>, headers: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if let Some(no) = unauthorized(&headers) {
        return no;
    }
    let msat: u64 = body["value_msat"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    let hash = base64::engine::general_purpose::STANDARD.decode(body["description_hash"].as_str().unwrap_or("")).unwrap_or_default();
    let Ok(hash) = <[u8; 32]>::try_from(hash) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "message": "description_hash must be 32 bytes" })));
    };
    let expiry: u64 = body["expiry"].as_str().and_then(|s| s.parse().ok()).unwrap_or(3600);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[0x41; 32]).unwrap();
    let preimage = sha256::Hash::hash(&now.as_nanos().to_be_bytes());
    let payment_hash = sha256::Hash::hash(preimage.as_byte_array());
    invoices.lock().unwrap().insert(hex(payment_hash.as_byte_array()), (preimage.to_byte_array(), None));
    let pr = InvoiceBuilder::new(Currency::Regtest)
        .description_hash(sha256::Hash::from_byte_array(hash))
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([7; 32]))
        .duration_since_epoch(now)
        .expiry_time(Duration::from_secs(expiry))
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(msat)
        .build_signed(|m| secp.sign_ecdsa_recoverable(m, &key))
        .unwrap();
    eprintln!("fake lnd: invoice for {msat} msat, payment hash {}", hex(payment_hash.as_byte_array()));
    (StatusCode::OK, Json(json!({ "payment_request": pr.to_string(), "r_hash": "" })))
}

/// LND's LookupInvoice: the state, and the preimage once settled.
async fn lookup(State(invoices): State<Invoices>, headers: HeaderMap, Path(hash): Path<String>) -> (StatusCode, Json<Value>) {
    if let Some(no) = unauthorized(&headers) {
        return no;
    }
    match invoices.lock().unwrap().get(&hash) {
        None => (StatusCode::NOT_FOUND, Json(json!({ "code": 5, "message": "unable to locate invoice" }))),
        Some((preimage, paid)) => (
            StatusCode::OK,
            Json(json!({
                "state": if paid.is_some() { "SETTLED" } else { "OPEN" },
                "r_preimage": base64::engine::general_purpose::STANDARD.encode(preimage),
                "settle_date": paid.unwrap_or(0).to_string(),
            })),
        ),
    }
}

/// Not LND: pretend the invoice was paid.
async fn pay(State(invoices): State<Invoices>, Path(hash): Path<String>) -> StatusCode {
    match invoices.lock().unwrap().get_mut(&hash) {
        None => StatusCode::NOT_FOUND,
        Some((_, paid)) => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            *paid = Some(now);
            eprintln!("fake lnd: {hash} paid");
            StatusCode::NO_CONTENT
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() {
    let relay = LocalRelay::new(RelayBuilder::default().port(7788));
    relay.run().await.expect("port 7788 is free");
    eprintln!("relay:    {}", relay.url().await);
    let lnd = tokio::net::TcpListener::bind("127.0.0.1:18080").await.expect("port 18080 is free");
    eprintln!("fake lnd: http://127.0.0.1:18080 (macaroon: demo)");
    let app = Router::new()
        .route("/v1/invoices", post(invoice))
        .route("/v1/invoice/{hash}", get(lookup))
        .route("/demo/pay/{hash}", post(pay))
        .with_state(Invoices::default());
    tokio::select! {
        _ = axum::serve(lnd, app) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
