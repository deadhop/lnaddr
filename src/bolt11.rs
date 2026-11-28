//! Checks on every invoice before it is handed out. The node checks what its
//! Lightning backend returned and the gateway checks what the node returned,
//! so a backend bug or a tampered reply never reaches a wallet as a wrong
//! invoice.

use std::str::FromStr;
use std::time::Duration;

use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef, Currency};

/// Which chain invoices must be for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl FromStr for Network {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            other => Err(format!(
                "unknown network {other:?} (bitcoin, testnet, signet or regtest)"
            )),
        }
    }
}

impl Network {
    fn matches(self, c: Currency) -> bool {
        matches!(
            (self, c),
            (Network::Bitcoin, Currency::Bitcoin)
                | (Network::Testnet, Currency::BitcoinTestnet)
                | (Network::Signet, Currency::Signet)
                | (Network::Regtest, Currency::Regtest)
        )
    }
}

/// What an invoice must say.
#[derive(Debug, Clone)]
pub struct Expect<'a> {
    pub amount_msat: u64,
    pub description_hash: [u8; 32],
    pub network: Option<Network>,
    /// Hex public key of the node that must have signed it.
    pub payee: Option<&'a str>,
    /// Seconds since the Unix epoch.
    pub now: u64,
    /// The invoice must stay payable at least this long.
    pub min_expiry: Duration,
}

/// Facts about an invoice that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub payment_hash: String,
    pub payee: String,
    /// When it stops being payable, in seconds since the Unix epoch.
    pub expires_at: u64,
}

/// The payment hash (hex) of a BOLT11 invoice, if it is one.
pub fn payment_hash(pr: &str) -> Option<String> {
    let inv = Bolt11Invoice::from_str(pr.trim()).ok().filter(|_| pr.len() <= 4096)?;
    Some(hex::encode(inv.payment_hash().to_byte_array()))
}

/// Parse a BOLT11 invoice and check it against `want`. The signature is
/// checked while parsing.
pub fn check(pr: &str, want: &Expect) -> Result<Checked, String> {
    if pr.len() > 4096 {
        return Err("invoice is too long".into());
    }
    let inv = Bolt11Invoice::from_str(pr.trim()).map_err(|e| format!("not a valid invoice: {e}"))?;
    if inv.amount_milli_satoshis() != Some(want.amount_msat) {
        return Err(format!(
            "invoice is for {:?} msat, not {} msat",
            inv.amount_milli_satoshis(),
            want.amount_msat
        ));
    }
    match inv.description() {
        Bolt11InvoiceDescriptionRef::Hash(h) if h.0.to_byte_array() == want.description_hash => {}
        _ => return Err("invoice does not commit to the metadata (description hash)".into()),
    }
    if let Some(net) = want.network {
        if !net.matches(inv.currency()) {
            return Err(format!("invoice is for {:?}, not {net:?}", inv.currency()));
        }
    }
    let payee = hex::encode(inv.get_payee_pub_key().serialize());
    if let Some(p) = want.payee {
        if !p.eq_ignore_ascii_case(&payee) {
            return Err(format!("invoice is signed by {payee}, not the pinned node {p}"));
        }
    }
    if inv.would_expire(Duration::from_secs(want.now) + want.min_expiry) {
        return Err("invoice expires too soon".into());
    }
    Ok(Checked {
        payment_hash: hex::encode(inv.payment_hash().to_byte_array()),
        payee,
        expires_at: inv.expires_at().map_or(u64::MAX, |t| t.as_secs()),
    })
}

use nostr_sdk::hashes::Hash as _;

#[cfg(test)]
pub mod testutil {
    //! Real, signed invoices for tests and fake Lightning backends.
    use super::*;
    use lightning_invoice::{InvoiceBuilder, PaymentSecret};
    use nostr_sdk::hashes::sha256;
    use nostr_sdk::secp256k1::{Secp256k1, SecretKey};

    pub const NODE_SECRET: [u8; 32] = [0x41; 32];

    pub fn node_pubkey() -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&NODE_SECRET).unwrap();
        hex::encode(sk.public_key(&secp).serialize())
    }

    /// An invoice signed by `secret` for the given amount and description hash.
    pub fn invoice_with(
        secret: [u8; 32],
        currency: Currency,
        amount_msat: u64,
        hash: [u8; 32],
        created: u64,
        expiry: u64,
    ) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).unwrap();
        let payment_hash = sha256::Hash::hash(&created.to_be_bytes()).to_byte_array();
        InvoiceBuilder::new(currency)
            .description_hash(sha256::Hash::from_byte_array(hash))
            .payment_hash(sha256::Hash::from_byte_array(payment_hash))
            .payment_secret(PaymentSecret([7; 32]))
            .duration_since_epoch(Duration::from_secs(created))
            .expiry_time(Duration::from_secs(expiry))
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(amount_msat)
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &sk))
            .unwrap()
            .to_string()
    }

    /// A regtest invoice from the test node, valid for an hour from now.
    pub fn invoice(amount_msat: u64, hash: [u8; 32]) -> String {
        invoice_with(
            NODE_SECRET,
            Currency::Regtest,
            amount_msat,
            hash,
            crate::unix_now(),
            3600,
        )
    }

    /// The same, paid to `sha256(preimage)`.
    pub fn invoice_paying(amount_msat: u64, hash: [u8; 32], preimage: [u8; 32]) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&NODE_SECRET).unwrap();
        InvoiceBuilder::new(Currency::Regtest)
            .description_hash(sha256::Hash::from_byte_array(hash))
            .payment_hash(sha256::Hash::hash(&preimage))
            .payment_secret(PaymentSecret([7; 32]))
            .duration_since_epoch(Duration::from_secs(crate::unix_now()))
            .expiry_time(Duration::from_secs(3600))
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(amount_msat)
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &sk))
            .unwrap()
            .to_string()
    }

    /// The same with a plain description instead of a hash.
    pub fn invoice_with_description(amount_msat: u64) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&NODE_SECRET).unwrap();
        InvoiceBuilder::new(Currency::Regtest)
            .description("plain".into())
            .payment_hash(sha256::Hash::from_byte_array([1; 32]))
            .payment_secret(PaymentSecret([7; 32]))
            .duration_since_epoch(Duration::from_secs(crate::unix_now()))
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(amount_msat)
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &sk))
            .unwrap()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn want(amount: u64, hash: [u8; 32]) -> Expect<'static> {
        Expect {
            amount_msat: amount,
            description_hash: hash,
            network: Some(Network::Regtest),
            payee: None,
            now: crate::unix_now(),
            min_expiry: Duration::from_secs(60),
        }
    }

    #[test]
    fn networks_parse() {
        assert_eq!("bitcoin".parse(), Ok(Network::Bitcoin));
        assert_eq!("mainnet".parse(), Ok(Network::Bitcoin));
        assert_eq!("testnet".parse(), Ok(Network::Testnet));
        assert_eq!("signet".parse(), Ok(Network::Signet));
        assert_eq!("regtest".parse(), Ok(Network::Regtest));
        assert!("litecoin".parse::<Network>().unwrap_err().contains("unknown network"));
        assert!(Network::Testnet.matches(Currency::BitcoinTestnet));
        assert!(Network::Signet.matches(Currency::Signet));
        assert!(Network::Bitcoin.matches(Currency::Bitcoin));
        assert!(!Network::Bitcoin.matches(Currency::Simnet));
    }

    #[test]
    fn a_matching_invoice_passes() {
        let pr = invoice(21_000, [9; 32]);
        let ok = check(&pr, &want(21_000, [9; 32])).unwrap();
        assert_eq!(ok.payee, node_pubkey());
        assert_eq!(ok.payment_hash.len(), 64);
        let pinned = Expect {
            payee: Some(Box::leak(node_pubkey().to_uppercase().into_boxed_str())),
            ..want(21_000, [9; 32])
        };
        assert!(check(&format!(" {pr}\n"), &pinned).is_ok());
        let any_net = Expect {
            network: None,
            ..want(21_000, [9; 32])
        };
        assert!(check(&pr, &any_net).is_ok());
    }

    #[test]
    fn every_mismatch_is_refused() {
        let pr = invoice(21_000, [9; 32]);
        assert!(check("lnbc1garbage", &want(1, [0; 32]))
            .unwrap_err()
            .contains("not a valid invoice"));
        assert!(check(&"x".repeat(5000), &want(1, [0; 32]))
            .unwrap_err()
            .contains("too long"));
        assert!(check(&pr, &want(21_001, [9; 32]))
            .unwrap_err()
            .contains("not 21001 msat"));
        assert!(check(&pr, &want(21_000, [8; 32]))
            .unwrap_err()
            .contains("description hash"));
        let plain = invoice_with_description(21_000);
        assert!(check(&plain, &want(21_000, [9; 32]))
            .unwrap_err()
            .contains("description hash"));
        let main = Expect {
            network: Some(Network::Bitcoin),
            ..want(21_000, [9; 32])
        };
        assert!(check(&pr, &main).unwrap_err().contains("not Bitcoin"));
        let other = Expect {
            payee: Some("02aa"),
            ..want(21_000, [9; 32])
        };
        assert!(check(&pr, &other).unwrap_err().contains("not the pinned node"));
        let old = invoice_with(
            NODE_SECRET,
            Currency::Regtest,
            21_000,
            [9; 32],
            crate::unix_now() - 3600,
            30,
        );
        assert!(check(&old, &want(21_000, [9; 32]))
            .unwrap_err()
            .contains("expires too soon"));
    }
}
