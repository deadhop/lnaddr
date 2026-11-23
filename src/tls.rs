//! TLS for the node's connection to its Lightning backend. LND and Core
//! Lightning serve self-signed certificates, so the usual trust model is a
//! pin: the SHA-256 of the exact certificate. Backends with a public
//! certificate (a hosted LNbits) use the web roots instead.

// The verifier, fingerprints and PEM reading are the shared pinning crate's.
pub use deadhop_tlspin::first_pem_cert;

/// SHA-256 of a DER certificate.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    deadhop_tlspin::parse_fingerprint(&deadhop_tlspin::fingerprint_hex(der)).expect("a SHA-256 is 32 bytes")
}

/// Parse one or more 64-character hex fingerprints, comma-separated (colons
/// allowed, as openssl prints them).
pub fn parse_pins(s: &str) -> Result<Vec<[u8; 32]>, String> {
    s.split(',')
        .map(|p| deadhop_tlspin::parse_fingerprint(p).ok_or(format!("{:?} is not a hex SHA-256 fingerprint", p.trim())))
        .collect()
}

/// Pins as hex, one per pinned certificate.
pub fn pins_hex(pins: &[[u8; 32]]) -> Vec<String> {
    pins.iter().map(hex::encode).collect()
}

/// Pins as hex, comma-separated (the form they are configured in).
pub fn pins_text(pins: &[[u8; 32]]) -> String {
    pins_hex(pins).join(",")
}

/// A rustls client configuration that trusts only the pinned certificates, or the web roots.
pub fn client_config(pins: Option<Vec<[u8; 32]>>) -> rustls::ClientConfig {
    deadhop_tlspin::tls_config(pins.map(|p| deadhop_tlspin::pinned(Some(p))))
}

/// An HTTP client trusting the web roots (ring, no system TLS).
pub fn http_client(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls(client_config(None))
        .timeout(timeout)
        .build()
        .expect("a client with a rustls configuration always builds")
}

#[cfg(test)]
pub mod testutil {
    //! A self-signed certificate and a TLS acceptor for fake backends.
    use std::sync::Arc;

    pub struct SelfSigned {
        pub der: Vec<u8>,
        pub pem: String,
        pub acceptor: tokio_rustls::TlsAcceptor,
    }

    pub fn self_signed() -> SelfSigned {
        build(false)
    }

    /// The same, speaking TLS 1.2 only.
    pub fn self_signed_tls12() -> SelfSigned {
        build(true)
    }

    fn build(tls12_only: bool) -> SelfSigned {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
            &[&rustls::version::TLS12]
        } else {
            rustls::DEFAULT_VERSIONS
        };
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone().into()], key)
            .unwrap();
        SelfSigned {
            der,
            pem: cert.cert.pem(),
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_parse_with_or_without_colons() {
        let hex64 = "ab".repeat(32);
        assert_eq!(parse_pins(&hex64).unwrap(), [[0xab; 32]]);
        let colons = vec!["AB"; 32].join(":");
        assert_eq!(parse_pins(&colons).unwrap(), [[0xab; 32]]);
        // Several pins, for a certificate about to be replaced.
        assert_eq!(
            parse_pins(&format!("{hex64}, {}", "cd".repeat(32))).unwrap(),
            [[0xab; 32], [0xcd; 32]]
        );
        assert!(parse_pins("zz").unwrap_err().contains("not a hex"));
        assert!(parse_pins(&format!("{hex64},abcd"))
            .unwrap_err()
            .contains("\"abcd\" is not a hex"));
    }

    #[test]
    fn pem_files_yield_their_first_certificate() {
        let s = testutil::self_signed();
        assert_eq!(first_pem_cert(&s.pem).unwrap(), s.der);
        assert!(first_pem_cert("nothing").unwrap_err().contains("no certificate"));
        assert!(first_pem_cert("-----BEGIN CERTIFICATE-----abc")
            .unwrap_err()
            .contains("unterminated"));
        let bad = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----";
        assert!(first_pem_cert(bad).unwrap_err().contains("not valid base64"));
    }

    #[test]
    fn both_trust_modes_build() {
        let _ = client_config(None);
        let _ = client_config(Some(vec![[0; 32]]));
        assert_eq!(
            pins_text(&[[0xab; 32], [0xcd; 32]]),
            format!("{},{}", "ab".repeat(32), "cd".repeat(32))
        );
    }
}
