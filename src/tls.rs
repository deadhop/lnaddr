//! TLS for the node's connection to its Lightning backend. LND and Core
//! Lightning serve self-signed certificates, so the usual trust model is a
//! pin: the SHA-256 of the exact certificate. Backends with a public
//! certificate (a hosted LNbits) use the web roots instead.

use std::sync::Arc;

use nostr_sdk::hashes::{sha256, Hash};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        if fp == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate {} does not match the pinned fingerprint",
                hex::encode(fp)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// SHA-256 of a DER certificate.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(der).to_byte_array()
}

/// The first certificate in a PEM file, as DER.
pub fn first_pem_cert(pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let begin = "-----BEGIN CERTIFICATE-----";
    let start = pem.find(begin).ok_or("no certificate in the PEM file")? + begin.len();
    let end = pem[start..].find("-----END CERTIFICATE-----").ok_or("unterminated certificate in the PEM file")?;
    let body: String = pem[start..start + end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| "the certificate in the PEM file is not valid base64".to_string())
}

/// Parse a 64-character hex fingerprint (colons allowed, as openssl prints them).
pub fn parse_pin(s: &str) -> Result<[u8; 32], String> {
    let clean: String = s.chars().filter(|c| *c != ':').collect();
    let bytes = hex::decode(&clean).map_err(|_| format!("{s:?} is not a hex SHA-256 fingerprint"))?;
    bytes.try_into().map_err(|_| format!("{s:?} is not 32 bytes"))
}

/// A rustls client configuration that trusts only `pin`, or the web roots.
pub fn client_config(pin: Option<[u8; 32]>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions");
    match pin {
        Some(pin) => builder.dangerous().with_custom_certificate_verifier(Arc::new(Pinned { pin, algs })).with_no_client_auth(),
        None => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    }
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
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone().into()], key)
            .unwrap();
        SelfSigned { der, pem: cert.cert.pem(), acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_parse_with_or_without_colons() {
        let hex64 = "ab".repeat(32);
        assert_eq!(parse_pin(&hex64).unwrap(), [0xab; 32]);
        let colons = vec!["AB"; 32].join(":");
        assert_eq!(parse_pin(&colons).unwrap(), [0xab; 32]);
        assert!(parse_pin("zz").unwrap_err().contains("not a hex"));
        assert!(parse_pin("abcd").unwrap_err().contains("not 32 bytes"));
    }

    #[test]
    fn pem_files_yield_their_first_certificate() {
        let s = testutil::self_signed();
        assert_eq!(first_pem_cert(&s.pem).unwrap(), s.der);
        assert!(first_pem_cert("nothing").unwrap_err().contains("no certificate"));
        assert!(first_pem_cert("-----BEGIN CERTIFICATE-----abc").unwrap_err().contains("unterminated"));
        let bad = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----";
        assert!(first_pem_cert(bad).unwrap_err().contains("not valid base64"));
    }

    #[test]
    fn both_trust_modes_build() {
        let _ = client_config(None);
        let _ = client_config(Some([0; 32]));
    }
}
