// SPDX-License-Identifier: MIT

//! The TLS configuration shared by all protocols.

use crate::TtfbError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::net::IpAddr;
use std::sync::Arc;
use url::{Host, Url};

/// Creates the rustls configuration for all measurements.
///
/// `allow_insecure_certificates` accepts invalid certificates (untrusted,
/// expired, wrong host), similar to `-k/--insecure` in `curl`. Otherwise, the
/// system's root certificates and the bundled Mozilla root certificates are
/// trusted.
///
/// rustls connections take the configuration as an [`Arc`], which lets them
/// share it, including the root certificates, without copying it.
pub fn config(allow_insecure_certificates: bool) -> Arc<ClientConfig> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring should support the default protocol versions");
    let builder = if allow_insecure_certificates {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AllowInvalidCertsVerifier))
    } else {
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        builder.with_root_certificates(roots)
    };
    Arc::new(builder.with_no_client_auth())
}

/// Returns the name to verify the server certificate against.
///
/// Certificates can also be issued for IP addresses. The URL holds IPv6
/// addresses in brackets, so they are taken from the parsed host.
pub fn server_name(url: &Url) -> Result<ServerName<'static>, TtfbError> {
    let host = url.host().expect("http and https URLs should have a host");
    match host {
        Host::Domain(domain) => ServerName::try_from(domain.to_owned())
            .map_err(|error| TtfbError::Tls(error.to_string())),
        Host::Ipv4(address) => Ok(ServerName::IpAddress(IpAddr::V4(address).into())),
        Host::Ipv6(address) => Ok(ServerName::IpAddress(IpAddr::V6(address).into())),
    }
}

/// Custom verifier that allows invalid certificates.
#[derive(Debug)]
struct AllowInvalidCertsVerifier;

impl ServerCertVerifier for AllowInvalidCertsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Return a list of all.
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_of_ip_addresses() {
        let ipv4 = Url::parse("https://1.1.1.1").unwrap();
        let ipv6 = Url::parse("https://[::1]:8443").unwrap();
        assert_eq!(
            server_name(&ipv4).unwrap(),
            ServerName::try_from("1.1.1.1").unwrap()
        );
        assert_eq!(
            server_name(&ipv6).unwrap(),
            ServerName::try_from("::1").unwrap()
        );
    }
}
