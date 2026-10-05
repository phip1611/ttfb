// SPDX-License-Identifier: MIT

//! Module for [`TtfbClient`].

use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, http11, tls};
use rustls::ClientConfig;
use std::sync::Arc;

/// Which HTTP protocol a [`TtfbClient`] measures.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ProtocolSelection {
    /// Let the client choose the HTTP protocol. Currently, this is always
    /// HTTP/1.1.
    #[default]
    Auto,
    /// Measure only this protocol.
    Only(HttpProtocol),
}

/// Configuration for [`TtfbClient`].
#[derive(Clone, Debug, Default)]
pub struct TtfbOptions {
    /// The HTTP protocol to measure.
    pub protocol: ProtocolSelection,
    /// Whether invalid TLS certificates (untrusted, expired, wrong host)
    /// are accepted. Similar to `-k/--insecure` in `curl`.
    pub allow_insecure_certificates: bool,
}

/// Measures the TTFB (time to first byte) of HTTP(S) requests, including the
/// timings of the intermediate steps, such as DNS lookup, TCP connect, and TLS
/// handshake.
///
/// A client can measure multiple URLs with the same [`TtfbOptions`].
#[derive(Clone, Debug)]
pub struct TtfbClient {
    options: TtfbOptions,
    tls_config: Arc<ClientConfig>,
}

impl TtfbClient {
    /// Creates a client that measures according to `options`.
    #[must_use]
    pub fn new(options: TtfbOptions) -> Self {
        Self {
            tls_config: tls::config(options.allow_insecure_certificates),
            options,
        }
    }

    /// Measures one GET request to `input`.
    ///
    /// `input` is a URL pointing to an HTTP server, such as:
    /// - `phip1611.de` (defaults to `http://`)
    /// - `http://phip1611.de`
    /// - `https://phip1611.de`
    /// - `https://phip1611.de?foo=bar`
    /// - `https://sub.domain.phip1611.de?foo=bar`
    /// - `http://12.34.56.78/foobar`
    /// - `https://1.1.1.1`
    /// - `12.34.56.78/foobar` (defaults to `http://`)
    /// - `12.34.56.78` (defaults to `http://`)
    pub fn measure(&self, input: impl AsRef<str>) -> Result<TtfbOutcome, TtfbError> {
        let target = Target::resolve(input.as_ref())?;
        let outcome = match self.options.protocol {
            ProtocolSelection::Auto | ProtocolSelection::Only(HttpProtocol::Http11) => {
                http11::measure(&target, Arc::clone(&self.tls_config))
            }
        }?;
        Ok(outcome.with_protocol_selection(self.options.protocol))
    }
}

/// Tests that rely on an external network connection.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;

    fn measure_http11(
        input: &str,
        allow_insecure_certificates: bool,
    ) -> Result<TtfbOutcome, TtfbError> {
        TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http11),
            allow_insecure_certificates,
        })
        .measure(input)
    }

    #[test]
    fn test_http_dns_lookup_duration() {
        let r = measure_http11("http://phip1611.de", false).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_http_no_tls_handshake() {
        let r = measure_http11("http://phip1611.de", false).unwrap();
        assert!(r.tls_handshake_duration().is_none());
    }

    #[test]
    fn test_https_dns_lookup_duration() {
        let r = measure_http11("https://phip1611.de", false).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_tls_handshake_duration() {
        let r = measure_http11("https://phip1611.de", false).unwrap();
        assert!(r.tls_handshake_duration().is_some());
    }

    #[test]
    fn test_https_expired_certificate_error() {
        let r = measure_http11("https://expired.badssl.com", false);
        assert!(r.is_err());
    }

    #[test]
    fn test_https_expired_certificate_ignore_error() {
        let r = measure_http11("https://expired.badssl.com", true).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_self_signed_certificate_error() {
        let r = measure_http11("https://self-signed.badssl.com", false);
        assert!(r.is_err());
    }

    #[test]
    fn test_https_self_signed_certificate_ignore_error() {
        let r = measure_http11("https://self-signed.badssl.com", true).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_wrong_host_certificate_error() {
        let r = measure_http11("https://wrong.host.badssl.com", false);
        assert!(r.is_err());
    }

    #[test]
    fn test_https_wrong_host_certificate_ignore_error() {
        let r = measure_http11("https://wrong.host.badssl.com", true).unwrap();
        assert!(r.dns_lookup_duration().is_some());
        assert!(r.tls_handshake_duration().is_some());
    }

    #[test]
    fn test_https_ip_address_tls_handshake() {
        let r = measure_http11("https://1.1.1.1", false).unwrap();
        assert!(
            r.tls_handshake_duration().is_some(),
            "must execute TLS handshake"
        );
    }
}
