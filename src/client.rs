// SPDX-License-Identifier: MIT

//! Module for [`TtfbClient`].

use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, http11, tls};
#[cfg(feature = "http2")]
use crate::{http2, run_in_tokio};
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
    /// Whether to send the request as TLS 1.3 early data (0-RTT). A warm-up
    /// request first obtains a TLS session, which the measured request
    /// resumes. Requires an HTTPS URL and [`HttpProtocol::Http11`].
    pub zero_rtt: bool,
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
            tls_config: tls::config(options.allow_insecure_certificates, options.zero_rtt),
            options,
        }
    }

    /// Measures `target` via HTTP/1.1, with a warm-up request first if 0-RTT is
    /// enabled.
    fn measure_http11(&self, target: &Target) -> Result<TtfbOutcome, TtfbError> {
        if self.options.zero_rtt {
            // The warm-up obtains a session ticket for the measured connection.
            http11::measure(target, Arc::clone(&self.tls_config), false)?;
        }
        http11::measure(target, Arc::clone(&self.tls_config), self.options.zero_rtt)
    }

    /// Measures `target` via HTTP/2. The asynchronous exchange runs on a
    /// dedicated Tokio runtime.
    #[cfg(feature = "http2")]
    fn measure_http2(&self, target: &Target) -> Result<TtfbOutcome, TtfbError> {
        run_in_tokio(http2::measure(target, Arc::clone(&self.tls_config)))
    }

    /// Fails, as the crate was built without the `http2` feature.
    #[cfg(not(feature = "http2"))]
    fn measure_http2(&self, _target: &Target) -> Result<TtfbOutcome, TtfbError> {
        Err(TtfbError::UnsupportedHttpProtocol(
            "ttfb was built without the http2 feature".into(),
        ))
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
        if self.options.zero_rtt
            && self.options.protocol != ProtocolSelection::Only(HttpProtocol::Http11)
        {
            return Err(TtfbError::UnsupportedHttpProtocol(
                "0-RTT requires HTTP/1.1 to be selected".into(),
            ));
        }
        let target = Target::resolve(input.as_ref())?;
        if self.options.zero_rtt && target.url.scheme() != "https" {
            return Err(TtfbError::UnsupportedHttpProtocol(
                "0-RTT requires an HTTPS URL".into(),
            ));
        }
        let outcome = match self.options.protocol {
            ProtocolSelection::Auto | ProtocolSelection::Only(HttpProtocol::Http11) => {
                self.measure_http11(&target)
            }
            ProtocolSelection::Only(HttpProtocol::Http2) => self.measure_http2(&target),
        }?;
        Ok(outcome.with_protocol_selection(self.options.protocol))
    }
}

/// Tests that rely on an external network connection.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;
    use crate::ZeroRttStatus;

    fn measure_http11(
        input: &str,
        allow_insecure_certificates: bool,
    ) -> Result<TtfbOutcome, TtfbError> {
        TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http11),
            allow_insecure_certificates,
            ..TtfbOptions::default()
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

    #[cfg(feature = "http2")]
    #[test]
    fn measures_well_known_http2_websites() {
        let client = TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http2),
            ..TtfbOptions::default()
        });
        for url in [
            "https://www.google.com",
            "https://github.com",
            "https://www.cloudflare.com",
        ] {
            let outcome = client.measure(url).unwrap();
            assert_eq!(outcome.protocol(), HttpProtocol::Http2, "{url}");
            assert!(outcome.tls_handshake_duration().is_some(), "{url}");
        }
    }

    /// These websites accept TLS 1.3 early data. They may change their
    /// configuration, so a failure can also mean that this list needs an
    /// update.
    #[test]
    fn well_known_websites_accept_http11_zero_rtt() {
        let client = TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http11),
            zero_rtt: true,
            ..TtfbOptions::default()
        });
        for url in [
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.fastly.com",
        ] {
            let outcome = client.measure(url).unwrap();
            assert_eq!(
                outcome.zero_rtt_status(),
                Some(ZeroRttStatus::Accepted),
                "{url}"
            );
        }
    }
}
