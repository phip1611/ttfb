// SPDX-License-Identifier: MIT

//! Module for [`TtfbClient`].

use crate::deadline::Deadline;
#[cfg(feature = "http2")]
use crate::http2;
#[cfg(feature = "http3")]
use crate::http3;
#[cfg(any(feature = "http2", feature = "http3"))]
use crate::run_in_tokio;
use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, http11, tls};
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;

/// Which HTTP protocol a [`TtfbClient`] measures.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ProtocolSelection {
    /// Let the client choose the best available HTTP protocol: HTTP/3, then
    /// HTTP/2, then HTTP/1.1.
    #[default]
    Auto,
    /// Measure only this protocol.
    Only(HttpProtocol),
}

/// Configuration for [`TtfbClient`].
#[derive(Clone, Debug)]
pub struct TtfbOptions {
    /// The HTTP protocol to measure.
    pub protocol: ProtocolSelection,
    /// Whether invalid TLS certificates (untrusted, expired, wrong host)
    /// are accepted. Similar to `-k/--insecure` in `curl`.
    pub allow_insecure_certificates: bool,
    /// The maximum duration of a measurement, from the DNS lookup to the end
    /// of the download. Defaults to [`TtfbOptions::DEFAULT_TIMEOUT`].
    pub timeout: Duration,
}

impl TtfbOptions {
    /// The default of [`TtfbOptions::timeout`].
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
    /// The minimum of [`TtfbOptions::timeout`].
    pub const MIN_TIMEOUT: Duration = Duration::from_secs(1);
    /// The maximum of [`TtfbOptions::timeout`].
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
}

impl Default for TtfbOptions {
    fn default() -> Self {
        Self {
            protocol: ProtocolSelection::default(),
            allow_insecure_certificates: false,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }
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

    /// Measures `target` via HTTP/1.1.
    fn measure_http11(
        &self,
        target: &Target,
        deadline: Deadline,
    ) -> Result<TtfbOutcome, TtfbError> {
        // The errors of the blocking I/O don't tell whether the deadline
        // caused them.
        http11::measure(target, Arc::clone(&self.tls_config), deadline)
            .map(|(outcome, _)| outcome)
            .map_err(|error| deadline.explain(error))
    }

    /// Measures `target` via HTTP/2. The asynchronous exchange runs on a
    /// dedicated Tokio runtime.
    #[cfg(feature = "http2")]
    fn measure_http2(&self, target: &Target, deadline: Deadline) -> Result<TtfbOutcome, TtfbError> {
        run_in_tokio(deadline.run(http2::measure(target, Arc::clone(&self.tls_config))))
            .map(|(outcome, _)| outcome)
    }

    /// Fails, as the crate was built without the `http2` feature.
    #[cfg(not(feature = "http2"))]
    fn measure_http2(
        &self,
        _target: &Target,
        _deadline: Deadline,
    ) -> Result<TtfbOutcome, TtfbError> {
        Err(TtfbError::UnsupportedHttpProtocol(
            "ttfb was built without the http2 feature".into(),
        ))
    }

    /// Measures `target` via HTTP/3. The asynchronous exchange runs on a
    /// dedicated Tokio runtime.
    #[cfg(feature = "http3")]
    fn measure_http3(&self, target: &Target, deadline: Deadline) -> Result<TtfbOutcome, TtfbError> {
        run_in_tokio(deadline.run(http3::measure(target, Arc::clone(&self.tls_config))))
    }

    /// Fails, as the crate was built without the `http3` feature.
    #[cfg(not(feature = "http3"))]
    fn measure_http3(
        &self,
        _target: &Target,
        _deadline: Deadline,
    ) -> Result<TtfbOutcome, TtfbError> {
        Err(TtfbError::UnsupportedHttpProtocol(
            "ttfb was built without the http3 feature".into(),
        ))
    }

    /// Measures `target` with the best protocol that is available: HTTP/3, then
    /// HTTP/2, then HTTP/1.1. Plain HTTP only supports HTTP/1.1.
    fn measure_auto(&self, target: &Target, deadline: Deadline) -> Result<TtfbOutcome, TtfbError> {
        if target.url.scheme() != "https" {
            return self.measure_http11(target, deadline);
        }
        self.measure_http3(target, deadline)
            .or_else(|error| match error {
                TtfbError::UnsupportedHttpProtocol(_) => self.measure_http2(target, deadline),
                error => Err(error),
            })
            .or_else(|error| match error {
                TtfbError::UnsupportedHttpProtocol(_) => self.measure_http11(target, deadline),
                error => Err(error),
            })
    }

    /// Checks that the options are valid.
    fn validate(&self) -> Result<(), TtfbError> {
        let timeout = self.options.timeout;
        if !(TtfbOptions::MIN_TIMEOUT..=TtfbOptions::MAX_TIMEOUT).contains(&timeout) {
            return Err(TtfbError::InvalidTimeout(timeout));
        }
        Ok(())
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
        self.validate()?;
        let deadline = Deadline::after(self.options.timeout);
        let target = Target::resolve(input.as_ref(), deadline)?;
        let outcome = match self.options.protocol {
            ProtocolSelection::Auto => self.measure_auto(&target, deadline),
            ProtocolSelection::Only(HttpProtocol::Http11) => self.measure_http11(&target, deadline),
            ProtocolSelection::Only(HttpProtocol::Http2) => self.measure_http2(&target, deadline),
            ProtocolSelection::Only(HttpProtocol::Http3) => self.measure_http3(&target, deadline),
        }?;
        Ok(outcome.with_protocol_selection(self.options.protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const TIMEOUT: Duration = TtfbOptions::MIN_TIMEOUT;

    /// Measures `url` via `protocol` with `timeout`.
    fn measure(
        url: &str,
        protocol: HttpProtocol,
        timeout: Duration,
    ) -> Result<TtfbOutcome, TtfbError> {
        TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(protocol),
            timeout,
            ..TtfbOptions::default()
        })
        .measure(url)
    }

    /// Returns a listener whose connections the OS accepts without accept(),
    /// but nobody answers, and its port.
    fn unresponsive_tcp_server() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("should bind a free port");
        let port = listener.local_addr().expect("should be bound").port();
        (listener, port)
    }

    #[test]
    fn http11_timeout() {
        let (_listener, port) = unresponsive_tcp_server();
        let result = measure(
            &format!("http://127.0.0.1:{port}"),
            HttpProtocol::Http11,
            TIMEOUT,
        );
        assert_eq!(result, Err(TtfbError::Timeout(TIMEOUT)));
    }

    #[test]
    fn https11_timeout() {
        let (_listener, port) = unresponsive_tcp_server();
        let result = measure(
            &format!("https://127.0.0.1:{port}"),
            HttpProtocol::Http11,
            TIMEOUT,
        );
        assert_eq!(result, Err(TtfbError::Timeout(TIMEOUT)));
    }

    #[cfg(feature = "http2")]
    #[test]
    fn http2_timeout() {
        let (_listener, port) = unresponsive_tcp_server();
        let result = measure(
            &format!("https://127.0.0.1:{port}"),
            HttpProtocol::Http2,
            TIMEOUT,
        );
        assert_eq!(result, Err(TtfbError::Timeout(TIMEOUT)));
    }

    #[test]
    fn invalid_timeout() {
        for timeout in [
            Duration::ZERO,
            TtfbOptions::MAX_TIMEOUT + Duration::from_secs(1),
        ] {
            let result = measure("http://127.0.0.1", HttpProtocol::Http11, timeout);
            assert_eq!(result, Err(TtfbError::InvalidTimeout(timeout)));
        }
    }
}

/// Tests that rely on an external network connection.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;
    use crate::ConnectionHandshake;

    fn has_tls_handshake(outcome: &TtfbOutcome) -> bool {
        matches!(
            outcome.connection_handshake(),
            ConnectionHandshake::Tcp { tls: Some(_), .. }
        )
    }

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
        assert!(!has_tls_handshake(&r));
    }

    #[test]
    fn test_https_dns_lookup_duration() {
        let r = measure_http11("https://phip1611.de", false).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_tls_handshake_duration() {
        let r = measure_http11("https://phip1611.de", false).unwrap();
        assert!(has_tls_handshake(&r));
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
        assert!(has_tls_handshake(&r));
    }

    #[test]
    fn test_https_ip_address_tls_handshake() {
        let r = measure_http11("https://1.1.1.1", false).unwrap();
        assert!(has_tls_handshake(&r), "must execute TLS handshake");
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
            assert!(has_tls_handshake(&outcome), "{url}");
        }
    }

    #[cfg(feature = "http3")]
    #[test]
    fn measures_well_known_http3_websites() {
        let client = TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http3),
            ..TtfbOptions::default()
        });
        for url in ["https://www.google.com", "https://www.cloudflare.com"] {
            let outcome = client.measure(url).unwrap();
            assert_eq!(outcome.protocol(), HttpProtocol::Http3, "{url}");
            assert!(
                matches!(outcome.connection_handshake(), ConnectionHandshake::Quic(_)),
                "{url}"
            );
        }
    }

    /// The automatic selection measures the best protocol a website supports.
    /// Websites may change what they support, so a failure can also mean that
    /// this list needs an update.
    #[cfg(all(feature = "http2", feature = "http3"))]
    #[test]
    fn auto_selects_the_best_supported_protocol() {
        let client = TtfbClient::new(TtfbOptions::default());
        for (url, expected) in [
            ("https://www.cloudflare.com", HttpProtocol::Http3),
            ("https://github.com", HttpProtocol::Http2),
            ("https://badssl.com", HttpProtocol::Http11),
        ] {
            let outcome = client
                .measure(url)
                .unwrap_or_else(|error| panic!("{url}: {error}"));
            assert_eq!(outcome.protocol(), expected, "{url}");
            assert_eq!(
                outcome.protocol_selection(),
                ProtocolSelection::Auto,
                "{url}"
            );
        }
    }

    /// Another protocol would fail with the same certificate, so the automatic
    /// selection must report the error instead of falling back.
    #[test]
    fn auto_does_not_fall_back_on_certificate_errors() {
        let error = TtfbClient::new(TtfbOptions::default())
            .measure("https://expired.badssl.com")
            .unwrap_err();
        assert!(matches!(error, TtfbError::Tls(_)), "{error}");
    }
}
