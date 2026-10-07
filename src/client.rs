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
use std::fmt::{self, Display, Formatter};
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

/// Which IP version a [`TtfbClient`] uses to connect to the host.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// Use IPv4 if the host has an IPv4 address, otherwise IPv6.
    ///
    /// Unlike browsers and curl, which try IPv6 and IPv4 in parallel ("Happy
    /// Eyeballs"), a measurement connects only once, so that its timings
    /// don't depend on a race. IPv4 works on most networks.
    #[default]
    Any,
    /// Use only IPv4.
    V4,
    /// Use only IPv6.
    V6,
}

impl Display for IpVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Any => "IPv4 or IPv6",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        };
        f.write_str(name)
    }
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
    /// The IP version to connect with. With [`IpVersion::V4`] or
    /// [`IpVersion::V6`], measurements of a host without an address of that
    /// version fail with [`TtfbError::NoAddressForIpVersion`].
    pub ip_version: IpVersion,
    /// Whether to send the request as TLS 1.3 early data (0-RTT), which
    /// requires an HTTPS URL. Early data needs a session ticket from an
    /// earlier connection, so a warm-up request precedes each measurement.
    /// The measured connection resumes the warm-up's TLS session, so its
    /// handshake is shorter than a full one. [`TtfbOutcome::zero_rtt`]
    /// reports whether the server accepted the early data.
    pub zero_rtt: bool,
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
            ip_version: IpVersion::default(),
            zero_rtt: false,
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
            tls_config: tls::config(options.allow_insecure_certificates, options.zero_rtt),
            options,
        }
    }

    /// Measures `target` via HTTP/1.1, after a warm-up request with 0-RTT.
    fn measure_http11(
        &self,
        target: &Target,
        deadline: Deadline,
    ) -> Result<TtfbOutcome, TtfbError> {
        let measure = |early_data| {
            // The errors of the blocking I/O don't tell whether the deadline
            // caused them.
            http11::measure(target, Arc::clone(&self.tls_config), deadline, early_data)
                .map_err(|error| deadline.explain(error))
        };
        if self.options.zero_rtt {
            // The warm-up obtains the session ticket for the early data.
            measure(false)?;
        }
        measure(self.options.zero_rtt)
    }

    /// Runs the asynchronous `measure` on a dedicated Tokio runtime, after a
    /// warm-up request with 0-RTT. `measure` takes whether to send early data.
    #[cfg(any(feature = "http2", feature = "http3"))]
    fn measure_async<F>(
        &self,
        deadline: Deadline,
        measure: impl Fn(bool) -> F + Sync,
    ) -> Result<TtfbOutcome, TtfbError>
    where
        F: Future<Output = Result<TtfbOutcome, TtfbError>> + Send,
    {
        run_in_tokio(deadline.run(async {
            if self.options.zero_rtt {
                // The warm-up obtains the session ticket for the early data.
                measure(false).await?;
            }
            measure(self.options.zero_rtt).await
        }))
    }

    /// Measures `target` via HTTP/2, after a warm-up request with 0-RTT.
    #[cfg(feature = "http2")]
    fn measure_http2(&self, target: &Target, deadline: Deadline) -> Result<TtfbOutcome, TtfbError> {
        self.measure_async(deadline, |early_data| {
            http2::measure(target, Arc::clone(&self.tls_config), early_data)
        })
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

    /// Measures `target` via HTTP/3, after a warm-up request with 0-RTT.
    #[cfg(feature = "http3")]
    fn measure_http3(&self, target: &Target, deadline: Deadline) -> Result<TtfbOutcome, TtfbError> {
        self.measure_async(deadline, |early_data| {
            http3::measure(target, Arc::clone(&self.tls_config), early_data)
        })
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
        let target = Target::resolve(input.as_ref(), self.options.ip_version, deadline)?;
        if self.options.zero_rtt && target.url.scheme() != "https" {
            return Err(TtfbError::UnsupportedHttpProtocol(
                "0-RTT requires an HTTPS URL".into(),
            ));
        }
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
    fn zero_rtt_requires_https() {
        let result = TtfbClient::new(TtfbOptions {
            zero_rtt: true,
            ..TtfbOptions::default()
        })
        .measure("http://127.0.0.1");
        assert!(
            matches!(result, Err(TtfbError::UnsupportedHttpProtocol(_))),
            "{result:?}"
        );
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
    use crate::{ConnectionHandshake, ZeroRtt};

    /// Returns the options for the tests, with a longer timeout than the
    /// default, as external sites, such as badssl.com, are sometimes slow.
    fn options() -> TtfbOptions {
        TtfbOptions {
            timeout: Duration::from_secs(30),
            ..TtfbOptions::default()
        }
    }

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
            ..options()
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
    fn test_https_status_and_headers() {
        let r = measure_http11("https://phip1611.de", false).unwrap();
        assert!(r.status().is_success());
        assert!(r.headers().contains_key("content-type"));
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
            ..options()
        });
        for url in [
            "https://www.google.com",
            "https://github.com",
            "https://www.cloudflare.com",
        ] {
            let outcome = client.measure(url).unwrap();
            assert_eq!(outcome.protocol(), HttpProtocol::Http2, "{url}");
            assert!(outcome.status().is_success(), "{url}");
            assert!(outcome.headers().contains_key("content-type"), "{url}");
            assert!(has_tls_handshake(&outcome), "{url}");
        }
    }

    #[cfg(feature = "http3")]
    #[test]
    fn measures_well_known_http3_websites() {
        let client = TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http3),
            ..options()
        });
        for url in ["https://www.google.com", "https://www.cloudflare.com"] {
            let outcome = client.measure(url).unwrap();
            assert_eq!(outcome.protocol(), HttpProtocol::Http3, "{url}");
            assert!(outcome.status().is_success(), "{url}");
            assert!(outcome.headers().contains_key("content-type"), "{url}");
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
        let client = TtfbClient::new(options());
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
        let error = TtfbClient::new(options())
            .measure("https://expired.badssl.com")
            .unwrap_err();
        assert!(matches!(error, TtfbError::Tls(_)), "{error}");
    }

    /// These websites accept TLS 1.3 early data. They may change their
    /// configuration, so a failure can also mean that this list needs an
    /// update.
    #[test]
    fn well_known_websites_accept_zero_rtt() {
        for protocol in [
            ProtocolSelection::Auto,
            ProtocolSelection::Only(HttpProtocol::Http11),
            #[cfg(feature = "http2")]
            ProtocolSelection::Only(HttpProtocol::Http2),
            #[cfg(feature = "http3")]
            ProtocolSelection::Only(HttpProtocol::Http3),
        ] {
            let client = TtfbClient::new(TtfbOptions {
                protocol,
                zero_rtt: true,
                ..options()
            });
            for url in [
                "https://www.google.com",
                "https://www.facebook.com",
                "https://www.fastly.com",
            ] {
                let outcome = client
                    .measure(url)
                    .unwrap_or_else(|error| panic!("{url} {protocol:?}: {error}"));
                assert_eq!(
                    outcome.zero_rtt(),
                    Some(ZeroRtt::Accepted),
                    "{url} {protocol:?}"
                );
                assert_eq!(
                    outcome.http_get_send_duration().relative(),
                    Duration::ZERO,
                    "{url} {protocol:?}"
                );
            }
        }
    }

    /// These websites don't offer TLS 1.3 early data, see
    /// [`well_known_websites_accept_zero_rtt`].
    #[test]
    fn well_known_websites_without_zero_rtt() {
        let client = TtfbClient::new(TtfbOptions {
            zero_rtt: true,
            ..options()
        });
        for url in ["https://www.cloudflare.com", "https://github.com"] {
            let outcome = client
                .measure(url)
                .unwrap_or_else(|error| panic!("{url}: {error}"));
            assert_eq!(outcome.zero_rtt(), Some(ZeroRtt::Unavailable), "{url}");
        }
    }
}
