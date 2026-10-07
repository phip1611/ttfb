// SPDX-License-Identifier: MIT

//! Module for [`TtfbClient`].

use crate::deadline::Deadline;
#[cfg(feature = "http2")]
use crate::http2;
#[cfg(feature = "http3")]
use crate::http3;
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
    async fn measure_http11(&self, target: &Target) -> Result<TtfbOutcome, TtfbError> {
        http11::measure(target, Arc::clone(&self.tls_config)).await
    }

    /// Measures `target` via HTTP/2.
    #[cfg(feature = "http2")]
    async fn measure_http2(&self, target: &Target) -> Result<TtfbOutcome, TtfbError> {
        http2::measure(target, Arc::clone(&self.tls_config)).await
    }

    /// Fails, as the crate was built without the `http2` feature.
    #[cfg(not(feature = "http2"))]
    async fn measure_http2(&self, _target: &Target) -> Result<TtfbOutcome, TtfbError> {
        Err(TtfbError::UnsupportedHttpProtocol(
            "ttfb was built without the http2 feature".into(),
        ))
    }

    /// Measures `target` via HTTP/3.
    #[cfg(feature = "http3")]
    async fn measure_http3(&self, target: &Target) -> Result<TtfbOutcome, TtfbError> {
        http3::measure(target, Arc::clone(&self.tls_config)).await
    }

    /// Fails, as the crate was built without the `http3` feature.
    #[cfg(not(feature = "http3"))]
    async fn measure_http3(&self, _target: &Target) -> Result<TtfbOutcome, TtfbError> {
        Err(TtfbError::UnsupportedHttpProtocol(
            "ttfb was built without the http3 feature".into(),
        ))
    }

    /// Measures `target` with the best protocol that is available: HTTP/3, then
    /// HTTP/2, then HTTP/1.1. Plain HTTP only supports HTTP/1.1.
    async fn measure_auto(&self, target: &Target) -> Result<TtfbOutcome, TtfbError> {
        if target.url.scheme() != "https" {
            return self.measure_http11(target).await;
        }
        match self.measure_http3(target).await {
            Err(TtfbError::UnsupportedHttpProtocol(_)) => {}
            result => return result,
        }
        match self.measure_http2(target).await {
            Err(TtfbError::UnsupportedHttpProtocol(_)) => {}
            result => return result,
        }
        self.measure_http11(target).await
    }

    /// Checks that the options are valid.
    fn validate(&self) -> Result<(), TtfbError> {
        let timeout = self.options.timeout;
        if !(TtfbOptions::MIN_TIMEOUT..=TtfbOptions::MAX_TIMEOUT).contains(&timeout) {
            return Err(TtfbError::InvalidTimeout(timeout));
        }
        Ok(())
    }

    /// Measures one GET request to `input` and blocks until it completes.
    ///
    /// This is the blocking variant of [`TtfbClient::measure_async`], which
    /// describes `input`. Async code should use that instead, as this blocks
    /// the thread of the executor.
    pub fn measure(&self, input: impl AsRef<str>) -> Result<TtfbOutcome, TtfbError> {
        // async-io's block_on also drives the reactor on this thread.
        async_io::block_on(self.measure_async(input))
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
    ///
    /// The future works with every executor, such as the ones of Tokio or
    /// smol: async-io drives the I/O and the timers on its own thread, and the
    /// DNS lookup runs on a helper thread.
    pub async fn measure_async(&self, input: impl AsRef<str>) -> Result<TtfbOutcome, TtfbError> {
        self.validate()?;
        let deadline = Deadline::after(self.options.timeout);
        let target = Target::resolve(input.as_ref(), self.options.ip_version, deadline).await?;
        let outcome = deadline
            .run(async {
                match self.options.protocol {
                    ProtocolSelection::Auto => self.measure_auto(&target).await,
                    ProtocolSelection::Only(HttpProtocol::Http11) => {
                        self.measure_http11(&target).await
                    }
                    ProtocolSelection::Only(HttpProtocol::Http2) => {
                        self.measure_http2(&target).await
                    }
                    ProtocolSelection::Only(HttpProtocol::Http3) => {
                        self.measure_http3(&target).await
                    }
                }
            })
            .await?;
        Ok(outcome.with_protocol_selection(self.options.protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusCode;
    use futures_lite::future;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tokio::runtime::Builder;

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

    /// Returns the URL of a local HTTP/1.1 server that answers one request.
    fn local_http_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("should bind a free port");
        let port = listener.local_addr().expect("should be bound").port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("should accept the client");
            // Unread request bytes would reset the connection on close.
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let read = stream.read(&mut buffer).expect("should read the request");
                request.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("should write the response");
        });
        format!("http://127.0.0.1:{port}")
    }

    /// Returns a client for HTTP/1.1 with the timeout [`TIMEOUT`].
    fn http11_client() -> TtfbClient {
        TtfbClient::new(TtfbOptions {
            protocol: ProtocolSelection::Only(HttpProtocol::Http11),
            timeout: TIMEOUT,
            ..TtfbOptions::default()
        })
    }

    /// The I/O and the timers work without the reactor of async-io on the
    /// thread of the executor.
    #[test]
    fn measure_async_with_futures_lite() {
        let client = http11_client();
        let outcome = future::block_on(client.measure_async(local_http_server()));
        assert_eq!(outcome.map(|outcome| outcome.status()), Ok(StatusCode::OK));
        let (_listener, port) = unresponsive_tcp_server();
        let url = format!("http://127.0.0.1:{port}");
        let result = future::block_on(client.measure_async(url));
        assert_eq!(result, Err(TtfbError::Timeout(TIMEOUT)));
    }

    /// The measurement doesn't need the I/O and time drivers of Tokio.
    #[test]
    fn measure_async_with_tokio() {
        let runtime = Builder::new_current_thread()
            .build()
            .expect("should be able to create a Tokio runtime");
        let client = http11_client();
        let outcome = runtime.block_on(client.measure_async(local_http_server()));
        assert_eq!(outcome.map(|outcome| outcome.status()), Ok(StatusCode::OK));
        let (_listener, port) = unresponsive_tcp_server();
        let url = format!("http://127.0.0.1:{port}");
        let result = runtime.block_on(client.measure_async(url));
        assert_eq!(result, Err(TtfbError::Timeout(TIMEOUT)));
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

    /// The future must be [`Send`] to run on multi-threaded executors.
    #[test]
    fn measure_async_is_send() {
        fn assert_send(_: &impl Send) {}
        let client = TtfbClient::new(TtfbOptions::default());
        assert_send(&client.measure_async("http://127.0.0.1"));
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
    use tokio::runtime::Builder;

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

    /// All protocols work in a Tokio runtime without its I/O and time drivers.
    #[cfg(all(feature = "http2", feature = "http3"))]
    #[test]
    fn measures_all_protocols_with_tokio() {
        let runtime = Builder::new_current_thread()
            .build()
            .expect("should be able to create a Tokio runtime");
        for protocol in [
            HttpProtocol::Http11,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ] {
            let client = TtfbClient::new(TtfbOptions {
                protocol: ProtocolSelection::Only(protocol),
                ..options()
            });
            let outcome = runtime
                .block_on(client.measure_async("https://www.cloudflare.com"))
                .unwrap_or_else(|error| panic!("{protocol}: {error}"));
            assert_eq!(outcome.protocol(), protocol);
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
}
