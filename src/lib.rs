// SPDX-License-Identifier: MIT

//! Library + CLI-Tool to measure the TTFB (time to first byte) of HTTP(S) requests.
//! Additionally, this crate measures the times of DNS lookup, TCP connect, and
//! TLS handshake. This crate currently only supports HTTP/1.1. It can cope with
//! TLS 1.2 and 1.3.LICENSE.
//!
//! See [`ttfb`] which is the main function of the public interface.
//!
//! ## Cross Platform
//! CLI + lib work on Linux, MacOS, and Windows.

#![deny(
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    clippy::must_use_candidate
)]
// I can't do anything about this; fault of the dependencies
#![allow(clippy::multiple_crate_versions)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]

pub use error::{InvalidUrlError, ResolveDnsError, TtfbError};
pub use outcome::{DurationPair, TtfbOutcome};

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use target::Target;
use url::Url;

mod error;
mod http11;
mod outcome;
mod target;
mod tls;

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Trait that combines [`IoWrite`] and [`IoRead`]. This is necessary, as
/// trait combinations such as `dyn A + B` are not allowed in Rust.
///
/// This trait abstracts over a `Tcp<Data>` Stream or a `Tcp<Tls<Data>>` stream.
trait IoReadAndWrite: IoWrite + IoRead {}

impl<T: IoRead + IoWrite> IoReadAndWrite for T {}

/// Takes a URL and connects to it via http/1.1. Measures time for DNS lookup,
/// TCP connection start, TLS handshake, and TTFB (Time to First Byte) of HTML
/// content.
///
/// ## Parameters
/// - `input`: URL pointing to a HTTP server. Can be one of
///   - `phip1611.de` (defaults to `http://`)
///   - `http://phip1611.de`
///   - `https://phip1611.de`
///   - `https://phip1611.de?foo=bar`
///   - `https://sub.domain.phip1611.de?foo=bar`
///   - `http://12.34.56.78/foobar`
///   - `https://1.1.1.1`
///   - `12.34.56.78/foobar` (defaults to `http://`)
///   - `12.34.56.78` (defaults to `http://`)
/// - `allow_insecure_certificates`: if illegal certificates (untrusted,
///   expired) should be accepted when https is used. Similar to
///   `-k/--insecure` in `curl`.
///
/// ## Return value
/// [`TtfbOutcome`] or [`TtfbError`].
pub fn ttfb(
    input: impl AsRef<str>,
    allow_insecure_certificates: bool,
) -> Result<TtfbOutcome, TtfbError> {
    let target = Target::resolve(input.as_ref())?;
    let (tcp, tcp_connect_duration) = tcp_connect(target.address, target.port)?;
    // Does TLS handshake if necessary: returns regular TCP stream if regular HTTP is used.
    // We can write to the "tcp" trait object whatever content we want to. The underlying
    // implementation will either send plain text or encrypt it for TLS.
    let (mut tcp, tls_handshake_duration) =
        tls_handshake_if_necessary(tcp, &target.url, tls::config(allow_insecure_certificates))?;
    let (http_get_send_duration, http_ttfb_duration, http_content_download_duration) =
        execute_http_get(&mut tcp, &target.url)?;

    Ok(TtfbOutcome::new(
        target.input,
        target.address,
        target.port,
        target.dns_duration,
        tcp_connect_duration,
        tls_handshake_duration,
        http_get_send_duration,
        http_ttfb_duration,
        http_content_download_duration,
    ))
}

/// Initializes the TCP connection to the IP address. Measures the duration.
fn tcp_connect(addr: IpAddr, port: u16) -> Result<(TcpStream, Duration), TtfbError> {
    let addr_w_port = (addr, port);
    let now = Instant::now();
    let mut tcp = TcpStream::connect(addr_w_port).map_err(TtfbError::CantConnectTcp)?;
    tcp.flush().map_err(TtfbError::OtherStreamError)?;
    let tcp_connect_duration = now.elapsed();
    Ok((tcp, tcp_connect_duration))
}

/// If the scheme is "https", this replaces the TCP-Stream with a `TLS<TCP>`-stream.
/// If TLS is used, it measures the time of the TLS handshake.
fn tls_handshake_if_necessary(
    mut tcp: TcpStream,
    url: &Url,
    tls_config: Arc<ClientConfig>,
) -> Result<(Box<dyn IoReadAndWrite>, Option<Duration>), TtfbError> {
    if url.scheme() == "https" {
        let server_name = tls::server_name(url)?;
        let now = Instant::now();
        let mut connection = ClientConnection::new(tls_config, server_name)
            .map_err(|error| TtfbError::Tls(error.to_string()))?;
        // Performs IO until the handshake is complete.
        connection
            .complete_io(&mut tcp)
            .map_err(|error| TtfbError::Tls(error.to_string()))?;
        let tls_handshake_duration = now.elapsed();
        Ok((
            Box::new(StreamOwned::new(connection, tcp)),
            Some(tls_handshake_duration),
        ))
    } else {
        Ok((Box::new(tcp), None))
    }
}

/// Executes the HTTP/1.1 GET-Request on the given socket. This works with TCP or `TLS<TCP>`.
/// Afterwards, it waits for the first byte and measures all the times.
fn execute_http_get(
    tcp: &mut Box<dyn IoReadAndWrite>,
    url: &Url,
) -> Result<(Duration, Duration, Duration), TtfbError> {
    let header = http11::build_request(url);
    let now = Instant::now();
    tcp.write_all(header.as_bytes())
        .map_err(TtfbError::CantConnectHttp)?;
    tcp.flush().map_err(TtfbError::OtherStreamError)?;
    let get_request_send_duration = now.elapsed();
    let mut one_byte_buf = [0_u8];
    let now = Instant::now();
    tcp.read_exact(&mut one_byte_buf)
        .map_err(|_e| TtfbError::NoHttpResponse)?;
    let http_ttfb_duration = now.elapsed();
    let now = Instant::now();
    http11::read_response(tcp.as_mut(), one_byte_buf[0])?;
    let http_content_download_duration = now.elapsed();
    Ok((
        get_request_send_duration,
        http_ttfb_duration,
        http_content_download_duration,
    ))
}

/// Tests that rely on an external network connection.
/// Sort of integration tests.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;

    #[test]
    fn test_http_dns_lookup_duration() {
        let r = ttfb("http://phip1611.de".to_string(), false).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_http_no_tls_handshake() {
        let r = ttfb("http://phip1611.de".to_string(), false).unwrap();
        assert!(r.tls_handshake_duration().is_none());
    }

    #[test]
    fn test_https_dns_lookup_duration() {
        let r = ttfb("https://phip1611.de".to_string(), false).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_tls_handshake_duration() {
        let r = ttfb("https://phip1611.de".to_string(), false).unwrap();
        assert!(r.tls_handshake_duration().is_some());
    }

    #[test]
    fn test_https_expired_certificate_error() {
        let r = ttfb("https://expired.badssl.com".to_string(), false);
        assert!(r.is_err());
    }

    #[test]
    fn test_https_expired_certificate_ignore_error() {
        let r = ttfb("https://expired.badssl.com".to_string(), true).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_self_signed_certificate_error() {
        let r = ttfb("https://self-signed.badssl.com".to_string(), false);
        assert!(r.is_err());
    }

    #[test]
    fn test_https_self_signed_certificate_ignore_error() {
        let r = ttfb("https://self-signed.badssl.com".to_string(), true).unwrap();
        assert!(r.dns_lookup_duration().is_some());
    }

    #[test]
    fn test_https_wrong_host_certificate_error() {
        let r = ttfb("https://wrong.host.badssl.com".to_string(), false);
        assert!(r.is_err());
    }

    #[test]
    fn test_https_wrong_host_certificate_ignore_error() {
        let r = ttfb("https://wrong.host.badssl.com".to_string(), true).unwrap();
        assert!(r.dns_lookup_duration().is_some());
        assert!(r.tls_handshake_duration().is_some());
    }

    #[test]
    fn test_https_ip_address_tls_handshake() {
        let r = ttfb("https://1.1.1.1".to_string(), false).unwrap();
        assert!(
            r.tls_handshake_duration().is_some(),
            "must execute TLS handshake"
        );
    }
}
