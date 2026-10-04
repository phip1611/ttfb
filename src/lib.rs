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
pub use outcome::{DurationPair, HttpProtocol, TtfbOutcome};

use target::Target;

mod error;
mod http11;
mod outcome;
mod target;
mod tls;

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    http11::measure(&target, tls::config(allow_insecure_certificates))
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
