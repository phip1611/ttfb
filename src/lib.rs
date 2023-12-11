/*
MIT License

Copyright (c) 2021 Philipp Schuster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
    // clippy::restriction,
    // clippy::pedantic
)]
// now allow a few rules which are denied by the above statement
// --> they are ridiculous and not necessary
#![allow(
    clippy::suboptimal_flops,
    clippy::redundant_pub_crate,
    clippy::fallible_impl_from
)]
// I can't do anything about this; fault of the dependencies
#![allow(clippy::multiple_crate_versions)]
// allow: required because of derive macro.. :(
#![allow(clippy::use_self)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]

pub use error::{InvalidUrlError, ResolveDnsError, TtfbError};
pub use outcome::{DurationPair, TtfbOutcome};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use rustls_connector::RustlsConnector;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use trust_dns_resolver::Resolver as DnsResolver;
use url::Url;

mod error;
mod outcome;

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
    let input = input.as_ref();
    if input.is_empty() {
        return Err(TtfbError::InvalidUrl(InvalidUrlError::MissingInput));
    }
    let input = input.to_string();
    let input = prepend_default_scheme_if_necessary(input);
    let url = parse_input_as_url(&input)?;
    // println!("final url: {}", url);
    check_scheme_is_allowed(&url)?;

    let (addr, dns_duration) = resolve_dns_if_necessary(&url)?;
    let port = url.port_or_known_default().unwrap();
    let (tcp, tcp_connect_duration) = tcp_connect(addr, port)?;
    // Does TLS handshake if necessary: returns regular TCP stream if regular HTTP is used.
    // We can write to the "tcp" trait object whatever content we want to. The underlying
    // implementation will either send plain text or encrypt it for TLS.
    let (mut tcp, tls_handshake_duration) =
        tls_handshake_if_necessary(tcp, &url, allow_insecure_certificates)?;
    let (http_get_send_duration, http_ttfb_duration) = execute_http_get(&mut tcp, &url)?;

    Ok(TtfbOutcome::new(
        input,
        addr,
        port,
        dns_duration,
        tcp_connect_duration,
        tls_handshake_duration,
        http_get_send_duration,
        http_ttfb_duration,
        // http_content_download_duration,
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
/// All data will be encrypted using the TLS-functionality of the crate `native-tls`.
/// If TLS is used, it measures the time of the TLS handshake.
fn tls_handshake_if_necessary(
    tcp: TcpStream,
    url: &Url,
    allow_insecure_certificates: bool,
) -> Result<(Box<dyn IoReadAndWrite>, Option<Duration>), TtfbError> {
    if url.scheme() == "https" {
        let connector: RustlsConnector = if allow_insecure_certificates {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AllowInvalidCertsVerifier))
                .with_no_client_auth()
                .into()
        } else {
            RustlsConnector::new_with_native_certs()
                .map_or_else(|_| RustlsConnector::new_with_webpki_roots_certs(), |v| v)
        };
        let now = Instant::now();

        // hostname not used for DNS, only for certificate validation
        // can also be a IP address, because Certificates can have the IP-Address in
        // the "cert subject alternative name" field.
        let certificate_host = url.host_str().unwrap_or("");
        let mut stream = connector
            .connect(certificate_host, tcp)
            .map_err(TtfbError::CantVerifyTls)?;
        stream.flush().map_err(TtfbError::OtherStreamError)?;
        let tls_handshake_duration = now.elapsed();
        Ok((Box::new(stream), Some(tls_handshake_duration)))
    } else {
        Ok((Box::new(tcp), None))
    }
}

/// Custom verifier that allows invalid certificates.
#[derive(Debug)]
pub struct AllowInvalidCertsVerifier;

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

/// Executes the HTTP/1.1 GET-Request on the given socket. This works with TCP or `TLS<TCP>`.
/// Afterwards, it waits for the first byte and measures all the times.
fn execute_http_get(
    tcp: &mut Box<dyn IoReadAndWrite>,
    url: &Url,
) -> Result<(Duration, Duration), TtfbError> {
    let header = build_http11_header(url);
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

    // todo can lead to error, not every server responds with EOF
    // need to parse the request header and get the length from that
    /*tcp.read_to_end(&mut content)
        .map_err(|_| TtfbError::CantConnectHttp)?;
    let http_content_download_duration = now.elapsed();
    println!("http content:\n{}", unsafe {
        String::from_utf8_unchecked(content)
    });*/
    Ok((
        get_request_send_duration,
        http_ttfb_duration,
        // http_content_download_duration,
    ))
}

/// Constructs the header for a HTTP/1.1 GET-Request.
fn build_http11_header(url: &Url) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
        Host: {host}\r\n\
        User-Agent: ttfb/{version}\r\n\
        Accept: */*\r\n\
        Accept-Encoding: gzip, deflate, br\r\n\
        \r\n",
        path = url.path(),
        host = url.host_str().unwrap(),
        version = CRATE_VERSION
    )
}

/// Parses the string input into an [`Url`] object.
fn parse_input_as_url(input: &str) -> Result<Url, TtfbError> {
    Url::parse(input)
        .map_err(|e| TtfbError::InvalidUrl(InvalidUrlError::WrongFormat(e.to_string())))
}

/// Prepends the default scheme `http://` is necessary to the user input.
fn prepend_default_scheme_if_necessary(url: String) -> String {
    const SCHEME_SEPARATOR: &str = "://";
    const DEFAULT_SCHEME: &str = "http";

    (!url.contains(SCHEME_SEPARATOR))
        .then(|| format!("{DEFAULT_SCHEME}://{url}"))
        .unwrap_or(url)
}

/// Checks the scheme is on the allow list. Currently, we only allow "http"
/// and "https".
fn check_scheme_is_allowed(url: &Url) -> Result<(), TtfbError> {
    let actual_scheme = url.scheme();
    let allowed_scheme = actual_scheme == "http" || actual_scheme == "https";
    if allowed_scheme {
        Ok(())
    } else {
        Err(TtfbError::InvalidUrl(InvalidUrlError::WrongScheme(
            actual_scheme.to_string(),
        )))
    }
}

/// Checks from the URL if we already have an IP address or not.
/// If the user gave us a domain name, we resolve it using the [`trust-dns-resolver`]
/// crate and measure the time for it.
fn resolve_dns_if_necessary(url: &Url) -> Result<(IpAddr, Option<Duration>), TtfbError> {
    Ok(if url.domain().is_none() {
        let mut ip_str = url.host_str().unwrap();
        // [a::b::c::d::e::f::0::1] => ipv6 address
        if ip_str.starts_with('[') {
            ip_str = &ip_str[1..ip_str.len() - 1];
        }
        let addr = IpAddr::from_str(ip_str)
            .map_err(|e| TtfbError::InvalidUrl(InvalidUrlError::WrongFormat(e.to_string())))?;
        (addr, None)
    } else {
        resolve_dns(url).map(|(addr, dur)| (addr, Some(dur)))?
    })
}

/// Actually resolves a domain using the systems default DNS resolver.
/// Helper function for [`resolve_dns_if_necessary`].
fn resolve_dns(url: &Url) -> Result<(IpAddr, Duration), TtfbError> {
    // Construct a new DNS Resolver.
    // On Unix/Posix systems, this will read: /etc/resolv.conf
    // In the end, this uses the name server of the system or falls back to
    // the library's default (usually Google DNS).
    let resolver = DnsResolver::from_system_conf()
        .or_else(|_| DnsResolver::default())
        .map_err(TtfbError::CantConfigureDNSError)?;

    let begin = Instant::now();

    // at least on Linux this gets cached somehow in the background
    // probably the DNS implementation/OS has a DNS cache
    let response = resolver
        .lookup_ip(url.host_str().unwrap())
        .map_err(|err| TtfbError::CantResolveDns(ResolveDnsError::Other(Box::new(err))))?;
    let duration = begin.elapsed();

    let ipv4_addrs = response
        .iter()
        .filter(|addr| addr.is_ipv4())
        .collect::<Vec<_>>();
    let ipv6_addrs = response
        .iter()
        .filter(|addr| addr.is_ipv6())
        .collect::<Vec<_>>();

    if !ipv4_addrs.is_empty() {
        Ok((ipv4_addrs[0], duration))
    } else if !ipv6_addrs.is_empty() {
        Ok((ipv6_addrs[0], duration))
    } else {
        Err(TtfbError::CantResolveDns(ResolveDnsError::NoResults))
    }
}

#[cfg(all(test, not(network_tests)))]
mod tests {
    use crate::parse_input_as_url;

    use super::*;

    #[test]
    fn test_parse_input_as_url() {
        parse_input_as_url("http://google.com").expect("to be valid");
        parse_input_as_url("https://google.com:443").expect("to be valid");
        parse_input_as_url("http://google.com:80").expect("to be valid");
        parse_input_as_url("google.com:80").expect("to be valid");
        parse_input_as_url("http://google.com/foobar").expect("to be valid");
        parse_input_as_url("https://google.com:443/foobar").expect("to be valid");
        parse_input_as_url("https://goo-gle.com:443/foobar").expect("to be valid");
        parse_input_as_url("https://goo-gle.com:443/foobar?124141").expect("to be valid");
        parse_input_as_url("https://subdomain.goo-gle.com:443/foobar?124141").expect("to be valid");
        parse_input_as_url("https://192.168.1.102:443/foobar?124141").expect("to be valid");
    }

    #[test]
    fn test_append_scheme_if_necessary() {
        assert_eq!(
            prepend_default_scheme_if_necessary("phip1611.de".to_owned()),
            "http://phip1611.de"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary("https://phip1611.de".to_owned()),
            "https://phip1611.de"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary("192.168.1.102:443/foobar?124141".to_owned()),
            "http://192.168.1.102:443/foobar?124141"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary(
                "https://192.168.1.102:443/foobar?124141".to_owned()
            ),
            "https://192.168.1.102:443/foobar?124141"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary("ftp://192.168.1.102:443/foobar?124141".to_owned()),
            "ftp://192.168.1.102:443/foobar?124141"
        );
    }

    #[test]
    fn test_check_scheme() {
        check_scheme_is_allowed(
            &Url::from_str(&prepend_default_scheme_if_necessary(
                "phip1611.de".to_owned(),
            ))
            .unwrap(),
        )
        .expect("must accept http");
        check_scheme_is_allowed(
            &Url::from_str(&prepend_default_scheme_if_necessary(
                "https://phip1611.de".to_owned(),
            ))
            .unwrap(),
        )
        .expect("must accept http");
        check_scheme_is_allowed(
            &Url::from_str(&prepend_default_scheme_if_necessary(
                "ftp://phip1611.de".to_owned(),
            ))
            .unwrap(),
        )
        .expect_err("must not accept ftp");
    }
}

/// Tests that rely on an external network connection.
/// Sort of integration tests.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;

    #[test]
    fn test_resolve_dns_if_necessary() {
        let url1 = Url::from_str("http://phip1611.de").expect("must be valid");
        let url2 = Url::from_str("https://phip1611.de").expect("must be valid");
        let url3 = Url::from_str("http://192.168.1.102").expect("must be valid");
        let url4 = Url::from_str("http://[2001:0db8:3c4d:0015::1a2f:1a2b]").expect("must be valid");
        let url5 = Url::from_str("http://[2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b]")
            .expect("must be valid");

        resolve_dns_if_necessary(&url1).expect("must be valid");
        resolve_dns_if_necessary(&url2).expect("must be valid");
        resolve_dns_if_necessary(&url3).expect("must be valid");
        resolve_dns_if_necessary(&url4).expect("must be valid");
        resolve_dns_if_necessary(&url5).expect("must be valid");
    }

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
