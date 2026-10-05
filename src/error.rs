// SPDX-License-Identifier: MIT

//! Module for [`TtfbError`].

use hickory_resolver::{ResolveError, ResolveErrorKind};
use std::io;
use thiserror::Error;

/// Errors during DNS resolving.
#[derive(Clone, Debug, Error)]
pub enum ResolveDnsError {
    /// Can't find DNS entry for the given host.
    #[error("Can't find DNS entry for the given host.")]
    NoResults,
    /// Couldn't resolve DNS for given host.
    #[error("Couldn't resolve DNS for given host because: {0}")]
    Other(#[source] Box<ResolveError>),
}

impl PartialEq for ResolveDnsError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NoResults, Self::NoResults) => true,
            (Self::Other(e1), Self::Other(e2)) => match (e1.kind(), e2.kind()) {
                (ResolveErrorKind::Msg(msg1), ResolveErrorKind::Msg(msg2)) => msg1.eq(msg2),
                (ResolveErrorKind::Message(msg1), ResolveErrorKind::Message(msg2)) => msg1.eq(msg2),
                (ResolveErrorKind::Proto(_e1), ResolveErrorKind::Proto(_e2)) => {
                    // nah, ignore it. Proper deep check is too complex.
                    // Shortcut is good enough for the sake of the library.
                    true
                }
                _ => false,
            },
            _ => false,
        }
    }
}

/// Errors during URL parsing.
#[derive(Clone, Debug, Error, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum InvalidUrlError {
    /// No input was provided. Provide a URL, such as <https://example.com> or <https://1.2.3.4:443>.
    #[error(
        "No input was provided. Provide a URL, such as https://example.com or https://1.2.3.4:443"
    )]
    MissingInput,
    /// The URL is illegal.
    #[error("The URL is illegal because: {0}")]
    WrongFormat(String),
    /// Wrong scheme. Only supports http and https.
    #[error("Wrong scheme '{0}://': Only supports http and https.")]
    WrongScheme(String),
    /// Other unknown error.
    #[error("Other unknown error.")]
    Other,
}

/// Errors of the public interface of this crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TtfbError {
    /// Invalid URL
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[source] InvalidUrlError),
    /// Can't resolve DNS.
    #[error("Can't resolve DNS because: {0}")]
    CantResolveDns(#[source] ResolveDnsError),
    /// Can't establish TCP-Connection.
    #[error("Can't establish TCP-Connection because: {0}")]
    CantConnectTcp(#[source] io::Error),
    /// Can't establish TLS-Connection, e.g., because the certificate is invalid.
    #[error("Can't establish TLS-Connection because: {0}")]
    Tls(String),
    /// Can't establish HTTP/1.1-Connection.
    #[error("Can't establish HTTP/1.1-Connection because: {0}")]
    CantConnectHttp(#[source] io::Error),
    /// Didn't receive any data after sending the HTTP GET request.
    #[error("Didn't receive any data. Is the host running a HTTP server?")]
    NoHttpResponse,
    /// The server returned an invalid or unsupported HTTP response.
    #[error("The HTTP response was invalid or unsupported: {0}")]
    InvalidHttpResponse(String),
    /// The requested HTTP protocol can't be used for this URL or server, or
    /// the crate was built without it.
    #[error("The requested HTTP protocol can't be used: {0}")]
    UnsupportedHttpProtocol(String),
    /// An HTTP/2 exchange failed.
    #[error("HTTP/2 failed: {0}")]
    Http2(String),
    /// An HTTP/3 exchange failed.
    #[error("HTTP/3 failed: {0}")]
    Http3(String),
    /// There was a problem with the TCP stream.
    #[error("There was a problem with the TCP stream because: {0}")]
    OtherStreamError(#[source] io::Error),
    /// Can't configure trust-dns-resolver configuration.
    #[error("Failed to configure DNS based on system or default settings: {0}")]
    CantConfigureDNSError(#[source] ResolveError),
}

impl PartialEq for TtfbError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidUrl(e1), Self::InvalidUrl(e2)) => e1.eq(e2),
            (Self::CantResolveDns(e1), Self::CantResolveDns(e2)) => e1.eq(e2),
            (Self::CantConnectTcp(e1), Self::CantConnectTcp(e2)) => e1.kind().eq(&e2.kind()),
            (Self::Tls(e1), Self::Tls(e2))
            | (Self::UnsupportedHttpProtocol(e1), Self::UnsupportedHttpProtocol(e2))
            | (Self::Http2(e1), Self::Http2(e2))
            | (Self::Http3(e1), Self::Http3(e2)) => e1.eq(e2),
            (Self::CantConnectHttp(e1), Self::OtherStreamError(e2)) => e1.kind().eq(&e2.kind()),
            (Self::CantConfigureDNSError(_e1), Self::CantConfigureDNSError(_e2)) => {
                // nah, ignore it. Proper deep check is too complex.
                // Shortcut is good enough for the sake of the library.
                true
            }
            (Self::NoHttpResponse, Self::NoHttpResponse) => true,
            (Self::InvalidHttpResponse(e1), Self::InvalidHttpResponse(e2)) => e1.eq(e2),
            _ => false,
        }
    }
}
