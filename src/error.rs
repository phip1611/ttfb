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
//! Module for [`TtfbError`].

use derive_more::Display;
use rustls_connector::HandshakeError;
use std::error::Error;
use std::io;
use std::net::TcpStream;
use trust_dns_resolver::error::ResolveError;

/// Errors during DNS resolving.
#[derive(Debug, Display)]
pub enum ResolveDnsError {
    /// Can't find DNS entry for the given host.
    #[display(fmt = "Can't find DNS entry for the given host.")]
    NoResults,
    /// Couldn't resolve DNS for given host.
    #[display(fmt = "Couldn't resolve DNS for given host because: {}", _0)]
    Other(Box<ResolveError>),
}

impl Error for ResolveDnsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Other(err) => Some(err),
            Self::NoResults => None,
        }
    }
}

/// Errors during URL parsing.
#[derive(Debug, Display)]
pub enum InvalidUrlError {
    /// No input was provided. Provide a URL, such as <https://example.com> or <https://1.2.3.4:443>.
    #[display(
        fmt = "No input was provided. Provide a URL, such as https://example.com or https://1.2.3.4:443"
    )]
    MissingInput,
    /// The URL is illegal.
    #[display(fmt = "The URL is illegal because: {}", _0)]
    WrongFormat(String),
    /// This tools only supports http and https.
    #[display(fmt = "This tools only supports http and https.")]
    WrongScheme,
    /// Other unknown error.
    #[display(fmt = "Other unknown error.")]
    Other,
}

impl Error for InvalidUrlError {}

/// Errors of the public interface of this crate.
#[derive(Debug, Display)]
pub enum TtfbError {
    /// Invalid URL
    #[display(fmt = "Invalid URL: {}", _0)]
    InvalidUrl(InvalidUrlError),
    /// Can't resolve DNS.
    #[display(fmt = "Can't resolve DNS because: {}", _0)]
    CantResolveDns(ResolveDnsError),
    /// Can't establish TCP-Connection.
    #[display(fmt = "Can't establish TCP-Connection because: {}", _0)]
    CantConnectTcp(io::Error),
    /// Can't establish TLS-Connection.
    #[display(fmt = "Can't establish TLS-Connection because: {}", _0)]
    CantConnectTls(rustls_connector::HandshakeError<std::net::TcpStream>),
    /// Can't verify TLS-Connection.
    #[display(fmt = "Can't verify TLS-Connection because: {}", _0)]
    CantVerifyTls(HandshakeError<TcpStream>),
    /// Can't establish HTTP/1.1-Connection.
    #[display(fmt = "Can't establish HTTP/1.1-Connection because: {}", _0)]
    CantConnectHttp(io::Error),
    /// Didn't receive any data after sending the HTTP GET request.
    #[display(fmt = "Didn't receive any data. Is the host running a HTTP server?")]
    NoHttpResponse,
    /// There was a problem with the TCP stream.
    #[display(fmt = "There was a problem with the TCP stream because: {}", _0)]
    OtherStreamError(io::Error),
    /// Can't configure trust-dns-resolver configuration.
    #[display(fmt = "Failed to configure DNS based on system or default settings: {_0}")]
    CantConfigureDNSError(io::Error),
}

impl Error for TtfbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TtfbError::InvalidUrl(err) => Some(err),
            TtfbError::CantResolveDns(err) => Some(err),
            TtfbError::CantConnectTls(err) => Some(err),
            TtfbError::CantConnectTcp(err) => Some(err),
            TtfbError::OtherStreamError(err) => Some(err),
            TtfbError::CantConnectHttp(err) => Some(err),
            TtfbError::NoHttpResponse => None,
            TtfbError::CantConfigureDNSError(err) => Some(err),
            TtfbError::CantVerifyTls(err) => Some(err),
        }
    }
}
