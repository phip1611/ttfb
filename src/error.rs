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

use derive_more::Display;
use native_tls::HandshakeError;
use std::error::Error;
use std::io;
use std::net::TcpStream;
use trust_dns_resolver::error::ResolveError;

#[derive(Debug, Display)]
pub enum ResolveDnsError {
    #[display(fmt = "Can't find DNS entry for the given host.")]
    NoResults,
    #[display(fmt = "Couldn't resolve DNS for given host because: {}", _0)]
    Other(ResolveError),
}

impl Error for ResolveDnsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ResolveDnsError::Other(err) => Some(err),
            ResolveDnsError::NoResults => None,
        }
    }
}

#[derive(Debug, Display)]
pub enum InvalidUrlError {
    #[display(
        fmt = "No input provided. Provide a URL, like https://example.com or https://1.2.3.4:443"
    )]
    MissingInput,
    #[display(fmt = "The URL is illegal, because of {}", _0)]
    WrongFormat(String),
    #[display(fmt = "This tools only supports http and https")]
    WrongScheme,
    #[display(
        fmt = "https can only be used when a domain name is given. IP addresses don't work."
    )]
    HttpsRequiresDomainName,
    Other,
}

impl Error for InvalidUrlError {}

#[derive(Debug, Display)]
pub enum TtfbError {
    #[display(fmt = "Invalid URL! {}", _0)]
    InvalidUrl(InvalidUrlError),
    #[display(fmt = "Can't resolve DNS! {}", _0)]
    CantResolveDns(ResolveDnsError),
    #[display(fmt = "Can't establish TCP-Connection! {}", _0)]
    CantConnectTcp(io::Error),
    #[display(fmt = "Can't establish TLS-Connection! {}", _0)]
    CantConnectTls(native_tls::Error),
    #[display(fmt = "Can't verify TLS-Connection! {}", _0)]
    CantVerifyTls(HandshakeError<TcpStream>),
    #[display(fmt = "Can't establish HTTP/1.1-Connection! {}", _0)]
    CantConnectHttp(io::Error),
    #[display(fmt = "There was a problem with the stream: {}", _0)]
    OtherStreamError(io::Error),
}

impl Error for TtfbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TtfbError::InvalidUrl(err) => Some(err),
            TtfbError::CantResolveDns(err) => Some(err),
            TtfbError::CantConnectTls(err) => Some(err),
            TtfbError::CantConnectTcp(err) => Some(err),
            TtfbError::OtherStreamError(err) => Some(err),
            TtfbError::CantVerifyTls(err) => Some(err),
            TtfbError::CantConnectHttp(err) => Some(err),
        }
    }
}
