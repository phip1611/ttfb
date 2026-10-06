// SPDX-License-Identifier: MIT

//! Library to measure the TTFB (time to first byte) of HTTP(S) requests.
//!
//! Besides the TTFB, each measurement reports how long every step of the
//! request took: the DNS lookup, the TCP connect and TLS handshake (or the
//! QUIC handshake with HTTP/3), sending the request, and downloading the
//! content.
//!
//! HTTP/1.1 is always available. HTTP/2 and HTTP/3 come with the `http2` and
//! `http3` features, which are enabled by default. Unless told otherwise, the
//! client picks the best protocol the server supports. TLS 1.2 and 1.3 are
//! supported.
//!
//! See [`TtfbClient`], which is the entry point of the public interface:
//!
//! ```no_run
//! use ttfb::{HttpProtocol, ProtocolSelection, TtfbClient, TtfbOptions};
//!
//! let client = TtfbClient::new(TtfbOptions {
//!     protocol: ProtocolSelection::Only(HttpProtocol::Http2),
//!     ..TtfbOptions::default()
//! });
//! let outcome = client.measure("https://example.com")?;
//! println!("{}: {:?}", outcome.protocol(), outcome.ttfb_duration().total());
//! # Ok::<(), ttfb::TtfbError>(())
//! ```
//!
//! ## Cross Platform
//! CLI + lib work on Linux, MacOS, and Windows.

#![deny(
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    clippy::absolute_paths,
    clippy::must_use_candidate
)]
// I can't do anything about this; fault of the dependencies
#![allow(clippy::multiple_crate_versions)]
// Crate-internal items are marked as such, also in private modules.
#![allow(clippy::redundant_pub_crate)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]

pub use client::{ProtocolSelection, TtfbClient, TtfbOptions};
pub use error::{InvalidUrlError, ResolveDnsError, TtfbError};
pub use outcome::{ConnectionHandshake, DurationPair, HttpProtocol, TtfbOutcome};

use std::{panic, thread};
use tokio::runtime::Builder;
#[cfg(any(feature = "http2", feature = "http3"))]
use {
    http::header::{ACCEPT, ACCEPT_ENCODING, USER_AGENT},
    url::Url,
};

mod client;
mod error;
mod http11;
#[cfg(feature = "http2")]
mod http2;
#[cfg(feature = "http3")]
mod http3;
mod outcome;
mod target;
mod tls;

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runs `future` to completion on a dedicated current-thread Tokio runtime.
///
/// The library has a blocking API but should also work inside a Tokio
/// runtime, where starting another runtime on the same thread panics. Hence,
/// the runtime runs in a dedicated thread. For the measurements, this
/// overhead is negligible.
///
/// More info: <https://stackoverflow.com/a/62536772/2891595>
fn run_in_tokio<F>(future: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    thread::scope(|scope| {
        scope
            .spawn(|| {
                Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .expect("should be able to create a Tokio runtime")
                    .block_on(future)
            })
            .join()
            .unwrap_or_else(|panic| panic::resume_unwind(panic))
    })
}

/// Builds the GET request for HTTP/2 and HTTP/3. Both derive the `:scheme`,
/// `:authority`, and `:path` pseudo-header fields from the absolute URI, which
/// excludes the fragment.
#[cfg(any(feature = "http2", feature = "http3"))]
fn build_http_request(url: &Url) -> Result<http::Request<()>, TtfbError> {
    http::Request::get(&url[..url::Position::AfterQuery])
        .header(USER_AGENT, format!("ttfb/{CRATE_VERSION}"))
        .header(ACCEPT, "*/*")
        .header(ACCEPT_ENCODING, "gzip, deflate, br, zstd")
        .body(())
        .map_err(|error| TtfbError::InvalidUrl(InvalidUrlError::WrongFormat(error.to_string())))
}
