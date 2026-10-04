// SPDX-License-Identifier: MIT

//! Library + CLI-Tool to measure the TTFB (time to first byte) of HTTP(S) requests.
//! Additionally, this crate measures the times of DNS lookup, TCP connect, and
//! TLS handshake. This crate supports HTTP/1.1 and, with the `http2` feature,
//! HTTP/2. It can cope with TLS 1.2 and 1.3.
//!
//! See [`TtfbClient`], which is the entry point of the public interface.
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

pub use client::{ProtocolSelection, TtfbClient, TtfbOptions};
pub use error::{InvalidUrlError, ResolveDnsError, TtfbError};
pub use outcome::{DurationPair, HttpProtocol, TtfbOutcome, ZeroRttStatus};

use std::{panic, thread};

mod client;
mod error;
mod http11;
#[cfg(feature = "http2")]
mod http2;
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
                tokio::runtime::Builder::new_current_thread()
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
