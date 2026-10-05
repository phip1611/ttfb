// SPDX-License-Identifier: MIT

//! Library + CLI-Tool to measure the TTFB (time to first byte) of HTTP(S) requests.
//! Additionally, this crate measures the times of DNS lookup, TCP connect, and
//! TLS handshake. This crate currently only supports HTTP/1.1. It can cope with
//! TLS 1.2 and 1.3.LICENSE.
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
pub use outcome::{DurationPair, HttpProtocol, TtfbOutcome};

mod client;
mod error;
mod http11;
mod outcome;
mod target;
mod tls;

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
