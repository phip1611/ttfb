// SPDX-License-Identifier: MIT

#![deny(
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    clippy::absolute_paths,
    clippy::must_use_candidate,
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
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]

use clap::Parser;
use crossterm::ExecutableCommand;
use crossterm::style::{Attribute, SetAttribute};
use std::fmt::{self, Display, Formatter};
use std::io::stdout;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::process::exit;
use std::str::FromStr;
use std::time::{Duration, Instant};
use ttfb::{
    ConnectionHandshake, HttpProtocol, ProtocolSelection, TtfbClient, TtfbError, TtfbOptions,
    TtfbOutcome,
};

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// DNS lookups faster than this (in ms) were probably answered by a cache.
const DNS_CACHED_MS: f64 = 2.0;

// The labels of the steps in the output.
const DNS_LOOKUP_STEP: &str = "DNS Lookup";
const TCP_CONNECT_STEP: &str = "TCP Connect";
const TLS_HANDSHAKE_STEP: &str = "TLS Handshake";
const QUIC_HANDSHAKE_STEP: &str = "QUIC Handshake";
const HTTP_SEND_GET_STEP: &str = "HTTP Send GET";
const TTFB_STEP: &str = "HTTP Resp TTFB";
const HTTP_DOWNLOAD_STEP: &str = "HTTP Download";
const TOTAL_STEP: &str = "Total";

macro_rules! unwrap_or_exit {
    ($ident:ident) => {
        if let Err(err) = $ident {
            $crate::exit_error(err);
        } else {
            $ident.unwrap()
        }
    };
}

/// How often or how long `--repeat` measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RepeatInput {
    /// The number of measurements.
    Times(NonZeroUsize),
    /// The time to measure repeatedly, but at least once.
    Duration(Duration),
}

impl RepeatInput {
    /// Whether to measure again after `measurements` measurements, which took
    /// `elapsed` in total.
    fn should_continue(self, measurements: usize, elapsed: Duration) -> bool {
        match self {
            Self::Times(times) => measurements < times.get(),
            Self::Duration(duration) => elapsed < duration,
        }
    }
}

impl FromStr for RepeatInput {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid =
            |_| "expected a number of measurements (e.g. 10) or of seconds (e.g. 5s)".to_string();
        if let Some(seconds) = value.strip_suffix('s') {
            let seconds: NonZeroU64 = seconds.parse().map_err(invalid)?;
            Ok(Self::Duration(Duration::from_secs(seconds.get())))
        } else {
            value.parse().map(Self::Times).map_err(invalid)
        }
    }
}

impl Display for RepeatInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Times(times) => write!(f, "{times}"),
            Self::Duration(duration) => write!(f, "{}s", duration.as_secs()),
        }
    }
}

/// CLI Arguments for `clap`.
#[derive(Parser, Debug)]
#[command(
    version,
    about = "CLI utility to measure the TTFB (time to first byte) of HTTP(S) \
    requests. This includes data of intermediate steps, such as the relative \
    and absolute timings of DNS lookup, TCP connect, and TLS handshake. \
    \n\n\
    For issues or merge requests, please visit https://github.com/phip1611/ttfb."
)]
struct TtfbArgs {
    /// Name of the host. An IP address or a URL. "https://"-prefix must be provided for HTTPS/TLS.
    host: String,
    /// Whether insecure TLS-certificates (e.g., expired, wrong domain name) are allowed.
    /// Similar to `-k` of `curl`.
    #[arg(short = 'k', long = "insecure")]
    allow_insecure_certificates: bool,
    /// Require HTTP/1.1.
    #[arg(long = "http1.1", conflicts_with_all = ["http2", "http3", "auto_protocol"])]
    http11: bool,
    /// Require HTTP/2.
    #[arg(long, conflicts_with_all = ["http11", "http3", "auto_protocol"])]
    http2: bool,
    /// Require HTTP/3.
    #[arg(long, conflicts_with_all = ["http11", "http2", "auto_protocol"])]
    http3: bool,
    /// Automatically choose the best supported HTTP protocol.
    #[arg(long, conflicts_with_all = ["http11", "http2", "http3"])]
    auto_protocol: bool,
    /// Measure N times, or with an "s" suffix repeatedly for N seconds, and
    /// print the minimum, median, mean, and maximum of each step.
    #[arg(long, value_name = "N|Ns")]
    repeat: Option<RepeatInput>,
    /// The maximum duration of a measurement in seconds, between 1 and 3600.
    /// With --repeat, it applies to each measurement.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = TtfbOptions::DEFAULT_TIMEOUT.as_secs(),
        value_parser = clap::value_parser!(u64).range(
            TtfbOptions::MIN_TIMEOUT.as_secs()..=TtfbOptions::MAX_TIMEOUT.as_secs()
        ),
    )]
    timeout: u64,
    /// Print the status line and the headers of the response. With --repeat,
    /// print those of the first measurement.
    #[arg(long)]
    headers: bool,
}

/// Small CLI binary wrapper around the [`ttfb`] lib.
fn main() {
    let input: TtfbArgs = TtfbArgs::parse();
    let protocol = if input.http11 {
        ProtocolSelection::Only(HttpProtocol::Http11)
    } else if input.http2 {
        ProtocolSelection::Only(HttpProtocol::Http2)
    } else if input.http3 {
        ProtocolSelection::Only(HttpProtocol::Http3)
    } else {
        ProtocolSelection::Auto
    };
    let options = TtfbOptions {
        protocol,
        allow_insecure_certificates: input.allow_insecure_certificates,
        timeout: Duration::from_secs(input.timeout),
    };
    if let Some(repeat) = input.repeat {
        let res = measure_repeatedly(options, &input.host, repeat);
        let outcomes = unwrap_or_exit!(res);
        print_statistics(&outcomes).unwrap();
        if input.headers {
            print_headers(&outcomes[0]).unwrap();
        }
    } else {
        let res = TtfbClient::new(options).measure(input.host);
        let ttfb = unwrap_or_exit!(res);
        print_outcome(&ttfb).unwrap();
        if input.headers {
            print_headers(&ttfb).unwrap();
        }
    }
}

/// Measures `host` repeatedly, as specified by `repeat`.
fn measure_repeatedly(
    options: TtfbOptions,
    host: &str,
    repeat: RepeatInput,
) -> Result<Vec<TtfbOutcome>, TtfbError> {
    let begin = Instant::now();
    let first = TtfbClient::new(options.clone()).measure(host)?;
    // An automatic selection would probe the protocols again in every
    // measurement. For servers without HTTP/3, each probe waits for the
    // HTTP/3 timeout, so stick to the protocol of the first measurement.
    let client = TtfbClient::new(TtfbOptions {
        protocol: ProtocolSelection::Only(first.protocol()),
        ..options
    });
    let mut outcomes = vec![first];
    while repeat.should_continue(outcomes.len(), begin.elapsed()) {
        outcomes.push(client.measure(host)?);
    }
    Ok(outcomes)
}

fn exit_error(err: TtfbError) -> ! {
    eprint!("\u{1b}[31m");
    eprint!("\u{1b}[1m");
    eprint!("ERROR: ",);
    eprint!("\u{1b}[0m");
    eprint!("{err}");
    eprintln!();
    exit(-1)
}

/// Prints the URL, the address, the HTTP protocol, and the response status of
/// the measurement.
fn print_title(ttfb: &TtfbOutcome) {
    println!(
        "TTFB for {url} (by ttfb@v{crate_version})",
        url = ttfb.user_input(),
        crate_version = CRATE_VERSION
    );
    let selection = match ttfb.protocol_selection() {
        ProtocolSelection::Auto => " (selected automatically)",
        ProtocolSelection::Only(_) => "",
    };
    let address = SocketAddr::new(ttfb.ip_addr(), ttfb.port());
    println!("{:<14}: {address}", "Address");
    println!("{:<14}: {}{selection}", "Protocol", ttfb.protocol());
    println!("{:<14}: {}", "Status", ttfb.status());
}

/// Returns the relative duration of each step of the measurement, followed by
/// the total duration.
fn steps(ttfb: &TtfbOutcome) -> Vec<(&'static str, Duration)> {
    let mut steps = Vec::new();
    if let Some(dns_lookup) = ttfb.dns_lookup_duration() {
        steps.push((DNS_LOOKUP_STEP, dns_lookup.relative()));
    }
    match ttfb.connection_handshake() {
        ConnectionHandshake::Tcp { connect, tls } => {
            steps.push((TCP_CONNECT_STEP, connect.relative()));
            if let Some(tls) = tls {
                steps.push((TLS_HANDSHAKE_STEP, tls.relative()));
            }
        }
        ConnectionHandshake::Quic(handshake) => {
            steps.push((QUIC_HANDSHAKE_STEP, handshake.relative()));
        }
    }
    steps.push((HTTP_SEND_GET_STEP, ttfb.http_get_send_duration().relative()));
    steps.push((TTFB_STEP, ttfb.ttfb_duration().relative()));
    steps.push((
        HTTP_DOWNLOAD_STEP,
        ttfb.http_content_download_duration().relative(),
    ));
    steps.push((TOTAL_STEP, ttfb.http_content_download_duration().total()));
    steps
}

/// Returns the minimum, median, mean, and maximum of `durations` in ms.
fn statistics(durations: &mut [Duration]) -> [f64; 4] {
    durations.sort_unstable();
    let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
    let len = durations.len();
    let median = if len % 2 == 0 {
        (ms(durations[len / 2 - 1]) + ms(durations[len / 2])) / 2.0
    } else {
        ms(durations[len / 2])
    };
    let mean = ms(durations.iter().sum()) / len as f64;
    [ms(durations[0]), median, mean, ms(durations[len - 1])]
}

/// Prints the statistics of each step over all `outcomes`.
fn print_statistics(outcomes: &[TtfbOutcome]) -> Result<(), String> {
    // All measurements use the same protocol, so they have the same steps.
    let mut rows: Vec<(&str, Vec<Duration>)> = steps(&outcomes[0])
        .into_iter()
        .map(|(property, _)| (property, Vec::new()))
        .collect();
    for outcome in outcomes {
        for ((_, durations), (_, duration)) in rows.iter_mut().zip(steps(outcome)) {
            durations.push(duration);
        }
    }

    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    print_title(&outcomes[0]);
    println!("{:<14}: {}", "Measurements", outcomes.len());
    println!(
        "{:<16}{:>13}   {:>13}   {:>13}   {:>13}",
        "PROPERTY", "MIN (ms)", "MEDIAN (ms)", "MEAN (ms)", "MAX (ms)"
    );
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;

    for (property, durations) in &mut rows {
        let [min, median, mean, max] = statistics(durations);
        let mut line =
            format!("{property:<14}: {min:>13.3}   {median:>13.3}   {mean:>13.3}   {max:>13.3}");
        // The first lookup may miss the cache, so judge by the median.
        if *property == DNS_LOOKUP_STEP && median < DNS_CACHED_MS {
            line.push_str("  (probably cached)");
        }
        if *property == TTFB_STEP {
            stdout()
                .execute(SetAttribute(Attribute::Bold))
                .map_err(|err| err.to_string())?;
            println!("{line}");
            stdout()
                .execute(SetAttribute(Attribute::Reset))
                .map_err(|err| err.to_string())?;
        } else {
            println!("{line}");
        }
    }

    Ok(())
}

/// Prints the status line and the headers of the response.
fn print_headers(ttfb: &TtfbOutcome) -> Result<(), String> {
    println!();
    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    println!("{} {}", ttfb.protocol(), ttfb.status());
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;
    for (name, value) in ttfb.headers() {
        // Header values may contain bytes that aren't valid UTF-8.
        println!("{name}: {}", String::from_utf8_lossy(value.as_bytes()));
    }
    Ok(())
}

fn print_outcome(ttfb: &TtfbOutcome) -> Result<(), String> {
    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    print_title(ttfb);
    println!("PROPERTY        REL TIME (ms)   ABS TIME (ms)");
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;

    if let Some(duration_pair) = ttfb.dns_lookup_duration() {
        // For DNS, abs and rel time is the same (because it happens first).
        let duration = duration_pair.relative().as_secs_f64() * 1000.0;
        print!(
            "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
            property = DNS_LOOKUP_STEP,
            rel_time = duration,
            abs_time = duration,
        );
        if duration < DNS_CACHED_MS {
            print!("  (probably cached)");
        }
        println!();
    }
    match ttfb.connection_handshake() {
        ConnectionHandshake::Tcp { connect, tls } => {
            println!(
                "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
                property = TCP_CONNECT_STEP,
                rel_time = connect.relative().as_secs_f64() * 1000.0,
                abs_time = connect.total().as_secs_f64() * 1000.0,
            );
            if let Some(tls) = tls {
                println!(
                    "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
                    property = TLS_HANDSHAKE_STEP,
                    rel_time = tls.relative().as_secs_f64() * 1000.0,
                    abs_time = tls.total().as_secs_f64() * 1000.0,
                );
            }
        }
        ConnectionHandshake::Quic(handshake) => {
            println!(
                "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
                property = QUIC_HANDSHAKE_STEP,
                rel_time = handshake.relative().as_secs_f64() * 1000.0,
                abs_time = handshake.total().as_secs_f64() * 1000.0,
            );
        }
    }
    println!(
        "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
        property = HTTP_SEND_GET_STEP,
        rel_time = ttfb.http_get_send_duration().relative().as_secs_f64() * 1000.0,
        abs_time = ttfb.http_get_send_duration().total().as_secs_f64() * 1000.0,
    );

    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    println!(
        "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
        property = TTFB_STEP,
        rel_time = ttfb.ttfb_duration().relative().as_secs_f64() * 1000.0,
        abs_time = ttfb.ttfb_duration().total().as_secs_f64() * 1000.0,
    );
    println!(
        "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
        property = HTTP_DOWNLOAD_STEP,
        rel_time = ttfb
            .http_content_download_duration()
            .relative()
            .as_secs_f64()
            * 1000.0,
        abs_time = ttfb.http_content_download_duration().total().as_secs_f64() * 1000.0,
    );
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repeat() {
        assert_eq!(
            "10".parse(),
            Ok(RepeatInput::Times(NonZeroUsize::new(10).unwrap()))
        );
        assert_eq!(
            "5s".parse(),
            Ok(RepeatInput::Duration(Duration::from_secs(5)))
        );
        for valid in ["10", "5s"] {
            assert_eq!(valid.parse::<RepeatInput>().unwrap().to_string(), valid);
        }
        for invalid in ["", "0", "0s", "s", "-1", "1.5s", "5m", "5 s"] {
            assert!(invalid.parse::<RepeatInput>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn statistics_odd_count() {
        let mut durations = [3, 1, 8].map(Duration::from_millis);
        assert_eq!(statistics(&mut durations), [1.0, 3.0, 4.0, 8.0]);
    }

    #[test]
    fn statistics_even_count() {
        let mut durations = [4, 1, 2, 9].map(Duration::from_millis);
        assert_eq!(statistics(&mut durations), [1.0, 3.0, 4.0, 9.0]);
    }
}
