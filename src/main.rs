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
use serde_json::to_string;
use std::array;
use std::fmt::{self, Display, Formatter};
use std::io::stdout;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::process::exit;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime};
use ttfb::{
    ConnectionHandshake, DurationPair, HttpProtocol, IpVersion, ProtocolSelection, TtfbClient,
    TtfbError, TtfbOptions, TtfbOutcome,
};

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// DNS lookups faster than this (in ms) were probably answered by a cache.
const DNS_CACHED_MS: f64 = 2.0;

/// The names of a step in the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StepName {
    /// The label in the table, e.g., "TCP Connect".
    label: &'static str,
    /// The key in the JSON output, e.g., "tcp_connect".
    key: &'static str,
}

impl StepName {
    const fn new(label: &'static str, key: &'static str) -> Self {
        Self { label, key }
    }
}

// The names of the steps in the output.
const DNS_LOOKUP_STEP: StepName = StepName::new("DNS Lookup", "dns_lookup");
const TCP_CONNECT_STEP: StepName = StepName::new("TCP Connect", "tcp_connect");
const TLS_HANDSHAKE_STEP: StepName = StepName::new("TLS Handshake", "tls_handshake");
const QUIC_HANDSHAKE_STEP: StepName = StepName::new("QUIC Handshake", "quic_handshake");
const HTTP_SEND_GET_STEP: StepName = StepName::new("HTTP Send GET", "http_get_send");
const TTFB_STEP: StepName = StepName::new("HTTP Resp TTFB", "ttfb");
const HTTP_DOWNLOAD_STEP: StepName = StepName::new("HTTP Download", "http_content_download");

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
    /// Connect only via IPv4. Fails for hosts without an IPv4 address.
    /// Without --ipv4 and --ipv6, IPv4 is preferred.
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    ipv4: bool,
    /// Connect only via IPv6. Fails for hosts without an IPv6 address.
    #[arg(short = '6', long, conflicts_with = "ipv4")]
    ipv6: bool,
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
    /// Print the results only as JSON in a single line.
    #[arg(long)]
    json: bool,
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
    let ip_version = if input.ipv4 {
        IpVersion::V4
    } else if input.ipv6 {
        IpVersion::V6
    } else {
        IpVersion::Any
    };
    let options = TtfbOptions {
        protocol,
        allow_insecure_certificates: input.allow_insecure_certificates,
        timeout: Duration::from_secs(input.timeout),
        ip_version,
    };
    if input.json {
        // Without --repeat, a single run is one measurement.
        let repeat = input
            .repeat
            .unwrap_or(RepeatInput::Times(NonZeroUsize::MIN));
        let started_at = SystemTime::now();
        let result = measure_repeatedly(options, &input.host, repeat);
        print_json(started_at, &result);
        if result.is_err() {
            exit(-1);
        }
    } else if let Some(repeat) = input.repeat {
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

/// A step of a measurement.
#[derive(Debug)]
struct Step {
    /// The names of the step in the output.
    name: StepName,
    /// The duration of the step itself.
    relative: Duration,
    /// The duration from the start of the measurement to the end of the step.
    absolute: Duration,
}

impl Step {
    const fn new(name: StepName, duration: DurationPair) -> Self {
        Self {
            name,
            relative: duration.relative(),
            absolute: duration.total(),
        }
    }

    /// Transforms a [`TtfbOutcome`] into the steps that the output reports.
    ///
    /// The steps are in the order in which they happened. Steps that didn't
    /// happen, such as the TLS handshake for plain HTTP, are left out.
    fn all(ttfb: &TtfbOutcome) -> Vec<Self> {
        let mut steps = Vec::new();
        if let Some(dns_lookup) = ttfb.dns_lookup_duration() {
            steps.push(Self::new(DNS_LOOKUP_STEP, dns_lookup));
        }
        match ttfb.connection_handshake() {
            ConnectionHandshake::Tcp { connect, tls } => {
                steps.push(Self::new(TCP_CONNECT_STEP, connect));
                if let Some(tls) = tls {
                    steps.push(Self::new(TLS_HANDSHAKE_STEP, tls));
                }
            }
            ConnectionHandshake::Quic(handshake) => {
                steps.push(Self::new(QUIC_HANDSHAKE_STEP, handshake));
            }
        }
        steps.push(Self::new(HTTP_SEND_GET_STEP, ttfb.http_get_send_duration()));
        steps.push(Self::new(TTFB_STEP, ttfb.ttfb_duration()));
        let download = ttfb.http_content_download_duration();
        steps.push(Self::new(HTTP_DOWNLOAD_STEP, download));
        steps
    }
}

/// Returns each step with its durations over all `outcomes`, as extracted by
/// `extract_duration`.
fn step_durations(
    outcomes: &[TtfbOutcome],
    extract_duration: fn(&Step) -> Duration,
) -> Vec<(Step, Vec<Duration>)> {
    // All measurements use the same protocol, so they have the same steps.
    let mut rows: Vec<(Step, Vec<Duration>)> = Step::all(&outcomes[0])
        .into_iter()
        .map(|step| (step, Vec::new()))
        .collect();
    for outcome in outcomes {
        for ((_, durations), step) in rows.iter_mut().zip(Step::all(outcome)) {
            durations.push(extract_duration(&step));
        }
    }
    rows
}

/// Formats `ms` with one decimal. Durations that would round to 0.0 are shown
/// as <0.1, as they are short but not zero.
fn format_ms(ms: f64) -> String {
    if ms < 0.05 {
        "<0.1".to_string()
    } else {
        format!("{ms:.1}")
    }
}

/// Returns the minimum, median, mean, and maximum of `durations` in ms.
fn calc_statistics_from_durations(durations: &[Duration]) -> [f64; 4] {
    let mut durations = durations.to_vec();
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

/// Returns the width of the widest of `values` in the table, but at least that
/// of 999.9, so typical tables keep their layout.
fn calc_max_width(values: impl IntoIterator<Item = f64>) -> usize {
    values
        .into_iter()
        .map(|value| format_ms(value).len())
        .max()
        .unwrap_or(0)
        .max("999.9".len())
}

/// Prints the statistics of each step over all `outcomes`.
fn print_statistics(outcomes: &[TtfbOutcome]) -> Result<(), String> {
    let steps_to_rel_durations_vec = step_durations(outcomes, |step| step.relative);
    let steps_to_abs_durations_vec = step_durations(outcomes, |step| step.absolute);
    // Each row: (step, [min, median, mean, max] of ABS, ... of REL), in ms.
    let steps_to_stats = steps_to_rel_durations_vec
        .into_iter()
        .zip(steps_to_abs_durations_vec)
        .map(|((step, rel_durations), (_, abs_durations))| {
            (
                step,
                calc_statistics_from_durations(&abs_durations),
                calc_statistics_from_durations(&rel_durations),
            )
        })
        .collect::<Vec<_>>();

    // Pad the absolute and the relative durations each to the widest one, so
    // the decimal points line up.
    let abs_width = calc_max_width(
        steps_to_stats
            .iter()
            .flat_map(|(_, abs_stats, _)| *abs_stats),
    );
    let rel_width = calc_max_width(
        steps_to_stats
            .iter()
            .flat_map(|(_, _, rel_stats)| *rel_stats),
    );
    let fmt_cell = |absolute: &dyn Display, relative: &dyn Display| {
        format!("{absolute:>abs_width$} ({relative:>rel_width$})")
    };
    let column_headers = ["MIN (ms)", "MEDIAN (ms)", "MEAN (ms)", "MAX (ms)"];
    // The sub-header is as wide as every cell.
    let sub_header = fmt_cell(&"ABS", &"REL");
    let max_header_width = column_headers
        .iter()
        .map(|header| header.len())
        .max()
        .expect("should have headers");
    let column_width = max_header_width.max(sub_header.len());
    // A row with a label and four right-aligned cells.
    let fmt_row = |label: &str, cells: [&str; 4]| {
        let padded_cells = cells.map(|cell| format!("{cell:>column_width$}"));
        // 16: the longest step label (14), the colon, and a space.
        format!("{label:<16}{}", padded_cells.join("   "))
    };

    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    print_title(&outcomes[0]);
    println!("{:<14}: {}", "Measurements", outcomes.len());
    println!("{}", fmt_row("PROPERTY", column_headers));
    println!("{}", fmt_row("", [sub_header.as_str(); 4]));
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;

    for (step, abs_stats, rel_stats) in steps_to_stats {
        let label = step.name.label;
        let [_, rel_median, _, _] = rel_stats;
        let cells: [String; 4] =
            array::from_fn(|i| fmt_cell(&format_ms(abs_stats[i]), &format_ms(rel_stats[i])));
        let mut line = fmt_row(
            &format!("{label:<14}:"),
            cells.each_ref().map(String::as_str),
        );
        // The first lookup may miss the cache, so judge by the median.
        if step.name == DNS_LOOKUP_STEP && rel_median < DNS_CACHED_MS {
            line.push_str("  (probably cached)");
        }
        if step.name == TTFB_STEP {
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

/// Prints the JSON output of the measurements that started at `started_at`.
fn print_json(started_at: SystemTime, result: &Result<Vec<TtfbOutcome>, TtfbError>) {
    let output = json::JsonOutput::new(started_at, result);
    let json = to_string(&output).expect("should serialize, as all map keys are strings");
    println!("{json}");
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

/// Prints the timings of each step of a single measurement.
fn print_outcome(ttfb: &TtfbOutcome) -> Result<(), String> {
    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    print_title(ttfb);
    println!(
        "{:<16}{:>13}   {:>13}",
        "PROPERTY", "REL TIME (ms)", "ABS TIME (ms)"
    );
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;

    for step in Step::all(ttfb) {
        let label = step.name.label;
        let rel_ms = step.relative.as_secs_f64() * 1000.0;
        let abs_ms = step.absolute.as_secs_f64() * 1000.0;
        let mut line = format!(
            "{label:<14}: {:>13}   {:>13}",
            format_ms(rel_ms),
            format_ms(abs_ms)
        );
        if step.name == DNS_LOOKUP_STEP && rel_ms < DNS_CACHED_MS {
            line.push_str("  (probably cached)");
        }
        if step.name == TTFB_STEP {
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

/// The JSON output of the measurements.
///
/// Its only export is [`JsonOutput`], which [`JsonOutput::new`] creates from
/// the measurements or their error, and which serializes to the JSON format.
mod json {
    use super::{calc_statistics_from_durations, step_durations};
    use humantime::format_rfc3339_millis;
    use serde::{Serialize, Serializer};
    use serde_json::value::RawValue;
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use ttfb::{ProtocolSelection, TtfbError, TtfbOutcome};

    /// The version of the JSON output. It increases with incompatible changes.
    const JSON_SCHEMA_VERSION: u32 = 1;

    /// Serializes `ms` with the precision of the text output. Otherwise, JSON
    /// would show floating-point noise such as `0.011871999999999999`.
    fn serialize_ms<S: Serializer>(ms: &f64, serializer: S) -> Result<S::Ok, S::Error> {
        RawValue::from_string(format!("{ms:.3}"))
            .expect("should be a valid JSON number, as durations are finite")
            .serialize(serializer)
    }

    /// The statistics of a step in the JSON output, in ms.
    #[derive(Debug, Serialize)]
    struct JsonStatistics {
        #[serde(serialize_with = "serialize_ms")]
        min: f64,
        #[serde(serialize_with = "serialize_ms")]
        median: f64,
        #[serde(serialize_with = "serialize_ms")]
        mean: f64,
        #[serde(serialize_with = "serialize_ms")]
        max: f64,
    }

    impl JsonStatistics {
        /// Returns the statistics of `durations`.
        fn of(durations: &[Duration]) -> Self {
            let [min, median, mean, max] = calc_statistics_from_durations(durations);
            Self {
                min,
                median,
                mean,
                max,
            }
        }
    }

    /// The statistics of the relative and the absolute duration of a step.
    #[derive(Debug, Serialize)]
    struct JsonDurationStatistics {
        relative: JsonStatistics,
        absolute: JsonStatistics,
    }

    /// The statistics of each step by its key, in the order of the steps.
    #[derive(Debug)]
    struct JsonStepStatistics(Vec<(&'static str, JsonDurationStatistics)>);

    // A derive would emit a list of pairs and a map type would sort the
    // keys, but the JSON object should keep the order of the steps.
    impl Serialize for JsonStepStatistics {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_map(self.0.iter().map(|(key, statistics)| (key, statistics)))
        }
    }

    impl JsonStepStatistics {
        /// Returns the statistics of each step over all `outcomes`.
        fn from_outcomes(outcomes: &[TtfbOutcome]) -> Self {
            if outcomes.is_empty() {
                return Self(Vec::new());
            }
            let relative = step_durations(outcomes, |step| step.relative);
            let absolute = step_durations(outcomes, |step| step.absolute);
            let statistics = relative
                .into_iter()
                .zip(absolute)
                .map(|((step, relative), (_, absolute))| {
                    let statistics = JsonDurationStatistics {
                        relative: JsonStatistics::of(&relative),
                        absolute: JsonStatistics::of(&absolute),
                    };
                    (step.name.key, statistics)
                })
                .collect();
            Self(statistics)
        }
    }

    /// The target and the response of a measurement in the JSON output.
    #[derive(Debug, Serialize)]
    struct JsonResponse {
        url: String,
        ip: IpAddr,
        port: u16,
        protocol: String,
        /// Whether the protocol was selected automatically ("auto") or
        /// explicitly ("explicit").
        protocol_selection: &'static str,
        status: u16,
    }

    impl JsonResponse {
        /// Returns the response of `ttfb`.
        fn from_outcome(ttfb: &TtfbOutcome) -> Self {
            Self {
                url: ttfb.user_input().to_string(),
                ip: ttfb.ip_addr(),
                port: ttfb.port(),
                protocol: ttfb.protocol().to_string(),
                protocol_selection: match ttfb.protocol_selection() {
                    ProtocolSelection::Auto => "auto",
                    ProtocolSelection::Only(_) => "explicit",
                },
                status: ttfb.status().as_u16(),
            }
        }
    }

    /// The error of a failed measurement in the JSON output.
    #[derive(Debug, Serialize)]
    struct JsonError {
        /// The kind of the error, which scripts can rely on, e.g., "timeout".
        kind: &'static str,
        /// The error message for humans.
        message: String,
    }

    impl JsonError {
        /// Returns the JSON error of `error`.
        fn from_error(error: &TtfbError) -> Self {
            let kind = match error {
                TtfbError::InvalidUrl(_) => "invalid_url",
                TtfbError::InvalidTimeout(_) => "invalid_timeout",
                TtfbError::CantResolveDns(_) | TtfbError::CantConfigureDNSError(_) => "dns",
                TtfbError::NoAddressForIpVersion(_) => "no_address_for_ip_version",
                TtfbError::CantConnectTcp(_) => "tcp_connect",
                TtfbError::Tls(_) => "tls",
                TtfbError::CantConnectHttp(_)
                | TtfbError::NoHttpResponse
                | TtfbError::InvalidHttpResponse(_)
                | TtfbError::Http2(_)
                | TtfbError::Http3(_) => "http",
                TtfbError::OtherStreamError(_) => "io",
                TtfbError::UnsupportedHttpProtocol(_) => "unsupported_protocol",
                TtfbError::Timeout(_) => "timeout",
                _ => "other",
            };
            Self {
                kind,
                message: error.to_string(),
            }
        }
    }

    /// The JSON output of one or more measurements of the same target.
    #[derive(Debug, Serialize)]
    pub(super) struct JsonOutput {
        schema_version: u32,
        /// When the first measurement started, in RFC 3339 format in UTC.
        started_at: String,
        /// When the first measurement started, as Unix timestamp in ms.
        started_at_unix_ms: u128,
        /// The error, if a measurement failed. Then, there are no statistics
        /// and no response.
        error: Option<JsonError>,
        /// The number of measurements.
        measurements_num: usize,
        /// The statistics of each step over all measurements. Steps that
        /// didn't happen are missing.
        statistics_ms: JsonStepStatistics,
        /// The response of the first measurement.
        first_response: Option<JsonResponse>,
    }

    impl JsonOutput {
        /// Creates the output of the measurements that started at
        /// `started_at`: either all of them or the error of the one that
        /// failed.
        pub(super) fn new(
            started_at: SystemTime,
            result: &Result<Vec<TtfbOutcome>, TtfbError>,
        ) -> Self {
            let (outcomes, error) = match result {
                Ok(outcomes) => (outcomes.as_slice(), None),
                Err(error) => (&[][..], Some(JsonError::from_error(error))),
            };
            Self {
                schema_version: JSON_SCHEMA_VERSION,
                started_at: format_rfc3339_millis(started_at).to_string(),
                started_at_unix_ms: started_at
                    .duration_since(UNIX_EPOCH)
                    .expect("system time should be after the Unix epoch")
                    .as_millis(),
                error,
                measurements_num: outcomes.len(),
                statistics_ms: JsonStepStatistics::from_outcomes(outcomes),
                first_response: outcomes.first().map(JsonResponse::from_outcome),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::{to_string, to_string_pretty};

        #[test]
        fn json_step_statistics_keep_the_order_of_the_steps() {
            let statistics = |ms| JsonStatistics {
                min: ms,
                median: ms,
                mean: ms,
                max: ms,
            };
            let step = |relative, absolute| JsonDurationStatistics {
                relative: statistics(relative),
                absolute: statistics(absolute),
            };
            let steps = JsonStepStatistics(vec![
                ("ttfb", step(2.0, 5.0)),
                ("http_content_download", step(7.0, 7.0)),
            ]);
            let expected = r#"{
  "ttfb": {
    "relative": {
      "min": 2.000,
      "median": 2.000,
      "mean": 2.000,
      "max": 2.000
    },
    "absolute": {
      "min": 5.000,
      "median": 5.000,
      "mean": 5.000,
      "max": 5.000
    }
  },
  "http_content_download": {
    "relative": {
      "min": 7.000,
      "median": 7.000,
      "mean": 7.000,
      "max": 7.000
    },
    "absolute": {
      "min": 7.000,
      "median": 7.000,
      "mean": 7.000,
      "max": 7.000
    }
  }
}"#;
            assert_eq!(to_string_pretty(&steps).unwrap(), expected);
        }

        #[test]
        fn json_output_of_an_error() {
            let output = JsonOutput::new(UNIX_EPOCH, &Err(TtfbError::NoHttpResponse));
            let expected = concat!(
                r#"{"schema_version":1,"started_at":"1970-01-01T00:00:00.000Z","#,
                r#""started_at_unix_ms":0,"#,
                r#""error":{"kind":"http","#,
                r#""message":"Didn't receive any data. Is the host running a HTTP server?"},"#,
                r#""measurements_num":0,"statistics_ms":{},"first_response":null}"#,
            );
            assert_eq!(to_string(&output).unwrap(), expected);
        }
    }
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
    fn format_ms_shows_short_durations_as_less_than_0_1() {
        assert_eq!(format_ms(0.0), "<0.1");
        assert_eq!(format_ms(0.049), "<0.1");
        assert_eq!(format_ms(0.05), "0.1");
        assert_eq!(format_ms(12.34), "12.3");
    }

    #[test]
    fn statistics_odd_count() {
        let durations = [3, 1, 8].map(Duration::from_millis);
        assert_eq!(
            calc_statistics_from_durations(&durations),
            [1.0, 3.0, 4.0, 8.0]
        );
    }

    #[test]
    fn statistics_even_count() {
        let durations = [4, 1, 2, 9].map(Duration::from_millis);
        assert_eq!(
            calc_statistics_from_durations(&durations),
            [1.0, 3.0, 4.0, 9.0]
        );
    }
}
