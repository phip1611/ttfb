// SPDX-License-Identifier: MIT

//! Module for [`TtfbOutcome`].

use crate::ProtocolSelection;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;

/// The HTTP protocol used for the measurement.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpProtocol {
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    Http2,
}

impl Display for HttpProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
        };
        f.write_str(name)
    }
}

/// Bundles the duration of a measurement step with the total duration since
/// the beginning of the overall measurement.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DurationPair {
    rel: Duration,
    total: Duration,
}

impl DurationPair {
    #[allow(clippy::missing_const_for_fn)] // MSRV blocker
    fn new(duration_step: Duration, absolute_duration_so_far: Duration) -> Self {
        Self {
            rel: duration_step,
            total: absolute_duration_so_far + duration_step,
        }
    }

    /// Returns the duration of that step.
    #[must_use]
    pub const fn relative(&self) -> Duration {
        self.rel
    }

    /// Returns the total duration between the start of the measurement
    /// and the end of this measurement step.
    #[must_use]
    pub const fn total(&self) -> Duration {
        self.total
    }
}

/// The relative durations of the measurement steps, i.e., how long each step
/// itself took.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TtfbTimings {
    /// The DNS lookup, if one was necessary.
    pub dns_lookup: Option<Duration>,
    /// The establishment of the TCP connection.
    pub tcp_connect: Duration,
    /// The TLS handshake, if TLS is used.
    pub tls_handshake: Option<Duration>,
    /// Sending the HTTP GET request.
    pub http_get_send: Duration,
    /// Waiting for the first byte of the response.
    pub http_ttfb: Duration,
    /// Receiving the rest of the response.
    pub http_content_download: Duration,
}

/// The final result of this library. It contains all the measured timings.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TtfbOutcome {
    /// Copy of the user input.
    user_input: String,
    /// The used IP address (resolved by DNS).
    ip_addr: IpAddr,
    /// The port.
    port: u16,
    /// The relative durations of the measurement steps.
    timings: TtfbTimings,
    /// The protocol used for the request.
    protocol: HttpProtocol,
    /// How the protocol was selected.
    protocol_selection: ProtocolSelection,
}

impl TtfbOutcome {
    pub(crate) const fn new(
        user_input: String,
        ip_addr: IpAddr,
        port: u16,
        timings: TtfbTimings,
        protocol: HttpProtocol,
    ) -> Self {
        Self {
            user_input,
            ip_addr,
            port,
            timings,
            protocol,
            protocol_selection: ProtocolSelection::Only(protocol),
        }
    }

    /// Getter for the provided user input (Host or IP address).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // MSRV blocker
    pub fn user_input(&self) -> &str {
        &self.user_input
    }

    /// Getter for `ip_addr` that was used.
    #[must_use]
    pub const fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    /// Getter for `port` that was used.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the [`DurationPair`] for the DNS step, if DNS lookup was necessary.
    #[must_use]
    pub fn dns_lookup_duration(&self) -> Option<DurationPair> {
        self.timings
            .dns_lookup
            .map(|d| DurationPair::new(d, Duration::default()))
    }

    /// Returns the [`DurationPair`] for the establishment of the TCP connection.
    #[must_use]
    pub fn tcp_connect_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.dns_lookup_duration().unwrap_or_default().total();
        DurationPair::new(self.timings.tcp_connect, abs_dur_so_far)
    }

    /// Returns the [`DurationPair`] for the TLS handshake, if the TLS handshake was necessary.
    #[must_use]
    pub fn tls_handshake_duration(&self) -> Option<DurationPair> {
        self.timings.tls_handshake.map(|dur| {
            let abs_dur_so_far = self.tcp_connect_duration().total();
            DurationPair::new(dur, abs_dur_so_far)
        })
    }

    /// Returns the [`DurationPair`] for the transmission of the HTTP GET request.
    #[must_use]
    pub fn http_get_send_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.tls_handshake_duration().unwrap_or_default().total();
        DurationPair::new(self.timings.http_get_send, abs_dur_so_far)
    }

    /// Returns the [`DurationPair`] for the time to first byte (TTFB) of the HTTP response.
    #[must_use]
    pub fn ttfb_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.http_get_send_duration().total();
        DurationPair::new(self.timings.http_ttfb, abs_dur_so_far)
    }

    /// Returns the time from the first response byte until the complete response message.
    #[must_use]
    pub fn http_content_download_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.ttfb_duration().total();
        DurationPair::new(self.timings.http_content_download, abs_dur_so_far)
    }

    /// Returns the HTTP protocol used for the request.
    #[must_use]
    pub const fn protocol(&self) -> HttpProtocol {
        self.protocol
    }

    /// Returns how the protocol was selected: automatically or explicitly.
    #[must_use]
    pub const fn protocol_selection(&self) -> ProtocolSelection {
        self.protocol_selection
    }

    /// Records how the protocol was selected, which only the client knows.
    pub(crate) const fn with_protocol_selection(mut self, selection: ProtocolSelection) -> Self {
        self.protocol_selection = selection;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::outcome::{HttpProtocol, TtfbOutcome, TtfbTimings};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn outcome_durations_are_sane() {
        let outcome = TtfbOutcome::new(
            "https://phip1611.de".to_string(),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            443,
            TtfbTimings {
                dns_lookup: Some(Duration::from_millis(1)),
                tcp_connect: Duration::from_millis(2),
                tls_handshake: Some(Duration::from_millis(3)),
                http_get_send: Duration::from_millis(4),
                http_ttfb: Duration::from_millis(5),
                http_content_download: Duration::from_millis(6),
            },
            HttpProtocol::Http11,
        );
        assert_eq!(
            outcome.dns_lookup_duration().unwrap().total().as_millis(),
            1,
            "DNS is the very first operation"
        );
        assert_eq!(
            outcome.tcp_connect_duration().total().as_millis(),
            1 + 2,
            "DNS + TCP connect"
        );
        println!("{outcome:#?}");
        assert_eq!(
            outcome
                .tls_handshake_duration()
                .unwrap()
                .total()
                .as_millis(),
            1 + 2 + 3,
            "DNS + TCP connect + TLS handshake"
        );
        assert_eq!(
            outcome.http_get_send_duration().total().as_millis(),
            1 + 2 + 3 + 4,
            "DNS + TCP connect + TLS handshake + HTTP GET send"
        );
        assert_eq!(
            outcome.ttfb_duration().total().as_millis(),
            1 + 2 + 3 + 4 + 5,
            "Total TTFB: DNS + TCP connect + TLS handshake + HTTP GET send + relative TTFB"
        );
        assert_eq!(
            outcome.http_content_download_duration().total().as_millis(),
            1 + 2 + 3 + 4 + 5 + 6,
            "Total response completion time"
        );
    }
}
