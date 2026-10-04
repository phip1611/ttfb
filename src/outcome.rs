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

/// Whether TLS 1.3 early data was used for a measurement.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ZeroRttStatus {
    /// The warm-up did not produce a session that permits early data.
    Unavailable,
    /// Early data was sent and accepted by the server.
    Accepted,
    /// Early data was sent, rejected, and the request was replayed.
    Replayed,
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

/// The final result of this library. It contains all the measured timings.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TtfbOutcome {
    /// Copy of the user input.
    user_input: String,
    /// The used IP address (resolved by DNS).
    ip_addr: IpAddr,
    /// The port.
    port: u16,
    /// If DNS was required, the relative duration of this operation.
    dns_duration_rel: Option<Duration>,
    /// Relative duration of the TCP connection start.
    tcp_connect_duration_rel: Duration,
    /// If https is used, the relative duration of the TLS handshake.
    tls_handshake_duration_rel: Option<Duration>,
    /// The relative duration of the HTTP GET request sending.
    http_get_send_duration_rel: Duration,
    /// The relative duration until the first byte from the HTTP response (the header) was
    /// received.
    http_ttfb_duration_rel: Duration,
    /// The relative duration from the first response byte until the complete response.
    http_content_download_duration_rel: Duration,
    /// The protocol used for the request.
    protocol: HttpProtocol,
    /// How the protocol was selected.
    protocol_selection: ProtocolSelection,
    /// Time from TCP connect completion until the early request was sent.
    zero_rtt_duration_rel: Option<Duration>,
    /// The outcome of a TLS 1.3 early-data attempt.
    zero_rtt_status: Option<ZeroRttStatus>,
}

impl TtfbOutcome {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        user_input: String,
        ip_addr: IpAddr,
        port: u16,
        dns_duration_rel: Option<Duration>,
        tcp_connect_duration_rel: Duration,
        tls_handshake_duration_rel: Option<Duration>,
        http_get_send_duration_rel: Duration,
        http_ttfb_duration_rel: Duration,
        http_content_download_duration_rel: Duration,
        protocol: HttpProtocol,
        zero_rtt_duration_rel: Option<Duration>,
        zero_rtt_status: Option<ZeroRttStatus>,
    ) -> Self {
        Self {
            user_input,
            ip_addr,
            port,
            dns_duration_rel,
            tcp_connect_duration_rel,
            tls_handshake_duration_rel,
            http_get_send_duration_rel,
            http_ttfb_duration_rel,
            http_content_download_duration_rel,
            protocol,
            protocol_selection: ProtocolSelection::Only(protocol),
            zero_rtt_duration_rel,
            zero_rtt_status,
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
        self.dns_duration_rel
            .map(|d| DurationPair::new(d, Duration::default()))
    }

    /// Returns the [`DurationPair`] for the establishment of the TCP connection.
    #[must_use]
    pub fn tcp_connect_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.dns_lookup_duration().unwrap_or_default().total();
        DurationPair::new(self.tcp_connect_duration_rel, abs_dur_so_far)
    }

    /// Returns the [`DurationPair`] for the TLS handshake, if the TLS handshake was necessary.
    #[must_use]
    pub fn tls_handshake_duration(&self) -> Option<DurationPair> {
        self.tls_handshake_duration_rel.map(|dur| {
            let abs_dur_so_far = self.tcp_connect_duration().total();
            DurationPair::new(dur, abs_dur_so_far)
        })
    }

    /// Returns the [`DurationPair`] for the transmission of the HTTP GET request.
    ///
    /// If the server accepted the request as TLS 1.3 early data, it was sent
    /// during the TLS handshake. Its absolute time then lies before the end of
    /// the handshake.
    #[must_use]
    pub fn http_get_send_duration(&self) -> DurationPair {
        if self.zero_rtt_status == Some(ZeroRttStatus::Accepted) {
            if let Some(zero_rtt) = self.zero_rtt_duration() {
                return DurationPair {
                    rel: self.http_get_send_duration_rel,
                    total: zero_rtt.total(),
                };
            }
        }
        let abs_dur_so_far = self.tls_handshake_duration().unwrap_or_default().total();
        DurationPair::new(self.http_get_send_duration_rel, abs_dur_so_far)
    }

    /// Returns the [`DurationPair`] for the time to first byte (TTFB) of the HTTP response.
    ///
    /// If the server accepted the request as TLS 1.3 early data, the TTFB starts
    /// when the request was sent and includes the rest of the TLS handshake.
    #[must_use]
    pub fn ttfb_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.http_get_send_duration().total();
        DurationPair::new(self.http_ttfb_duration_rel, abs_dur_so_far)
    }

    /// Returns the time from the first response byte until the complete response message.
    #[must_use]
    pub fn http_content_download_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.ttfb_duration().total();
        DurationPair::new(self.http_content_download_duration_rel, abs_dur_so_far)
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

    /// Returns the time from TCP connection completion until the request was
    /// sent as early data.
    ///
    /// This duration overlaps the TLS handshake and is therefore not part of the normal
    /// sequential timing chain.
    #[must_use]
    pub fn zero_rtt_duration(&self) -> Option<DurationPair> {
        self.zero_rtt_duration_rel
            .map(|duration| DurationPair::new(duration, self.tcp_connect_duration().total()))
    }

    /// Returns the result of the TLS 1.3 early-data attempt.
    #[must_use]
    pub const fn zero_rtt_status(&self) -> Option<ZeroRttStatus> {
        self.zero_rtt_status
    }
}

#[cfg(test)]
mod tests {
    use crate::outcome::{HttpProtocol, TtfbOutcome, ZeroRttStatus};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn outcome_durations_are_sane() {
        let outcome = TtfbOutcome::new(
            "https://phip1611.de".to_string(),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            443,
            Some(Duration::from_millis(1)),
            Duration::from_millis(2),
            Some(Duration::from_millis(3)),
            Duration::from_millis(4),
            Duration::from_millis(5),
            Duration::from_millis(6),
            HttpProtocol::Http11,
            None,
            None,
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

    #[test]
    fn accepted_zero_rtt_request_overlaps_tls_handshake() {
        let outcome = TtfbOutcome::new(
            "https://phip1611.de".to_string(),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            443,
            Some(Duration::from_millis(1)),
            Duration::from_millis(2),
            Some(Duration::from_millis(30)),
            Duration::from_millis(4),
            Duration::from_millis(5),
            Duration::from_millis(6),
            HttpProtocol::Http11,
            Some(Duration::from_millis(7)),
            Some(ZeroRttStatus::Accepted),
        );
        assert_eq!(
            outcome.http_get_send_duration().total().as_millis(),
            1 + 2 + 7,
            "DNS + TCP connect + early request; the TLS handshake overlaps"
        );
        assert_eq!(
            outcome.ttfb_duration().total().as_millis(),
            1 + 2 + 7 + 5,
            "Total TTFB continues after the early request"
        );
    }
}
