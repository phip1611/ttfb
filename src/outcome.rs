/*
MIT License

Copyright (c) 2024 Philipp Schuster

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
//! Module for [`TtfbOutcome`].

use std::net::IpAddr;
use std::time::Duration;

/// Bundles the duration of a measurement step with the total duration since
/// the beginning of the overall measurement.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DurationPair {
    rel: Duration,
    total: Duration,
}

impl DurationPair {
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
    // http_content_download_duration: Duration,
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
        // http_content_download_duration: Duration,
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
            // http_content_download_duration,
        }
    }

    /// Getter for the provided user input (Host or IP address).
    #[must_use]
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
    #[must_use]
    pub fn http_get_send_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.tls_handshake_duration().unwrap_or_default().total();
        DurationPair::new(self.http_get_send_duration_rel, abs_dur_so_far)
    }

    /// Returns the [`DurationPair`] for the time to first byte (TTFB) of the HTTP response.
    #[must_use]
    pub fn ttfb_duration(&self) -> DurationPair {
        let abs_dur_so_far = self.http_get_send_duration().total();
        DurationPair::new(self.http_ttfb_duration_rel, abs_dur_so_far)
    }
}

#[cfg(test)]
mod tests {
    use crate::outcome::TtfbOutcome;
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
    }
}
