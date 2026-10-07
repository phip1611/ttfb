// SPDX-License-Identifier: MIT

//! HTTP/2 measurements over TLS.

use crate::outcome::{Connect, ResponseHead, TtfbTimings};
use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, ZeroRtt, build_http_request, tls};
use h2::client::Builder;
use rustls::{ClientConfig, ClientConnection};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

/// The flow-control windows that Chrome uses for a stream and for the whole
/// connection. h2's defaults of 65,535 bytes each would limit downloads to
/// that amount per round trip, which inflates the download duration of
/// larger bodies.
const STREAM_WINDOW_SIZE: u32 = 6 * 1024 * 1024;
const CONNECTION_WINDOW_SIZE: u32 = 15 * 1024 * 1024;

fn http2_error(error: h2::Error) -> TtfbError {
    TtfbError::Http2(error.to_string())
}

fn http2_not_negotiated() -> TtfbError {
    TtfbError::UnsupportedHttpProtocol("server did not negotiate HTTP/2 via ALPN".into())
}

/// Performs the TLS handshake and checks that the server selected HTTP/2.
///
/// The client offers `h2` via ALPN (Application-Layer Protocol Negotiation),
/// the TLS extension through which client and server agree on the application
/// protocol during the handshake. It also offers `http/1.1`, so that servers
/// without HTTP/2 complete the handshake instead of failing it. This reports
/// them as not supporting HTTP/2, which lets the client fall back to
/// HTTP/1.1.
///
/// With `early_data`, this returns before the handshake if the resumed session
/// permits early data. The first writes then go out as early data, and the
/// handshake completes when they are flushed. The protocol is only known then.
async fn connect_tls(
    tcp: TcpStream,
    url: &Url,
    tls_config: Arc<ClientConfig>,
    early_data: bool,
) -> Result<TlsStream<TcpStream>, TtfbError> {
    let tls = TlsConnector::from(tls_config)
        .early_data(early_data)
        .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .connect(tls::server_name(url)?, tcp)
        .await
        .map_err(|error| TtfbError::Tls(error.to_string()))?;
    let session = tls.get_ref().1;
    if !session.is_handshaking() && session.alpn_protocol() != Some(b"h2") {
        return Err(http2_not_negotiated());
    }
    Ok(tls)
}

/// The end of a TLS handshake.
#[derive(Clone, Copy, Debug)]
struct HandshakeEnd {
    instant: Instant,
    early_data_accepted: bool,
    http2_negotiated: bool,
}

impl HandshakeEnd {
    /// Returns the end of the handshake of `session`, if it is complete.
    fn of(session: &ClientConnection) -> Option<Self> {
        (!session.is_handshaking()).then(|| Self {
            instant: Instant::now(),
            early_data_accepted: session.is_early_data_accepted(),
            http2_negotiated: session.alpn_protocol() == Some(b"h2"),
        })
    }
}

/// A TLS stream that records the end of its handshake. With early data, the
/// handshake completes in the background, during the HTTP/2 exchange.
struct ObservedTls {
    tls: TlsStream<TcpStream>,
    handshake_end: Arc<OnceLock<HandshakeEnd>>,
}

impl ObservedTls {
    fn new(tls: TlsStream<TcpStream>, handshake_end: Arc<OnceLock<HandshakeEnd>>) -> Self {
        let tls = Self { tls, handshake_end };
        tls.observe();
        tls
    }

    /// Records the end of the handshake once it is complete.
    fn observe(&self) {
        if self.handshake_end.get().is_none() {
            if let Some(end) = HandshakeEnd::of(self.tls.get_ref().1) {
                let _ = self.handshake_end.set(end);
            }
        }
    }
}

impl AsyncRead for ObservedTls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.tls).poll_read(context, buffer);
        self.observe();
        result
    }
}

impl AsyncWrite for ObservedTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.tls).poll_write(context, buffer);
        self.observe();
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.tls).poll_flush(context);
        self.observe();
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls).poll_shutdown(context)
    }
}

/// Reads the complete response body.
///
/// HTTP/2 flow control limits how much data the server may send before the
/// client confirms that it consumed it. Hence, every received chunk must
/// release its capacity, otherwise the server stops sending once the window
/// is used up.
async fn download_body(mut body: h2::RecvStream) -> Result<(), TtfbError> {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(http2_error)?;
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(http2_error)?;
    }
    Ok(())
}

/// Measures one GET request via HTTP/2: TCP connect, the TLS handshake with
/// ALPN, sending the request, receiving the response headers, and the download
/// of the body.
///
/// Sending covers writing the HTTP/2 connection preface and queuing the
/// request. h2 writes the queued frames in the background, so the TTFB
/// includes their transmission.
///
/// HTTP/2 is only supported over TLS (`https://`). With `early_data`, the
/// connection preface and the request are sent as TLS 1.3 early data if the
/// resumed TLS session permits it. If the server rejects the early data,
/// tokio-rustls sends them again after the handshake.
pub async fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
    early_data: bool,
) -> Result<TtfbOutcome, TtfbError> {
    if target.url.scheme() != "https" {
        return Err(TtfbError::UnsupportedHttpProtocol(
            "HTTP/2 requires an HTTPS URL".into(),
        ));
    }

    // Connect, with a TLS handshake that negotiates HTTP/2.
    let (tcp, tcp_duration) = {
        let begin = Instant::now();
        let tcp = TcpStream::connect((target.address, target.port))
            .await
            .map_err(TtfbError::CantConnectTcp)?;
        (tcp, begin.elapsed())
    };
    let tls_begin = Instant::now();
    let tls = connect_tls(tcp, &target.url, tls_config, early_data).await?;
    let handshake_end = Arc::new(OnceLock::new());
    let tls = ObservedTls::new(tls, Arc::clone(&handshake_end));
    let sent_early = handshake_end.get().is_none();

    // Send the request after the HTTP/2 connection preface.
    let (response, send_begin) = {
        let request = build_http_request(&target.url)?;
        let begin = Instant::now();
        let (mut sender, connection) = Builder::new()
            .initial_window_size(STREAM_WINDOW_SIZE)
            .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
            // The request has no body, so any body buffer type works.
            .handshake::<_, &[u8]>(tls)
            .await
            .map_err(http2_error)?;
        // The connection future drives the HTTP/2 protocol in the background.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let (response, _) = sender.send_request(request, true).map_err(http2_error)?;
        (response, begin)
    };
    let send_end = Instant::now();

    // Wait for the response headers.
    let response = response.await.map_err(http2_error)?;
    let first_byte = Instant::now();

    // The handshake is complete, as the response arrived through it.
    let handshake_end = *handshake_end
        .get()
        .expect("the handshake should be complete once the response arrived");
    if !handshake_end.http2_negotiated {
        return Err(http2_not_negotiated());
    }
    let zero_rtt = early_data.then_some(match (sent_early, handshake_end.early_data_accepted) {
        (false, _) => ZeroRtt::Unavailable,
        (true, true) => ZeroRtt::Accepted,
        (true, false) => ZeroRtt::Rejected,
    });
    // Without early data, the handshake ends before sending. With early data,
    // sending ends before the handshake; it takes no time of its own then, and
    // the TTFB starts at the end of the handshake.
    let tls_duration = handshake_end.instant.duration_since(tls_begin);
    let send_duration = send_end.saturating_duration_since(send_begin.max(handshake_end.instant));
    let ttfb_duration = first_byte.saturating_duration_since(send_end.max(handshake_end.instant));

    let (head, body) = response.into_parts();

    // Download the body.
    let download_duration = {
        let begin = Instant::now();
        download_body(body).await?;
        begin.elapsed()
    };

    Ok(TtfbOutcome::new(
        target.input.clone(),
        target.address,
        target.port,
        TtfbTimings {
            dns_lookup: target.dns_duration,
            connect: Connect::Tcp {
                connect: tcp_duration,
                tls: Some(tls_duration),
            },
            http_get_send: send_duration,
            http_ttfb: ttfb_duration,
            http_content_download: download_duration,
        },
        HttpProtocol::Http2,
        ResponseHead {
            status: head.status,
            headers: head.headers,
        },
        zero_rtt,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpVersion;
    use crate::deadline::Deadline;
    use crate::run_in_tokio;

    #[test]
    fn requires_https() {
        let target =
            Target::resolve("http://localhost:1", IpVersion::Any, Deadline::for_tests()).unwrap();
        let result = run_in_tokio(measure(&target, tls::config(false, false), false));
        assert!(matches!(result, Err(TtfbError::UnsupportedHttpProtocol(_))));
    }
}

#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;
    use crate::deadline::Deadline;
    use crate::{IpVersion, http11, run_in_tokio};

    /// A server accepts early data only for the protocol that the resumed
    /// session negotiated via ALPN [0]. After an HTTP/1.1 warm-up without
    /// ALPN, servers therefore reject the HTTP/2 early data.
    ///
    /// [0]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10
    #[test]
    fn rejected_early_data_is_sent_again() {
        let deadline = Deadline::for_tests();
        let target = Target::resolve("https://www.google.com", IpVersion::Any, deadline).unwrap();
        let tls_config = tls::config(false, true);
        http11::measure(&target, Arc::clone(&tls_config), deadline, false).unwrap();
        let outcome = run_in_tokio(measure(&target, tls_config, true)).unwrap();
        assert_eq!(outcome.zero_rtt(), Some(ZeroRtt::Rejected));
        assert!(outcome.status().is_success());
    }
}
