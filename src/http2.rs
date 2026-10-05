// SPDX-License-Identifier: MIT

//! HTTP/2 measurements over TLS.

use crate::target::Target;
use crate::{CRATE_VERSION, HttpProtocol, TtfbError, TtfbOutcome, ZeroRttStatus, tls};
use http::header::{ACCEPT, ACCEPT_ENCODING, USER_AGENT};
use rustls::ClientConfig;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
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

/// Performs the TLS handshake and checks that the server selected HTTP/2.
///
/// The client offers `h2` via ALPN (Application-Layer Protocol Negotiation),
/// the TLS extension through which client and server agree on the application
/// protocol during the handshake. With `early_data`, the handshake may still
/// be in progress when this returns; the protocol is then checked once the
/// handshake completes.
async fn connect_tls(
    tcp: TcpStream,
    url: &Url,
    tls_config: Arc<ClientConfig>,
    early_data: bool,
) -> Result<TlsStream<TcpStream>, TtfbError> {
    let tls = TlsConnector::from(tls_config)
        .early_data(early_data)
        .with_alpn(vec![b"h2".to_vec()])
        .connect(tls::server_name(url)?, tcp)
        .await
        .map_err(|error| TtfbError::Tls(error.to_string()))?;
    let session = tls.get_ref().1;
    if !session.is_handshaking() && session.alpn_protocol() != Some(b"h2") {
        return Err(TtfbError::UnsupportedHttpProtocol(
            "server did not negotiate HTTP/2 via ALPN".into(),
        ));
    }
    Ok(tls)
}

/// Builds the GET request. h2 derives the `:scheme`, `:authority`, and `:path`
/// pseudo-header fields from the absolute URI, which excludes the fragment.
fn build_request(url: &Url) -> Result<http::Request<()>, TtfbError> {
    http::Request::get(&url[..url::Position::AfterQuery])
        .header(USER_AGENT, format!("ttfb/{CRATE_VERSION}"))
        .header(ACCEPT, "*/*")
        .header(ACCEPT_ENCODING, "gzip, deflate, br, zstd")
        .body(())
        .map_err(|error| TtfbError::Http2(error.to_string()))
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

/// What [`ObservedTls`] learns about a TLS handshake that completes in the
/// background.
#[derive(Debug)]
struct HandshakeObservation {
    accepted: Option<bool>,
    h2_negotiated: Option<bool>,
    duration: Option<Duration>,
    started: Instant,
}

/// A TLS stream that records when its handshake completes, whether the server
/// accepted the early data, and whether ALPN selected HTTP/2.
struct ObservedTls<T> {
    inner: TlsStream<T>,
    observation: Arc<Mutex<HandshakeObservation>>,
}

impl<T> ObservedTls<T> {
    const fn new(inner: TlsStream<T>, observation: Arc<Mutex<HandshakeObservation>>) -> Self {
        Self { inner, observation }
    }

    fn observe_handshake(&self) {
        let session = self.inner.get_ref().1;
        if !session.is_handshaking() {
            let mut observation = self
                .observation
                .lock()
                .expect("the observation lock should not be poisoned");
            if observation.duration.is_none() {
                observation.duration = Some(observation.started.elapsed());
            }
            observation
                .accepted
                .get_or_insert_with(|| session.is_early_data_accepted());
            observation
                .h2_negotiated
                .get_or_insert_with(|| session.alpn_protocol() == Some(b"h2"));
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for ObservedTls<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        self.observe_handshake();
        result
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ObservedTls<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        self.observe_handshake();
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(context);
        self.observe_handshake();
        result
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Measures one GET request via HTTP/2: TCP connect, the TLS handshake with
/// ALPN, sending the request, receiving the response headers, and the download
/// of the body.
///
/// Sending covers writing the HTTP/2 connection preface and queuing the
/// request. h2 writes the queued frames in the background, so the TTFB
/// includes their transmission.
///
/// HTTP/2 is only supported over TLS (`https://`). With `try_zero_rtt`, the
/// connection preface and the request are sent as TLS 1.3 early data if the
/// resumed session permits it.
pub async fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
    try_zero_rtt: bool,
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
    let mut tls = connect_tls(tcp, &target.url, tls_config, try_zero_rtt).await?;
    let tls_duration = tls_begin.elapsed();

    // With early data, the handshake continues in the background while the
    // HTTP/2 exchange starts.
    let attempted = try_zero_rtt && tls.get_mut().1.early_data().is_some();
    let observation = Arc::new(Mutex::new(HandshakeObservation {
        accepted: None,
        h2_negotiated: None,
        duration: (!tls.get_ref().1.is_handshaking()).then_some(tls_duration),
        started: tls_begin,
    }));
    let tls = ObservedTls::new(tls, Arc::clone(&observation));

    // Send the request after the HTTP/2 connection preface.
    let (response, send_duration) = {
        let request = build_request(&target.url)?;
        let begin = Instant::now();
        let (mut sender, connection) = h2::client::Builder::new()
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
        (response, begin.elapsed())
    };
    let zero_rtt_duration = attempted.then_some(tls_begin.elapsed());

    // Wait for the response headers.
    let ttfb_begin = Instant::now();
    let response = response.await.map_err(http2_error)?;
    let ttfb_end = Instant::now();

    // Download the body.
    let download_duration = {
        download_body(response.into_body()).await?;
        ttfb_end.elapsed()
    };

    // Evaluate the handshake, which may have completed only during the
    // exchange.
    let (tls_duration, zero_rtt_status) = {
        let observation = observation
            .lock()
            .expect("the observation lock should not be poisoned");
        if observation.h2_negotiated != Some(true) {
            return Err(TtfbError::UnsupportedHttpProtocol(
                "server did not negotiate HTTP/2 via ALPN".into(),
            ));
        }
        let status = try_zero_rtt.then_some(match (attempted, observation.accepted) {
            (false, _) => ZeroRttStatus::Unavailable,
            (true, Some(true)) => ZeroRttStatus::Accepted,
            (true, _) => ZeroRttStatus::Replayed,
        });
        (observation.duration.unwrap_or(tls_duration), status)
    };

    // tokio-rustls replays rejected early data once the handshake has completed,
    // so the request only waits for its response from that moment on.
    let ttfb_duration = if zero_rtt_status == Some(ZeroRttStatus::Replayed) {
        ttfb_end.saturating_duration_since(tls_begin + tls_duration)
    } else {
        ttfb_end.duration_since(ttfb_begin)
    };

    Ok(TtfbOutcome::new(
        target.input.clone(),
        target.address,
        target.port,
        target.dns_duration,
        tcp_duration,
        Some(tls_duration),
        send_duration,
        ttfb_duration,
        download_duration,
        HttpProtocol::Http2,
        zero_rtt_duration,
        zero_rtt_status,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_in_tokio;

    #[test]
    fn requires_https() {
        let target = Target::resolve("http://localhost:1").unwrap();
        let result = run_in_tokio(measure(&target, tls::config(false, false), false));
        assert!(matches!(result, Err(TtfbError::UnsupportedHttpProtocol(_))));
    }
}
