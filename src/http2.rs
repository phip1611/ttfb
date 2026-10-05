// SPDX-License-Identifier: MIT

//! HTTP/2 measurements over TLS.

use crate::target::Target;
use crate::{CRATE_VERSION, HttpProtocol, TtfbError, TtfbOutcome, tls};
use http::header::{ACCEPT, ACCEPT_ENCODING, USER_AGENT};
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

fn http2_error(error: h2::Error) -> TtfbError {
    TtfbError::Http2(error.to_string())
}

/// Performs the TLS handshake and checks that the server selected HTTP/2.
///
/// The client offers `h2` via ALPN (Application-Layer Protocol Negotiation),
/// the TLS extension through which client and server agree on the application
/// protocol during the handshake.
async fn connect_tls(
    tcp: TcpStream,
    url: &Url,
    tls_config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>, TtfbError> {
    let tls = TlsConnector::from(tls_config)
        .with_alpn(vec![b"h2".to_vec()])
        .connect(tls::server_name(url)?, tcp)
        .await
        .map_err(|error| TtfbError::Tls(error.to_string()))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
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

/// Measures one GET request via HTTP/2: TCP connect, the TLS handshake with
/// ALPN, sending the request, receiving the response headers, and the download
/// of the body.
///
/// Sending covers writing the HTTP/2 connection preface and queuing the
/// request. h2 writes the queued frames in the background, so the TTFB
/// includes their transmission.
///
/// HTTP/2 is only supported over TLS (`https://`).
pub async fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
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
    let (tls, tls_duration) = {
        let begin = Instant::now();
        let tls = connect_tls(tcp, &target.url, tls_config).await?;
        (tls, begin.elapsed())
    };

    // Send the request after the HTTP/2 connection preface.
    let (response, send_duration) = {
        let request = build_request(&target.url)?;
        let begin = Instant::now();
        let (mut sender, connection) = h2::client::handshake(tls).await.map_err(http2_error)?;
        // The connection future drives the HTTP/2 protocol in the background.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let (response, _) = sender.send_request(request, true).map_err(http2_error)?;
        (response, begin.elapsed())
    };

    // Wait for the response headers.
    let (response, ttfb_duration) = {
        let begin = Instant::now();
        let response = response.await.map_err(http2_error)?;
        (response, begin.elapsed())
    };

    // Download the body.
    let download_duration = {
        let begin = Instant::now();
        download_body(response.into_body()).await?;
        begin.elapsed()
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
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_in_tokio;

    #[test]
    fn requires_https() {
        let target = Target::resolve("http://localhost:1").unwrap();
        let result = run_in_tokio(measure(&target, tls::config(false)));
        assert!(matches!(result, Err(TtfbError::UnsupportedHttpProtocol(_))));
    }
}
