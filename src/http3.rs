// SPDX-License-Identifier: MIT

//! HTTP/3 measurements over QUIC.

use crate::outcome::{Connect, TtfbTimings};
use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, build_http_request, tls};
use rustls::ClientConfig;
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

fn http3_error(error: impl Display) -> TtfbError {
    TtfbError::Http3(error.to_string())
}

fn unavailable(error: impl Display) -> TtfbError {
    TtfbError::UnsupportedHttpProtocol(format!("HTTP/3 unavailable: {error}"))
}

/// Creates the local QUIC endpoint, which uses the TLS configuration with
/// ALPN `h3`.
fn create_endpoint(
    target: &Target,
    tls_config: &ClientConfig,
) -> Result<quinn::Endpoint, TtfbError> {
    let mut crypto = tls_config.clone();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(unavailable)?;

    // The local socket must belong to the address family of the target.
    let local_address: SocketAddr = if target.address.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = quinn::Endpoint::client(local_address).map_err(unavailable)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

/// Establishes the QUIC connection.
async fn connect(
    endpoint: &quinn::Endpoint,
    target: &Target,
) -> Result<quinn::Connection, TtfbError> {
    let server_name = tls::server_name(&target.url)?;
    endpoint
        .connect((target.address, target.port).into(), &server_name.to_str())
        .map_err(unavailable)?
        .await
        .map_err(unavailable)
}

/// Measures one GET request via HTTP/3: the QUIC handshake (which includes the
/// TLS handshake), sending the request, receiving the response headers, and
/// the download of the body.
///
/// HTTP/3 is only supported over TLS (`https://`).
pub async fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
) -> Result<TtfbOutcome, TtfbError> {
    if target.url.scheme() != "https" {
        return Err(TtfbError::UnsupportedHttpProtocol(
            "HTTP/3 requires an HTTPS URL".into(),
        ));
    }

    // Establish the QUIC connection, which includes the TLS handshake.
    let endpoint = create_endpoint(target, &tls_config)?;
    let (connection, handshake_duration) = {
        let begin = Instant::now();
        let connection = connect(&endpoint, target).await?;
        (connection, begin.elapsed())
    };

    // The driver drives the HTTP/3 connection in the background.
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(http3_error)?;
    tokio::spawn(async move {
        driver.wait_idle().await;
    });

    // Send the request.
    let (mut stream, send_duration) = {
        let request = build_http_request(&target.url)?;
        let begin = Instant::now();
        let mut stream = sender.send_request(request).await.map_err(http3_error)?;
        stream.finish().await.map_err(http3_error)?;
        (stream, begin.elapsed())
    };

    // Wait for the response headers.
    let ttfb_duration = {
        let begin = Instant::now();
        stream.recv_response().await.map_err(http3_error)?;
        begin.elapsed()
    };

    // Download the body.
    let download_duration = {
        let begin = Instant::now();
        while stream.recv_data().await.map_err(http3_error)?.is_some() {}
        begin.elapsed()
    };

    Ok(TtfbOutcome::new(
        target.input.clone(),
        target.address,
        target.port,
        TtfbTimings {
            dns_lookup: target.dns_duration,
            connect: Connect::Quic(handshake_duration),
            http_get_send: send_duration,
            http_ttfb: ttfb_duration,
            http_content_download: download_duration,
        },
        HttpProtocol::Http3,
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
