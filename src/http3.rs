// SPDX-License-Identifier: MIT

//! HTTP/3 measurements over QUIC.

use crate::outcome::{Connect, ResponseHead, TtfbTimings};
use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, build_http_request, drive, tls};
use async_io::Timer;
use bytes::Bytes;
use futures_lite::future;
use h3::client as h3_client;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{EndpointConfig, SmolRuntime};
use rustls::ClientConfig;
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The maximum time to establish the QUIC connection. Networks may drop UDP
/// silently, and a server without HTTP/3 doesn't answer at all.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

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
    let crypto = QuicClientConfig::try_from(crypto).map_err(unavailable)?;

    // The local socket must belong to the address family of the target.
    let local_address: SocketAddr = if target.address.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local_address).map_err(unavailable)?;
    // quinn's default runtime depends on the caller's runtime and on the
    // enabled features of quinn, but the smol runtime works with any.
    let mut endpoint = quinn::Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(SmolRuntime),
    )
    .map_err(unavailable)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

/// Establishes the QUIC connection within [`CONNECT_TIMEOUT`].
async fn connect(
    endpoint: &quinn::Endpoint,
    target: &Target,
) -> Result<quinn::Connection, TtfbError> {
    let server_name = tls::server_name(&target.url)?;
    let connecting = endpoint
        .connect((target.address, target.port).into(), &server_name.to_str())
        .map_err(unavailable)?;
    let timeout = async {
        Timer::after(CONNECT_TIMEOUT).await;
        Err(unavailable("the connection attempt timed out"))
    };
    future::or(async { connecting.await.map_err(unavailable) }, timeout).await
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

    // The driver drives the HTTP/3 connection during the exchange. GREASE is
    // disabled, as some servers reset the request when they receive a GREASE
    // frame on the request stream.
    let (mut driver, mut sender) = h3_client::builder()
        .send_grease(false)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .map_err(http3_error)?;
    let exchange = async {
        // Send the request.
        let (mut stream, send_duration) = {
            let request = build_http_request(&target.url)?;
            let begin = Instant::now();
            let mut stream = sender.send_request(request).await.map_err(http3_error)?;
            stream.finish().await.map_err(http3_error)?;
            (stream, begin.elapsed())
        };

        // Wait for the response headers.
        let (head, ttfb_duration) = {
            let begin = Instant::now();
            let response = stream.recv_response().await.map_err(http3_error)?;
            (response.into_parts().0, begin.elapsed())
        };

        // Download the body.
        let download_duration = {
            let begin = Instant::now();
            while stream.recv_data().await.map_err(http3_error)?.is_some() {}
            begin.elapsed()
        };

        Ok::<_, TtfbError>((head, send_duration, ttfb_duration, download_duration))
    };
    let (head, send_duration, ttfb_duration, download_duration) =
        drive(driver.wait_idle(), exchange).await?;

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
        ResponseHead {
            status: head.status,
            headers: head.headers,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpVersion;
    use crate::deadline::Deadline;

    #[test]
    fn requires_https() {
        let target = async_io::block_on(Target::resolve(
            "http://localhost:1",
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .unwrap();
        let result = async_io::block_on(measure(&target, tls::config(false)));
        assert!(matches!(result, Err(TtfbError::UnsupportedHttpProtocol(_))));
    }
}
