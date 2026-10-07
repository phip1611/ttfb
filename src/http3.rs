// SPDX-License-Identifier: MIT

//! HTTP/3 measurements over QUIC.

use crate::outcome::{Connect, ResponseHead, TtfbTimings, send_and_ttfb_durations};
use crate::target::Target;
use crate::{HttpProtocol, TtfbError, TtfbOutcome, ZeroRtt, build_http_request, tls};
use bytes::Bytes;
use h3::client::{self as h3_client, RequestStream, SendRequest};
use h3_quinn::{BidiStream, OpenStreams};
use quinn::ZeroRttAccepted;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use url::Url;

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
    let mut endpoint = quinn::Endpoint::client(local_address).map_err(unavailable)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

/// Establishes the QUIC connection within [`CONNECT_TIMEOUT`].
///
/// With `early_data`, this returns before the handshake if the resumed session
/// permits 0-RTT. The returned future then resolves when the handshake
/// completes, to whether the server accepted the 0-RTT data.
async fn connect(
    endpoint: &quinn::Endpoint,
    target: &Target,
    early_data: bool,
) -> Result<(quinn::Connection, Option<ZeroRttAccepted>), TtfbError> {
    let server_name = tls::server_name(&target.url)?;
    let mut connecting = endpoint
        .connect((target.address, target.port).into(), &server_name.to_str())
        .map_err(unavailable)?;
    if early_data {
        match connecting.into_0rtt() {
            Ok((connection, accepted)) => return Ok((connection, Some(accepted))),
            Err(handshaking) => connecting = handshaking,
        }
    }
    let connection = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| unavailable("the connection attempt timed out"))?
        .map_err(unavailable)?;
    Ok((connection, None))
}

/// An HTTP/3 request whose response is pending.
struct Request {
    /// Drives the HTTP/3 connection in the background.
    driver: JoinHandle<()>,
    /// Dropping the last sender closes the HTTP/3 connection.
    _sender: SendRequest<OpenStreams, Bytes>,
    stream: RequestStream<BidiStream<Bytes>, Bytes>,
    send_begin: Instant,
    send_end: Instant,
}

/// Sets up HTTP/3 on `connection` and sends the GET request to `url`.
async fn send_request(connection: quinn::Connection, url: &Url) -> Result<Request, TtfbError> {
    // GREASE is disabled, as some servers reset the request when they receive
    // a GREASE frame on the request stream.
    let (mut driver, mut sender) = h3_client::builder()
        .send_grease(false)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .map_err(http3_error)?;
    let driver = tokio::spawn(async move {
        driver.wait_idle().await;
    });

    let request = build_http_request(url)?;
    let send_begin = Instant::now();
    let mut stream = sender.send_request(request).await.map_err(http3_error)?;
    stream.finish().await.map_err(http3_error)?;
    Ok(Request {
        driver,
        _sender: sender,
        stream,
        send_begin,
        send_end: Instant::now(),
    })
}

/// Measures one GET request via HTTP/3: the QUIC handshake (which includes the
/// TLS handshake), sending the request, receiving the response headers, and
/// the download of the body.
///
/// HTTP/3 is only supported over TLS (`https://`). With `early_data`, the
/// request is sent as 0-RTT data if the resumed TLS session permits it. If the
/// server rejects the 0-RTT data, the request is sent again after the
/// handshake.
pub async fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
    early_data: bool,
) -> Result<TtfbOutcome, TtfbError> {
    if target.url.scheme() != "https" {
        return Err(TtfbError::UnsupportedHttpProtocol(
            "HTTP/3 requires an HTTPS URL".into(),
        ));
    }

    // Establish the QUIC connection, which includes the TLS handshake. With
    // 0-RTT, the handshake completes in the background while the request goes
    // out.
    let endpoint = create_endpoint(target, &tls_config)?;
    let handshake_begin = Instant::now();
    let (connection, zero_rtt_accepted) = connect(&endpoint, target, early_data).await?;
    let connected = Instant::now();
    let handshake = zero_rtt_accepted.map(|accepted| {
        tokio::spawn(async move {
            let accepted = accepted.await;
            (Instant::now(), accepted)
        })
    });

    // Send the request and wait for the response headers. If the server
    // rejects the 0-RTT data, quinn fails the request once the handshake
    // completes.
    let mut request = send_request(connection.clone(), &target.url).await?;
    let mut response = request.stream.recv_response().await;
    let mut first_byte = Instant::now();

    let (handshake_end, zero_rtt) = match handshake {
        None => (connected, early_data.then_some(ZeroRtt::Unavailable)),
        Some(handshake) => {
            let (handshake_end, accepted) = handshake
                .await
                .expect("waiting for the handshake should not panic");
            if accepted {
                (handshake_end, Some(ZeroRtt::Accepted))
            } else {
                // The server discarded the 0-RTT data. Hence, the HTTP/3
                // connection needs a new setup, and the request is sent again.
                // Without its driver, the first setup no longer closes the
                // QUIC connection once it is dropped.
                request.driver.abort();
                request = send_request(connection, &target.url).await?;
                response = request.stream.recv_response().await;
                first_byte = Instant::now();
                (handshake_end, Some(ZeroRtt::Rejected))
            }
        }
    };
    let head = response.map_err(http3_error)?.into_parts().0;
    let handshake_duration = handshake_end.duration_since(handshake_begin);
    let (send_duration, ttfb_duration) = send_and_ttfb_durations(
        handshake_end,
        request.send_begin,
        request.send_end,
        first_byte,
    );

    // Download the body.
    let download_duration = {
        let begin = Instant::now();
        while request
            .stream
            .recv_data()
            .await
            .map_err(http3_error)?
            .is_some()
        {}
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
    use crate::{IpVersion, run_in_tokio};

    /// The servers of graph.facebook.com share the certificate of
    /// www.facebook.com, but reject 0-RTT data with sessions of the servers
    /// of www.facebook.com. Facebook may change its setup, so a failure can
    /// also mean that this test needs an update.
    #[test]
    fn rejected_early_data_is_sent_again() {
        let resolve = |url| Target::resolve(url, IpVersion::V4, Deadline::for_tests()).unwrap();
        let target = resolve("https://www.facebook.com");
        let other_server = Target {
            address: resolve("https://graph.facebook.com").address,
            ..target.clone()
        };
        let tls_config = tls::config(false, true);
        run_in_tokio(measure(&target, Arc::clone(&tls_config), false)).unwrap();
        let outcome = run_in_tokio(measure(&other_server, tls_config, true)).unwrap();
        assert_eq!(outcome.zero_rtt(), Some(ZeroRtt::Rejected));
        assert!(outcome.status().is_success());
    }
}
