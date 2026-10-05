// SPDX-License-Identifier: MIT

//! HTTP/1.1 measurements over TCP or TLS, including the response framing.

use crate::outcome::TtfbTimings;
use crate::target::Target;
use crate::{CRATE_VERSION, HttpProtocol, TtfbError, TtfbOutcome, ZeroRttStatus, tls};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Size of a single socket read. Arbitrarily chosen.
const READ_BUFFER_SIZE: usize = 8 * 1024;
/// Upper bound for the response head. RFC 9112 sets no limit; this is an
/// arbitrary guard against unbounded buffering.
const MAX_HEAD_SIZE: usize = 64 * 1024;

// Header names in lowercase, as normalized by `read_head`.
const CONTENT_LENGTH: &str = "content-length";
const TRANSFER_ENCODING: &str = "transfer-encoding";

type Headers = Vec<(String, String)>;

/// Trait that combines [`IoWrite`] and [`IoRead`].
///
/// This trait abstracts over a `Tcp<Data>` Stream or a `Tcp<Tls<Data>>` stream.
trait IoReadAndWrite: IoWrite + IoRead {}

impl<T: IoRead + IoWrite> IoReadAndWrite for T {}

/// How the end of a response body was determined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// The status code implies that there is no body.
    NoBody,
    /// Chunked transfer coding.
    Chunked,
    /// A `Content-Length` header.
    ContentLength,
    /// The server closed the connection.
    CloseDelimited,
}

/// Constructs the header for a HTTP/1.1 GET-Request.
///
/// Sets the following default headers:
/// - `Accept-Encoding: gzip, deflate, br, zstd` (default of Chrome v123)
/// - `User-Agent: ttfb/<version>`
/// - `Connection: close` with `close_connection`
fn build_request(url: &Url, close_connection: bool) -> String {
    let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let connection = if close_connection {
        "Connection: close\r\n"
    } else {
        ""
    };
    format!(
        "GET {path} HTTP/1.1\r\n\
        Host: {host}\r\n\
        User-Agent: ttfb/{CRATE_VERSION}\r\n\
        Accept: */*\r\n\
        Accept-Encoding: gzip, deflate, br, zstd\r\n\
        {connection}\
        \r\n"
    )
}

/// Reads one complete HTTP/1.1 response after its first byte has already arrived.
///
/// Returns how the end of the body was determined.
fn read_response(tcp: &mut dyn IoReadAndWrite, first_byte: u8) -> Result<Framing, TtfbError> {
    let mut response = vec![first_byte];
    let (head_len, status, headers) = loop {
        let (head_len, status, headers) = read_head(tcp, &mut response)?;
        // Skip interim responses. 101 Switching Protocols is a final response.
        if (100..200).contains(&status) && status != 101 {
            // The buffer may already hold (parts of) the next response.
            response.drain(..head_len);
        } else {
            break (head_len, status, headers);
        }
    };
    let body = response.split_off(head_len);

    // Responses with these status codes never have a body.
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Framing::NoBody);
    }

    // The last transfer coding decides whether the body is chunked.
    let transfer_is_chunked = headers
        .iter()
        .filter(|(name, _)| name == TRANSFER_ENCODING)
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .next_back()
        .is_some_and(|coding| coding.eq_ignore_ascii_case("chunked"));
    if transfer_is_chunked {
        return read_chunked_body(tcp, body).map(|()| Framing::Chunked);
    }

    // A fixed-length body ends after Content-Length bytes.
    if let Some(content_length) = content_length(&headers)? {
        if body.len() > content_length {
            return Err(TtfbError::InvalidHttpResponse(
                "response contains more bytes than Content-Length".into(),
            ));
        }
        // Read and discard the rest of the body.
        let mut remaining = content_length - body.len();
        let mut buffer = [0_u8; READ_BUFFER_SIZE];
        while remaining > 0 {
            let count = remaining.min(buffer.len());
            tcp.read_exact(&mut buffer[..count])
                .map_err(TtfbError::CantConnectHttp)?;
            remaining -= count;
        }
        return Ok(Framing::ContentLength);
    }

    // Without explicit framing, the body ends when the server closes the connection.
    let mut buffer = [0_u8; READ_BUFFER_SIZE];
    loop {
        let read = tcp.read(&mut buffer).map_err(TtfbError::CantConnectHttp)?;
        if read == /* EOF */ 0 {
            return Ok(Framing::CloseDelimited);
        }
    }
}

/// Reads until `response` holds a complete response head and parses its status code and headers.
fn read_head(
    tcp: &mut dyn IoReadAndWrite,
    response: &mut Vec<u8>,
) -> Result<(usize, u16, Headers), TtfbError> {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(response) {
            Ok(httparse::Status::Complete(head_len)) => {
                let status = parsed.code.ok_or_else(|| {
                    TtfbError::InvalidHttpResponse("response does not contain a status code".into())
                })?;
                // All header names as lowercase UTF-8 with trimmed UTF-8 content.
                let headers = parsed
                    .headers
                    .iter()
                    .map(|header| {
                        let value = std::str::from_utf8(header.value).map_err(|_| {
                            TtfbError::InvalidHttpResponse(
                                "response contains a non-UTF-8 header value".into(),
                            )
                        })?;
                        Ok((header.name.to_ascii_lowercase(), value.trim().to_owned()))
                    })
                    .collect::<Result<Headers, TtfbError>>()?;
                return Ok((head_len, status, headers));
            }
            Ok(httparse::Status::Partial) => {
                if response.len() >= MAX_HEAD_SIZE {
                    return Err(TtfbError::InvalidHttpResponse(
                        "response headers exceed 64 KiB".into(),
                    ));
                }
                read_more(tcp, response)?;
            }
            Err(error) => {
                return Err(TtfbError::InvalidHttpResponse(format!(
                    "could not parse response headers: {error}"
                )));
            }
        }
    }
}

/// Returns the body length announced by the Content-Length headers, if any.
fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, TtfbError> {
    let values = headers
        .iter()
        .filter(|(name, _)| name == CONTENT_LENGTH)
        .map(|(_, value)| value);
    let mut parsed = values.map(|value| {
        value.parse::<usize>().map_err(|_| {
            TtfbError::InvalidHttpResponse("response has an invalid Content-Length".into())
        })
    });
    let Some(first) = parsed.next().transpose()? else {
        return Ok(None);
    };
    if parsed.any(|value| value.ok() != Some(first)) {
        return Err(TtfbError::InvalidHttpResponse(
            "response has conflicting Content-Length headers".into(),
        ));
    }
    Ok(Some(first))
}

/// Reads and discards a body with chunked transfer coding.
///
/// `body` holds the body bytes that already arrived together with the response
/// head. Every chunk starts with a line containing its size in hex (optionally
/// followed by extensions) and its data is followed by CRLF. A chunk of size
/// zero ends the body. It is followed by optional trailer fields and an empty
/// line.
fn read_chunked_body(tcp: &mut dyn IoReadAndWrite, mut body: Vec<u8>) -> Result<(), TtfbError> {
    loop {
        // Wait for the complete chunk-size line.
        let line_end = loop {
            if let Some(index) = find_bytes(&body, b"\r\n") {
                break index;
            }
            read_more(tcp, &mut body)?;
        };
        // Parse the hex size and ignore chunk extensions after ';'.
        let chunk_size = std::str::from_utf8(&body[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or_else(|| TtfbError::InvalidHttpResponse("invalid chunk size".into()))?;
        if chunk_size == 0 {
            // Last chunk: wait for the end of the (possibly empty) trailer section.
            let trailers_start = line_end + 2 /* CRLF */;
            loop {
                let trailers = &body[trailers_start..];
                if trailers.starts_with(b"\r\n") || find_bytes(trailers, b"\r\n\r\n").is_some() {
                    return Ok(());
                }
                read_more(tcp, &mut body)?;
            }
        }
        // Wait for the chunk data and its CRLF, then drop the whole chunk.
        let chunk_end = line_end + 2 /* CRLF */ + chunk_size + 2 /* CRLF */;
        while body.len() < chunk_end {
            read_more(tcp, &mut body)?;
        }
        if &body[chunk_end - 2 /* CRLF */..chunk_end] != b"\r\n" {
            return Err(TtfbError::InvalidHttpResponse(
                "chunk data is not followed by CRLF".into(),
            ));
        }
        body.drain(..chunk_end);
    }
}

/// Appends the next data from `tcp` to `buffer`.
///
/// Fails if the connection was closed, as the caller still expects more data
/// for a complete response.
fn read_more(tcp: &mut dyn IoReadAndWrite, buffer: &mut Vec<u8>) -> Result<(), TtfbError> {
    let mut chunk = [0_u8; READ_BUFFER_SIZE];
    let read = tcp.read(&mut chunk).map_err(TtfbError::CantConnectHttp)?;
    if read == /* EOF */ 0 {
        return Err(TtfbError::InvalidHttpResponse(
            "connection closed before the response was complete".into(),
        ));
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Initializes the TCP connection to the IP address. Measures the duration.
fn tcp_connect(addr: IpAddr, port: u16) -> Result<(TcpStream, Duration), TtfbError> {
    let addr_w_port = (addr, port);
    let now = Instant::now();
    let mut tcp = TcpStream::connect(addr_w_port).map_err(TtfbError::CantConnectTcp)?;
    tcp.flush().map_err(TtfbError::OtherStreamError)?;
    let tcp_connect_duration = now.elapsed();
    Ok((tcp, tcp_connect_duration))
}

/// A request that was sent as TLS 1.3 early data.
struct EarlyData {
    /// The duration from the start of the TLS handshake until the request was
    /// sent.
    sent_after: Duration,
    /// The moment the request was sent.
    sent_at: Instant,
    /// The duration of writing the request and the ClientHello.
    send_duration: Duration,
    /// Whether the server accepted the early data. Otherwise, the request has
    /// to be sent again after the handshake.
    accepted: bool,
}

/// A connection that is ready for the HTTP exchange.
struct Connection {
    /// The TCP stream, or the TLS stream on top of it.
    stream: Box<dyn IoReadAndWrite>,
    /// The duration of the TLS handshake, if TLS is used.
    tls_handshake_duration: Option<Duration>,
    /// The request sent as early data, if any.
    early_data: Option<EarlyData>,
}

/// Sends `request` as TLS 1.3 early data together with the ClientHello, if
/// the resumed TLS session permits it.
///
/// The server limits the amount of early data. A request that doesn't fit
/// isn't sent here but after the handshake.
fn send_early_data(
    connection: &mut ClientConnection,
    tcp: &mut TcpStream,
    request: &[u8],
    handshake_begin: Instant,
) -> Result<Option<EarlyData>, TtfbError> {
    let Some(mut writer) = connection
        .early_data()
        .filter(|writer| writer.bytes_left() >= request.len())
    else {
        return Ok(None);
    };
    let send_begin = Instant::now();
    writer
        .write_all(request)
        .map_err(TtfbError::CantConnectHttp)?;
    while connection.wants_write() {
        connection
            .write_tls(tcp)
            .map_err(TtfbError::CantConnectHttp)?;
    }
    Ok(Some(EarlyData {
        sent_after: handshake_begin.elapsed(),
        sent_at: Instant::now(),
        send_duration: send_begin.elapsed(),
        accepted: false,
    }))
}

/// If the scheme is "https", this replaces the TCP-Stream with a `TLS<TCP>`-stream.
/// If TLS is used, it measures the time of the TLS handshake.
///
/// With `early_request`, the request is sent as TLS 1.3 early data together
/// with the ClientHello, if the resumed TLS session permits it.
fn tls_handshake_if_necessary(
    mut tcp: TcpStream,
    url: &Url,
    tls_config: Arc<ClientConfig>,
    early_request: Option<&[u8]>,
) -> Result<Connection, TtfbError> {
    if url.scheme() != "https" {
        return Ok(Connection {
            stream: Box::new(tcp),
            tls_handshake_duration: None,
            early_data: None,
        });
    }

    let server_name = tls::server_name(url)?;
    let now = Instant::now();
    let mut connection = ClientConnection::new(tls_config, server_name)
        .map_err(|error| TtfbError::Tls(error.to_string()))?;

    // Send the request early, if requested and possible.
    let mut early_data = match early_request {
        Some(request) => send_early_data(&mut connection, &mut tcp, request, now)?,
        None => None,
    };

    // Complete the handshake and learn whether the server accepted the early
    // data.
    connection
        .complete_io(&mut tcp)
        .map_err(|error| TtfbError::Tls(error.to_string()))?;
    let tls_handshake_duration = now.elapsed();
    if let Some(early_data) = &mut early_data {
        early_data.accepted = connection.is_early_data_accepted();
    }

    Ok(Connection {
        stream: Box::new(StreamOwned::new(connection, tcp)),
        tls_handshake_duration: Some(tls_handshake_duration),
        early_data,
    })
}

/// Measures one GET request via HTTP/1.1: TCP connect, the TLS handshake for
/// HTTPS, sending the request, the first response byte, and the download of
/// the complete response.
///
/// With `try_zero_rtt`, the request is sent as TLS 1.3 early data if the
/// resumed TLS session permits it. If the server rejects the early data, the
/// request is sent again after the handshake.
pub fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
    try_zero_rtt: bool,
) -> Result<TtfbOutcome, TtfbError> {
    // A server may answer an early request before it has read the rest of
    // the handshake. If it then closes the connection as requested, the
    // unread handshake messages make the kernel reset the connection, which
    // discards the response in transit. Hence, with 0-RTT, the request keeps
    // the connection open, also if it is sent after the handshake; the
    // response framing tells where the response ends.
    let header = build_request(&target.url, !try_zero_rtt);

    // Connect, with a TLS handshake for HTTPS, which may carry the request.
    let (tcp, tcp_connect_duration) = tcp_connect(target.address, target.port)?;
    let Connection {
        stream: mut tcp,
        tls_handshake_duration,
        early_data,
    } = tls_handshake_if_necessary(
        tcp,
        &target.url,
        tls_config,
        try_zero_rtt.then_some(header.as_bytes()),
    )?;
    let zero_rtt_status = try_zero_rtt.then_some(match &early_data {
        None => ZeroRttStatus::Unavailable,
        Some(early_data) if early_data.accepted => ZeroRttStatus::Accepted,
        Some(_) => ZeroRttStatus::Replayed,
    });

    // Send the request, unless the server accepted it as early data. An
    // accepted early request waits for its response from the moment it was
    // sent, which includes the remainder of the TLS handshake.
    let (http_get_send_duration, ttfb_begin) = match &early_data {
        Some(early_data) if early_data.accepted => (early_data.send_duration, early_data.sent_at),
        _ => {
            let now = Instant::now();
            tcp.write_all(header.as_bytes())
                .map_err(TtfbError::CantConnectHttp)?;
            tcp.flush().map_err(TtfbError::OtherStreamError)?;
            (now.elapsed(), Instant::now())
        }
    };

    // Wait for the first byte of the response.
    let mut first_byte = [0_u8];
    let http_ttfb_duration = {
        tcp.read_exact(&mut first_byte)
            .map_err(|_e| TtfbError::NoHttpResponse)?;
        ttfb_begin.elapsed()
    };

    // Read the rest of the response.
    let http_content_download_duration = {
        let now = Instant::now();
        read_response(tcp.as_mut(), first_byte[0])?;
        now.elapsed()
    };

    Ok(TtfbOutcome::new(
        target.input.clone(),
        target.address,
        target.port,
        TtfbTimings {
            dns_lookup: target.dns_duration,
            tcp_connect: tcp_connect_duration,
            tls_handshake: tls_handshake_duration,
            http_get_send: http_get_send_duration,
            http_ttfb: http_ttfb_duration,
            http_content_download: http_content_download_duration,
            zero_rtt: early_data.map(|early_data| early_data.sent_after),
        },
        HttpProtocol::Http11,
        zero_rtt_status,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse_response(response: &[u8]) -> Result<Framing, TtfbError> {
        let mut stream = Cursor::new(response[1..].to_vec());
        read_response(&mut stream, response[0])
    }

    #[test]
    fn reads_fixed_length_response() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
            Ok(Framing::ContentLength)
        );
    }

    /// Chunked transfer coding is common for dynamically generated responses
    /// whose length is not known upfront. Trailer fields after the last chunk
    /// are rare (e.g., checksums or gRPC status) but valid and must be read.
    #[test]
    fn reads_chunked_response_with_trailer() {
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nChecksum: valid\r\n\r\n",
            ),
            Ok(Framing::Chunked)
        );
    }

    #[test]
    fn reads_close_delimited_response() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\nhello"),
            Ok(Framing::CloseDelimited)
        );
    }

    #[test]
    fn reads_response_without_body() {
        assert_eq!(
            parse_response(b"HTTP/1.1 204 No Content\r\n\r\n"),
            Ok(Framing::NoBody)
        );
    }

    #[test]
    fn skips_interim_response() {
        assert_eq!(
            parse_response(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            ),
            Ok(Framing::ContentLength)
        );
    }

    /// Differing Content-Length values make the body length ambiguous. They come
    /// from broken servers or proxies, or indicate a response smuggling attempt,
    /// so RFC 9112 requires treating the response as invalid.
    #[test]
    fn rejects_conflicting_content_lengths() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"),
            Err(TtfbError::InvalidHttpResponse(
                "response has conflicting Content-Length headers".into()
            ))
        );
    }

    #[test]
    fn request_includes_query_and_non_default_port() {
        let url = Url::parse("http://localhost:8080/path?query=yes#fragment").unwrap();
        let request = build_request(&url, true);
        assert!(request.starts_with("GET /path?query=yes HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: localhost:8080\r\n"));
        assert!(!request.contains("fragment"));
    }
}

/// Checks the response framing of well-known websites. Sites may change how
/// they frame responses, so a failure can also mean that this list needs an
/// update.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;

    /// Requests `url` and returns how the response body was framed.
    fn framing_of(url: &str) -> Result<Framing, TtfbError> {
        let target = Target::resolve(url)?;
        let (tcp, _) = tcp_connect(target.address, target.port)?;
        let mut stream =
            tls_handshake_if_necessary(tcp, &target.url, tls::config(false, false), None)?.stream;
        stream
            .write_all(build_request(&target.url, true).as_bytes())
            .map_err(TtfbError::CantConnectHttp)?;
        let mut first_byte = [0];
        stream
            .read_exact(&mut first_byte)
            .map_err(|_| TtfbError::NoHttpResponse)?;
        read_response(stream.as_mut(), first_byte[0])
    }

    #[test]
    fn well_known_websites_cover_all_framings() {
        let cases = [
            ("https://example.com", Framing::Chunked),
            ("https://github.com", Framing::Chunked),
            // Bodies that need further reads after the response head.
            ("https://rust-lang.org", Framing::ContentLength),
            ("https://duckduckgo.com", Framing::ContentLength),
            ("https://fedoraproject.org", Framing::ContentLength),
            // Redirects with `Content-Length: 0`.
            ("http://github.com", Framing::ContentLength),
            ("http://crates.io", Framing::ContentLength),
            ("https://un.org", Framing::CloseDelimited),
            ("http://vercel.com", Framing::CloseDelimited),
            ("https://httpbin.org/status/204", Framing::NoBody),
        ];
        let failures = cases
            .iter()
            .filter_map(|(url, expected)| {
                let actual = framing_of(url);
                (actual.as_ref() != Ok(expected))
                    .then(|| format!("{url}: expected {expected:?}, got {actual:?}"))
            })
            .collect::<Vec<_>>();
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
