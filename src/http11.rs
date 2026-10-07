// SPDX-License-Identifier: MIT

//! HTTP/1.1 measurements over TCP or TLS, including the response framing.

use crate::deadline::Deadline;
use crate::outcome::{Connect, ResponseHead, TtfbTimings};
use crate::target::Target;
use crate::{CRATE_VERSION, HttpProtocol, TtfbError, TtfbOutcome, ZeroRtt, tls};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{self, ErrorKind, Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Size of a single socket read. Arbitrarily chosen.
const READ_BUFFER_SIZE: usize = 8 * 1024;
/// Upper bound for the response head. RFC 9112 sets no limit; this is an
/// arbitrary guard against unbounded buffering.
const MAX_HEAD_SIZE: usize = 64 * 1024;

/// Trait that combines [`IoWrite`] and [`IoRead`].
///
/// This trait abstracts over a `Tcp<Data>` Stream or a `Tcp<Tls<Data>>` stream.
trait IoReadAndWrite: IoWrite + IoRead {}

impl<T: IoRead + IoWrite> IoReadAndWrite for T {}

/// A TCP stream whose reads and writes fail when the deadline passes.
///
/// Socket timeouts only limit a single read or write, so each one is
/// limited to the time that remains until the deadline.
struct DeadlineStream {
    tcp: TcpStream,
    deadline: Deadline,
}

impl DeadlineStream {
    /// Returns the time until the deadline.
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .remaining()
            .map_err(|_| io::Error::from(ErrorKind::TimedOut))
    }
}

impl IoRead for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.remaining()?))?;
        self.tcp.read(buf)
    }
}

impl IoWrite for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.remaining()?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

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
/// Returns the head of the final response and how the end of its body was
/// determined.
fn read_response(
    tcp: &mut dyn IoReadAndWrite,
    first_byte: u8,
) -> Result<(ResponseHead, Framing), TtfbError> {
    let mut response = vec![first_byte];
    let (head_len, status, headers) = loop {
        let (head_len, status, headers) = read_head(tcp, &mut response)?;
        // Skip interim responses. 101 Switching Protocols is a final response.
        if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
            // The buffer may already hold (parts of) the next response.
            response.drain(..head_len);
        } else {
            break (head_len, status, headers);
        }
    };
    let body = response.split_off(head_len);
    let framing = read_body(tcp, status, &headers, body)?;
    Ok((ResponseHead { status, headers }, framing))
}

/// Reads the body of a response with `status` and `headers`. `body` holds the
/// body bytes that arrived together with the head.
///
/// Returns how the end of the body was determined.
fn read_body(
    tcp: &mut dyn IoReadAndWrite,
    status: StatusCode,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Framing, TtfbError> {
    // Responses with these status codes never have a body.
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Ok(Framing::NoBody);
    }

    // The last transfer coding decides whether the body is chunked.
    let transfer_is_chunked = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .next_back()
        .map(|value| {
            value.to_str().map_err(|_| {
                TtfbError::InvalidHttpResponse("response has an invalid Transfer-Encoding".into())
            })
        })
        .transpose()?
        .and_then(|value| value.rsplit(',').next())
        .is_some_and(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
    if transfer_is_chunked {
        return read_chunked_body(tcp, body).map(|()| Framing::Chunked);
    }

    // A fixed-length body ends after Content-Length bytes.
    if let Some(content_length) = content_length(headers)? {
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
) -> Result<(usize, StatusCode, HeaderMap), TtfbError> {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(response) {
            Ok(httparse::Status::Complete(head_len)) => {
                let status = parsed
                    .code
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .ok_or_else(|| {
                        TtfbError::InvalidHttpResponse(
                            "response does not contain a valid status code".into(),
                        )
                    })?;
                let mut headers = HeaderMap::new();
                for header in parsed.headers.iter() {
                    let name = HeaderName::from_bytes(header.name.as_bytes());
                    let value = HeaderValue::from_bytes(header.value);
                    let (Ok(name), Ok(value)) = (name, value) else {
                        return Err(TtfbError::InvalidHttpResponse(
                            "response contains an invalid header".into(),
                        ));
                    };
                    headers.append(name, value);
                }
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
fn content_length(headers: &HeaderMap) -> Result<Option<usize>, TtfbError> {
    let mut parsed = headers.get_all(CONTENT_LENGTH).iter().map(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .ok_or_else(|| {
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
        let chunk_size = str::from_utf8(&body[..line_end])
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

/// Initializes the TCP connection to the IP address until `deadline`.
/// Measures the duration.
fn tcp_connect(
    addr: IpAddr,
    port: u16,
    deadline: Deadline,
) -> Result<(DeadlineStream, Duration), TtfbError> {
    let addr_w_port = SocketAddr::from((addr, port));
    let now = Instant::now();
    let tcp = TcpStream::connect_timeout(&addr_w_port, deadline.remaining()?)
        .map_err(TtfbError::CantConnectTcp)?;
    let mut tcp = DeadlineStream { tcp, deadline };
    tcp.flush().map_err(TtfbError::OtherStreamError)?;
    let tcp_connect_duration = now.elapsed();
    Ok((tcp, tcp_connect_duration))
}

/// A connection that is ready for the HTTP exchange.
struct Connection {
    /// The TCP stream, or the TLS stream on top of it.
    stream: Box<dyn IoReadAndWrite>,
    /// The duration of the TLS handshake, if TLS is used.
    tls_handshake_duration: Option<Duration>,
    /// What happened to the early request, if there was one.
    zero_rtt: Option<ZeroRtt>,
}

/// Writes `request` as TLS 1.3 early data, which goes out together with the
/// ClientHello. Returns `false` if the resumed session doesn't permit early
/// data or the request exceeds the amount the server accepts.
fn write_early_data(connection: &mut ClientConnection, request: &[u8]) -> Result<bool, TtfbError> {
    let Some(mut early_data) = connection
        .early_data()
        .filter(|early_data| early_data.bytes_left() >= request.len())
    else {
        return Ok(false);
    };
    early_data
        .write_all(request)
        .map_err(TtfbError::CantConnectHttp)?;
    Ok(true)
}

/// If the scheme is "https", this replaces the TCP-Stream with a `TLS<TCP>`-stream.
/// If TLS is used, it measures the time of the TLS handshake.
///
/// With `early_request`, the request is sent as TLS 1.3 early data if
/// possible.
fn tls_handshake_if_necessary(
    mut tcp: DeadlineStream,
    url: &Url,
    tls_config: Arc<ClientConfig>,
    early_request: Option<&[u8]>,
) -> Result<Connection, TtfbError> {
    if url.scheme() != "https" {
        return Ok(Connection {
            stream: Box::new(tcp),
            tls_handshake_duration: None,
            zero_rtt: None,
        });
    }
    let server_name = tls::server_name(url)?;
    let now = Instant::now();
    let mut connection = ClientConnection::new(tls_config, server_name)
        .map_err(|error| TtfbError::Tls(error.to_string()))?;
    let early_data_written = match early_request {
        Some(request) => Some(write_early_data(&mut connection, request)?),
        None => None,
    };
    // Performs IO until the handshake is complete.
    connection
        .complete_io(&mut tcp)
        .map_err(|error| TtfbError::Tls(error.to_string()))?;
    let tls_handshake_duration = now.elapsed();
    let zero_rtt = early_data_written.map(|written| match written {
        false => ZeroRtt::Unavailable,
        true if connection.is_early_data_accepted() => ZeroRtt::Accepted,
        true => ZeroRtt::Rejected,
    });
    Ok(Connection {
        stream: Box::new(StreamOwned::new(connection, tcp)),
        tls_handshake_duration: Some(tls_handshake_duration),
        zero_rtt,
    })
}

/// Measures one GET request via HTTP/1.1: TCP connect, the TLS handshake for
/// HTTPS, sending the request, the first response byte, and the download of
/// the complete response. Reads and writes fail when `deadline` passes.
///
/// With `early_data`, the request is sent as TLS 1.3 early data if the resumed
/// TLS session permits it. If the server rejects the early data, the request
/// is sent again after the handshake.
pub fn measure(
    target: &Target,
    tls_config: Arc<ClientConfig>,
    deadline: Deadline,
    early_data: bool,
) -> Result<TtfbOutcome, TtfbError> {
    // A server may answer an early request before it has read the rest of
    // the handshake. If it then closes the connection as requested, the
    // unread handshake messages make the kernel reset the connection, which
    // discards the response in transit. Hence, with early data, the request
    // keeps the connection open; the response framing tells where the
    // response ends.
    let header = build_request(&target.url, !early_data);

    // Connect, with a TLS handshake for HTTPS, which may carry the request.
    let (tcp, tcp_connect_duration) = tcp_connect(target.address, target.port, deadline)?;
    let Connection {
        stream: mut tcp,
        tls_handshake_duration,
        zero_rtt,
    } = tls_handshake_if_necessary(
        tcp,
        &target.url,
        tls_config,
        early_data.then_some(header.as_bytes()),
    )?;

    // Send the request, unless the server accepted it as early data.
    let http_get_send_duration = if zero_rtt == Some(ZeroRtt::Accepted) {
        Duration::ZERO
    } else {
        let now = Instant::now();
        tcp.write_all(header.as_bytes())
            .map_err(TtfbError::CantConnectHttp)?;
        tcp.flush().map_err(TtfbError::OtherStreamError)?;
        now.elapsed()
    };

    // Wait for the first byte of the response.
    let mut first_byte = [0_u8];
    let http_ttfb_duration = {
        let now = Instant::now();
        tcp.read_exact(&mut first_byte)
            .map_err(|_e| TtfbError::NoHttpResponse)?;
        now.elapsed()
    };

    // Read the rest of the response.
    let (response, http_content_download_duration) = {
        let now = Instant::now();
        let (response, _) = read_response(tcp.as_mut(), first_byte[0])?;
        (response, now.elapsed())
    };

    Ok(TtfbOutcome::new(
        target.input.clone(),
        target.address,
        target.port,
        TtfbTimings {
            dns_lookup: target.dns_duration,
            connect: Connect::Tcp {
                connect: tcp_connect_duration,
                tls: tls_handshake_duration,
            },
            http_get_send: http_get_send_duration,
            http_ttfb: http_ttfb_duration,
            http_content_download: http_content_download_duration,
        },
        HttpProtocol::Http11,
        response,
        zero_rtt,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse_response(response: &[u8]) -> Result<Framing, TtfbError> {
        let mut stream = Cursor::new(response[1..].to_vec());
        read_response(&mut stream, response[0]).map(|(_, framing)| framing)
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

    #[test]
    fn returns_head_of_final_response() {
        let response = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 404 Not Found\r\nServer: test\r\nContent-Length: 0\r\n\r\n";
        let mut stream = Cursor::new(response[1..].to_vec());
        let (head, _) = read_response(&mut stream, response[0]).unwrap();
        assert_eq!(head.status, StatusCode::NOT_FOUND);
        assert_eq!(head.headers.get("server").unwrap(), "test");
        assert!(head.headers.get("link").is_none());
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

/// Tests against well-known websites.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;
    use crate::IpVersion;
    use crate::deadline::Deadline;
    #[cfg(feature = "http2")]
    use crate::{http2, run_in_tokio};

    /// Requests `url` and returns how the response body was framed.
    fn framing_of(url: &str) -> Result<Framing, TtfbError> {
        let target = Target::resolve(url, IpVersion::Any, Deadline::for_tests())?;
        let (tcp, _) = tcp_connect(target.address, target.port, Deadline::for_tests())?;
        let mut stream =
            tls_handshake_if_necessary(tcp, &target.url, tls::config(false, false), None)?.stream;
        stream
            .write_all(build_request(&target.url, true).as_bytes())
            .map_err(TtfbError::CantConnectHttp)?;
        let mut first_byte = [0];
        stream
            .read_exact(&mut first_byte)
            .map_err(|_| TtfbError::NoHttpResponse)?;
        read_response(stream.as_mut(), first_byte[0]).map(|(_, framing)| framing)
    }

    /// Sites may change how they frame responses, so a failure can also mean
    /// that this list needs an update.
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

    /// A server accepts early data only for the protocol that the resumed
    /// session negotiated via ALPN [0]. After an HTTP/2 warm-up, servers
    /// therefore reject the HTTP/1.1 early data, which offers no ALPN.
    ///
    /// [0]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10
    #[cfg(feature = "http2")]
    #[test]
    fn rejected_early_data_is_sent_again() {
        let deadline = Deadline::for_tests();
        let target = Target::resolve("https://www.google.com", IpVersion::Any, deadline).unwrap();
        let tls_config = tls::config(false, true);
        run_in_tokio(http2::measure(&target, Arc::clone(&tls_config))).unwrap();
        let outcome = measure(&target, tls_config, deadline, true).unwrap();
        assert_eq!(outcome.zero_rtt(), Some(ZeroRtt::Rejected));
        assert!(outcome.status().is_success());
    }
}
