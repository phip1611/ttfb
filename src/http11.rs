// SPDX-License-Identifier: MIT

//! HTTP/1.1 request construction and response framing.

use crate::{CRATE_VERSION, IoReadAndWrite, TtfbError};
use url::Url;

/// Size of a single socket read. Arbitrarily chosen.
const READ_BUFFER_SIZE: usize = 8 * 1024;
/// Upper bound for the response head. RFC 9112 sets no limit; this is an
/// arbitrary guard against unbounded buffering.
const MAX_HEAD_SIZE: usize = 64 * 1024;

// Header names in lowercase, as normalized by `read_head`.
const CONTENT_LENGTH: &str = "content-length";

type Headers = Vec<(String, String)>;

/// Constructs the header for a HTTP/1.1 GET-Request.
///
/// Sets the following default headers:
/// - `Accept-Encoding: gzip, deflate, br, zstd` (default of Chrome v123)
/// - `User-Agent: ttfb/<version>`
pub fn build_request(url: &Url) -> String {
    let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
    format!(
        "GET {path} HTTP/1.1\r\n\
        Host: {host}\r\n\
        User-Agent: ttfb/{CRATE_VERSION}\r\n\
        Accept: */*\r\n\
        Accept-Encoding: gzip, deflate, br, zstd\r\n\
        Connection: close\r\n\
        \r\n"
    )
}

/// Reads one complete HTTP/1.1 response after its first byte has already arrived.
pub fn read_response(tcp: &mut dyn IoReadAndWrite, first_byte: u8) -> Result<(), TtfbError> {
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
        return Ok(());
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
        return Ok(());
    }

    // Without explicit framing, the body ends when the server closes the connection.
    let mut buffer = [0_u8; READ_BUFFER_SIZE];
    loop {
        let read = tcp.read(&mut buffer).map_err(TtfbError::CantConnectHttp)?;
        if read == /* EOF */ 0 {
            return Ok(());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse_response(response: &[u8]) -> Result<(), TtfbError> {
        let mut stream = Cursor::new(response[1..].to_vec());
        read_response(&mut stream, response[0])
    }

    #[test]
    fn reads_fixed_length_response() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
            Ok(())
        );
    }

    #[test]
    fn reads_close_delimited_response() {
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\n\r\nhello"), Ok(()));
    }

    #[test]
    fn reads_response_without_body() {
        assert_eq!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n"), Ok(()));
    }

    #[test]
    fn skips_interim_response() {
        assert_eq!(
            parse_response(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            ),
            Ok(())
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
        let request = build_request(&url);
        assert!(request.starts_with("GET /path?query=yes HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: localhost:8080\r\n"));
        assert!(!request.contains("fragment"));
    }
}
