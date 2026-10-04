// SPDX-License-Identifier: MIT

//! HTTP/1.1 request construction and response framing.

use crate::{CRATE_VERSION, IoReadAndWrite, TtfbError};
use url::Url;

/// Size of a single socket read. Arbitrarily chosen.
const READ_BUFFER_SIZE: usize = 8 * 1024;
/// Upper bound for the response head. RFC 9112 sets no limit; this is an
/// arbitrary guard against unbounded buffering.
const MAX_HEAD_SIZE: usize = 64 * 1024;

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
    let status = loop {
        let (head_len, status) = read_head(tcp, &mut response)?;
        // Skip interim responses. 101 Switching Protocols is a final response.
        if (100..200).contains(&status) && status != 101 {
            // The buffer may already hold (parts of) the next response.
            response.drain(..head_len);
        } else {
            break status;
        }
    };

    // Responses with these status codes never have a body.
    if (100..200).contains(&status) || status == 204 || status == 304 {
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

/// Reads until `response` holds a complete response head and parses its status code.
fn read_head(
    tcp: &mut dyn IoReadAndWrite,
    response: &mut Vec<u8>,
) -> Result<(usize, u16), TtfbError> {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(response) {
            Ok(httparse::Status::Complete(head_len)) => {
                let status = parsed.code.ok_or_else(|| {
                    TtfbError::InvalidHttpResponse("response does not contain a status code".into())
                })?;
                return Ok((head_len, status));
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

    #[test]
    fn request_includes_query_and_non_default_port() {
        let url = Url::parse("http://localhost:8080/path?query=yes#fragment").unwrap();
        let request = build_request(&url);
        assert!(request.starts_with("GET /path?query=yes HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: localhost:8080\r\n"));
        assert!(!request.contains("fragment"));
    }
}
