// SPDX-License-Identifier: MIT

//! HTTP/1.1 request construction and response framing.

use crate::CRATE_VERSION;
use url::Url;

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
        \r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_includes_query_and_non_default_port() {
        let url = Url::parse("http://localhost:8080/path?query=yes#fragment").unwrap();
        let request = build_request(&url);
        assert!(request.starts_with("GET /path?query=yes HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: localhost:8080\r\n"));
        assert!(!request.contains("fragment"));
    }
}
