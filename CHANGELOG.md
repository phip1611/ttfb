# About

As this crate exports a library and a binary, both are released simultaneously.
However, some releases might only change things in the library and some might
only change something for the binary.

# v2.0.0 (UNRELEASED)

## ttfb lib

- **BREAKING** The `ttfb()` function is replaced by `TtfbClient`, which is
  configured with `TtfbOptions`:
  `TtfbClient::new(TtfbOptions::default()).measure(url)`.
  `TtfbOptions::protocol` takes a `ProtocolSelection`, and
  `TtfbOutcome::protocol_selection()` reports it.
- **BREAKING** `TtfbError` is `#[non_exhaustive]`.
- **BREAKING** `TtfbError::CantConnectTls` and `TtfbError::CantVerifyTls`
  are replaced by `TtfbError::Tls`, which describes the error as a string.
  The lib no longer depends on `rustls-connector`.
- **BREAKING** `AllowInvalidCertsVerifier` is no longer public. It was
  exported by accident.
- **BREAKING** `TtfbOutcome::tcp_connect_duration()` and
  `TtfbOutcome::tls_handshake_duration()` are replaced by
  `TtfbOutcome::connection_handshake()`. It reports how the connection was
  established as the new `ConnectionHandshake`: a TCP connect with an optional
  TLS handshake, or a QUIC handshake for HTTP/3.
- **BREAKING** `TtfbError` has the new variants `UnsupportedHttpProtocol`,
  `Http2`, and `Http3`.
- **BREAKING** `ResolveDnsError::Other` and `TtfbError::CantConfigureDNSError`
  describe the error as a string instead of exposing the `ResolveError` of
  `hickory-resolver`, so that the DNS resolver can change without a breaking
  change.
- TLS trusts the system's root certificates and the bundled Mozilla root
  certificates together. Previously, the bundled ones were only used if the
  system's could not be loaded.
- HTTPS works with IPv6 addresses, such as `https://[2606:4700:4700::1111]`.
- `TtfbError` compares `CantConnectHttp` and `OtherStreamError` correctly.
  Before, two errors of the same variant were never equal, while the two
  variants were equal with the same `io::ErrorKind`.
- The duration of the DNS lookup no longer includes starting the internal Tokio
  runtime and its thread, which took about 0.1-0.3 ms.
- Added `TtfbOutcome::protocol()`, which reports the HTTP protocol used as
  `HttpProtocol`.
- Added HTTP/2 measurements over TLS with `HttpProtocol::Http2`. They need
  the Cargo feature `http2`, which is enabled by default. Without it, they
  fail with the new `TtfbError::UnsupportedHttpProtocol`.
- Added HTTP/3 measurements over QUIC with `HttpProtocol::Http3`. They need
  the Cargo feature `http3`, which is enabled by default.
- `ProtocolSelection::Auto`, the default, selects HTTP/3, HTTP/2, or
  HTTP/1.1, whichever the server supports first in this order. Protocols built
  without their Cargo feature are skipped.
- `TtfbOptions::ip_version` selects the IP version of the connection:
  `IpVersion::Any`, the default, prefers IPv4 as before, while `IpVersion::V4`
  and `IpVersion::V6` use only that version. A host without an address of that
  version fails with the new `TtfbError::NoAddressForIpVersion`.
- `TtfbOptions::timeout` limits the duration of a measurement, from the DNS
  lookup to the end of the download. It defaults to 10 s and must be between
  1 s and 60 min. A measurement that exceeds it fails with the new
  `TtfbError::Timeout`.
- `TtfbOutcome::status()` and `TtfbOutcome::headers()` return the status code
  and the headers of the final response. The types `StatusCode` and
  `HeaderMap` of the `http` crate are re-exported.
- `TtfbOptions::zero_rtt` sends the request as TLS 1.3 early data (0-RTT),
  after a warm-up request that obtains the session ticket.
  `TtfbOutcome::zero_rtt()` reports as `ZeroRtt` whether the server accepted
  the early data.

## ttfb binary

- **BREAKING** The protocol is now chosen automatically by default: HTTP/3,
  then HTTP/2, then HTTP/1.1. Use `--http1.1` for the previous behavior.
  For HTTPS servers without HTTP/3, the HTTP/3 attempt usually waits for its
  timeout of 1 s, which prolongs the run but not the measured timings.
- Added `--http1.1`, `--http2`, `--http3`, and `--auto-protocol` to select
  the HTTP protocol.
- Added `--repeat N` and `--repeat Ns`, which measure N times or repeatedly
  for N seconds and print the minimum, median, mean, and maximum of the
  relative and the absolute duration of each step.
- Added `--timeout <SECS>`, the maximum duration of a measurement, which
  defaults to 10 s and must be between 1 s and 3600 s.
- Added `-4/--ipv4` and `-6/--ipv6` to require an IP version. Without them,
  IPv4 is preferred as before.
- Added `--headers`, which prints the status line and the headers of the
  response.
- Added `--json`, which prints the results only as JSON in a single line, e.g.,
  for scripts. Its dependencies grow the release binary by 41 KiB (33 KiB
  stripped).
- The tables show the timings in ms with one decimal. More decimals only
  showed measurement noise. Durations below 0.05 ms are shown as `<0.1`.
- The output shows the IP address and port, the HTTP protocol, the status, and
  the download of the response.
- The output labels "TCP connect" and "HTTP GET Req" are now "TCP Connect"
  and "HTTP Send GET".
- The output shows the QUIC handshake of HTTP/3 measurements instead of the
  TCP connect and the TLS handshake.
- The release binary grows with the HTTP/2 and HTTP/3 support. On Linux,
  built with Rust 1.99 (sizes when stripped in parentheses):
  - v1.15.0: 3.2 MiB (2.5 MiB)
  - without `http2` and `http3`: 3.2 MiB (2.5 MiB)
  - with `http2`: 3.5 MiB (2.8 MiB)
  - with `http3`: 4.0 MiB (3.2 MiB)
  - with `http2` and `http3`, the default: 4.3 MiB (3.4 MiB)

# v1.15.0 (2025-04-02)

## ttfb lib

- **BREAKING** The MSRV is now `1.85.0` stable. The Rust edition is now `2024`.
- dependency updates
- As I had to update `hickory-resolver`, we now have a forced dependency on
  `tokio`, unfortunately.

## ttfb binary

- **BREAKING** The MSRV is now `1.85.0` stable. The Rust edition is now `2024`.
- dependency updates
- The release binary is now (on Linux) 3.3 MiB in size or 2.8 MiB when stripped.

# v1.14.0 (2024-12-04)

## ttfb lib

- **BREAKING** The MSRV is now `1.75.0` stable.
- dependency updates

## ttfb binary

- **BREAKING** The MSRV is now `1.75.0` stable.
- dependency updates

# v1.13.1 (2024-12-04)

## ttfb lib

- Pin dependencies to guarantee MSRV build.

# v1.13.0 (2024-08-02)

## ttfb lib

- **BREAKING** The MSRV is now `1.70.0` stable.

# v1.12.0 (2024-05-02)

## ttfb lib

- **BREAKING** The MSRV is now `1.67.0` stable.
- dependency updates

## ttfb binary

- dependency updates

# v1.11.0 (2024-04-09)

## ttfb lib

- fix: use this library in a tokio runtime without raising a panic
- `TtfbError` now implements `PartialEq`
- dependency updates

## ttfb binary

- **BREAKING** The MSRV of the binary is `1.74.1` stable.
- dependency updates

# v1.10.0 (2023-12-11)

## ttfb lib

- **BREAKING** Signature of `InvalidUrlError::WrongScheme` changed to `WrongScheme(String)`.
- removed dependency to `regex`

## ttfb binary

- reduced binary size from 4.5MB to 3.5MB (release)


# v1.9.1 (2023-11-30)

## ttfb lib

## ttfb binary

- Improved `--help` output.


# v1.9.0 (2023-11-30)

## ttfb lib

- **BREAKING** The MSRV of the library is `1.65.0` stable.
- The dependency requirements are now less strict.

## ttfb binary


# v1.8.0 (2023-11-14)

## ttfb lib

- `ttfb` can no longer panic when `resolv.conf` cannot be found:
  Huge thanks to _Firaenix_: https://github.com/phip1611/ttfb/pull/26
- **BREAKING** `TtfbError::CantConnectTls`'s inner type has switched from
  `native_tls::Error` to `rustls_connector::HandshakeError<std::net::TcpStream>`
- **MAYBE BREAKING** Introduced new `TtfbError::CantConfigureDNSError` variant
- The lib no longer depends on `openssl` but only on `rustls`

## ttfb binary

- The binary is now smaller; it is stripped and uses LTO. This shrinks the size
  from roughly 14MiB to 4MiB (release build).


# v1.7.0 (2023-09-22)

- **BREAKING** The MSRV of the library is `1.64.0` stable.
- **BREAKING** The MSRV of the binary is `1.70.0` stable.
- introduced new `DurationPair` struct
- **BREAKING** replaced several getters
-  - replaced `TtfbOutcome::dns_duration_rel` and `TtfbOutcome::dns_duration_abs`
    with `TtfbOutcome::dns_lookup_duration` which returns a `DurationPair`
  - replaced `TtfbOutcome::tcp_connect_duration_rel` and `TtfbOutcome::tcp_connect_duration_abs`
    with `TtfbOutcome::tcp_connect_duration` which returns a `DurationPair`
  - replaced `TtfbOutcome::tls_handshake_duration_rel` and `TtfbOutcome::tls_handshake_duration_abs`
    with `TtfbOutcome::tls_handshake_duration` which returns a `DurationPair`
  - replaced `TtfbOutcome::http_get_send_duration_rel` and `TtfbOutcome::http_get_send_duration_abs`
    with `TtfbOutcome::http_get_send_duration` which returns a `DurationPair`
  - replaced `TtfbOutcome::http_ttfb_duration_rel` and `TtfbOutcome::http_ttfb_duration_abs`
    with `TtfbOutcome::ttfb_duration` which returns a `DurationPair`
- dependencies updated
- added `TtfbError::NoHttpResponse`


# v1.6.0 (2023-01-26)

- MSRV of the binary is now 1.64.0
- MSRV of the library is 1.57.0


# v1.5.1 (2022-12-01)

- minor internal improvement


# v1.5.0 (2022-12-01)

- updated dependencies
- the MSRV is 1.60.0 for the CLI utility (binary) but still 1.56.1 if you use
  this crate as library.


# v1.4.0 (2022-06-09)

- small **breaking** change: import paths of `ttfb::outcome::TtfbOutcome` and `ttfb::error::TtfbError`
  were flattened to `ttfb::{TtfbError, TtfbOutcome}`
- small internal code and documentation improvements


# v1.3.1 (2022-03-22)

- bugfix, also allow https for IP-Addresses (`$ ttfb https://1.1.1.1` is valid)
- updated dependencies


# v1.3.0 (2022-01-19)

- improved code quality
- improved doc
- updated dependencies
- Rust edition 2021
- MSRV is 1.56.1 stable


# v1.2.0 (2021-07-16)

- added `-k/--insecure` to CLI
- added `allow_insecure_certificates` as second parameter to library function

This is breaking but because my library doesn't have much or zero users yet,
it's okay not to bump the major version.

Example: `$ ttfb -k https://expired.badssl.com`

You can also type `$ ttfb --help` now.

CLI parsing is backed up by the crate `clap` now.


# v1.1.2 (2021-07-13)

- Typo in README


# v1.1.1 (2021-07-12)

- better error handling
- call flush to make sure all the streams are actually committed


# v1.1.0 (2021-07-10)

- better output of CLI
- removed Display-trait for struct `TtfbOutcome`
- all times are given relative and total


# v1.0.1 (2021-07-09)

- removed "termion" dependency
- cross-platform now (Linux, Mac, Windows)


# v1.0.0 (2021-07-09)

- initial release
