# TTFB: CLI + Lib to Measure the TTFB of HTTP Requests

Similar to the network tab in Google Chrome or Mozilla Firefox, this
crate helps you find the timings for:

- DNS lookup (if domain is specified, i.e., no IP is given)
- TCP connection start
- TLS handshake (if https/TLS is used)
- QUIC handshake (if HTTP/3 is used)
- Initial GET-Request
- TTFB (Time To First Byte)
- Content download

HTTP/1.1, HTTP/2, and HTTP/3 are supported. The content download covers the
response from its first byte until it is complete, as transferred; compressed
content is not decompressed.

It builds upon the crates [hickory-resolver](https://crates.io/crates/hickory-resolver)
for DNS resolving, [rustls](https://crates.io/crates/rustls) for TLS 1.2/1.3,
[h2](https://crates.io/crates/h2) for HTTP/2, and
[quinn](https://crates.io/crates/quinn) with [h3](https://crates.io/crates/h3)
for HTTP/3.

## Cross Platform
CLI + lib work on Linux, MacOS, and Windows.

## Usage Binary/CLI tool
Install with `cargo install ttfb --features bin`. It takes one argument and passes it to the library.
The string you pass here as first argument is the same as for `TtfbClient::measure()`.

Additionally, the CLI takes a `-k/--insecure` option. \
Example: `$ ttfb -k https://expired.badssl.com`

By default, the CLI tries HTTP/3, then HTTP/2, and finally HTTP/1.1. For HTTPS
servers without HTTP/3, the HTTP/3 attempt usually waits for its timeout of
1 s, which prolongs the run but not the measured timings. Use `--http1.1`,
`--http2`, or `--http3` to require a protocol.

With `--repeat N`, the CLI measures N times, and with `--repeat Ns`
repeatedly for N seconds. Then, it prints the minimum, median, mean, and
maximum of each step and of the total time. All measurements use the protocol of the first one. \
Example: `$ ttfb --repeat 10 https://phip1611.de` or
`$ ttfb --repeat 5s https://phip1611.de`

A measurement fails if it takes longer than 10 s. Use `--timeout <SECS>` to
change this limit to between 1 s and 3600 s. With `--repeat`, it applies to
each measurement.

With `--headers`, the CLI also prints the status line and the headers of the
response, which often explain the timings, e.g., `cache-status` or
`server-timing`. With `--repeat`, it prints those of the first measurement.

## Usage Library
The library exposes `TtfbClient`, which is configured with `TtfbOptions`:

```rust
use ttfb::{HttpProtocol, ProtocolSelection, TtfbClient, TtfbOptions};

let client = TtfbClient::new(TtfbOptions {
    protocol: ProtocolSelection::Only(HttpProtocol::Http2),
    ..TtfbOptions::default()
});
let outcome = client.measure("https://phip1611.de")?;
```

HTTP/2 and HTTP/3 support come with the Cargo features `http2` and `http3`,
which are enabled by default. Without them, measurements with the respective
protocol fail with `TtfbError::UnsupportedHttpProtocol`, and the automatic
protocol selection skips it.

The input string can be for example:
- `phip1611.de` (defaults to `http://`)
- `http://phip1611.de`
- `https://phip1611.de`
- `https://phip1611.de?foo=bar`
- `https://sub.domain.phip1611.de?foo=bar`
- `http://12.34.56.78/foobar`
- `https://1.1.1.1`
- `12.34.56.78/foobar` (defaults to `http://`)
- `12.34.56.78` (defaults to `http://`)

## Example Output
If you installed the CLI and invoke it like `$ ttfb https://phip1611.de`, the output will look like:
```text
TTFB for https://phip1611.de (by ttfb@v2.0.0)
Address       : 85.13.155.159:443
Protocol      : HTTP/2 (selected automatically)
Status        : 200 OK
PROPERTY        REL TIME (ms)   ABS TIME (ms)
DNS Lookup    :           1.1             1.1  (probably cached)
TCP Connect   :           8.0             9.1
TLS Handshake :          15.3            24.5
HTTP Send GET :           0.1            24.6
HTTP Resp TTFB:          32.1            56.7
HTTP Download :           0.0            56.7
```

For HTTP/3, the QUIC handshake replaces the TCP connect and the TLS handshake:
```text
TTFB for https://www.cloudflare.com (by ttfb@v2.0.0)
Address       : 104.16.124.96:443
Protocol      : HTTP/3 (selected automatically)
Status        : 200 OK
PROPERTY        REL TIME (ms)   ABS TIME (ms)
DNS Lookup    :           1.1             1.1  (probably cached)
QUIC Handshake:          16.6            17.6
HTTP Send GET :           0.1            17.7
HTTP Resp TTFB:          80.4            98.1
HTTP Download :         295.3           393.5
```

With `--repeat`, the output shows statistics of each step and of the total time
instead:
```text
$ ttfb --repeat 2s https://phip1611.de
TTFB for https://phip1611.de (by ttfb@v2.0.0)
Address       : 85.13.155.159:443
Protocol      : HTTP/2 (selected automatically)
Status        : 200 OK
Measurements  : 19
PROPERTY             MIN (ms)     MEDIAN (ms)       MEAN (ms)        MAX (ms)
DNS Lookup    :           0.9             1.1             1.3             3.3  (probably cached)
TCP Connect   :           6.7             7.8             8.0            12.5
TLS Handshake :          12.8            14.6            14.7            16.0
HTTP Send GET :           0.1             0.1             0.1             0.2
HTTP Resp TTFB:          17.4            29.9            27.6            38.4
HTTP Download :           0.0             0.0             0.0             0.0
Total         :          38.9            53.6            51.7            62.8
```

## MSRV
The MSRV of the library is `1.85.0` stable.
The MSRV of the binary is `1.85.0` stable.
