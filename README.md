# TTFB: CLI + Lib to Measure the TTFB of HTTP/1.1 Requests

Similar to the network tab in Google Chrome or Mozilla Firefox, this
crate helps you find the timings for:

- DNS lookup (if domain is specified, i.e., no IP is given)
- TCP connection start
- TLS handshake (if https/TLS is used)
- Initial GET-Request
- TTFB (Time To First Byte)

It builds upon the crates [trust-dns-resolver](crates.io/crate/trust-dns-resolver) for modern and secure
DNS resolving of domains and [native-tls](crates.io/crate/native-tls) for handling TLS v1.2/1.3.

## Cross Platform
CLI + lib work on Linux, MacOS, and Windows.

## Usage Binary/CLI tool
Install with `cargo install ttfb --features bin`. It takes one argument and passes it to the library.
The string you pass here as first argument is the same as for the library function.

Additionally, the CLI takes a `-k/--insecure` option. \
Example: `$ ttfb -k https://expired.badssl.com`

## Usage Library
The library exposes the function `ttfb(url: String)`. The string can be for example:
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
TTFB for https://phip1611.de (by ttfb@v1.1.1)
PROPERTY        REL TIME (ms)   ABS TIME (ms)
DNS Lookup    :         0.755           0.755  (probably cached)
TCP connect   :        35.484          36.239
TLS Handshake :        36.363          72.603
HTTP GET Req  :         0.011          72.614
HTTP Resp TTFB:        76.432         149.046
```

## MSRV
The MSRV of the library is `1.75.0` stable.
The MSRV of the binary is `1.75.0` stable.
