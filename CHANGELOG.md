# Unreleased (Yet)

- fix: use this library in a tokio runtime without raising a panic
- `TtfbError` now implements `PartialEq`

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
