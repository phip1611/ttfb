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
- cross platform now (Linux, Mac, Windows)

# v1.0.0 (2021-07-09)
- initial release
