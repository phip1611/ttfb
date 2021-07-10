/*
MIT License

Copyright (c) 2021 Philipp Schuster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use crossterm::style::{Attribute, SetAttribute};
use crossterm::ExecutableCommand;
use std::env::args;
use std::io::stdout;
use std::process::exit;
use ttfb::error::{InvalidUrlError, TtfbError};
use ttfb::outcome::TtfbOutcome;
use std::time::Duration;

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

macro_rules! unwrap_or_exit {
    ($ident:ident) => {
        if let Err(err) = $ident {
            $crate::exit_error(err);
        } else {
            $ident.unwrap()
        }
    };
}

fn main() {
    let input = get_url_from_user();
    let input = unwrap_or_exit!(input);
    let res = ttfb::ttfb(input);
    let ttfb = unwrap_or_exit!(res);
    print_outcome(&ttfb).unwrap();
}

fn exit_error(err: TtfbError) -> ! {
    eprint!("\u{1b}[31m");
    eprint!("\u{1b}[1m");
    eprint!("ERROR: ",);
    eprint!("\u{1b}[0m");
    eprint!("{}", err);
    eprintln!();
    exit(-1)
}

/// Get the URL we want to check from the user as argument.
fn get_url_from_user() -> Result<String, TtfbError> {
    let args = args().collect::<Vec<_>>();
    args.get(1)
        .map(|s| s.to_owned())
        .ok_or(TtfbError::InvalidUrl(InvalidUrlError::MissingInput))
}

fn print_outcome(ttfb: &TtfbOutcome) -> Result<(), String> {
    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    println!(
        "TTFB for {url} (by ttfb@v{crate_version})",
        url = ttfb.user_input(),
        crate_version = CRATE_VERSION
    );
    println!("PROPERTY        REL TIME (ms)   ABS TIME (ms)");
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;
    if ttfb.dns_duration_rel().is_some() {
        print!(
            "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
            property = "DNS Lookup",
            rel_time = as_milli_fraction(ttfb.dns_duration_rel().unwrap()),
            // for DNS abs and rel time is the same (because it happens first)
            abs_time = as_milli_fraction(ttfb.dns_duration_rel().unwrap()),
        );
        if ttfb.dns_duration_rel().unwrap().as_millis() < 2 {
            print!("  (probably cached)");
        }
        println!();
    }
    println!(
        "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
        property = "TCP connect",
        rel_time = as_milli_fraction(&ttfb.tcp_connect_duration_rel()),
        abs_time = as_milli_fraction(&ttfb.tcp_connect_duration_abs()),
    );
    if ttfb.tls_handshake_duration_rel().is_some() {
        println!(
            "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
            property = "TLS Handshake",
            rel_time = as_milli_fraction(ttfb.tls_handshake_duration_rel().unwrap()),
            // for DNS abs and rel time is the same (because it happens first)
            abs_time = as_milli_fraction(&ttfb.tls_handshake_duration_abs().unwrap()),
        );
    }
    println!(
        "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
        property = "HTTP GET Req",
        rel_time = as_milli_fraction(&ttfb.http_get_send_duration_rel()),
        abs_time = as_milli_fraction(&ttfb.http_get_send_duration_abs()),
    );

    stdout()
        .execute(SetAttribute(Attribute::Bold))
        .map_err(|err| err.to_string())?;
    println!(
        "{property:<14}: {rel_time:>13.3}   {abs_time:>13.3}",
        property = "HTTP Resp TTFB",
        rel_time = as_milli_fraction(&ttfb.http_ttfb_duration_rel()),
        abs_time = as_milli_fraction(&ttfb.http_ttfb_duration_abs()),
    );
    stdout()
        .execute(SetAttribute(Attribute::Reset))
        .map_err(|err| err.to_string())?;

    Ok(())
}

fn as_milli_fraction(dur: &Duration) -> f64 {
    dur.as_micros() as f64 / 1000.0
}