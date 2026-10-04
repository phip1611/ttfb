// SPDX-License-Identifier: MIT

//! URL parsing and DNS resolution of the measurement target.

use crate::{InvalidUrlError, ResolveDnsError, TtfbError};
use hickory_resolver::Resolver as DnsResolver;
use std::net::IpAddr;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

/// Parses the string input into an [`Url`] object.
pub fn parse_input_as_url(input: &str) -> Result<Url, TtfbError> {
    Url::parse(input)
        .map_err(|e| TtfbError::InvalidUrl(InvalidUrlError::WrongFormat(e.to_string())))
}

/// Prepends the default scheme `http://` is necessary to the user input.
pub fn prepend_default_scheme_if_necessary(url: String) -> String {
    const SCHEME_SEPARATOR: &str = "://";
    const DEFAULT_SCHEME: &str = "http";

    if url.contains(SCHEME_SEPARATOR) {
        url
    } else {
        format!("{DEFAULT_SCHEME}://{url}")
    }
}

/// Checks the scheme is on the allow list. Currently, we only allow "http"
/// and "https".
pub fn check_scheme_is_allowed(url: &Url) -> Result<(), TtfbError> {
    let actual_scheme = url.scheme();
    let allowed_scheme = actual_scheme == "http" || actual_scheme == "https";
    if allowed_scheme {
        Ok(())
    } else {
        Err(TtfbError::InvalidUrl(InvalidUrlError::WrongScheme(
            actual_scheme.to_string(),
        )))
    }
}

/// Checks from the URL if we already have an IP address or not.
/// If the user gave us a domain name, we resolve it using the
/// [`hickory_resolver`] crate and measure the time for it.
pub fn resolve_dns_if_necessary(url: &Url) -> Result<(IpAddr, Option<Duration>), TtfbError> {
    match url.domain() {
        Some(domain) => {
            // shortcut
            if domain.eq("localhost") {
                Ok((
                    IpAddr::from_str("127.0.0.1").unwrap(),
                    Some(Duration::default()),
                ))
            } else {
                resolve_dns(url).map(|(addr, dur)| (addr, Some(dur)))
            }
        }
        None => {
            let mut ip_str = url.host_str().unwrap();
            // [a::b::c::d::e::f::0::1] => ipv6 address
            let is_ipv6_addr = ip_str.starts_with('[');
            if is_ipv6_addr {
                ip_str = &ip_str[1..ip_str.len() - 1];
            }
            let addr = IpAddr::from_str(ip_str)
                .map_err(|e| TtfbError::InvalidUrl(InvalidUrlError::WrongFormat(e.to_string())))?;

            Ok((addr, None))
        }
    }
}

/// Actually resolves a domain using the systems default DNS resolver.
/// Helper function for [`resolve_dns_if_necessary`].
fn resolve_dns(url: &Url) -> Result<(IpAddr, Duration), TtfbError> {
    // Construct a new DNS Resolver.
    // On Unix/Posix systems, this will read: /etc/resolv.conf
    // In the end, this uses the name server of the system or falls back to
    // the library's default (usually Google DNS).
    let resolver = DnsResolver::builder_tokio()
        .map_err(TtfbError::CantConfigureDNSError)?
        .build();

    let begin = Instant::now();

    // We do the DNS resolving in a tokio runtime in a background task. There
    // are two reasons for that:
    // - I must use tokio because of `hickory_resolver`; I'd like to get rid of
    //   it
    // - This library is designed with a blocking API but should be embeddable
    //   in a tokio runtime. To prevent the start of a tokio runtime in a thread
    //   already having a tokio runtime, we spawn a dedicated thread.
    //
    // For the performance/measurements, this overhead is negligible.
    //
    // More info: https://stackoverflow.com/a/62536772/2891595
    let response = {
        thread::scope(|s| {
            s.spawn(|| {
                let tokio = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .enable_io()
                    .build()
                    .unwrap();
                tokio.block_on(async {
                    resolver
                        .lookup_ip(url.host_str().unwrap())
                        .await
                        .map(|res| res.iter().collect::<Vec<IpAddr>>())
                        .map_err(|err| {
                            TtfbError::CantResolveDns(ResolveDnsError::Other(Box::new(err)))
                        })
                })
            })
            .join()
            .unwrap()
        })
    }?;

    let duration = begin.elapsed();

    let ipv4_addrs = response
        .iter()
        .filter(|addr| addr.is_ipv4())
        .collect::<Vec<_>>();
    let ipv6_addrs = response
        .iter()
        .filter(|addr| addr.is_ipv6())
        .collect::<Vec<_>>();

    if !ipv4_addrs.is_empty() {
        Ok((*ipv4_addrs[0], duration))
    } else if !ipv6_addrs.is_empty() {
        Ok((*ipv6_addrs[0], duration))
    } else {
        Err(TtfbError::CantResolveDns(ResolveDnsError::NoResults))
    }
}

#[cfg(all(test, not(network_tests)))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_input_as_url() {
        parse_input_as_url("http://google.com").expect("to be valid");
        parse_input_as_url("https://google.com:443").expect("to be valid");
        parse_input_as_url("http://google.com:80").expect("to be valid");
        parse_input_as_url("google.com:80").expect("to be valid");
        parse_input_as_url("http://google.com/foobar").expect("to be valid");
        parse_input_as_url("https://google.com:443/foobar").expect("to be valid");
        parse_input_as_url("https://goo-gle.com:443/foobar").expect("to be valid");
        parse_input_as_url("https://goo-gle.com:443/foobar?124141").expect("to be valid");
        parse_input_as_url("https://subdomain.goo-gle.com:443/foobar?124141").expect("to be valid");
        parse_input_as_url("https://192.168.1.102:443/foobar?124141").expect("to be valid");

        parse_input_as_url("http://localhost").expect("to be valid");
    }

    #[test]
    fn test_append_scheme_if_necessary() {
        assert_eq!(
            prepend_default_scheme_if_necessary("phip1611.de".to_owned()),
            "http://phip1611.de"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary("https://phip1611.de".to_owned()),
            "https://phip1611.de"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary("192.168.1.102:443/foobar?124141".to_owned()),
            "http://192.168.1.102:443/foobar?124141"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary(
                "https://192.168.1.102:443/foobar?124141".to_owned()
            ),
            "https://192.168.1.102:443/foobar?124141"
        );
        assert_eq!(
            prepend_default_scheme_if_necessary("ftp://192.168.1.102:443/foobar?124141".to_owned()),
            "ftp://192.168.1.102:443/foobar?124141"
        );
    }

    #[test]
    fn test_dns_if_necessary_localhost_shortcut() {
        let url = url::Url::from_str("http://localhost").unwrap();
        assert_eq!(
            resolve_dns_if_necessary(&url),
            Ok((
                IpAddr::from_str("127.0.0.1").unwrap(),
                Some(Duration::from_secs(0))
            ))
        );
    }

    #[test]
    fn test_check_scheme() {
        check_scheme_is_allowed(
            &Url::from_str(&prepend_default_scheme_if_necessary(
                "phip1611.de".to_owned(),
            ))
            .unwrap(),
        )
        .expect("must accept http");
        check_scheme_is_allowed(
            &Url::from_str(&prepend_default_scheme_if_necessary(
                "https://phip1611.de".to_owned(),
            ))
            .unwrap(),
        )
        .expect("must accept http");
        check_scheme_is_allowed(
            &Url::from_str(&prepend_default_scheme_if_necessary(
                "ftp://phip1611.de".to_owned(),
            ))
            .unwrap(),
        )
        .expect_err("must not accept ftp");
    }
}

/// Tests that rely on an external network connection.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;

    #[test]
    fn test_resolve_dns_if_necessary() {
        let url1 = Url::from_str("http://phip1611.de").expect("must be valid");
        let url2 = Url::from_str("https://phip1611.de").expect("must be valid");
        let url3 = Url::from_str("http://192.168.1.102").expect("must be valid");
        let url4 = Url::from_str("http://[2001:0db8:3c4d:0015::1a2f:1a2b]").expect("must be valid");
        let url5 = Url::from_str("http://[2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b]")
            .expect("must be valid");

        resolve_dns_if_necessary(&url1).expect("must be valid");
        resolve_dns_if_necessary(&url2).expect("must be valid");
        resolve_dns_if_necessary(&url3).expect("must be valid");
        resolve_dns_if_necessary(&url4).expect("must be valid");
        resolve_dns_if_necessary(&url5).expect("must be valid");
    }
}
