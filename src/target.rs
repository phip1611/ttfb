// SPDX-License-Identifier: MIT

//! URL parsing and DNS resolution of the measurement target.

use crate::deadline::Deadline;
use crate::{InvalidUrlError, IpVersion, TtfbError, dns};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use url::Url;

/// Parses the string input into an [`Url`] object.
fn parse_input_as_url(input: &str) -> Result<Url, TtfbError> {
    Url::parse(input)
        .map_err(|e| TtfbError::InvalidUrl(InvalidUrlError::WrongFormat(e.to_string())))
}

/// Prepends the default scheme `http://` is necessary to the user input.
fn prepend_default_scheme_if_necessary(url: String) -> String {
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
fn check_scheme_is_allowed(url: &Url) -> Result<(), TtfbError> {
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

/// Checks that `addr` has the IP version `ip_version`.
const fn check_ip_version(addr: IpAddr, ip_version: IpVersion) -> Result<(), TtfbError> {
    match (ip_version, addr) {
        (IpVersion::V4, IpAddr::V6(_)) | (IpVersion::V6, IpAddr::V4(_)) => {
            Err(TtfbError::NoAddressForIpVersion(ip_version))
        }
        _ => Ok(()),
    }
}

/// Checks from the URL if we already have an IP address or not.
/// If the user gave us a domain name, we resolve it with [`dns::lookup`] and
/// measure the time for it. The address has the IP version `ip_version`.
async fn resolve_dns_if_necessary(
    url: &Url,
    ip_version: IpVersion,
    deadline: Deadline,
) -> Result<(IpAddr, Option<Duration>), TtfbError> {
    match url.domain() {
        Some(domain) => {
            // shortcut
            if domain.eq("localhost") {
                let localhost = match ip_version {
                    IpVersion::Any | IpVersion::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpVersion::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
                };
                Ok((localhost, Some(Duration::default())))
            } else {
                let host = domain.to_owned();
                let (addr, duration) = dns::lookup(host, ip_version, deadline).await?;
                Ok((addr, Some(duration)))
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
            check_ip_version(addr, ip_version)?;

            Ok((addr, None))
        }
    }
}

/// The resolved destination of a measurement.
#[derive(Clone, Debug)]
pub struct Target {
    /// The user input, including the default scheme if it was missing.
    pub input: String,
    /// The parsed URL.
    pub url: Url,
    /// The resolved IP address.
    pub address: IpAddr,
    /// The port, explicit or the scheme's default.
    pub port: u16,
    /// The duration of the DNS lookup, if one was necessary.
    pub dns_duration: Option<Duration>,
}

impl Target {
    /// Parses `input` as an HTTP(S) URL and resolves its host to an address of
    /// the IP version `ip_version` until `deadline`.
    ///
    /// `input` without a scheme defaults to `http://`.
    pub async fn resolve(
        input: &str,
        ip_version: IpVersion,
        deadline: Deadline,
    ) -> Result<Self, TtfbError> {
        if input.is_empty() {
            return Err(TtfbError::InvalidUrl(InvalidUrlError::MissingInput));
        }
        let input = prepend_default_scheme_if_necessary(input.to_owned());
        let url = parse_input_as_url(&input)?;
        check_scheme_is_allowed(&url)?;
        let (address, dns_duration) = resolve_dns_if_necessary(&url, ip_version, deadline).await?;
        let port = url
            .port_or_known_default()
            .expect("http and https URLs should have a known default port");
        Ok(Self {
            input,
            url,
            address,
            port,
            dns_duration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_io::block_on;

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
            block_on(resolve_dns_if_necessary(
                &url,
                IpVersion::Any,
                Deadline::for_tests()
            )),
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

    #[test]
    fn resolve_defaults_to_http() {
        let target = block_on(Target::resolve(
            "localhost",
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .unwrap();
        assert_eq!(target.input, "http://localhost");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn resolve_localhost_with_ip_version() {
        for (ip_version, expected) in [
            (IpVersion::Any, "127.0.0.1"),
            (IpVersion::V4, "127.0.0.1"),
            (IpVersion::V6, "::1"),
        ] {
            let target = block_on(Target::resolve(
                "localhost",
                ip_version,
                Deadline::for_tests(),
            ))
            .unwrap();
            assert_eq!(target.address, IpAddr::from_str(expected).unwrap());
        }
    }

    #[test]
    fn resolve_ip_address_with_ip_version() {
        let resolve = |input, ip_version| {
            block_on(Target::resolve(input, ip_version, Deadline::for_tests()))
                .map(|target| target.address)
        };
        let ipv4 = IpAddr::from_str("1.1.1.1").unwrap();
        let ipv6 = IpAddr::from_str("::1").unwrap();
        assert_eq!(resolve("http://1.1.1.1", IpVersion::Any), Ok(ipv4));
        assert_eq!(resolve("http://1.1.1.1", IpVersion::V4), Ok(ipv4));
        assert_eq!(
            resolve("http://1.1.1.1", IpVersion::V6),
            Err(TtfbError::NoAddressForIpVersion(IpVersion::V6))
        );
        assert_eq!(resolve("http://[::1]", IpVersion::Any), Ok(ipv6));
        assert_eq!(
            resolve("http://[::1]", IpVersion::V4),
            Err(TtfbError::NoAddressForIpVersion(IpVersion::V4))
        );
        assert_eq!(resolve("http://[::1]", IpVersion::V6), Ok(ipv6));
    }

    #[test]
    fn resolve_rejects_empty_input() {
        assert_eq!(
            block_on(Target::resolve("", IpVersion::Any, Deadline::for_tests())).unwrap_err(),
            TtfbError::InvalidUrl(InvalidUrlError::MissingInput)
        );
    }
}

/// Tests that rely on an external network connection.
#[cfg(all(test, network_tests))]
mod network_tests {
    use super::*;
    use async_io::block_on;

    #[test]
    fn test_resolve_dns_if_necessary() {
        let url1 = Url::from_str("http://phip1611.de").expect("must be valid");
        let url2 = Url::from_str("https://phip1611.de").expect("must be valid");
        let url3 = Url::from_str("http://192.168.1.102").expect("must be valid");
        let url4 = Url::from_str("http://[2001:0db8:3c4d:0015::1a2f:1a2b]").expect("must be valid");
        let url5 = Url::from_str("http://[2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b]")
            .expect("must be valid");

        block_on(resolve_dns_if_necessary(
            &url1,
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .expect("must be valid");
        block_on(resolve_dns_if_necessary(
            &url2,
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .expect("must be valid");
        block_on(resolve_dns_if_necessary(
            &url3,
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .expect("must be valid");
        block_on(resolve_dns_if_necessary(
            &url4,
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .expect("must be valid");
        block_on(resolve_dns_if_necessary(
            &url5,
            IpVersion::Any,
            Deadline::for_tests(),
        ))
        .expect("must be valid");
    }

    #[test]
    fn resolve_dns_with_ip_version() {
        // one.one.one.one has IPv4 and IPv6 addresses.
        let address = |ip_version| {
            block_on(Target::resolve(
                "one.one.one.one",
                ip_version,
                Deadline::for_tests(),
            ))
            .unwrap()
            .address
        };
        assert!(address(IpVersion::Any).is_ipv4());
        assert!(address(IpVersion::V4).is_ipv4());
        assert!(address(IpVersion::V6).is_ipv6());
    }

    #[test]
    fn resolve_dns_without_address_of_ip_version() {
        // ipv4.google.com only has IPv4 addresses.
        assert_eq!(
            block_on(Target::resolve(
                "ipv4.google.com",
                IpVersion::V6,
                Deadline::for_tests()
            ))
            .unwrap_err(),
            TtfbError::NoAddressForIpVersion(IpVersion::V6)
        );
    }
}
