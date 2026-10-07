// SPDX-License-Identifier: MIT

//! DNS lookups via the system's DNS configuration.
//!
//! hickory-resolver requires a Tokio runtime. So that measurements work with
//! every executor, each lookup runs on a helper thread with its own Tokio
//! runtime.

use crate::deadline::Deadline;
use crate::{IpVersion, ResolveDnsError, TtfbError};
use futures_channel::oneshot;
use hickory_resolver::Resolver as DnsResolver;
use hickory_resolver::config::LookupIpStrategy;
use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};
use tokio::runtime::Builder;

/// Looks up an address of `host` with the IP version `ip_version` until
/// `deadline`. Returns the address and the duration of the lookup.
pub async fn lookup(
    host: String,
    ip_version: IpVersion,
    deadline: Deadline,
) -> Result<(IpAddr, Duration), TtfbError> {
    let (sender, receiver) = oneshot::channel();
    // The deadline also ends the thread if the caller drops the lookup.
    thread::spawn(move || {
        let result = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("should be able to create a Tokio runtime")
            .block_on(deadline.run(lookup_with_hickory(&host, ip_version)));
        // The receiver is gone if the caller dropped the lookup.
        let _ = sender.send(result);
    });
    receiver
        .await
        .expect("the DNS lookup thread should send a result")
}

/// Looks up an address of `host` with the IP version `ip_version` via
/// hickory-resolver, which must run in a Tokio runtime.
async fn lookup_with_hickory(
    host: &str,
    ip_version: IpVersion,
) -> Result<(IpAddr, Duration), TtfbError> {
    // Construct a new DNS Resolver.
    // On Unix/Posix systems, this will read: /etc/resolv.conf
    // In the end, this uses the name server of the system or falls back to
    // the library's default (usually Google DNS).
    let mut builder = DnsResolver::builder_tokio()
        .map_err(|error| TtfbError::CantConfigureDNSError(error.to_string()))?;
    builder.options_mut().ip_strategy = match ip_version {
        IpVersion::Any => LookupIpStrategy::Ipv4thenIpv6,
        IpVersion::V4 => LookupIpStrategy::Ipv4Only,
        IpVersion::V6 => LookupIpStrategy::Ipv6Only,
    };
    let resolver = builder.build();

    let begin = Instant::now();
    let response = resolver
        .lookup_ip(host)
        .await
        .map(|res| res.iter().collect::<Vec<IpAddr>>())
        .map_err(|err| {
            if ip_version != IpVersion::Any && err.is_no_records_found() {
                TtfbError::NoAddressForIpVersion(ip_version)
            } else {
                TtfbError::CantResolveDns(ResolveDnsError::Other(err.to_string()))
            }
        })?;
    let duration = begin.elapsed();

    let ipv4_addr = response.iter().find(|addr| addr.is_ipv4());
    let ipv6_addr = response.iter().find(|addr| addr.is_ipv6());
    let addr = match ip_version {
        IpVersion::Any => ipv4_addr.or(ipv6_addr),
        IpVersion::V4 => ipv4_addr,
        IpVersion::V6 => ipv6_addr,
    };
    match addr {
        Some(addr) => Ok((*addr, duration)),
        None if ip_version == IpVersion::Any => {
            Err(TtfbError::CantResolveDns(ResolveDnsError::NoResults))
        }
        None => Err(TtfbError::NoAddressForIpVersion(ip_version)),
    }
}
