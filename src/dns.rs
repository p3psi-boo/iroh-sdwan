//! DNS-facing V2 status and reverse-zone helpers.
//!
//! V2 Presence owns peer discovery. The removed V1 mesh directory is not a
//! DNS data source; a future V2 catalog publisher consumes authenticated
//! `PresenceDirectoryV2` snapshots directly.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStatus {
    pub domain: String,
    pub listen_addr: SocketAddr,
    pub queries: u64,
    pub catalog_generation: u64,
    pub nodes: u64,
    pub conflicting_labels: u64,
}

/// Convert an arbitrary IP prefix into the smallest set of octet/nibble
/// aligned reverse-DNS routing domains without claiming a broader prefix.
pub fn reverse_routing_domains(prefix: IpNet) -> Vec<String> {
    match prefix {
        IpNet::V4(prefix) => reverse_v4_domains(prefix.network(), prefix.prefix_len()),
        IpNet::V6(prefix) => reverse_v6_domains(prefix.network(), prefix.prefix_len()),
    }
}

fn reverse_v4_domains(network: Ipv4Addr, prefix_len: u8) -> Vec<String> {
    let aligned = prefix_len.div_ceil(8) * 8;
    let count = 1_u16 << (aligned - prefix_len);
    let step = if aligned == 0 {
        0
    } else {
        1_u32 << (32 - aligned)
    };
    let base = u32::from(network);
    (0..count)
        .map(|offset| {
            let address = Ipv4Addr::from(base + u32::from(offset) * step);
            let octets = address.octets();
            let labels = octets[..usize::from(aligned / 8)]
                .iter()
                .rev()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".");
            if labels.is_empty() {
                "in-addr.arpa".into()
            } else {
                format!("{labels}.in-addr.arpa")
            }
        })
        .collect()
}

fn reverse_v6_domains(network: Ipv6Addr, prefix_len: u8) -> Vec<String> {
    let aligned = prefix_len.div_ceil(4) * 4;
    let count = 1_u16 << (aligned - prefix_len);
    let step = match aligned {
        0 => 0,
        128 => 1,
        _ => 1_u128 << (128 - aligned),
    };
    let base = u128::from(network);
    (0..count)
        .map(|offset| {
            let hex = format!("{:032x}", base + u128::from(offset) * step);
            let labels = hex[..usize::from(aligned / 4)]
                .chars()
                .rev()
                .map(|nibble| nibble.to_string())
                .collect::<Vec<_>>()
                .join(".");
            if labels.is_empty() {
                "ip6.arpa".into()
            } else {
                format!("{labels}.ip6.arpa")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_routing_does_not_broaden_non_aligned_prefixes() {
        assert_eq!(
            reverse_routing_domains("0.0.0.0/0".parse().unwrap()),
            ["in-addr.arpa"]
        );
        assert_eq!(
            reverse_routing_domains("::/0".parse().unwrap()),
            ["ip6.arpa"]
        );
        let domains = reverse_routing_domains("100.64.0.0/10".parse().unwrap());
        assert_eq!(domains.len(), 64);
        assert_eq!(domains.first().unwrap(), "64.100.in-addr.arpa");
        assert_eq!(domains.last().unwrap(), "127.100.in-addr.arpa");
        let domains = reverse_routing_domains("fd42:6972:6f68::/64".parse().unwrap());
        assert_eq!(domains.len(), 1);
        assert!(domains[0].ends_with("ip6.arpa"));
    }
}
