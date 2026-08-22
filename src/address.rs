use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use iroh::{EndpointAddr, unstable_net_report::NetReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nat64Prefix {
    pub network: Ipv6Addr,
    pub prefix_len: u8,
}

impl Nat64Prefix {
    pub fn synthesize(self, address: Ipv4Addr) -> Ipv6Addr {
        let mut out = self.network.octets();
        let v4 = address.octets();
        match self.prefix_len {
            32 => {
                out[4..8].copy_from_slice(&v4);
                out[8] = 0;
            }
            40 => {
                out[5..8].copy_from_slice(&v4[..3]);
                out[8] = 0;
                out[9] = v4[3];
            }
            48 => {
                out[6..8].copy_from_slice(&v4[..2]);
                out[8] = 0;
                out[9..11].copy_from_slice(&v4[2..]);
            }
            56 => {
                out[7] = v4[0];
                out[8] = 0;
                out[9..12].copy_from_slice(&v4[1..]);
            }
            64 => {
                out[8] = 0;
                out[9..13].copy_from_slice(&v4);
            }
            96 => out[12..16].copy_from_slice(&v4),
            _ => unreachable!("validated RFC 6052 prefix length"),
        }
        Ipv6Addr::from(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateStatus {
    pub address: SocketAddr,
    pub kind: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDiscoveryStatus {
    pub udp_ipv4: bool,
    pub udp_ipv6: bool,
    pub mapping_varies_by_destination_ipv4: Option<bool>,
    pub mapping_varies_by_destination_ipv6: Option<bool>,
    pub global_ipv4: Option<SocketAddr>,
    pub global_ipv6: Option<SocketAddr>,
    pub nat64_prefix: Option<Nat64Prefix>,
    pub candidates: Vec<CandidateStatus>,
}

pub fn network_discovery_status(
    endpoint_addr: &EndpointAddr,
    report: Option<&NetReport>,
    nat64_prefix: Option<Nat64Prefix>,
) -> NetworkDiscoveryStatus {
    let global_v4 = report
        .and_then(|report| report.global_v4)
        .map(SocketAddr::V4);
    let global_v6 = report
        .and_then(|report| report.global_v6)
        .map(SocketAddr::V6);
    let mut candidates = endpoint_addr
        .ip_addrs()
        .copied()
        .map(|address| CandidateStatus {
            address,
            kind: candidate_kind(address, global_v4, global_v6).into(),
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| (candidate.kind.clone(), candidate.address));
    NetworkDiscoveryStatus {
        udp_ipv4: report.is_some_and(|report| report.udp_v4),
        udp_ipv6: report.is_some_and(|report| report.udp_v6),
        mapping_varies_by_destination_ipv4: report
            .and_then(|report| report.mapping_varies_by_dest_ipv4),
        mapping_varies_by_destination_ipv6: report
            .and_then(|report| report.mapping_varies_by_dest_ipv6),
        global_ipv4: global_v4,
        global_ipv6: global_v6,
        nat64_prefix,
        candidates,
    }
}

fn candidate_kind(
    address: SocketAddr,
    global_v4: Option<SocketAddr>,
    global_v6: Option<SocketAddr>,
) -> &'static str {
    if Some(address) == global_v4 {
        return "qad_ipv4";
    }
    if Some(address) == global_v6 {
        return "qad_ipv6";
    }
    match address.ip() {
        std::net::IpAddr::V4(ip) if ip.is_private() || ip.is_link_local() => "host_ipv4",
        std::net::IpAddr::V4(ip)
            if global_v4.is_some_and(|global| global.ip() == std::net::IpAddr::V4(ip)) =>
        {
            "portmapped_or_static_ipv4"
        }
        std::net::IpAddr::V4(_) => "public_or_portmapped_ipv4",
        std::net::IpAddr::V6(ip) if ip.is_unique_local() || ip.is_unicast_link_local() => {
            "host_ipv6"
        }
        std::net::IpAddr::V6(_) => "public_ipv6",
    }
}

pub fn discover_nat64_prefix(addresses: impl IntoIterator<Item = Ipv6Addr>) -> Option<Nat64Prefix> {
    const PROBES: [[u8; 4]; 2] = [[192, 0, 0, 170], [192, 0, 0, 171]];
    for address in addresses {
        let bytes = address.octets();
        for (prefix_len, positions) in [
            (32, [4, 5, 6, 7]),
            (40, [5, 6, 7, 9]),
            (48, [6, 7, 9, 10]),
            (56, [7, 9, 10, 11]),
            (64, [9, 10, 11, 12]),
            (96, [12, 13, 14, 15]),
        ] {
            let embedded = positions.map(|position| bytes[position]);
            if PROBES.contains(&embedded) {
                let mut network = bytes;
                clear_after_prefix(&mut network, prefix_len);
                return Some(Nat64Prefix {
                    network: Ipv6Addr::from(network),
                    prefix_len,
                });
            }
        }
    }
    None
}

fn clear_after_prefix(bytes: &mut [u8; 16], prefix_len: u8) {
    let full = usize::from(prefix_len / 8);
    let partial = prefix_len % 8;
    if partial != 0 {
        bytes[full] &= u8::MAX << (8 - partial);
    }
    let start = full + usize::from(partial != 0);
    bytes[start..].fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{EndpointAddr, SecretKey};

    #[test]
    fn discovers_and_uses_well_known_nat64_prefix() {
        let prefix = discover_nat64_prefix(["64:ff9b::c000:aa".parse().unwrap()]).unwrap();
        assert_eq!(prefix.prefix_len, 96);
        assert_eq!(prefix.network, "64:ff9b::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            prefix.synthesize(Ipv4Addr::new(203, 0, 113, 8)),
            "64:ff9b::cb00:7108".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn discovers_rfc6052_non_96_prefix() {
        let prefix = Nat64Prefix {
            network: "2001:db8:1200::".parse().unwrap(),
            prefix_len: 40,
        };
        let probe = prefix.synthesize(Ipv4Addr::new(192, 0, 0, 170));
        assert_eq!(discover_nat64_prefix([probe]), Some(prefix));
    }

    #[test]
    fn exposes_qad_host_portmapped_and_ipv6_candidate_kinds() {
        let mut report = NetReport::default();
        report.udp_v4 = true;
        report.udp_v6 = true;
        report.global_v4 = Some("203.0.113.9:41000".parse().unwrap());
        report.global_v6 = Some("[2001:db8::9]:41000".parse().unwrap());
        report.mapping_varies_by_dest_ipv4 = Some(true);
        report.mapping_varies_by_dest_ipv6 = Some(false);
        let endpoint_addr = EndpointAddr::new(SecretKey::from_bytes(&[9; 32]).public())
            .with_ip_addr("192.168.1.4:10119".parse().unwrap())
            .with_ip_addr("203.0.113.9:41000".parse().unwrap())
            .with_ip_addr("203.0.113.9:10119".parse().unwrap())
            .with_ip_addr("[2001:db8::9]:41000".parse().unwrap());
        let status = network_discovery_status(&endpoint_addr, Some(&report), None);
        let kinds = status
            .candidates
            .iter()
            .map(|candidate| candidate.kind.as_str())
            .collect::<Vec<_>>();
        assert!(kinds.contains(&"host_ipv4"));
        assert!(kinds.contains(&"qad_ipv4"));
        assert!(kinds.contains(&"qad_ipv6"));
        assert!(kinds.contains(&"portmapped_or_static_ipv4"));
        assert_eq!(status.mapping_varies_by_destination_ipv4, Some(true));
        assert_eq!(status.mapping_varies_by_destination_ipv6, Some(false));
    }

    #[test]
    fn network_change_replaces_mapping_classification_and_candidates() {
        let endpoint_id = SecretKey::from_bytes(&[10; 32]).public();
        let mut before_report = NetReport::default();
        before_report.global_v4 = Some("198.51.100.1:40001".parse().unwrap());
        before_report.mapping_varies_by_dest_ipv4 = Some(false);
        let before = network_discovery_status(
            &EndpointAddr::new(endpoint_id).with_ip_addr("198.51.100.1:40001".parse().unwrap()),
            Some(&before_report),
            None,
        );
        let mut after_report = NetReport::default();
        after_report.global_v4 = Some("198.51.100.2:53000".parse().unwrap());
        after_report.mapping_varies_by_dest_ipv4 = Some(true);
        let after = network_discovery_status(
            &EndpointAddr::new(endpoint_id).with_ip_addr("198.51.100.2:53000".parse().unwrap()),
            Some(&after_report),
            Some(Nat64Prefix {
                network: "64:ff9b::".parse().unwrap(),
                prefix_len: 96,
            }),
        );
        assert_ne!(before, after);
        assert_eq!(after.mapping_varies_by_destination_ipv4, Some(true));
        assert!(after.nat64_prefix.is_some());
    }
}
