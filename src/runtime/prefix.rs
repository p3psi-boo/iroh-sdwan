//! Immutable prefix indexes shared by every dataplane shard.

use std::net::IpAddr;

use ipnet::IpNet;
use iroh::EndpointId;
use rustc_hash::{FxHashMap, FxHashSet};

/// Prefix membership indexed by the distinct lengths present in the immutable
/// generation. Fx hashing keeps the lookup cheap while avoiding a scan over
/// every configured prefix.
#[derive(Debug, Default)]
pub(super) struct IpPrefixSet {
    v4: FxHashSet<(u8, u32)>,
    v6: FxHashSet<(u8, u128)>,
    v4_lengths: Vec<u8>,
    v6_lengths: Vec<u8>,
}

impl IpPrefixSet {
    pub(super) fn from_prefixes(prefixes: impl IntoIterator<Item = IpNet>) -> Self {
        let mut set = Self::default();
        for prefix in prefixes {
            match prefix {
                IpNet::V4(prefix) => {
                    let length = prefix.prefix_len();
                    set.v4
                        .insert((length, mask_v4(u32::from(prefix.network()), length)));
                }
                IpNet::V6(prefix) => {
                    let length = prefix.prefix_len();
                    set.v6
                        .insert((length, mask_v6(u128::from(prefix.network()), length)));
                }
            }
        }
        set.v4_lengths = set.v4.iter().map(|(length, _)| *length).collect();
        set.v4_lengths
            .sort_unstable_by(|left, right| right.cmp(left));
        set.v4_lengths.dedup();
        set.v6_lengths = set.v6.iter().map(|(length, _)| *length).collect();
        set.v6_lengths
            .sort_unstable_by(|left, right| right.cmp(left));
        set.v6_lengths.dedup();
        set
    }

    pub(super) fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => {
                let address = u32::from(address);
                self.v4_lengths
                    .iter()
                    .any(|length| self.v4.contains(&(*length, mask_v4(address, *length))))
            }
            IpAddr::V6(address) => {
                let address = u128::from(address);
                self.v6_lengths
                    .iter()
                    .any(|length| self.v6.contains(&(*length, mask_v6(address, *length))))
            }
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct PrefixOwnerTable {
    v4: FxHashMap<(u8, u32), EndpointId>,
    v6: FxHashMap<(u8, u128), EndpointId>,
    v4_lengths: Vec<u8>,
    v6_lengths: Vec<u8>,
}

impl PrefixOwnerTable {
    pub(super) fn from_origins(origins: impl IntoIterator<Item = (EndpointId, IpNet)>) -> Self {
        let mut table = Self::default();
        for (owner, prefix) in origins {
            match prefix {
                IpNet::V4(prefix) => {
                    let length = prefix.prefix_len();
                    table.v4.insert(
                        (length, mask_v4(u32::from(prefix.network()), length)),
                        owner,
                    );
                    table.v4_lengths.push(length);
                }
                IpNet::V6(prefix) => {
                    let length = prefix.prefix_len();
                    table.v6.insert(
                        (length, mask_v6(u128::from(prefix.network()), length)),
                        owner,
                    );
                    table.v6_lengths.push(length);
                }
            }
        }
        table
            .v4_lengths
            .sort_unstable_by(|left, right| right.cmp(left));
        table.v4_lengths.dedup();
        table
            .v6_lengths
            .sort_unstable_by(|left, right| right.cmp(left));
        table.v6_lengths.dedup();
        table
    }

    pub(super) fn owner(&self, address: IpAddr) -> Option<EndpointId> {
        match address {
            IpAddr::V4(address) => {
                let address = u32::from(address);
                self.v4_lengths
                    .iter()
                    .find_map(|length| self.v4.get(&(*length, mask_v4(address, *length))).copied())
            }
            IpAddr::V6(address) => {
                let address = u128::from(address);
                self.v6_lengths
                    .iter()
                    .find_map(|length| self.v6.get(&(*length, mask_v6(address, *length))).copied())
            }
        }
    }
}

fn mask_v4(address: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        address
            & u32::MAX
                .checked_shl(u32::from(32 - prefix_len))
                .unwrap_or(0)
    }
}

fn mask_v6(address: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        address
            & u128::MAX
                .checked_shl(u32::from(128 - prefix_len))
                .unwrap_or(0)
    }
}
