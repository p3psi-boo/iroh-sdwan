use std::{collections::BTreeMap, net::SocketAddr};

use ipnet::IpNet;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::config::NodeInfo;

/// Signed, gossipable node state. Pairwise link locators deliberately have no
/// representation here and therefore cannot leak through directory gossip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub endpoint_id: EndpointId,
    pub sequence: u64,
    pub issued_unix_secs: u64,
    pub expires_unix_secs: u64,
    #[serde(default)]
    pub capabilities: Vec<u16>,
    #[serde(default)]
    pub public_locators: Vec<SocketAddr>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    #[serde(default)]
    pub owned_prefixes: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
    /// Opaque extension values are signed and forwarded unchanged.
    #[serde(default)]
    pub extensions: BTreeMap<u16, Vec<u8>>,
}
