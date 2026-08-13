use std::collections::BTreeMap;

use ipnet::IpNet;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteOrigin {
    pub owner: EndpointId,
    pub sequence: u64,
    pub prefixes: Vec<IpNet>,
    #[serde(default)]
    pub attributes: BTreeMap<u16, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePath {
    pub origin: EndpointId,
    pub next_hop: EndpointId,
    pub path: Vec<EndpointId>,
    pub metric: u32,
    #[serde(default)]
    pub attributes: BTreeMap<u16, Vec<u8>>,
}
