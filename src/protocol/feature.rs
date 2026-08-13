use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const DATA_PLANE: u16 = 1;
pub const ROUTING: u16 = 2;
pub const NODE_RECORD: u16 = 3;
pub const TRANSIT: u16 = 4;
pub const FEC: u16 = 5;
pub const MESH: u16 = 6;
pub const PRIVATE_LINK: u16 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureOffer {
    pub id: u16,
    pub min_version: u16,
    pub max_version: u16,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedFeature {
    pub id: u16,
    pub version: u16,
}

pub fn core_offers(transit: bool, fec: bool, mesh: bool, private_link: bool) -> Vec<FeatureOffer> {
    let mut offers = vec![
        offer(DATA_PLANE, true),
        offer(ROUTING, true),
        offer(NODE_RECORD, true),
    ];
    if transit {
        offers.push(offer(TRANSIT, false));
    }
    if fec {
        offers.push(offer(FEC, false));
    }
    if mesh {
        offers.push(offer(MESH, false));
    }
    if private_link {
        offers.push(offer(PRIVATE_LINK, true));
    }
    offers
}

fn offer(id: u16, required: bool) -> FeatureOffer {
    FeatureOffer {
        id,
        min_version: 1,
        max_version: 1,
        required,
    }
}

pub fn negotiate(
    local: &[FeatureOffer],
    remote: &[FeatureOffer],
) -> Result<Vec<NegotiatedFeature>> {
    validate(local)?;
    validate(remote)?;
    let remote_by_id = remote
        .iter()
        .map(|value| (value.id, value))
        .collect::<BTreeMap<_, _>>();
    let local_by_id = local
        .iter()
        .map(|value| (value.id, value))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::new();
    for offer in local {
        let Some(peer) = remote_by_id.get(&offer.id) else {
            ensure!(
                !offer.required,
                "required feature {} is unavailable",
                offer.id
            );
            continue;
        };
        let min = offer.min_version.max(peer.min_version);
        let max = offer.max_version.min(peer.max_version);
        ensure!(
            min <= max || (!offer.required && !peer.required),
            "feature {} has no compatible version",
            offer.id
        );
        if min <= max {
            selected.push(NegotiatedFeature {
                id: offer.id,
                version: max,
            });
        }
    }
    for offer in remote {
        ensure!(
            !offer.required || local_by_id.contains_key(&offer.id),
            "remote requires unsupported feature {}",
            offer.id
        );
    }
    selected.sort_by_key(|feature| feature.id);
    Ok(selected)
}

pub fn validate_selection(local: &[FeatureOffer], selected: &[NegotiatedFeature]) -> Result<()> {
    validate(local)?;
    let mut ids = BTreeSet::new();
    for feature in selected {
        ensure!(
            ids.insert(feature.id),
            "duplicate negotiated feature {}",
            feature.id
        );
        let offer = local
            .iter()
            .find(|offer| offer.id == feature.id)
            .ok_or_else(|| anyhow::anyhow!("peer selected unsupported feature {}", feature.id))?;
        ensure!(
            (offer.min_version..=offer.max_version).contains(&feature.version),
            "peer selected unsupported version for feature {}",
            feature.id
        );
    }
    for required in local.iter().filter(|offer| offer.required) {
        ensure!(
            selected.iter().any(|feature| feature.id == required.id),
            "peer omitted required feature {}",
            required.id
        );
    }
    Ok(())
}

fn validate(offers: &[FeatureOffer]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for offer in offers {
        ensure!(offer.id != 0, "feature id zero is reserved");
        ensure!(offer.min_version > 0, "feature version zero is reserved");
        ensure!(
            offer.min_version <= offer.max_version,
            "invalid feature version range"
        );
        ensure!(ids.insert(offer.id), "duplicate feature offer {}", offer.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_unknown_features_do_not_block_negotiation() {
        let local = core_offers(true, false, false, false);
        let mut remote = local.clone();
        remote.push(FeatureOffer {
            id: 999,
            min_version: 1,
            max_version: 1,
            required: false,
        });
        let selected = negotiate(&local, &remote).unwrap();
        assert!(!selected.iter().any(|feature| feature.id == 999));
        validate_selection(&local, &selected).unwrap();
    }

    #[test]
    fn required_unknown_feature_fails_closed() {
        let local = core_offers(false, false, false, false);
        let mut remote = local.clone();
        remote.push(FeatureOffer {
            id: 999,
            min_version: 1,
            max_version: 1,
            required: true,
        });
        assert!(negotiate(&local, &remote).is_err());
    }
}
