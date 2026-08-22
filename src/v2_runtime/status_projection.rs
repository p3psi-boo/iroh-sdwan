//! Runtime-owned projection into the public V2 status DTOs.
//!
//! This stays deliberately small: it publishes immutable status snapshots
//! from the runtime's locks and telemetry, without owning the runtime state
//! or changing any dataplane/policy decision.

use std::{
    sync::{Arc, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ipnet::IpNet;
use iroh::{EndpointId, endpoint::Connection};

use super::{
    V2RuntimeState,
    telemetry::{RuntimeMetrics, path_endpoint_identity},
};
use crate::protocol::v2::{
    learner::LearnerTraceV2,
    policy_tick::{PolicySlotStatusV1, ShadowEvaluationV2},
    presence::PresenceDirectoryV2,
    tuning::TuneDecisionV2,
    utility::UtilitySample,
};

#[derive(Debug, Clone)]
pub(super) struct TuneStatusSampleV2<'a> {
    pub(super) decision: TuneDecisionV2,
    pub(super) utility: UtilitySample,
    pub(super) learner: LearnerTraceV2,
    pub(super) policy_id: &'a str,
    pub(super) policy_source: &'a str,
    pub(super) shadow_policy_id: Option<&'a str>,
    pub(super) shadow: Option<ShadowEvaluationV2>,
    pub(super) live: PolicySlotStatusV1,
    pub(super) shadow_slot: Option<PolicySlotStatusV1>,
    pub(super) egress_requested_bytes_per_second: u64,
    pub(super) egress_assigned_bytes_per_second: u64,
}

impl From<PolicySlotStatusV1> for crate::status::PolicySlotStatus {
    fn from(slot: PolicySlotStatusV1) -> Self {
        Self {
            policy_id: slot.policy_id,
            backend: slot.backend,
            policy_version: slot.policy_version,
            abi_version: slot.abi_version,
            module_digest: slot.module_digest,
            signer_id: slot.signer_id,
            module_generation: slot.module_generation,
            health: slot.health,
            state_schema: u64::from(slot.state_schema),
            state_bytes: slot.state_bytes,
            last_call_micros: slot.last_call_micros,
            fuel_consumed: slot.fuel_consumed,
            faults_total: slot.faults_total,
            timeouts_total: slot.timeouts_total,
            quarantines_total: slot.quarantines_total,
            clamped_fields_total: slot.clamped_fields_total,
            last_clamp_reasons: slot.last_clamp_reasons,
        }
    }
}

fn project_policy_slot(
    slot: PolicySlotStatusV1,
    fallback_policy_id: Option<&str>,
) -> crate::status::PolicySlotStatus {
    let mut status = crate::status::PolicySlotStatus::from(slot);
    if status.policy_id.is_empty() {
        status.policy_id = fallback_policy_id.unwrap_or_default().to_owned();
    }
    status
}

impl V2RuntimeState {
    pub(super) fn publish_routes(&self, prefixes: impl IntoIterator<Item = IpNet>) {
        let mut prefixes = prefixes.into_iter().collect::<Vec<_>>();
        prefixes
            .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        prefixes.dedup();
        *self
            .routes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = prefixes
            .into_iter()
            .map(|prefix| crate::status::RouteStatus {
                prefix: prefix.to_string(),
                present: true,
            })
            .collect();
        self.routes_ready.store(true, Ordering::Release);
    }

    pub(super) fn peer_status(
        interface: &str,
        tun_mtu: u16,
        endpoint_id: EndpointId,
    ) -> crate::status::PeerStatus {
        crate::status::PeerStatus {
            name: endpoint_id.to_string(),
            endpoint_id: endpoint_id.to_string(),
            interface: interface.to_owned(),
            protocol_major: u64::from(crate::protocol::v2::MAJOR),
            traffic: crate::status::PeerTrafficStatus {
                tun_mtu: u64::from(tun_mtu),
                ..crate::status::PeerTrafficStatus::default()
            },
            ..crate::status::PeerStatus::default()
        }
    }

    pub(super) fn mark_connected(&self, connection: &Connection) {
        let remote_id = connection.remote_id();
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peer = peers
            .entry(remote_id)
            .or_insert_with(|| Self::peer_status(&self.interface, self.tun_mtu, remote_id));
        peer.connected = true;
        peer.connection_events = peer.connection_events.saturating_add(1);
        self.connections
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(remote_id, connection.clone());
        Self::refresh_path(peer, connection);
    }

    pub(super) fn attach_metrics(&self, remote_id: EndpointId, metrics: Arc<RuntimeMetrics>) {
        self.metrics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(remote_id, metrics);
    }

    pub(super) fn publish_tune_status(
        &self,
        remote_id: EndpointId,
        sample: TuneStatusSampleV2<'_>,
    ) {
        let TuneStatusSampleV2 {
            decision,
            utility,
            learner,
            policy_id,
            policy_source,
            shadow_policy_id,
            shadow,
            live,
            shadow_slot,
            egress_requested_bytes_per_second,
            egress_assigned_bytes_per_second,
        } = sample;
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peer = peers
            .entry(remote_id)
            .or_insert_with(|| Self::peer_status(&self.interface, self.tun_mtu, remote_id));
        peer.tune_reason = format!("{:?}", decision.reason);
        peer.fec_geometry = decision.fec.map_or_else(
            || "off".to_owned(),
            |geometry| format!("{}+{}", geometry.data_cells, geometry.parity_cells),
        );
        peer.train_target_bytes = decision.train_target_bytes as u64;
        peer.bbr_preset = format!("{:?}", decision.bbr.preset);
        peer.utility_total = utility.total;
        peer.learner_mode = format!("{:?}", learner.mode);
        peer.learner_context = format!(
            "r{}-b{}-l{}-{}",
            learner.context.rtt_class,
            learner.context.rate_class,
            learner.context.loss_class,
            if learner.context.reliable {
                "reliable"
            } else {
                "datagram"
            }
        );
        peer.learner_rollbacks = learner.rollbacks;
        let live = project_policy_slot(live, Some(policy_id));
        let shadow_slot_status =
            shadow_slot.map(|slot| project_policy_slot(slot, shadow_policy_id));
        peer.policy = crate::status::PeerPolicyStatus {
            live,
            policy_source: policy_source.to_owned(),
            shadow: shadow_slot_status,
            shadow_preset: shadow.map_or_else(String::new, |candidate| {
                format!("{:?}", candidate.trace.proposed_preset)
            }),
            shadow_advantage: shadow.map_or(0.0, |candidate| candidate.trace.predicted_advantage),
        };
        peer.egress_requested_bytes_per_second = egress_requested_bytes_per_second;
        peer.egress_assigned_bytes_per_second = egress_assigned_bytes_per_second;
    }

    pub(super) fn publish_presence_directory(
        &self,
        directory: &PresenceDirectoryV2,
        max_total_peers: usize,
    ) {
        let mut nodes = directory
            .records()
            .map(|presence| crate::status::MeshNodeStatus {
                endpoint_id: presence.body.owner.to_string(),
                sequence: presence.body.sequence,
                expires_unix_secs: presence.body.expires_unix_secs,
                direct_addresses: presence.body.direct_addresses.clone(),
                node_addresses: presence.body.node_addresses.clone(),
                prefixes: presence.body.prefixes.clone(),
                transit_enabled: presence.body.transit_enabled,
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        *self
            .mesh
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = crate::status::MeshStatus {
            enabled: true,
            directory_entries: nodes.len(),
            max_total_peers,
            nodes,
        };
    }

    fn refresh_path(peer: &mut crate::status::PeerStatus, connection: &Connection) {
        let paths = connection.paths();
        peer.open_paths = paths.len() as u64;
        if let Some(path) = paths.iter().find(|path| path.is_selected()) {
            let stats = path.stats();
            peer.path_rtt_micros = stats.rtt.as_micros().min(u128::from(u64::MAX)) as u64;
            peer.path_cwnd_bytes = stats.cwnd;
            peer.path_mtu = u64::from(stats.current_mtu);
            peer.selected_path_remote = path_endpoint_identity(path.remote_addr());
            peer.selected_path_transport = if path.is_relay() {
                "relay".to_owned()
            } else {
                "direct".to_owned()
            };
        }
    }

    fn refresh_metrics(peer: &mut crate::status::PeerStatus, metrics: &RuntimeMetrics) {
        peer.traffic = metrics.traffic_snapshot(peer.traffic.tun_mtu);
    }

    pub async fn live_snapshot(&self) -> Result<crate::status::RuntimeStatus> {
        let mut peers = self
            .peers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let connections = self
            .connections
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let metrics = self
            .metrics
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for peer in &mut peers {
            let Ok(endpoint_id) = peer.endpoint_id.parse::<EndpointId>() else {
                continue;
            };
            if let Some(connection) = connections.get(&endpoint_id) {
                Self::refresh_path(peer, connection);
            }
            if let Some(peer_metrics) = metrics.get(&endpoint_id) {
                Self::refresh_metrics(peer, peer_metrics);
            }
        }
        peers.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        let routes_ready = self.routes_ready.load(Ordering::Acquire);
        let ready = !peers.is_empty() && peers.iter().all(|peer| peer.connected) && routes_ready;
        let updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(crate::status::RuntimeStatus {
            ready,
            endpoint_id: self.endpoint_id.to_string(),
            started_unix: self.started_unix,
            updated_unix,
            uptime_seconds: self.started_at.elapsed().as_secs(),
            routes_ready,
            routes: self
                .routes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            peers,
            mesh: self
                .mesh
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            gateway: self.gateway.clone(),
            tun_admission_drop_records: self
                .tun_ingress_metrics
                .tun_admission_drop_records
                .load(Ordering::Relaxed),
            tun_admission_drop_bytes: self
                .tun_ingress_metrics
                .tun_admission_drop_bytes
                .load(Ordering::Relaxed),
            ..crate::status::RuntimeStatus::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::Ordering,
        time::{SystemTime, UNIX_EPOCH},
    };

    use iroh::SecretKey;

    use super::*;
    use crate::protocol::v2::presence::{PresenceBodyV2, SignedPresenceV2};

    #[test]
    fn policy_slot_projection_keeps_slot_values_and_uses_only_empty_id_fallback() {
        let projected = project_policy_slot(
            PolicySlotStatusV1 {
                backend: "native".to_owned(),
                policy_id: String::new(),
                policy_version: "1.2.3".to_owned(),
                abi_version: "1.0".to_owned(),
                module_generation: 7,
                state_schema: 4,
                state_bytes: 512,
                health: "healthy".to_owned(),
                ..PolicySlotStatusV1::default()
            },
            Some("builtin"),
        );
        assert_eq!(projected.policy_id, "builtin");
        assert_eq!(projected.backend, "native");
        assert_eq!(projected.policy_version, "1.2.3");
        assert_eq!(projected.module_generation, 7);
        assert_eq!(projected.state_schema, 4);
        assert_eq!(projected.state_bytes, 512);
        assert_eq!(projected.health, "healthy");

        let preserved = project_policy_slot(
            PolicySlotStatusV1 {
                policy_id: "explicit-slot".to_owned(),
                ..PolicySlotStatusV1::default()
            },
            Some("fallback"),
        );
        assert_eq!(preserved.policy_id, "explicit-slot");
    }

    #[test]
    fn runtime_metrics_refreshes_only_v2_native_peer_telemetry() {
        let metrics = RuntimeMetrics::default();
        metrics.tun_ingress_records.store(11, Ordering::Relaxed);
        metrics.tun_ingress_bytes.store(12_000, Ordering::Relaxed);
        metrics.tun_rx_packets.store(7, Ordering::Relaxed);
        metrics.tun_rx_bytes.store(8_000, Ordering::Relaxed);
        metrics.trains_built.store(3, Ordering::Relaxed);
        metrics.cells_built.store(9, Ordering::Relaxed);
        metrics.fec_recovered_cells.store(2, Ordering::Relaxed);
        metrics
            .repair_completed_requests
            .store(1, Ordering::Relaxed);
        metrics.train_queue_bytes.store(4_096, Ordering::Relaxed);

        let mut peer = crate::status::PeerStatus::default();
        V2RuntimeState::refresh_metrics(&mut peer, &metrics);
        assert_eq!(peer.protocol_major, 0);
        assert_eq!(peer.traffic.tx_packets, 11);
        assert_eq!(peer.traffic.tx_bytes, 12_000);
        assert_eq!(peer.traffic.rx_packets, 7);
        assert_eq!(peer.traffic.rx_bytes, 8_000);
        assert_eq!(peer.traffic.trains_built, 3);
        assert_eq!(peer.traffic.cells_built, 9);
        assert_eq!(peer.traffic.fec_recovered_cells, 2);
        assert_eq!(peer.traffic.repair_completed_requests, 1);
        assert_eq!(peer.traffic.packet_train_queue_bytes, 4_096);

        let json = serde_json::to_value(peer).unwrap();
        let object = json.as_object().unwrap();
        for removed in [
            "delivery_tagged_packets",
            "tx_fragments",
            "fec_tx_recovery_shards",
            "capacity_probe_attempts",
        ] {
            assert!(!object.contains_key(removed), "stale V1 field {removed}");
        }
    }

    #[tokio::test]
    async fn live_snapshot_publishes_gateway_and_signed_presence_directory() {
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../config/example.toml")).unwrap();
        config.routing.transit_enabled = true;
        config.routing.nat_enabled = true;
        config.advertised_prefixes = vec!["11.6.1.0/24".parse().unwrap()];
        let runtime = super::super::V2RuntimeConfig::from_product_config(&config).unwrap();
        let local_key = SecretKey::from_bytes(&[51; 32]);
        let remote_key = SecretKey::from_bytes(&[52; 32]);
        let state = V2RuntimeState::new(&runtime, local_key.public());
        let now = SystemTime::now();
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut directory = PresenceDirectoryV2::new(runtime.network_id.clone()).unwrap();
        for (key, sequence, node_address, prefix) in [
            (&local_key, 1, "21.0.0.1/32", "11.6.1.0/24"),
            (&remote_key, 2, "21.0.0.2/32", "10.52.0.0/16"),
        ] {
            let presence = SignedPresenceV2::sign(
                PresenceBodyV2 {
                    owner: key.public(),
                    sequence,
                    issued_unix_secs: now_secs,
                    expires_unix_secs: now_secs + 180,
                    direct_addresses: vec!["[2001:db8::1]:4000".parse().unwrap()],
                    node_addresses: vec![node_address.parse().unwrap()],
                    prefixes: vec![prefix.parse().unwrap()],
                    links: Vec::new(),
                    transit_enabled: key.public() == local_key.public(),
                },
                key,
                &runtime.network_id,
            )
            .unwrap();
            directory.insert(presence, now).unwrap();
        }
        state.publish_presence_directory(&directory, 32);
        state.publish_routes([
            "21.0.0.2/32".parse().unwrap(),
            "10.52.0.0/16".parse().unwrap(),
        ]);

        let snapshot = state.live_snapshot().await.unwrap();
        assert!(snapshot.routes_ready);
        assert_eq!(snapshot.routes.len(), 2);
        assert!(snapshot.routes.iter().all(|route| route.present));
        assert!(snapshot.gateway.transit_enabled);
        assert!(snapshot.gateway.subnet_nat_enabled);
        assert_eq!(
            snapshot.gateway.advertised_prefixes,
            config.advertised_prefixes
        );
        assert!(snapshot.mesh.enabled);
        assert_eq!(snapshot.mesh.directory_entries, 2);
        assert_eq!(snapshot.mesh.max_total_peers, 32);
        assert_eq!(snapshot.mesh.nodes.len(), 2);
        assert!(snapshot.mesh.nodes.iter().any(|node| {
            node.endpoint_id == remote_key.public().to_string()
                && node.node_addresses == ["21.0.0.2/32".parse().unwrap()]
                && node.prefixes == ["10.52.0.0/16".parse().unwrap()]
        }));
    }
}
