//! Host adapter for Policy ABI V1.
//!
//! The ABI types themselves live in the dependency-free `ironet-policy-abi`
//! crate (shared with `ironet-policy-core` and every guest) and are
//! re-exported here unchanged, so `crate::protocol::v2::policy::api::{...}`
//! remains the single import path inside the host. This module adds only the
//! conversions between ABI types and the host runtime structs in
//! `tuning.rs`/`utility.rs`/`fec.rs`:
//!
//! - closed-enum `From` impls in both directions;
//! - extension traits ([`TelemetryHostExt`], [`UtilityHostExt`],
//!   [`LimitsHostExt`], [`BbrHostExt`], [`FecHostExt`], [`EffectiveHostExt`],
//!   [`CandidateHostExt`], [`InputHostExt`]) that attach the host-side
//!   constructors/projections to the foreign ABI types (inherent impls are
//!   not possible across crates). Bring them into scope with
//!   `use crate::protocol::v2::policy::api::*;`.
//!
//! `TuneDecisionV2 -> EffectiveActionV1 -> TuneDecisionV2` is lossless (see
//! tests). Durations convert to microseconds saturating at `u64::MAX`;
//! `usize` fields saturate at their ABI width, which no guardrail-bounded
//! value reaches.

pub use ironet_policy_abi::*;

use crate::protocol::v2::{
    fec::FecGeometryV2,
    tuning::{
        AutoTuneBoundsV2, Bbr3PresetV2, Bbr3ProposalV2, CoverTrafficProfileV2, PathReliability,
        PathTelemetryV2, RepairWaitPolicyV2, TuneDecisionV2, TuneReasonV2,
    },
    utility::{Objective, UtilitySample},
};

// ---------------------------------------------------------------------------
// Closed enums
// ---------------------------------------------------------------------------

impl From<PathReliability> for PathReliabilityV1 {
    fn from(value: PathReliability) -> Self {
        match value {
            PathReliability::Datagram => Self::Datagram,
            PathReliability::ReliableRelay => Self::ReliableRelay,
        }
    }
}

impl From<PathReliabilityV1> for PathReliability {
    fn from(value: PathReliabilityV1) -> Self {
        match value {
            PathReliabilityV1::Datagram => Self::Datagram,
            PathReliabilityV1::ReliableRelay => Self::ReliableRelay,
        }
    }
}

impl From<TuneReasonV2> for ActionReasonV1 {
    fn from(value: TuneReasonV2) -> Self {
        match value {
            TuneReasonV2::ColdStart => Self::ColdStart,
            TuneReasonV2::TelemetryUnavailable => Self::TelemetryUnavailable,
            TuneReasonV2::PathChanged => Self::PathChanged,
            TuneReasonV2::HealthyLowLoss => Self::HealthyLowLoss,
            TuneReasonV2::RandomLoss => Self::RandomLoss,
            TuneReasonV2::BurstLoss => Self::BurstLoss,
            TuneReasonV2::Congested => Self::Congested,
            TuneReasonV2::CpuLimited => Self::CpuLimited,
            TuneReasonV2::ReliablePath => Self::ReliablePath,
        }
    }
}

impl From<ActionReasonV1> for TuneReasonV2 {
    fn from(value: ActionReasonV1) -> Self {
        match value {
            ActionReasonV1::ColdStart => Self::ColdStart,
            ActionReasonV1::TelemetryUnavailable => Self::TelemetryUnavailable,
            ActionReasonV1::PathChanged => Self::PathChanged,
            ActionReasonV1::HealthyLowLoss => Self::HealthyLowLoss,
            ActionReasonV1::RandomLoss => Self::RandomLoss,
            ActionReasonV1::BurstLoss => Self::BurstLoss,
            ActionReasonV1::Congested => Self::Congested,
            ActionReasonV1::CpuLimited => Self::CpuLimited,
            ActionReasonV1::ReliablePath => Self::ReliablePath,
        }
    }
}

impl From<CoverTrafficProfileV2> for CoverProfileV1 {
    fn from(value: CoverTrafficProfileV2) -> Self {
        match value {
            CoverTrafficProfileV2::Idle => Self::Idle,
            CoverTrafficProfileV2::LiveBroadcast => Self::LiveBroadcast,
            CoverTrafficProfileV2::InteractiveVideo => Self::InteractiveVideo,
            CoverTrafficProfileV2::GenericH3Bulk => Self::GenericH3Bulk,
        }
    }
}

impl From<CoverProfileV1> for CoverTrafficProfileV2 {
    fn from(value: CoverProfileV1) -> Self {
        match value {
            CoverProfileV1::Idle => Self::Idle,
            CoverProfileV1::LiveBroadcast => Self::LiveBroadcast,
            CoverProfileV1::InteractiveVideo => Self::InteractiveVideo,
            CoverProfileV1::GenericH3Bulk => Self::GenericH3Bulk,
        }
    }
}

impl From<RepairWaitPolicyV2> for RepairWaitPolicyV1 {
    fn from(value: RepairWaitPolicyV2) -> Self {
        match value {
            RepairWaitPolicyV2::HostDefault => Self::HostDefault,
            RepairWaitPolicyV2::Eager => Self::Eager,
            RepairWaitPolicyV2::AfterFecWindow => Self::AfterFecWindow,
            RepairWaitPolicyV2::Patient => Self::Patient,
        }
    }
}

impl From<RepairWaitPolicyV1> for RepairWaitPolicyV2 {
    fn from(value: RepairWaitPolicyV1) -> Self {
        match value {
            RepairWaitPolicyV1::HostDefault => Self::HostDefault,
            RepairWaitPolicyV1::Eager => Self::Eager,
            RepairWaitPolicyV1::AfterFecWindow => Self::AfterFecWindow,
            RepairWaitPolicyV1::Patient => Self::Patient,
        }
    }
}

impl From<Bbr3PresetV2> for Bbr3PresetV1 {
    fn from(value: Bbr3PresetV2) -> Self {
        match value {
            Bbr3PresetV2::SharedConservative => Self::SharedConservative,
            Bbr3PresetV2::PrivateAggressive => Self::PrivateAggressive,
            Bbr3PresetV2::LossyRadio => Self::LossyRadio,
            Bbr3PresetV2::Policer => Self::Policer,
            Bbr3PresetV2::LongFat => Self::LongFat,
            Bbr3PresetV2::RelayReliable => Self::RelayReliable,
            Bbr3PresetV2::LowRttHost => Self::LowRttHost,
        }
    }
}

impl From<Bbr3PresetV1> for Bbr3PresetV2 {
    fn from(value: Bbr3PresetV1) -> Self {
        match value {
            Bbr3PresetV1::SharedConservative => Self::SharedConservative,
            Bbr3PresetV1::PrivateAggressive => Self::PrivateAggressive,
            Bbr3PresetV1::LossyRadio => Self::LossyRadio,
            Bbr3PresetV1::Policer => Self::Policer,
            Bbr3PresetV1::LongFat => Self::LongFat,
            Bbr3PresetV1::RelayReliable => Self::RelayReliable,
            Bbr3PresetV1::LowRttHost => Self::LowRttHost,
        }
    }
}

impl From<Objective> for ObjectiveV1 {
    fn from(value: Objective) -> Self {
        match value {
            Objective::Balanced => Self::Balanced,
            Objective::Throughput => Self::Throughput,
            Objective::Latency => Self::Latency,
        }
    }
}

impl From<ObjectiveV1> for Objective {
    fn from(value: ObjectiveV1) -> Self {
        match value {
            ObjectiveV1::Balanced => Self::Balanced,
            ObjectiveV1::Throughput => Self::Throughput,
            ObjectiveV1::Latency => Self::Latency,
        }
    }
}

// ---------------------------------------------------------------------------
// Width helpers
// ---------------------------------------------------------------------------

fn micros_u64(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn u16_saturating(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn milli_i32(value: f64) -> i32 {
    if value.is_nan() {
        return 0;
    }
    // `as` saturates for finite and infinite floats.
    (value * 1_000.0).round() as i32
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

/// Host conversions for [`PolicyTelemetryV1`].
pub trait TelemetryHostExt: Sized {
    /// Lossless projection of runtime telemetry (durations to micros).
    fn from_runtime(sample: &PathTelemetryV2) -> Self;
    /// Inverse of [`Self::from_runtime`] for replay/golden tooling;
    /// `path_epoch` and `reliability` come from the enclosing input.
    fn to_runtime(&self, path_epoch: u64, reliability: PathReliabilityV1) -> PathTelemetryV2;
}

impl TelemetryHostExt for PolicyTelemetryV1 {
    fn from_runtime(sample: &PathTelemetryV2) -> Self {
        Self {
            path_rtt_micros: micros_u64(sample.rtt),
            path_min_rtt_micros: micros_u64(sample.min_rtt),
            path_queue_delay_micros: micros_u64(sample.queue_delay),
            local_tx_wire_rate_bytes_per_second: sample.delivery_rate_bytes_per_second,
            local_tx_tun_ingress_bytes_per_second: sample.tun_ingress_bytes_per_second,
            local_tx_real_traffic_bytes_per_second: sample.real_traffic_bytes_per_second,
            local_tx_train_build_bytes_per_second: sample.train_build_bytes_per_second,
            local_tx_packets_per_second: sample.packets_per_second,
            local_tx_loss_ppm: sample.loss_ppm,
            local_tx_burst_loss_cells: sample.burst_loss_cells,
            local_tx_average_record_bytes: sample.average_record_bytes,
            local_tx_gso_ingress_ratio_ppm: sample.gso_ingress_ratio_ppm,
            local_tx_packet_train_queue_bytes: sample.packet_train_queue_bytes,
            local_tx_latency_queue_bytes: sample.latency_queue_bytes,
            local_tx_bulk_preemption_delay_average_micros: sample
                .bulk_preemption_delay_average_micros,
            local_tx_controller_pacing_rate_bytes_per_second: sample
                .controller_pacing_rate_bytes_per_second,
            local_tx_controller_send_quantum_bytes: sample.controller_send_quantum_bytes,
            local_tx_controller_state: sample.controller_state,
            local_tx_controller_bw_bytes_per_second: sample.controller_bw_bytes_per_second,
            local_tx_controller_inflight_longterm_bytes: sample.controller_inflight_longterm_bytes,
            local_tx_controller_guard_transitions_delta: sample.controller_guard_transitions_delta,
            local_tx_controller_app_limited: sample.controller_app_limited,
            local_tx_controller_tunables_generation: sample.controller_tunables_generation,
            local_tx_controller_params_generation: sample.controller_params_generation,
            local_tx_controller_clamped_writes: sample.controller_clamped_writes,
            local_rx_wire_rate_bytes_per_second: sample.receive_rate_bytes_per_second,
            local_rx_reassembly_pressure_evictions: sample.reassembly_pressure_evictions,
            remote_goodput_bytes_per_second: sample.receiver_goodput_bytes_per_second,
            remote_residual_loss_ppm: sample.residual_loss_ppm,
            remote_reorder_ppm: sample.reorder_ppm,
            remote_expired_stripes_delta: sample.remote_expired_stripes_delta,
            remote_wasted_parity_per_mille: sample.wasted_parity_per_mille,
            remote_fec_recovery_per_mille: sample.fec_recovery_per_mille,
            remote_repair_hit_per_mille: sample.repair_hit_per_mille,
            remote_repair_completed_requests: sample.repair_completed_requests,
            remote_repair_response_latency_micros: micros_u64(sample.repair_response_latency),
            latency_sojourn_p50_micros: sample.latency_sojourn_p50_micros,
            latency_sojourn_p95_micros: sample.latency_sojourn_p95_micros,
            latency_sojourn_p99_micros: sample.latency_sojourn_p99_micros,
            latency_queue_recently_nonempty: sample.latency_queue_recently_nonempty,
            host_cpu_utilization_per_mille: sample.cpu_utilization_per_mille,
        }
    }

    fn to_runtime(&self, path_epoch: u64, reliability: PathReliabilityV1) -> PathTelemetryV2 {
        use std::time::Duration;
        PathTelemetryV2 {
            path_epoch,
            reliability: reliability.into(),
            rtt: Duration::from_micros(self.path_rtt_micros),
            min_rtt: Duration::from_micros(self.path_min_rtt_micros),
            queue_delay: Duration::from_micros(self.path_queue_delay_micros),
            loss_ppm: self.local_tx_loss_ppm,
            burst_loss_cells: self.local_tx_burst_loss_cells,
            reorder_ppm: self.remote_reorder_ppm,
            receiver_goodput_bytes_per_second: self.remote_goodput_bytes_per_second,
            residual_loss_ppm: self.remote_residual_loss_ppm,
            latency_sojourn_p95_micros: self.latency_sojourn_p95_micros,
            latency_sojourn_p50_micros: self.latency_sojourn_p50_micros,
            latency_sojourn_p99_micros: self.latency_sojourn_p99_micros,
            latency_queue_recently_nonempty: self.latency_queue_recently_nonempty,
            delivery_rate_bytes_per_second: self.local_tx_wire_rate_bytes_per_second,
            controller_pacing_rate_bytes_per_second: self
                .local_tx_controller_pacing_rate_bytes_per_second,
            controller_send_quantum_bytes: self.local_tx_controller_send_quantum_bytes,
            controller_state: self.local_tx_controller_state,
            controller_bw_bytes_per_second: self.local_tx_controller_bw_bytes_per_second,
            controller_inflight_longterm_bytes: self.local_tx_controller_inflight_longterm_bytes,
            controller_guard_transitions_delta: self.local_tx_controller_guard_transitions_delta,
            controller_app_limited: self.local_tx_controller_app_limited,
            controller_tunables_generation: self.local_tx_controller_tunables_generation,
            controller_params_generation: self.local_tx_controller_params_generation,
            controller_clamped_writes: self.local_tx_controller_clamped_writes,
            receive_rate_bytes_per_second: self.local_rx_wire_rate_bytes_per_second,
            packets_per_second: self.local_tx_packets_per_second,
            tun_ingress_bytes_per_second: self.local_tx_tun_ingress_bytes_per_second,
            average_record_bytes: self.local_tx_average_record_bytes,
            gso_ingress_ratio_ppm: self.local_tx_gso_ingress_ratio_ppm,
            packet_train_queue_bytes: self.local_tx_packet_train_queue_bytes,
            latency_queue_bytes: self.local_tx_latency_queue_bytes,
            reassembly_pressure_evictions: self.local_rx_reassembly_pressure_evictions,
            remote_expired_stripes_delta: self.remote_expired_stripes_delta,
            train_build_bytes_per_second: self.local_tx_train_build_bytes_per_second,
            bulk_preemption_delay_average_micros: self
                .local_tx_bulk_preemption_delay_average_micros,
            cpu_utilization_per_mille: self.host_cpu_utilization_per_mille,
            wasted_parity_per_mille: self.remote_wasted_parity_per_mille,
            fec_recovery_per_mille: self.remote_fec_recovery_per_mille,
            repair_hit_per_mille: self.remote_repair_hit_per_mille,
            repair_completed_requests: self.remote_repair_completed_requests,
            repair_response_latency: Duration::from_micros(
                self.remote_repair_response_latency_micros,
            ),
            real_traffic_bytes_per_second: self.local_tx_real_traffic_bytes_per_second,
        }
    }
}

impl From<&PathTelemetryV2> for PolicyTelemetryV1 {
    fn from(sample: &PathTelemetryV2) -> Self {
        Self::from_runtime(sample)
    }
}

/// Host conversions for [`PolicyInputV1`].
pub trait InputHostExt {
    /// Reconstruct the runtime telemetry sample (replay/golden tooling).
    fn telemetry_runtime(&self) -> PathTelemetryV2;
}

impl InputHostExt for PolicyInputV1 {
    fn telemetry_runtime(&self) -> PathTelemetryV2 {
        self.telemetry.to_runtime(self.path_epoch, self.reliability)
    }
}

// ---------------------------------------------------------------------------
// Utility and limits
// ---------------------------------------------------------------------------

/// Host conversions for [`HostUtilityV1`].
pub trait UtilityHostExt: Sized {
    /// Fixed-point projection of a host utility sample. Lossy by design
    /// (floats never enter the ABI); there is no inverse.
    fn from_sample(objective: Objective, sample: &UtilitySample) -> Self;
}

impl UtilityHostExt for HostUtilityV1 {
    fn from_sample(objective: Objective, sample: &UtilitySample) -> Self {
        let [
            throughput,
            queue_delay,
            latency_sojourn,
            residual_loss,
            jitter,
            cpu,
            wire_overhead,
            memory,
        ] = sample.components;
        Self {
            objective: objective.into(),
            valid: true,
            utility_milli: milli_i32(sample.total),
            throughput_milli: milli_i32(throughput),
            queue_delay_milli: milli_i32(queue_delay),
            latency_sojourn_milli: milli_i32(latency_sojourn),
            residual_loss_milli: milli_i32(residual_loss),
            jitter_milli: milli_i32(jitter),
            cpu_milli: milli_i32(cpu),
            wire_overhead_milli: milli_i32(wire_overhead),
            memory_milli: milli_i32(memory),
            goodput_bytes_per_second: sample.goodput_bytes_per_second,
        }
    }
}

/// Host conversions for [`HostLimitsV1`].
pub trait LimitsHostExt: Sized {
    /// Derive limits from the runtime auto-tune bounds plus the fixed FEC and
    /// extension budgets of the ABI.
    fn from_bounds(bounds: &AutoTuneBoundsV2) -> Self;
}

impl LimitsHostExt for HostLimitsV1 {
    fn from_bounds(bounds: &AutoTuneBoundsV2) -> Self {
        Self {
            train_target_floor_bytes: u32_saturating(bounds.minimum_train_bytes),
            train_target_cap_bytes: u32_saturating(bounds.maximum_train_bytes),
            send_buffer_floor_bytes: u64_saturating(bounds.minimum_socket_buffer_bytes),
            send_buffer_cap_bytes: u64_saturating(bounds.maximum_socket_buffer_bytes),
            receive_buffer_floor_bytes: u64_saturating(bounds.minimum_receive_buffer_bytes),
            receive_buffer_cap_bytes: u64_saturating(bounds.maximum_socket_buffer_bytes),
            receive_batch_cap: u16_saturating(bounds.maximum_receive_batch).max(1),
            repair_cache_cap_bytes: u64_saturating(bounds.maximum_socket_buffer_bytes),
            cover_overhead_cap_per_mille: bounds.maximum_cover_overhead_per_mille,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// BBR / FEC sub-domains
// ---------------------------------------------------------------------------

/// Host conversions for [`BbrEffectiveV1`].
pub trait BbrHostExt: Sized {
    /// Expand a legacy proposal into its full preset-resolved BBR action (see
    /// [`BbrEffectiveV1::expand_preset`]). The telemetry-dependent host
    /// finalization happens after this conversion.
    fn from_proposal(proposal: &Bbr3ProposalV2) -> Self;
    /// Project back onto the legacy proposal (the five fields it carries).
    fn to_proposal(&self) -> Bbr3ProposalV2;
}

impl BbrHostExt for BbrEffectiveV1 {
    fn from_proposal(proposal: &Bbr3ProposalV2) -> Self {
        Self::expand_preset(
            proposal.preset.into(),
            proposal.up_gain_milli,
            proposal.headroom_milli,
            proposal.cwnd_gain_milli,
            proposal.pacing_cap_bytes_per_second,
            proposal.loss_is_congestion,
        )
    }

    fn to_proposal(&self) -> Bbr3ProposalV2 {
        Bbr3ProposalV2 {
            preset: self.preset.into(),
            up_gain_milli: self.probe_bw_up_pacing_gain_milli,
            headroom_milli: self.headroom_milli,
            cwnd_gain_milli: self.default_cwnd_gain_milli,
            pacing_cap_bytes_per_second: self.pacing_cap_bytes_per_second,
            loss_is_congestion: self.loss_is_congestion,
        }
    }
}

/// Host conversions for [`FecEffectiveV1`].
pub trait FecHostExt: Sized {
    /// Lossless projection of the runtime geometry option.
    fn from_geometry(geometry: Option<FecGeometryV2>) -> Self;
    /// Inverse of [`Self::from_geometry`].
    fn to_geometry(&self) -> Option<FecGeometryV2>;
}

impl FecHostExt for FecEffectiveV1 {
    fn from_geometry(geometry: Option<FecGeometryV2>) -> Self {
        match geometry {
            Some(geometry) => Self {
                enabled: true,
                data_cells: u8::try_from(geometry.data_cells).unwrap_or(u8::MAX),
                parity_cells: u8::try_from(geometry.parity_cells).unwrap_or(u8::MAX),
                preset_family: FecPresetFamilyV1::Unspecified,
            },
            None => Self::default(),
        }
    }

    fn to_geometry(&self) -> Option<FecGeometryV2> {
        self.enabled.then_some(FecGeometryV2 {
            data_cells: usize::from(self.data_cells),
            parity_cells: usize::from(self.parity_cells),
        })
    }
}

// ---------------------------------------------------------------------------
// Effective / candidate adapters for the legacy decision
// ---------------------------------------------------------------------------

/// Host conversions for [`EffectiveActionV1`].
pub trait EffectiveHostExt: Sized {
    /// Lift a legacy `TuneDecisionV2` into the effective action shape.
    /// Fields `TuneDecisionV2` does not carry (`bulk_admission_window_bytes`,
    /// `datagram_admission_bytes`, `producer_window_bytes`, `egress`, hints)
    /// are set to their "host default" zero values.
    fn from_tune_decision(decision: &TuneDecisionV2) -> Self;
    /// Project onto the legacy data-plane decision.
    fn to_tune_decision(&self) -> TuneDecisionV2;
}

impl EffectiveHostExt for EffectiveActionV1 {
    fn from_tune_decision(decision: &TuneDecisionV2) -> Self {
        Self {
            reason: decision.reason.into(),
            path_epoch: decision.path_epoch,
            sample_count: decision.sample_count,
            bbr: BbrEffectiveV1::from_proposal(&decision.bbr),
            scheduler: SchedulerEffectiveV1 {
                train_target_bytes: u32_saturating(decision.train_target_bytes),
                bulk_quantum_cells: u16_saturating(decision.bulk_quantum_cells),
                bulk_admission_window_bytes: 0,
                preset_hint: SchedulerPresetHintV1::HostDefault,
            },
            fec: FecEffectiveV1::from_geometry(decision.fec),
            repair: RepairEffectiveV1 {
                cache_bytes: u64_saturating(decision.repair_cache_bytes),
                retention_target_millis: decision.repair_retention_millis,
                wait_policy: decision.repair_wait_policy.into(),
                responsibility: ProtectionResponsibilityV1::HostDefault,
            },
            tx: TxEffectiveV1 {
                send_buffer_bytes: u64_saturating(decision.send_buffer_bytes),
                datagram_admission_bytes: 0,
                producer_window_bytes: 0,
            },
            rx: RxEffectiveV1 {
                receive_buffer_bytes: u64_saturating(decision.receive_buffer_bytes),
                receive_batch: u16_saturating(decision.receive_batch),
                reassembly_budget_bytes: u64_saturating(decision.reassembly_budget_bytes),
                active_train_budget: decision.active_train_budget,
            },
            cover: CoverEffectiveV1 {
                profile: decision.cover_profile.into(),
                overhead_per_mille: decision.cover_overhead_per_mille,
                padding_bytes_per_second: decision.cover_padding_bytes_per_second,
            },
            egress: EgressRequestV1::default(),
        }
    }

    fn to_tune_decision(&self) -> TuneDecisionV2 {
        TuneDecisionV2 {
            reason: self.reason.into(),
            path_epoch: self.path_epoch,
            sample_count: self.sample_count,
            train_target_bytes: usize::try_from(self.scheduler.train_target_bytes)
                .unwrap_or(usize::MAX),
            bulk_quantum_cells: usize::from(self.scheduler.bulk_quantum_cells),
            fec: self.fec.to_geometry(),
            repair_cache_bytes: usize_from_u64(self.repair.cache_bytes),
            repair_retention_millis: self.repair.retention_target_millis,
            repair_wait_policy: self.repair.wait_policy.into(),
            send_buffer_bytes: usize_from_u64(self.tx.send_buffer_bytes),
            receive_buffer_bytes: usize_from_u64(self.rx.receive_buffer_bytes),
            reassembly_budget_bytes: usize_from_u64(self.rx.reassembly_budget_bytes),
            active_train_budget: self.rx.active_train_budget,
            receive_batch: usize::from(self.rx.receive_batch),
            cover_profile: self.cover.profile.into(),
            cover_overhead_per_mille: self.cover.overhead_per_mille,
            cover_padding_bytes_per_second: self.cover.padding_bytes_per_second,
            bbr: self.bbr.to_proposal(),
        }
    }
}

impl From<&TuneDecisionV2> for EffectiveActionV1 {
    fn from(decision: &TuneDecisionV2) -> Self {
        Self::from_tune_decision(decision)
    }
}

impl From<&EffectiveActionV1> for TuneDecisionV2 {
    fn from(action: &EffectiveActionV1) -> Self {
        action.to_tune_decision()
    }
}

/// Host conversions for [`CandidateActionV1`].
pub trait CandidateHostExt: Sized {
    /// Treat a legacy decision as a candidate: only the fields
    /// `TuneDecisionV2` carries are set, everything else stays `None`.
    fn from_tune_decision(decision: &TuneDecisionV2) -> Self;
}

impl CandidateHostExt for CandidateActionV1 {
    fn from_tune_decision(decision: &TuneDecisionV2) -> Self {
        let fec = match decision.fec {
            Some(geometry) => FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(u8::try_from(geometry.data_cells).unwrap_or(u8::MAX)),
                parity_cells: Some(u8::try_from(geometry.parity_cells).unwrap_or(u8::MAX)),
                preset_family: None,
            },
            None => FecCandidateV1 {
                enabled: Some(false),
                ..FecCandidateV1::default()
            },
        };
        Self {
            bbr: Some(BbrCandidateV1 {
                preset: Some(decision.bbr.preset.into()),
                probe_bw_up_pacing_gain_milli: Some(decision.bbr.up_gain_milli),
                default_cwnd_gain_milli: Some(decision.bbr.cwnd_gain_milli),
                headroom_milli: Some(decision.bbr.headroom_milli),
                loss_is_congestion: Some(decision.bbr.loss_is_congestion),
                pacing_cap_bytes_per_second: Some(decision.bbr.pacing_cap_bytes_per_second),
                ..BbrCandidateV1::default()
            }),
            scheduler: Some(SchedulerCandidateV1 {
                train_target_bytes: Some(u32_saturating(decision.train_target_bytes)),
                bulk_quantum_cells: Some(u16_saturating(decision.bulk_quantum_cells)),
                bulk_admission_window_bytes: None,
                preset_hint: None,
            }),
            fec: Some(fec),
            repair: Some(RepairCandidateV1 {
                cache_bytes: Some(u64_saturating(decision.repair_cache_bytes)),
                ..RepairCandidateV1::default()
            }),
            tx: Some(TxCandidateV1 {
                send_buffer_bytes: Some(u64_saturating(decision.send_buffer_bytes)),
                ..TxCandidateV1::default()
            }),
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: Some(u64_saturating(decision.receive_buffer_bytes)),
                receive_batch: Some(u16_saturating(decision.receive_batch)),
                ..RxCandidateV1::default()
            }),
            cover: Some(CoverCandidateV1 {
                profile: Some(decision.cover_profile.into()),
                overhead_per_mille: Some(decision.cover_overhead_per_mille),
                padding_bytes_per_second: Some(decision.cover_padding_bytes_per_second),
            }),
            egress_request: None,
            extensions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn telemetry() -> PathTelemetryV2 {
        PathTelemetryV2 {
            path_epoch: 7,
            reliability: PathReliability::Datagram,
            rtt: Duration::from_micros(23_456),
            min_rtt: Duration::from_micros(20_001),
            queue_delay: Duration::from_micros(3_455),
            loss_ppm: 1_200,
            burst_loss_cells: 3,
            reorder_ppm: 45,
            receiver_goodput_bytes_per_second: 12_345_678,
            residual_loss_ppm: 9,
            latency_sojourn_p95_micros: 1_500,
            latency_sojourn_p50_micros: 400,
            latency_sojourn_p99_micros: 2_900,
            latency_queue_recently_nonempty: true,
            delivery_rate_bytes_per_second: 13_000_000,
            controller_pacing_rate_bytes_per_second: 14_000_000,
            controller_send_quantum_bytes: 65_535,
            controller_state: 3,
            controller_bw_bytes_per_second: 15_000_000,
            controller_inflight_longterm_bytes: 300_000,
            controller_guard_transitions_delta: 2,
            controller_app_limited: false,
            controller_tunables_generation: 11,
            controller_params_generation: 10,
            controller_clamped_writes: 1,
            receive_rate_bytes_per_second: 2_000_000,
            packets_per_second: 9_000,
            tun_ingress_bytes_per_second: 12_900_000,
            average_record_bytes: 1_380,
            gso_ingress_ratio_ppm: 250_000,
            packet_train_queue_bytes: 48_000,
            latency_queue_bytes: 2_000,
            reassembly_pressure_evictions: 4,
            remote_expired_stripes_delta: 1,
            train_build_bytes_per_second: 12_800_000,
            bulk_preemption_delay_average_micros: 120,
            cpu_utilization_per_mille: 420,
            wasted_parity_per_mille: 30,
            fec_recovery_per_mille: 600,
            repair_hit_per_mille: 900,
            repair_completed_requests: 77,
            repair_response_latency: Duration::from_micros(21_000),
            real_traffic_bytes_per_second: 12_700_000,
        }
    }

    fn decision() -> TuneDecisionV2 {
        TuneDecisionV2 {
            reason: TuneReasonV2::RandomLoss,
            path_epoch: 7,
            sample_count: 42,
            train_target_bytes: 32 * 1024,
            bulk_quantum_cells: 2,
            fec: Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 2,
            }),
            repair_cache_bytes: 4 * 1024 * 1024,
            send_buffer_bytes: 512 * 1024,
            receive_buffer_bytes: 16 * 1024 * 1024,
            receive_batch: 32,
            cover_profile: CoverTrafficProfileV2::InteractiveVideo,
            cover_overhead_per_mille: 25,
            cover_padding_bytes_per_second: 12_000,
            repair_retention_millis: 7_500,
            repair_wait_policy: RepairWaitPolicyV2::AfterFecWindow,
            reassembly_budget_bytes: 4 * 1024 * 1024,
            active_train_budget: 96,
            bbr: Bbr3ProposalV2 {
                preset: Bbr3PresetV2::LossyRadio,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 9_000_000,
                loss_is_congestion: false,
            },
        }
    }

    fn telemetry_eq(left: &PathTelemetryV2, right: &PathTelemetryV2) -> bool {
        // PathTelemetryV2 has no PartialEq; compare through a Debug rendering
        // which covers every field.
        format!("{left:?}") == format!("{right:?}")
    }

    #[test]
    fn telemetry_round_trips_through_abi() {
        let sample = telemetry();
        let abi = PolicyTelemetryV1::from_runtime(&sample);
        let back = abi.to_runtime(sample.path_epoch, sample.reliability.into());
        assert!(telemetry_eq(&sample, &back), "{abi:?}");

        let mut relay = sample;
        relay.reliability = PathReliability::ReliableRelay;
        relay.path_epoch = 9;
        let abi = PolicyTelemetryV1::from(&relay);
        let back = abi.to_runtime(9, PathReliabilityV1::ReliableRelay);
        assert!(telemetry_eq(&relay, &back));

        let input = PolicyInputV1 {
            path_epoch: 9,
            reliability: PathReliabilityV1::ReliableRelay,
            telemetry: abi,
            ..PolicyInputV1::default()
        };
        assert!(telemetry_eq(&relay, &input.telemetry_runtime()));
    }

    #[test]
    fn closed_enums_round_trip() {
        for preset in Bbr3PresetV1::ALL {
            assert_eq!(Bbr3PresetV1::from(Bbr3PresetV2::from(preset)), preset);
        }
        for reason in ActionReasonV1::ALL {
            assert_eq!(ActionReasonV1::from(TuneReasonV2::from(reason)), reason);
        }
        for profile in CoverProfileV1::ALL {
            assert_eq!(
                CoverProfileV1::from(CoverTrafficProfileV2::from(profile)),
                profile
            );
        }
        for objective in ObjectiveV1::ALL {
            assert_eq!(ObjectiveV1::from(Objective::from(objective)), objective);
        }
        for reliability in PathReliabilityV1::ALL {
            assert_eq!(
                PathReliabilityV1::from(PathReliability::from(reliability)),
                reliability
            );
        }
    }

    #[test]
    fn tune_decision_round_trips_through_effective_action() {
        let original = decision();
        let effective = EffectiveActionV1::from_tune_decision(&original);
        assert_eq!(effective.to_tune_decision(), original);

        let mut no_fec = original;
        no_fec.fec = None;
        no_fec.reason = TuneReasonV2::ReliablePath;
        no_fec.bbr = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LowRttHost, 1_000_000);
        no_fec.cover_profile = CoverTrafficProfileV2::Idle;
        let effective = EffectiveActionV1::from(&no_fec);
        assert_eq!(
            effective.bbr.cwnd_floor_bytes,
            LOW_RTT_HOST_CWND_FLOOR_BYTES
        );
        assert!(!effective.fec.enabled);
        assert_eq!(TuneDecisionV2::from(&effective), no_fec);

        for preset in Bbr3PresetV1::ALL {
            let proposal = Bbr3ProposalV2::for_preset(preset.into(), 5_000_000);
            assert_eq!(
                BbrEffectiveV1::from_proposal(&proposal).to_proposal(),
                proposal
            );
        }

        // The ABI default BBR expansion is the host cold-start proposal.
        assert_eq!(
            BbrEffectiveV1::default(),
            BbrEffectiveV1::from_proposal(&Bbr3ProposalV2::for_preset(
                Bbr3PresetV2::SharedConservative,
                0
            ))
        );
    }

    #[test]
    fn candidate_from_decision_overlays_onto_any_base() {
        let target = decision();
        let mut base_decision = decision();
        base_decision.reason = TuneReasonV2::ColdStart;
        base_decision.sample_count = 0;
        base_decision.fec = None;
        base_decision.train_target_bytes = 8 * 1024;
        base_decision.bbr = Bbr3ProposalV2::for_preset(Bbr3PresetV2::SharedConservative, 0);
        base_decision.cover_profile = CoverTrafficProfileV2::Idle;
        base_decision.cover_overhead_per_mille = 0;
        let base = EffectiveActionV1::from_tune_decision(&base_decision);

        let candidate = CandidateActionV1::from_tune_decision(&target);
        assert!(candidate.validate(&HostLimitsV1::default()).is_ok());
        let merged = candidate.apply_over(&base);

        // Domain fields follow the candidate; bookkeeping follows the base.
        let mut expected = target;
        expected.reason = base_decision.reason;
        expected.sample_count = base_decision.sample_count;
        assert_eq!(merged.to_tune_decision(), expected);

        // Fields the candidate did not set keep the base's preset expansion.
        assert_eq!(
            merged.bbr.queue_guard_inflation_milli,
            base.bbr.queue_guard_inflation_milli
        );

        // An explicit FEC-off candidate keeps the base geometry but disables.
        let off = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(false),
                ..FecCandidateV1::default()
            }),
            ..CandidateActionV1::default()
        };
        let merged = off.apply_over(&EffectiveActionV1::from_tune_decision(&target));
        assert!(!merged.fec.enabled);
        assert_eq!(merged.fec.data_cells, 8);
        assert_eq!(merged.to_tune_decision().fec, None);
    }

    #[test]
    fn serde_round_trips_host_built_input() {
        let sample = telemetry();
        let input = PolicyInputV1 {
            logical_tick: 99,
            deterministic_seed: 0xdead_beef_cafe_f00d,
            peer_hash: [0xab; 32],
            path_epoch: sample.path_epoch,
            reliability: sample.reliability.into(),
            telemetry: PolicyTelemetryV1::from_runtime(&sample),
            previous: EffectiveActionV1::from_tune_decision(&decision()),
            previous_utility: HostUtilityV1::from_sample(
                Objective::Latency,
                &UtilitySample {
                    total: 1.234_5,
                    components: [2.0, -0.25, -0.1, -0.0001, -0.3, -0.05, -0.02, -0.007],
                    goodput_bytes_per_second: 12_345_678,
                },
            ),
            limits: HostLimitsV1::from_bounds(&AutoTuneBoundsV2::default()),
            capabilities: HostCapabilitiesV1 {
                extension_tags: vec![1, 7],
                ..HostCapabilitiesV1::default()
            },
            egress: EgressAllocationViewV1 {
                assigned_rate_bytes_per_second: 1,
                node_cap_bytes_per_second: 2,
                node_demand_bytes_per_second: 3,
                pressure_per_mille: 1_500,
                active_peers: 4,
                allocation_generation: 5,
            },
            extensions: vec![PolicyExtensionV1 {
                tag: 7,
                payload: vec![1, 2, 3],
            }],
            state: vec![9, 8, 7],
        };
        assert_eq!(input.previous_utility.utility_milli, 1_235);
        assert_eq!(input.previous_utility.throughput_milli, 2_000);
        assert_eq!(input.previous_utility.residual_loss_milli, 0);
        assert_eq!(input.previous_utility.objective, ObjectiveV1::Latency);
        let json = serde_json::to_string(&input).unwrap();
        let back: PolicyInputV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input);
        assert!(telemetry_eq(&back.telemetry_runtime(), &sample));
    }

    #[test]
    fn host_limits_follow_auto_tune_bounds() {
        // The ABI crate's Default mirrors the host's default bounds.
        assert_eq!(
            HostLimitsV1::from_bounds(&AutoTuneBoundsV2::default()),
            HostLimitsV1::default()
        );
        let bounds = AutoTuneBoundsV2 {
            minimum_train_bytes: 1_000,
            maximum_train_bytes: 2_000,
            minimum_socket_buffer_bytes: 3_000,
            minimum_receive_buffer_bytes: 4_000,
            maximum_socket_buffer_bytes: 5_000,
            maximum_receive_batch: 6,
            maximum_cover_overhead_per_mille: 7,
        };
        let limits = HostLimitsV1::from_bounds(&bounds);
        assert_eq!(limits.train_target_floor_bytes, 1_000);
        assert_eq!(limits.train_target_cap_bytes, 2_000);
        assert_eq!(limits.send_buffer_floor_bytes, 3_000);
        assert_eq!(limits.receive_buffer_floor_bytes, 4_000);
        assert_eq!(limits.send_buffer_cap_bytes, 5_000);
        assert_eq!(limits.receive_batch_cap, 6);
        assert_eq!(limits.cover_overhead_cap_per_mille, 7);
        assert_eq!(limits.fec_data_cells_cap, 16);
        assert_eq!(limits.fec_parity_cells_cap, 8);
    }

    #[test]
    fn utility_projection_saturates_and_ignores_nan() {
        let sample = UtilitySample {
            total: f64::NAN,
            components: [
                f64::INFINITY,
                f64::NEG_INFINITY,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
            ],
            goodput_bytes_per_second: 1,
        };
        let utility = HostUtilityV1::from_sample(Objective::Balanced, &sample);
        assert_eq!(utility.utility_milli, 0);
        assert_eq!(utility.throughput_milli, i32::MAX);
        assert_eq!(utility.queue_delay_milli, i32::MIN);
        assert!(utility.valid);
        assert!(!HostUtilityV1::unavailable(ObjectiveV1::Throughput).valid);
    }
}
