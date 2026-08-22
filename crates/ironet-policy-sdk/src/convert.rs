//! Conversions between the Rust ABI mirror and `wit-bindgen`'s guest records.
//!
//! The generated records intentionally remain visible through [`crate::bindings`]
//! for guests that need the raw WIT surface.  Normal guests should use the
//! ABI records instead; the conversions below keep the two representations
//! explicit and make malformed lengths a policy fault rather than a panic.

use core::convert::TryFrom;

use ironet_policy_abi::{
    ActionReasonV1, Bbr3PresetV1, BbrCandidateV1, BbrEffectiveV1, CandidateActionV1, ClampEntryV1,
    ClampFieldV1, ClampReasonV1, ClampReportV1, CoverCandidateV1, CoverEffectiveV1, CoverProfileV1,
    EffectiveActionV1, EgressAllocationViewV1, EgressRequestV1, FecCandidateV1, FecEffectiveV1,
    FecPresetFamilyV1, HostCapabilitiesV1, HostLimitsV1, HostUtilityV1, ObjectiveV1,
    POLICY_EXTENSION_MAX_COUNT, POLICY_EXTENSION_MAX_PAYLOAD_BYTES, POLICY_LABEL_BYTES,
    POLICY_STATE_MAX_BYTES, PathReliabilityV1, PolicyDecisionKindV1, PolicyDiagnosticsV1,
    PolicyExtensionV1, PolicyFaultV1, PolicyInputV1, PolicyLabelV1, PolicyOutputV1,
    PolicyTelemetryV1, ProtectionResponsibilityV1, RepairCandidateV1, RepairEffectiveV1,
    RepairWaitPolicyV1, RxCandidateV1, RxEffectiveV1, SchedulerCandidateV1, SchedulerEffectiveV1,
    SchedulerPresetHintV1, TxCandidateV1, TxEffectiveV1,
};

use crate::bindings::ironet::policy::types as wit;

macro_rules! enum_conversion {
    ($abi:ty, $wit:ty, { $($a:path => $w:path),+ $(,)? }) => {
        impl From<$abi> for $wit {
            fn from(value: $abi) -> Self {
                match value {
                    $($a => $w,)+
                }
            }
        }

        impl From<$wit> for $abi {
            fn from(value: $wit) -> Self {
                match value {
                    $($w => $a,)+
                }
            }
        }
    };
}

macro_rules! record_mixed {
    (
        $abi:ty,
        $wit:ty,
        copy: [$($copy:ident),* $(,)?],
        enums: [$($enum:ident),* $(,)?],
        option_enums: [$($option_enum:ident),* $(,)?]
    ) => {
        impl From<$abi> for $wit {
            fn from(value: $abi) -> Self {
                Self {
                    $($copy: value.$copy,)*
                    $($enum: value.$enum.into(),)*
                    $($option_enum: value.$option_enum.map(Into::into),)*
                }
            }
        }

        impl TryFrom<$wit> for $abi {
            type Error = PolicyFaultV1;

            fn try_from(value: $wit) -> Result<Self, Self::Error> {
                Ok(Self {
                    $($copy: value.$copy,)*
                    $($enum: value.$enum.into(),)*
                    $($option_enum: value.$option_enum.map(Into::into),)*
                })
            }
        }
    };
}

enum_conversion!(PathReliabilityV1, wit::PathReliability, {
    PathReliabilityV1::Datagram => wit::PathReliability::Datagram,
    PathReliabilityV1::ReliableRelay => wit::PathReliability::ReliableRelay,
});
enum_conversion!(ActionReasonV1, wit::ActionReason, {
    ActionReasonV1::ColdStart => wit::ActionReason::ColdStart,
    ActionReasonV1::TelemetryUnavailable => wit::ActionReason::TelemetryUnavailable,
    ActionReasonV1::PathChanged => wit::ActionReason::PathChanged,
    ActionReasonV1::HealthyLowLoss => wit::ActionReason::HealthyLowLoss,
    ActionReasonV1::RandomLoss => wit::ActionReason::RandomLoss,
    ActionReasonV1::BurstLoss => wit::ActionReason::BurstLoss,
    ActionReasonV1::Congested => wit::ActionReason::Congested,
    ActionReasonV1::CpuLimited => wit::ActionReason::CpuLimited,
    ActionReasonV1::ReliablePath => wit::ActionReason::ReliablePath,
});
enum_conversion!(CoverProfileV1, wit::CoverProfile, {
    CoverProfileV1::Idle => wit::CoverProfile::Idle,
    CoverProfileV1::LiveBroadcast => wit::CoverProfile::LiveBroadcast,
    CoverProfileV1::InteractiveVideo => wit::CoverProfile::InteractiveVideo,
    CoverProfileV1::GenericH3Bulk => wit::CoverProfile::GenericH3Bulk,
});
enum_conversion!(Bbr3PresetV1, wit::Bbr3Preset, {
    Bbr3PresetV1::SharedConservative => wit::Bbr3Preset::SharedConservative,
    Bbr3PresetV1::PrivateAggressive => wit::Bbr3Preset::PrivateAggressive,
    Bbr3PresetV1::LossyRadio => wit::Bbr3Preset::LossyRadio,
    Bbr3PresetV1::Policer => wit::Bbr3Preset::Policer,
    Bbr3PresetV1::LongFat => wit::Bbr3Preset::LongFat,
    Bbr3PresetV1::RelayReliable => wit::Bbr3Preset::RelayReliable,
    Bbr3PresetV1::LowRttHost => wit::Bbr3Preset::LowRttHost,
});
enum_conversion!(ObjectiveV1, wit::Objective, {
    ObjectiveV1::Balanced => wit::Objective::Balanced,
    ObjectiveV1::Throughput => wit::Objective::Throughput,
    ObjectiveV1::Latency => wit::Objective::Latency,
});
enum_conversion!(FecPresetFamilyV1, wit::FecPresetFamily, {
    FecPresetFamilyV1::Unspecified => wit::FecPresetFamily::Unspecified,
    FecPresetFamilyV1::Sparse => wit::FecPresetFamily::Sparse,
    FecPresetFamilyV1::Balanced => wit::FecPresetFamily::Balanced,
    FecPresetFamilyV1::Dense => wit::FecPresetFamily::Dense,
});
enum_conversion!(RepairWaitPolicyV1, wit::RepairWaitPolicy, {
    RepairWaitPolicyV1::HostDefault => wit::RepairWaitPolicy::HostDefault,
    RepairWaitPolicyV1::Eager => wit::RepairWaitPolicy::Eager,
    RepairWaitPolicyV1::AfterFecWindow => wit::RepairWaitPolicy::AfterFecWindow,
    RepairWaitPolicyV1::Patient => wit::RepairWaitPolicy::Patient,
});
enum_conversion!(ProtectionResponsibilityV1, wit::ProtectionResponsibility, {
    ProtectionResponsibilityV1::HostDefault => wit::ProtectionResponsibility::HostDefault,
    ProtectionResponsibilityV1::PreferFec => wit::ProtectionResponsibility::PreferFec,
    ProtectionResponsibilityV1::PreferRepair => wit::ProtectionResponsibility::PreferRepair,
    ProtectionResponsibilityV1::Both => wit::ProtectionResponsibility::Both,
});
enum_conversion!(SchedulerPresetHintV1, wit::SchedulerPresetHint, {
    SchedulerPresetHintV1::HostDefault => wit::SchedulerPresetHint::HostDefault,
    SchedulerPresetHintV1::LatencyFirst => wit::SchedulerPresetHint::LatencyFirst,
    SchedulerPresetHintV1::Balanced => wit::SchedulerPresetHint::Balanced,
    SchedulerPresetHintV1::BulkThroughput => wit::SchedulerPresetHint::BulkThroughput,
});
enum_conversion!(PolicyDecisionKindV1, wit::PolicyDecisionKind, {
    PolicyDecisionKindV1::Hold => wit::PolicyDecisionKind::Hold,
    PolicyDecisionKindV1::Exploit => wit::PolicyDecisionKind::Exploit,
    PolicyDecisionKindV1::Explore => wit::PolicyDecisionKind::Explore,
    PolicyDecisionKindV1::Rollback => wit::PolicyDecisionKind::Rollback,
    PolicyDecisionKindV1::ColdStart => wit::PolicyDecisionKind::ColdStart,
    PolicyDecisionKindV1::Fallback => wit::PolicyDecisionKind::Fallback,
});
enum_conversion!(ClampFieldV1, wit::ClampField, {
    ClampFieldV1::BbrPreset => wit::ClampField::BbrPreset,
    ClampFieldV1::BbrProbeBwUpPacingGainMilli => wit::ClampField::BbrProbeBwUpPacingGainMilli,
    ClampFieldV1::BbrProbeBwDownPacingGainMilli => wit::ClampField::BbrProbeBwDownPacingGainMilli,
    ClampFieldV1::BbrCruisePacingGainMilli => wit::ClampField::BbrCruisePacingGainMilli,
    ClampFieldV1::BbrDefaultCwndGainMilli => wit::ClampField::BbrDefaultCwndGainMilli,
    ClampFieldV1::BbrProbeBwUpCwndGainMilli => wit::ClampField::BbrProbeBwUpCwndGainMilli,
    ClampFieldV1::BbrHeadroomMilli => wit::ClampField::BbrHeadroomMilli,
    ClampFieldV1::BbrBetaMilli => wit::ClampField::BbrBetaMilli,
    ClampFieldV1::BbrLossThresholdMilli => wit::ClampField::BbrLossThresholdMilli,
    ClampFieldV1::BbrLossIsCongestion => wit::ClampField::BbrLossIsCongestion,
    ClampFieldV1::BbrQueueGuardInflationMilli => wit::ClampField::BbrQueueGuardInflationMilli,
    ClampFieldV1::BbrQueueGuardSlackMicros => wit::ClampField::BbrQueueGuardSlackMicros,
    ClampFieldV1::BbrProbeRttIntervalMillis => wit::ClampField::BbrProbeRttIntervalMillis,
    ClampFieldV1::BbrProbeRttDurationMillis => wit::ClampField::BbrProbeRttDurationMillis,
    ClampFieldV1::BbrProbeRttCwndGainMilli => wit::ClampField::BbrProbeRttCwndGainMilli,
    ClampFieldV1::BbrMinProbeWaitMillis => wit::ClampField::BbrMinProbeWaitMillis,
    ClampFieldV1::BbrMaxAddedProbeWaitMillis => wit::ClampField::BbrMaxAddedProbeWaitMillis,
    ClampFieldV1::BbrPacingCapBytesPerSecond => wit::ClampField::BbrPacingCapBytesPerSecond,
    ClampFieldV1::BbrCwndFloorBytes => wit::ClampField::BbrCwndFloorBytes,
    ClampFieldV1::BbrCwndCapBytes => wit::ClampField::BbrCwndCapBytes,
    ClampFieldV1::BbrStartupBwHintBytesPerSecond => wit::ClampField::BbrStartupBwHintBytesPerSecond,
    ClampFieldV1::SchedulerTrainTargetBytes => wit::ClampField::SchedulerTrainTargetBytes,
    ClampFieldV1::SchedulerBulkQuantumCells => wit::ClampField::SchedulerBulkQuantumCells,
    ClampFieldV1::SchedulerBulkAdmissionWindowBytes => wit::ClampField::SchedulerBulkAdmissionWindowBytes,
    ClampFieldV1::SchedulerPresetHint => wit::ClampField::SchedulerPresetHint,
    ClampFieldV1::FecEnabled => wit::ClampField::FecEnabled,
    ClampFieldV1::FecDataCells => wit::ClampField::FecDataCells,
    ClampFieldV1::FecParityCells => wit::ClampField::FecParityCells,
    ClampFieldV1::FecPresetFamily => wit::ClampField::FecPresetFamily,
    ClampFieldV1::RepairCacheBytes => wit::ClampField::RepairCacheBytes,
    ClampFieldV1::RepairRetentionTargetMillis => wit::ClampField::RepairRetentionTargetMillis,
    ClampFieldV1::RepairWaitPolicy => wit::ClampField::RepairWaitPolicy,
    ClampFieldV1::RepairResponsibility => wit::ClampField::RepairResponsibility,
    ClampFieldV1::TxSendBufferBytes => wit::ClampField::TxSendBufferBytes,
    ClampFieldV1::TxDatagramAdmissionBytes => wit::ClampField::TxDatagramAdmissionBytes,
    ClampFieldV1::TxProducerWindowBytes => wit::ClampField::TxProducerWindowBytes,
    ClampFieldV1::RxReceiveBufferBytes => wit::ClampField::RxReceiveBufferBytes,
    ClampFieldV1::RxReceiveBatch => wit::ClampField::RxReceiveBatch,
    ClampFieldV1::RxReassemblyBudgetBytes => wit::ClampField::RxReassemblyBudgetBytes,
    ClampFieldV1::RxActiveTrainBudget => wit::ClampField::RxActiveTrainBudget,
    ClampFieldV1::CoverProfile => wit::ClampField::CoverProfile,
    ClampFieldV1::CoverOverheadPerMille => wit::ClampField::CoverOverheadPerMille,
    ClampFieldV1::CoverPaddingBytesPerSecond => wit::ClampField::CoverPaddingBytesPerSecond,
    ClampFieldV1::EgressDesiredRateBytesPerSecond => wit::ClampField::EgressDesiredRateBytesPerSecond,
    ClampFieldV1::EgressMinimumRateBytesPerSecond => wit::ClampField::EgressMinimumRateBytesPerSecond,
    ClampFieldV1::EgressPriority => wit::ClampField::EgressPriority,
    ClampFieldV1::EgressExploring => wit::ClampField::EgressExploring,
    ClampFieldV1::Extension => wit::ClampField::Extension,
});
enum_conversion!(ClampReasonV1, wit::ClampReason, {
    ClampReasonV1::BelowFloor => wit::ClampReason::BelowFloor,
    ClampReasonV1::AboveCap => wit::ClampReason::AboveCap,
    ClampReasonV1::InvalidValue => wit::ClampReason::InvalidValue,
    ClampReasonV1::Overflow => wit::ClampReason::Overflow,
    ClampReasonV1::CrossFieldConstraint => wit::ClampReason::CrossFieldConstraint,
    ClampReasonV1::UnknownExtension => wit::ClampReason::UnknownExtension,
    ClampReasonV1::ExtensionTooLarge => wit::ClampReason::ExtensionTooLarge,
    ClampReasonV1::TooManyExtensions => wit::ClampReason::TooManyExtensions,
    ClampReasonV1::ReliableUnderlay => wit::ClampReason::ReliableUnderlay,
    ClampReasonV1::CpuPressure => wit::ClampReason::CpuPressure,
    ClampReasonV1::QueuePressure => wit::ClampReason::QueuePressure,
    ClampReasonV1::Capability => wit::ClampReason::Capability,
    ClampReasonV1::MemoryBudget => wit::ClampReason::MemoryBudget,
    ClampReasonV1::WireOverhead => wit::ClampReason::WireOverhead,
    ClampReasonV1::EgressArbitration => wit::ClampReason::EgressArbitration,
    ClampReasonV1::TransitionHold => wit::ClampReason::TransitionHold,
    ClampReasonV1::Unsupported => wit::ClampReason::Unsupported,
});
enum_conversion!(PolicyFaultV1, wit::PolicyFault, {
    PolicyFaultV1::Trap => wit::PolicyFault::Trap,
    PolicyFaultV1::Timeout => wit::PolicyFault::Timeout,
    PolicyFaultV1::FuelExhausted => wit::PolicyFault::FuelExhausted,
    PolicyFaultV1::OutOfMemory => wit::PolicyFault::OutOfMemory,
    PolicyFaultV1::InputTooLarge => wit::PolicyFault::InputTooLarge,
    PolicyFaultV1::OutputTooLarge => wit::PolicyFault::OutputTooLarge,
    PolicyFaultV1::InvalidOutput => wit::PolicyFault::InvalidOutput,
    PolicyFaultV1::StateTooLarge => wit::PolicyFault::StateTooLarge,
    PolicyFaultV1::AbiMismatch => wit::PolicyFault::AbiMismatch,
    PolicyFaultV1::Unavailable => wit::PolicyFault::Unavailable,
    PolicyFaultV1::Internal => wit::PolicyFault::Internal,
});

/// Convert a fixed ABI diagnostics label to the WIT list representation.
pub fn label_to_wit(value: PolicyLabelV1) -> wit::PolicyLabel {
    value.0.to_vec()
}

/// Convert a WIT diagnostics label, rejecting values larger than the ABI's
/// fixed 16-byte slot.  The fault is selected by the caller because labels
/// only occur in output records today.
pub fn label_from_wit(value: wit::PolicyLabel) -> Result<PolicyLabelV1, PolicyFaultV1> {
    if value.len() > POLICY_LABEL_BYTES {
        return Err(PolicyFaultV1::InvalidOutput);
    }
    let mut label = [0; POLICY_LABEL_BYTES];
    label[..value.len()].copy_from_slice(&value);
    Ok(PolicyLabelV1(label))
}

impl From<PolicyExtensionV1> for wit::PolicyExtension {
    fn from(value: PolicyExtensionV1) -> Self {
        Self {
            tag: value.tag,
            payload: value.payload,
        }
    }
}

impl TryFrom<wit::PolicyExtension> for PolicyExtensionV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::PolicyExtension) -> Result<Self, Self::Error> {
        if value.payload.len() > POLICY_EXTENSION_MAX_PAYLOAD_BYTES as usize {
            return Err(PolicyFaultV1::AbiMismatch);
        }
        Ok(Self {
            tag: value.tag,
            payload: value.payload,
        })
    }
}

record_mixed!(
    PolicyTelemetryV1,
    wit::PolicyTelemetry,
    copy: [
        path_rtt_micros,
        path_min_rtt_micros,
        path_queue_delay_micros,
        local_tx_wire_rate_bytes_per_second,
        local_tx_tun_ingress_bytes_per_second,
        local_tx_real_traffic_bytes_per_second,
        local_tx_train_build_bytes_per_second,
        local_tx_packets_per_second,
        local_tx_loss_ppm,
        local_tx_burst_loss_cells,
        local_tx_average_record_bytes,
        local_tx_gso_ingress_ratio_ppm,
        local_tx_packet_train_queue_bytes,
        local_tx_latency_queue_bytes,
        local_tx_bulk_preemption_delay_average_micros,
        local_tx_controller_pacing_rate_bytes_per_second,
        local_tx_controller_send_quantum_bytes,
        local_tx_controller_state,
        local_tx_controller_bw_bytes_per_second,
        local_tx_controller_inflight_longterm_bytes,
        local_tx_controller_guard_transitions_delta,
        local_tx_controller_app_limited,
        local_tx_controller_tunables_generation,
        local_tx_controller_params_generation,
        local_tx_controller_clamped_writes,
        local_rx_wire_rate_bytes_per_second,
        local_rx_reassembly_pressure_evictions,
        remote_goodput_bytes_per_second,
        remote_residual_loss_ppm,
        remote_reorder_ppm,
        remote_expired_stripes_delta,
        remote_wasted_parity_per_mille,
        remote_fec_recovery_per_mille,
        remote_repair_hit_per_mille,
        remote_repair_completed_requests,
        remote_repair_response_latency_micros,
        latency_sojourn_p50_micros,
        latency_sojourn_p95_micros,
        latency_sojourn_p99_micros,
        latency_queue_recently_nonempty,
        host_cpu_utilization_per_mille,
    ],
    enums: [],
    option_enums: []
);

record_mixed!(
    HostUtilityV1,
    wit::HostUtility,
    copy: [
        valid,
        utility_milli,
        throughput_milli,
        queue_delay_milli,
        latency_sojourn_milli,
        residual_loss_milli,
        jitter_milli,
        cpu_milli,
        wire_overhead_milli,
        memory_milli,
        goodput_bytes_per_second,
    ],
    enums: [objective],
    option_enums: []
);

record_mixed!(
    HostLimitsV1,
    wit::HostLimits,
    copy: [
        train_target_floor_bytes,
        train_target_cap_bytes,
        bulk_quantum_floor_cells,
        bulk_quantum_cap_cells,
        send_buffer_floor_bytes,
        send_buffer_cap_bytes,
        receive_buffer_floor_bytes,
        receive_buffer_cap_bytes,
        receive_batch_cap,
        repair_cache_cap_bytes,
        fec_data_cells_cap,
        fec_parity_cells_cap,
        fec_parity_per_mille_cap,
        cover_overhead_cap_per_mille,
        cover_padding_cap_bytes_per_second,
        pacing_cap_bytes_per_second,
        egress_priority_cap,
        state_cap_bytes,
        extension_payload_cap_bytes,
        extension_count_cap,
    ],
    enums: [],
    option_enums: []
);

record_mixed!(
    HostCapabilitiesV1,
    wit::HostCapabilities,
    copy: [
        abi_major,
        abi_minor,
        fec_supported,
        repair_supported,
        cover_supported,
        bbr_tunables_writable,
        egress_coordinator,
        shadow,
        extension_tags,
    ],
    enums: [],
    option_enums: []
);

record_mixed!(
    EgressAllocationViewV1,
    wit::EgressAllocationView,
    copy: [
        assigned_rate_bytes_per_second,
        node_cap_bytes_per_second,
        node_demand_bytes_per_second,
        pressure_per_mille,
        active_peers,
        allocation_generation,
    ],
    enums: [],
    option_enums: []
);

record_mixed!(
    BbrEffectiveV1,
    wit::BbrEffective,
    copy: [
        probe_bw_up_pacing_gain_milli,
        probe_bw_down_pacing_gain_milli,
        cruise_pacing_gain_milli,
        default_cwnd_gain_milli,
        probe_bw_up_cwnd_gain_milli,
        headroom_milli,
        beta_milli,
        loss_threshold_milli,
        loss_is_congestion,
        queue_guard_inflation_milli,
        queue_guard_slack_micros,
        probe_rtt_interval_millis,
        probe_rtt_duration_millis,
        probe_rtt_cwnd_gain_milli,
        min_probe_wait_millis,
        max_added_probe_wait_millis,
        pacing_cap_bytes_per_second,
        cwnd_floor_bytes,
        cwnd_cap_bytes,
        startup_bw_hint_bytes_per_second,
    ],
    enums: [preset],
    option_enums: []
);

record_mixed!(
    SchedulerEffectiveV1,
    wit::SchedulerEffective,
    copy: [train_target_bytes, bulk_quantum_cells, bulk_admission_window_bytes],
    enums: [preset_hint],
    option_enums: []
);
record_mixed!(
    FecEffectiveV1,
    wit::FecEffective,
    copy: [enabled, data_cells, parity_cells],
    enums: [preset_family],
    option_enums: []
);
record_mixed!(
    RepairEffectiveV1,
    wit::RepairEffective,
    copy: [cache_bytes, retention_target_millis],
    enums: [wait_policy, responsibility],
    option_enums: []
);
record_mixed!(
    TxEffectiveV1,
    wit::TxEffective,
    copy: [send_buffer_bytes, datagram_admission_bytes, producer_window_bytes],
    enums: [],
    option_enums: []
);
record_mixed!(
    RxEffectiveV1,
    wit::RxEffective,
    copy: [receive_buffer_bytes, receive_batch, reassembly_budget_bytes, active_train_budget],
    enums: [],
    option_enums: []
);
record_mixed!(
    CoverEffectiveV1,
    wit::CoverEffective,
    copy: [overhead_per_mille, padding_bytes_per_second],
    enums: [profile],
    option_enums: []
);
record_mixed!(
    EgressRequestV1,
    wit::EgressRequest,
    copy: [desired_rate_bytes_per_second, minimum_rate_bytes_per_second, priority, exploring],
    enums: [],
    option_enums: []
);

impl From<EffectiveActionV1> for wit::EffectiveAction {
    fn from(value: EffectiveActionV1) -> Self {
        Self {
            reason: value.reason.into(),
            path_epoch: value.path_epoch,
            sample_count: value.sample_count,
            bbr: value.bbr.into(),
            scheduler: value.scheduler.into(),
            fec: value.fec.into(),
            repair: value.repair.into(),
            tx: value.tx.into(),
            rx: value.rx.into(),
            cover: value.cover.into(),
            egress: value.egress.into(),
        }
    }
}

impl TryFrom<wit::EffectiveAction> for EffectiveActionV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::EffectiveAction) -> Result<Self, Self::Error> {
        Ok(Self {
            reason: value.reason.into(),
            path_epoch: value.path_epoch,
            sample_count: value.sample_count,
            bbr: value.bbr.try_into()?,
            scheduler: value.scheduler.try_into()?,
            fec: value.fec.try_into()?,
            repair: value.repair.try_into()?,
            tx: value.tx.try_into()?,
            rx: value.rx.try_into()?,
            cover: value.cover.try_into()?,
            egress: value.egress.try_into()?,
        })
    }
}

record_mixed!(
    BbrCandidateV1,
    wit::BbrCandidate,
    copy: [
        probe_bw_up_pacing_gain_milli,
        probe_bw_down_pacing_gain_milli,
        cruise_pacing_gain_milli,
        default_cwnd_gain_milli,
        probe_bw_up_cwnd_gain_milli,
        headroom_milli,
        beta_milli,
        loss_threshold_milli,
        loss_is_congestion,
        queue_guard_inflation_milli,
        queue_guard_slack_micros,
        probe_rtt_interval_millis,
        probe_rtt_duration_millis,
        probe_rtt_cwnd_gain_milli,
        min_probe_wait_millis,
        max_added_probe_wait_millis,
        pacing_cap_bytes_per_second,
        cwnd_floor_bytes,
        cwnd_cap_bytes,
        startup_bw_hint_bytes_per_second,
    ],
    enums: [],
    option_enums: [preset]
);
record_mixed!(
    SchedulerCandidateV1,
    wit::SchedulerCandidate,
    copy: [train_target_bytes, bulk_quantum_cells, bulk_admission_window_bytes],
    enums: [],
    option_enums: [preset_hint]
);
record_mixed!(
    FecCandidateV1,
    wit::FecCandidate,
    copy: [enabled, data_cells, parity_cells],
    enums: [],
    option_enums: [preset_family]
);
record_mixed!(
    RepairCandidateV1,
    wit::RepairCandidate,
    copy: [cache_bytes, retention_target_millis],
    enums: [],
    option_enums: [wait_policy, responsibility]
);
record_mixed!(
    TxCandidateV1,
    wit::TxCandidate,
    copy: [send_buffer_bytes, datagram_admission_bytes, producer_window_bytes],
    enums: [],
    option_enums: []
);
record_mixed!(
    RxCandidateV1,
    wit::RxCandidate,
    copy: [receive_buffer_bytes, receive_batch, reassembly_budget_bytes, active_train_budget],
    enums: [],
    option_enums: []
);
record_mixed!(
    CoverCandidateV1,
    wit::CoverCandidate,
    copy: [overhead_per_mille, padding_bytes_per_second],
    enums: [],
    option_enums: [profile]
);

impl From<ClampEntryV1> for wit::ClampEntry {
    fn from(value: ClampEntryV1) -> Self {
        Self {
            field: value.field.into(),
            requested: value.requested,
            effective: value.effective,
            reason: value.reason.into(),
        }
    }
}

impl TryFrom<wit::ClampEntry> for ClampEntryV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::ClampEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            field: value.field.into(),
            requested: value.requested,
            effective: value.effective,
            reason: value.reason.into(),
        })
    }
}

impl From<ClampReportV1> for wit::ClampReport {
    fn from(value: ClampReportV1) -> Self {
        Self {
            entries: value.entries.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<wit::ClampReport> for ClampReportV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::ClampReport) -> Result<Self, Self::Error> {
        Ok(Self {
            entries: value
                .entries
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<CandidateActionV1> for wit::CandidateAction {
    fn from(value: CandidateActionV1) -> Self {
        Self {
            bbr: value.bbr.map(Into::into),
            scheduler: value.scheduler.map(Into::into),
            fec: value.fec.map(Into::into),
            repair: value.repair.map(Into::into),
            tx: value.tx.map(Into::into),
            rx: value.rx.map(Into::into),
            cover: value.cover.map(Into::into),
            egress_request: value.egress_request.map(Into::into),
            extensions: value.extensions.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<wit::CandidateAction> for CandidateActionV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::CandidateAction) -> Result<Self, Self::Error> {
        if value.extensions.len() > POLICY_EXTENSION_MAX_COUNT as usize {
            return Err(PolicyFaultV1::InvalidOutput);
        }
        Ok(Self {
            bbr: value.bbr.map(TryInto::try_into).transpose()?,
            scheduler: value.scheduler.map(TryInto::try_into).transpose()?,
            fec: value.fec.map(TryInto::try_into).transpose()?,
            repair: value.repair.map(TryInto::try_into).transpose()?,
            tx: value.tx.map(TryInto::try_into).transpose()?,
            rx: value.rx.map(TryInto::try_into).transpose()?,
            cover: value.cover.map(TryInto::try_into).transpose()?,
            egress_request: value.egress_request.map(TryInto::try_into).transpose()?,
            extensions: value
                .extensions
                .into_iter()
                .map(|extension| {
                    PolicyExtensionV1::try_from(extension).map_err(|_| PolicyFaultV1::InvalidOutput)
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<PolicyDiagnosticsV1> for wit::PolicyDiagnostics {
    fn from(value: PolicyDiagnosticsV1) -> Self {
        Self {
            decision_kind: value.decision_kind.into(),
            context_label: label_to_wit(value.context_label),
            applied_arm_label: label_to_wit(value.applied_arm_label),
            baseline_arm_label: label_to_wit(value.baseline_arm_label),
            predicted_advantage_milli: value.predicted_advantage_milli,
            confidence_per_mille: value.confidence_per_mille,
            exploring: value.exploring,
            rollback: value.rollback,
            rollbacks: value.rollbacks,
            guest_utility_milli: value.guest_utility_milli,
            state_schema: value.state_schema,
        }
    }
}

impl TryFrom<wit::PolicyDiagnostics> for PolicyDiagnosticsV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::PolicyDiagnostics) -> Result<Self, Self::Error> {
        Ok(Self {
            decision_kind: value.decision_kind.into(),
            context_label: label_from_wit(value.context_label)
                .map_err(|_| PolicyFaultV1::InvalidOutput)?,
            applied_arm_label: label_from_wit(value.applied_arm_label)
                .map_err(|_| PolicyFaultV1::InvalidOutput)?,
            baseline_arm_label: label_from_wit(value.baseline_arm_label)
                .map_err(|_| PolicyFaultV1::InvalidOutput)?,
            predicted_advantage_milli: value.predicted_advantage_milli,
            confidence_per_mille: value.confidence_per_mille,
            exploring: value.exploring,
            rollback: value.rollback,
            rollbacks: value.rollbacks,
            guest_utility_milli: value.guest_utility_milli,
            state_schema: value.state_schema,
        })
    }
}

impl From<PolicyInputV1> for wit::PolicyInput {
    fn from(value: PolicyInputV1) -> Self {
        Self {
            logical_tick: value.logical_tick,
            deterministic_seed: value.deterministic_seed,
            peer_hash: value.peer_hash.to_vec(),
            path_epoch: value.path_epoch,
            reliability: value.reliability.into(),
            telemetry: value.telemetry.into(),
            previous: value.previous.into(),
            previous_utility: value.previous_utility.into(),
            limits: value.limits.into(),
            capabilities: value.capabilities.into(),
            egress: value.egress.into(),
            extensions: value.extensions.into_iter().map(Into::into).collect(),
            state: value.state,
        }
    }
}

impl TryFrom<wit::PolicyInput> for PolicyInputV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::PolicyInput) -> Result<Self, Self::Error> {
        let peer_hash: [u8; 32] = value
            .peer_hash
            .try_into()
            .map_err(|_| PolicyFaultV1::AbiMismatch)?;
        if value.extensions.len() > POLICY_EXTENSION_MAX_COUNT as usize {
            return Err(PolicyFaultV1::AbiMismatch);
        }
        if value.state.len() > POLICY_STATE_MAX_BYTES as usize {
            return Err(PolicyFaultV1::AbiMismatch);
        }
        Ok(Self {
            logical_tick: value.logical_tick,
            deterministic_seed: value.deterministic_seed,
            peer_hash,
            path_epoch: value.path_epoch,
            reliability: value.reliability.into(),
            telemetry: value.telemetry.try_into()?,
            previous: value.previous.try_into()?,
            previous_utility: value.previous_utility.try_into()?,
            limits: value.limits.try_into()?,
            capabilities: value.capabilities.try_into()?,
            egress: value.egress.try_into()?,
            extensions: value
                .extensions
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            state: value.state,
        })
    }
}

impl From<PolicyOutputV1> for wit::PolicyOutput {
    fn from(value: PolicyOutputV1) -> Self {
        Self {
            candidate: value.candidate.into(),
            next_state: value.next_state,
            diagnostics: value.diagnostics.into(),
        }
    }
}

impl TryFrom<wit::PolicyOutput> for PolicyOutputV1 {
    type Error = PolicyFaultV1;

    fn try_from(value: wit::PolicyOutput) -> Result<Self, Self::Error> {
        if value.next_state.len() > POLICY_STATE_MAX_BYTES as usize {
            return Err(PolicyFaultV1::InvalidOutput);
        }
        Ok(Self {
            candidate: value.candidate.try_into()?,
            next_state: value.next_state,
            diagnostics: value.diagnostics.try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_and_output_round_trip() {
        let input = PolicyInputV1 {
            peer_hash: [7; 32],
            extensions: vec![PolicyExtensionV1 {
                tag: 3,
                payload: vec![1, 2, 3],
            }],
            state: vec![9, 8, 7],
            ..PolicyInputV1::default()
        };
        let raw: wit::PolicyInput = input.clone().into();
        assert_eq!(PolicyInputV1::try_from(raw).unwrap(), input);

        let output = PolicyOutputV1 {
            candidate: CandidateActionV1 {
                bbr: Some(BbrCandidateV1 {
                    preset: Some(Bbr3PresetV1::LossyRadio),
                    ..BbrCandidateV1::default()
                }),
                ..CandidateActionV1::default()
            },
            next_state: vec![4, 5],
            ..PolicyOutputV1::default()
        };
        let raw: wit::PolicyOutput = output.clone().into();
        assert_eq!(PolicyOutputV1::try_from(raw).unwrap(), output);
    }

    #[test]
    fn malformed_lengths_map_to_the_right_fault() {
        let mut input: wit::PolicyInput = PolicyInputV1::default().into();
        input.peer_hash.clear();
        assert_eq!(
            PolicyInputV1::try_from(input),
            Err(PolicyFaultV1::AbiMismatch)
        );

        let mut output: wit::PolicyOutput = PolicyOutputV1::default().into();
        output.next_state = vec![0; POLICY_STATE_MAX_BYTES as usize + 1];
        assert_eq!(
            PolicyOutputV1::try_from(output),
            Err(PolicyFaultV1::InvalidOutput)
        );

        let label: wit::PolicyLabel = vec![0; POLICY_LABEL_BYTES + 1];
        assert_eq!(label_from_wit(label), Err(PolicyFaultV1::InvalidOutput));
    }
}
