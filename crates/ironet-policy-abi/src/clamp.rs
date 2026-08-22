//! Clamp report: what the host changed while deriving the effective action.

use serde::{Deserialize, Serialize};

/// Every candidate field the host may clamp, reject or ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClampFieldV1 {
    BbrPreset,
    BbrProbeBwUpPacingGainMilli,
    BbrProbeBwDownPacingGainMilli,
    BbrCruisePacingGainMilli,
    BbrDefaultCwndGainMilli,
    BbrProbeBwUpCwndGainMilli,
    BbrHeadroomMilli,
    BbrBetaMilli,
    BbrLossThresholdMilli,
    BbrLossIsCongestion,
    BbrQueueGuardInflationMilli,
    BbrQueueGuardSlackMicros,
    BbrProbeRttIntervalMillis,
    BbrProbeRttDurationMillis,
    BbrProbeRttCwndGainMilli,
    BbrMinProbeWaitMillis,
    BbrMaxAddedProbeWaitMillis,
    BbrPacingCapBytesPerSecond,
    BbrCwndFloorBytes,
    BbrCwndCapBytes,
    BbrStartupBwHintBytesPerSecond,
    SchedulerTrainTargetBytes,
    SchedulerBulkQuantumCells,
    SchedulerBulkAdmissionWindowBytes,
    SchedulerPresetHint,
    FecEnabled,
    FecDataCells,
    FecParityCells,
    FecPresetFamily,
    RepairCacheBytes,
    RepairRetentionTargetMillis,
    RepairWaitPolicy,
    RepairResponsibility,
    TxSendBufferBytes,
    TxDatagramAdmissionBytes,
    TxProducerWindowBytes,
    RxReceiveBufferBytes,
    RxReceiveBatch,
    RxReassemblyBudgetBytes,
    RxActiveTrainBudget,
    CoverProfile,
    CoverOverheadPerMille,
    CoverPaddingBytesPerSecond,
    EgressDesiredRateBytesPerSecond,
    EgressMinimumRateBytesPerSecond,
    EgressPriority,
    EgressExploring,
    /// A TLV extension entry; `requested` carries the tag.
    Extension,
}

impl ClampFieldV1 {
    pub const ALL: [Self; 48] = [
        Self::BbrPreset,
        Self::BbrProbeBwUpPacingGainMilli,
        Self::BbrProbeBwDownPacingGainMilli,
        Self::BbrCruisePacingGainMilli,
        Self::BbrDefaultCwndGainMilli,
        Self::BbrProbeBwUpCwndGainMilli,
        Self::BbrHeadroomMilli,
        Self::BbrBetaMilli,
        Self::BbrLossThresholdMilli,
        Self::BbrLossIsCongestion,
        Self::BbrQueueGuardInflationMilli,
        Self::BbrQueueGuardSlackMicros,
        Self::BbrProbeRttIntervalMillis,
        Self::BbrProbeRttDurationMillis,
        Self::BbrProbeRttCwndGainMilli,
        Self::BbrMinProbeWaitMillis,
        Self::BbrMaxAddedProbeWaitMillis,
        Self::BbrPacingCapBytesPerSecond,
        Self::BbrCwndFloorBytes,
        Self::BbrCwndCapBytes,
        Self::BbrStartupBwHintBytesPerSecond,
        Self::SchedulerTrainTargetBytes,
        Self::SchedulerBulkQuantumCells,
        Self::SchedulerBulkAdmissionWindowBytes,
        Self::SchedulerPresetHint,
        Self::FecEnabled,
        Self::FecDataCells,
        Self::FecParityCells,
        Self::FecPresetFamily,
        Self::RepairCacheBytes,
        Self::RepairRetentionTargetMillis,
        Self::RepairWaitPolicy,
        Self::RepairResponsibility,
        Self::TxSendBufferBytes,
        Self::TxDatagramAdmissionBytes,
        Self::TxProducerWindowBytes,
        Self::RxReceiveBufferBytes,
        Self::RxReceiveBatch,
        Self::RxReassemblyBudgetBytes,
        Self::RxActiveTrainBudget,
        Self::CoverProfile,
        Self::CoverOverheadPerMille,
        Self::CoverPaddingBytesPerSecond,
        Self::EgressDesiredRateBytesPerSecond,
        Self::EgressMinimumRateBytesPerSecond,
        Self::EgressPriority,
        Self::EgressExploring,
        Self::Extension,
    ];
}

/// Why a candidate field was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClampReasonV1 {
    /// Requested value below the host floor.
    BelowFloor,
    /// Requested value above the host cap.
    AboveCap,
    /// Enum discriminant or flag combination is not meaningful.
    InvalidValue,
    /// Arithmetic on the value would overflow the host width.
    Overflow,
    /// Violates a relation with another field (floor > cap, duration >
    /// interval, parity > data, ...).
    CrossFieldConstraint,
    /// Extension tag is not registered on this host.
    UnknownExtension,
    /// Extension payload exceeds the per-entry cap.
    ExtensionTooLarge,
    /// More entries than the extension count cap.
    TooManyExtensions,
    /// Path is a reliable relay; protection/cover domains are forced off.
    ReliableUnderlay,
    /// Host CPU guardrail.
    CpuPressure,
    /// Queue/latency guardrail.
    QueuePressure,
    /// Peer/path capability does not support the domain.
    Capability,
    /// Memory budget guardrail.
    MemoryBudget,
    /// Wire overhead guardrail.
    WireOverhead,
    /// Node egress coordinator assigned a different rate.
    EgressArbitration,
    /// Transition controller held the previous value (hysteresis/dwell).
    TransitionHold,
    /// Domain is not supported by this host build.
    Unsupported,
}

impl ClampReasonV1 {
    pub const ALL: [Self; 17] = [
        Self::BelowFloor,
        Self::AboveCap,
        Self::InvalidValue,
        Self::Overflow,
        Self::CrossFieldConstraint,
        Self::UnknownExtension,
        Self::ExtensionTooLarge,
        Self::TooManyExtensions,
        Self::ReliableUnderlay,
        Self::CpuPressure,
        Self::QueuePressure,
        Self::Capability,
        Self::MemoryBudget,
        Self::WireOverhead,
        Self::EgressArbitration,
        Self::TransitionHold,
        Self::Unsupported,
    ];
}

/// One field the host changed, rejected or ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClampEntryV1 {
    pub field: ClampFieldV1,
    /// Value the candidate asked for (widened to `i64`, saturating; bool as
    /// 0/1, enums as discriminant index, extension tag for `Extension`).
    pub requested: i64,
    /// Value the host used instead (same encoding as `requested`).
    pub effective: i64,
    pub reason: ClampReasonV1,
}

impl ClampEntryV1 {
    pub const fn new(
        field: ClampFieldV1,
        requested: i64,
        effective: i64,
        reason: ClampReasonV1,
    ) -> Self {
        Self {
            field,
            requested,
            effective,
            reason,
        }
    }
}

/// All clamps applied while turning a candidate into an effective action.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClampReportV1 {
    pub entries: Vec<ClampEntryV1>,
}

impl ClampReportV1 {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
