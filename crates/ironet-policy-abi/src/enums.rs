//! Closed enums shared by input, candidate and effective types. Every enum
//! exposes `ALL` (declaration order == WIT order) for exhaustive tooling.

use serde::{Deserialize, Serialize};

/// Underlay reliability of the current path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathReliabilityV1 {
    /// Plain datagram path; loss and reordering are visible end to end.
    #[default]
    Datagram,
    /// Relay/stream underlay that already retransmits; FEC/Repair add no value.
    ReliableRelay,
}

impl PathReliabilityV1 {
    pub const ALL: [Self; 2] = [Self::Datagram, Self::ReliableRelay];
}

/// Host-side classification of why an effective action has its shape.
/// Diagnostics only; carried so the migration adapter can round-trip the
/// legacy `TuneDecisionV2::reason`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionReasonV1 {
    #[default]
    ColdStart,
    TelemetryUnavailable,
    PathChanged,
    HealthyLowLoss,
    RandomLoss,
    BurstLoss,
    Congested,
    CpuLimited,
    ReliablePath,
}

impl ActionReasonV1 {
    pub const ALL: [Self; 9] = [
        Self::ColdStart,
        Self::TelemetryUnavailable,
        Self::PathChanged,
        Self::HealthyLowLoss,
        Self::RandomLoss,
        Self::BurstLoss,
        Self::Congested,
        Self::CpuLimited,
        Self::ReliablePath,
    ];
}

/// Cover-traffic shaping profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverProfileV1 {
    #[default]
    Idle,
    LiveBroadcast,
    InteractiveVideo,
    GenericH3Bulk,
}

impl CoverProfileV1 {
    pub const ALL: [Self; 4] = [
        Self::Idle,
        Self::LiveBroadcast,
        Self::InteractiveVideo,
        Self::GenericH3Bulk,
    ];
}

/// BBRv3 preset family. In the ABI a preset is a hint: the explicit tunables
/// in `BbrCandidateV1` always win when set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bbr3PresetV1 {
    #[default]
    SharedConservative,
    PrivateAggressive,
    LossyRadio,
    Policer,
    LongFat,
    RelayReliable,
    LowRttHost,
}

impl Bbr3PresetV1 {
    pub const ALL: [Self; 7] = [
        Self::SharedConservative,
        Self::PrivateAggressive,
        Self::LossyRadio,
        Self::Policer,
        Self::LongFat,
        Self::RelayReliable,
        Self::LowRttHost,
    ];
}

/// Utility objective the host used to compute `HostUtilityV1`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectiveV1 {
    #[default]
    Balanced,
    Throughput,
    Latency,
}

impl ObjectiveV1 {
    pub const ALL: [Self; 3] = [Self::Balanced, Self::Throughput, Self::Latency];
}

/// FEC geometry family hint. The host may use it to pick a geometry when the
/// candidate leaves `data_cells`/`parity_cells` unset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FecPresetFamilyV1 {
    /// No hint; explicit cells or the host baseline apply.
    #[default]
    Unspecified,
    /// One parity cell over a long stripe (congestion-safe, ~6% overhead).
    Sparse,
    /// Moderate parity ratio for random-loss WANs.
    Balanced,
    /// Highest allowed parity ratio for bursty radio paths.
    Dense,
}

impl FecPresetFamilyV1 {
    pub const ALL: [Self; 4] = [Self::Unspecified, Self::Sparse, Self::Balanced, Self::Dense];
}

/// When the local receiver sends Repair requests for a detected gap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairWaitPolicyV1 {
    /// Host baseline behaviour.
    #[default]
    HostDefault,
    /// Request as soon as a gap is detected.
    Eager,
    /// Wait for the FEC stripe to close before requesting.
    AfterFecWindow,
    /// Wait an extra RTT for late reordering before requesting.
    Patient,
}

impl RepairWaitPolicyV1 {
    pub const ALL: [Self; 4] = [
        Self::HostDefault,
        Self::Eager,
        Self::AfterFecWindow,
        Self::Patient,
    ];
}

/// Which protection mechanism should carry the loss-recovery budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionResponsibilityV1 {
    #[default]
    HostDefault,
    /// Spend wire budget on parity first; Repair is a fallback.
    PreferFec,
    /// Keep parity minimal and rely on Repair round trips.
    PreferRepair,
    /// Use both at the maximum the guardrails allow.
    Both,
}

impl ProtectionResponsibilityV1 {
    pub const ALL: [Self; 4] = [
        Self::HostDefault,
        Self::PreferFec,
        Self::PreferRepair,
        Self::Both,
    ];
}

/// Scheduler behaviour hint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchedulerPresetHintV1 {
    #[default]
    HostDefault,
    LatencyFirst,
    Balanced,
    BulkThroughput,
}

impl SchedulerPresetHintV1 {
    pub const ALL: [Self; 4] = [
        Self::HostDefault,
        Self::LatencyFirst,
        Self::Balanced,
        Self::BulkThroughput,
    ];
}

/// Kind of decision the policy reports for diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyDecisionKindV1 {
    /// No candidate change versus the previous effective action.
    #[default]
    Hold,
    /// Exploitation of the best known arm.
    Exploit,
    /// Exploration of a non-best arm.
    Explore,
    /// Roll back an exploration that regressed the host utility.
    Rollback,
    /// First ticks without learned state.
    ColdStart,
    /// Policy could not decide and returned the conservative baseline.
    Fallback,
}

impl PolicyDecisionKindV1 {
    pub const ALL: [Self; 6] = [
        Self::Hold,
        Self::Exploit,
        Self::Explore,
        Self::Rollback,
        Self::ColdStart,
        Self::Fallback,
    ];
}
