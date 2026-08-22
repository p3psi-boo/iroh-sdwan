//! Host-authoritative effective action.

use serde::{Deserialize, Serialize};

use crate::{
    ActionReasonV1, Bbr3PresetV1, CoverProfileV1, EgressRequestV1, FecPresetFamilyV1,
    ProtectionResponsibilityV1, RepairWaitPolicyV1, SchedulerPresetHintV1,
};

/// Static cwnd floor the `LowRttHost` preset requests.
pub const LOW_RTT_HOST_CWND_FLOOR_BYTES: u64 = 512 * 1024;

/// Fully resolved BBRv3 tunables the host writes to `Bbr3Tunables`. Units as
/// in `BbrCandidateV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbrEffectiveV1 {
    /// Preset the values were derived from (diagnostics/round-trip only).
    pub preset: Bbr3PresetV1,
    pub probe_bw_up_pacing_gain_milli: u32,
    pub probe_bw_down_pacing_gain_milli: u32,
    pub cruise_pacing_gain_milli: u32,
    pub default_cwnd_gain_milli: u32,
    pub probe_bw_up_cwnd_gain_milli: u32,
    pub headroom_milli: u32,
    pub beta_milli: u32,
    pub loss_threshold_milli: u32,
    pub loss_is_congestion: bool,
    pub queue_guard_inflation_milli: u32,
    pub queue_guard_slack_micros: u64,
    pub probe_rtt_interval_millis: u64,
    pub probe_rtt_duration_millis: u64,
    pub probe_rtt_cwnd_gain_milli: u32,
    pub min_probe_wait_millis: u64,
    pub max_added_probe_wait_millis: u64,
    pub pacing_cap_bytes_per_second: u64,
    pub cwnd_floor_bytes: u64,
    pub cwnd_cap_bytes: u64,
    pub startup_bw_hint_bytes_per_second: u64,
}

impl BbrEffectiveV1 {
    /// Expand a preset plus the five learner-controlled knobs into the full
    /// static tunable set: `cruise`, `queue guard`, `probe RTT interval` and
    /// the static cwnd floor come from the preset table, the rest are
    /// controller defaults. The runtime later finalizes its telemetry-derived
    /// cwnd floor before applying the action.
    pub fn expand_preset(
        preset: Bbr3PresetV1,
        up_gain_milli: u32,
        headroom_milli: u32,
        cwnd_gain_milli: u32,
        pacing_cap_bytes_per_second: u64,
        loss_is_congestion: bool,
    ) -> Self {
        let (cruise, guard, probe_interval, cwnd_floor) = match preset {
            Bbr3PresetV1::SharedConservative => (1_000, 500, 10_000, 0),
            Bbr3PresetV1::PrivateAggressive => (1_000, 500, 5_000, 0),
            Bbr3PresetV1::LossyRadio => (1_000, 800, 10_000, 0),
            Bbr3PresetV1::Policer => (970, 500, 10_000, 0),
            Bbr3PresetV1::LongFat => (1_000, 800, 20_000, 0),
            Bbr3PresetV1::RelayReliable => (980, 500, 10_000, 0),
            Bbr3PresetV1::LowRttHost => (1_000, 500, 5_000, LOW_RTT_HOST_CWND_FLOOR_BYTES),
        };
        Self {
            preset,
            probe_bw_up_pacing_gain_milli: up_gain_milli,
            probe_bw_down_pacing_gain_milli: 900,
            cruise_pacing_gain_milli: cruise,
            default_cwnd_gain_milli: cwnd_gain_milli,
            probe_bw_up_cwnd_gain_milli: cwnd_gain_milli.max(1_500),
            headroom_milli,
            beta_milli: 700,
            loss_threshold_milli: 20,
            loss_is_congestion,
            queue_guard_inflation_milli: guard,
            queue_guard_slack_micros: 5_000,
            probe_rtt_interval_millis: probe_interval,
            probe_rtt_duration_millis: 200,
            probe_rtt_cwnd_gain_milli: 500,
            min_probe_wait_millis: 2_000,
            max_added_probe_wait_millis: 1_000,
            pacing_cap_bytes_per_second,
            cwnd_floor_bytes: cwnd_floor,
            cwnd_cap_bytes: 0,
            startup_bw_hint_bytes_per_second: 0,
        }
    }
}

impl Default for BbrEffectiveV1 {
    /// The shared-conservative preset (host cold-start baseline).
    fn default() -> Self {
        Self::expand_preset(
            Bbr3PresetV1::SharedConservative,
            1_150,
            250,
            2_000,
            0,
            false,
        )
    }
}

/// Resolved scheduler values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEffectiveV1 {
    /// Target PacketTrain size.
    pub train_target_bytes: u32,
    /// Bulk cells per scheduler quantum.
    pub bulk_quantum_cells: u16,
    /// Bulk admission window (0 = host default).
    pub bulk_admission_window_bytes: u32,
    /// Behaviour hint in force.
    pub preset_hint: SchedulerPresetHintV1,
}

/// Resolved FEC values. `enabled == false` means no parity regardless of the
/// cell counts (which are retained for round-trips and diagnostics).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecEffectiveV1 {
    pub enabled: bool,
    pub data_cells: u8,
    pub parity_cells: u8,
    pub preset_family: FecPresetFamilyV1,
}

/// Resolved Repair values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairEffectiveV1 {
    pub cache_bytes: u64,
    /// 0 = host default.
    pub retention_target_millis: u32,
    pub wait_policy: RepairWaitPolicyV1,
    pub responsibility: ProtectionResponsibilityV1,
}

/// Resolved transmit-side values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxEffectiveV1 {
    pub send_buffer_bytes: u64,
    /// 0 = host default.
    pub datagram_admission_bytes: u32,
    /// 0 = host default.
    pub producer_window_bytes: u64,
}

/// Resolved receive-side values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RxEffectiveV1 {
    pub receive_buffer_bytes: u64,
    pub receive_batch: u16,
    /// 0 = follow `receive_buffer_bytes`.
    pub reassembly_budget_bytes: u64,
    /// 0 = host default.
    pub active_train_budget: u16,
}

/// Resolved cover-traffic values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverEffectiveV1 {
    pub profile: CoverProfileV1,
    pub overhead_per_mille: u16,
    pub padding_bytes_per_second: u64,
}

/// Host-authoritative action. Every field holds a concrete value; the data
/// plane never sees an `Option`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveActionV1 {
    /// Host classification of the action (diagnostics).
    pub reason: ActionReasonV1,
    /// Path epoch the action was derived for.
    pub path_epoch: u64,
    /// Telemetry samples observed in this epoch when the action was derived.
    pub sample_count: u32,
    pub bbr: BbrEffectiveV1,
    pub scheduler: SchedulerEffectiveV1,
    pub fec: FecEffectiveV1,
    pub repair: RepairEffectiveV1,
    pub tx: TxEffectiveV1,
    pub rx: RxEffectiveV1,
    pub cover: CoverEffectiveV1,
    /// Egress request the host accepted for the next coordinator round.
    pub egress: EgressRequestV1,
}

/// The effective action as fed back to the policy on the next tick. V1 feeds
/// back the full effective action, so this is an alias.
pub type EffectiveActionViewV1 = EffectiveActionV1;
