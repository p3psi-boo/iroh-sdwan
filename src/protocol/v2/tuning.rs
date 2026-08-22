use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{
    fec::FecGeometryV2,
    policy::{
        api::{
            BbrCandidateV1, CandidateActionV1, ClampReportV1, CoverCandidateV1, EffectiveActionV1,
            EffectiveHostExt, FecCandidateV1, HostLimitsV1, RxCandidateV1, SchedulerCandidateV1,
            TxCandidateV1,
        },
        guardrails::{GuardrailContextV1, GuardrailsV1},
        transition::{TransitionContextV1, TransitionControllerV1},
    },
};

pub(crate) const RECEIVE_PRESSURE_GROWTH_STEP_BYTES: usize = 8 * 1024 * 1024;
const RECEIVE_PRESSURE_HOLD_SAMPLES: u8 = 10;
pub const INITIAL_SEND_BUFFER_BYTES_V2: usize = 256 * 1024;
/// Host default Repair cache retention when the policy leaves
/// `TuneDecisionV2::repair_retention_millis` at zero.
pub const REPAIR_CACHE_DEFAULT_TTL_V2: Duration = Duration::from_secs(2);
const MINIMUM_PROTECTION_TRAFFIC_BYTES_PER_SECOND: u64 = 64 * 1024;
const MINIMUM_PROTECTION_PACKETS_PER_SECOND: u64 = 128;
// A saturated producer can be throttled below the ordinary evidence floors
// by the very loss that protection is meant to recover from.  A real Bulk
// backlog distinguishes that state from idle keepalive/PMTU probe loss.
const MINIMUM_BACKLOG_PROTECTION_BYTES: u64 = 64 * 1024;
const MINIMUM_BACKLOG_PROTECTION_PACKETS_PER_SECOND: u64 = 32;

fn has_protection_evidence(sample: PathTelemetryV2) -> bool {
    (sample.real_traffic_bytes_per_second >= MINIMUM_PROTECTION_TRAFFIC_BYTES_PER_SECOND
        && sample.packets_per_second >= MINIMUM_PROTECTION_PACKETS_PER_SECOND)
        || (sample.packet_train_queue_bytes >= MINIMUM_BACKLOG_PROTECTION_BYTES
            && sample.packets_per_second >= MINIMUM_BACKLOG_PROTECTION_PACKETS_PER_SECOND)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathReliability {
    Datagram,
    ReliableRelay,
}

#[derive(Debug, Clone, Copy)]
pub struct PathTelemetryV2 {
    pub path_epoch: u64,
    pub reliability: PathReliability,
    pub rtt: Duration,
    pub min_rtt: Duration,
    pub queue_delay: Duration,
    pub loss_ppm: u32,
    pub burst_loss_cells: u16,
    pub reorder_ppm: u32,
    /// Payload bytes delivered by the remote receiver per second. This is the
    /// end-to-end goodput reward and intentionally excludes FEC/Repair/cover.
    pub receiver_goodput_bytes_per_second: u64,
    /// Remote receiver gaps that remained when PacketTrains closed.
    pub residual_loss_ppm: u32,
    /// Local semantic-latency queue p95 over the latest telemetry interval.
    pub latency_sojourn_p95_micros: u64,
    pub latency_sojourn_p50_micros: u64,
    pub latency_sojourn_p99_micros: u64,
    /// The latency lane was queued or served during the latest interval.
    pub latency_queue_recently_nonempty: bool,
    /// Locally transmitted QUIC wire rate. All TX scheduling, FEC and
    /// producer-admission decisions are derived from this direction only.
    pub delivery_rate_bytes_per_second: u64,
    pub controller_pacing_rate_bytes_per_second: u64,
    pub controller_send_quantum_bytes: u64,
    pub controller_state: u8,
    pub controller_bw_bytes_per_second: u64,
    pub controller_inflight_longterm_bytes: u64,
    pub controller_guard_transitions_delta: u64,
    pub controller_app_limited: bool,
    pub controller_tunables_generation: u64,
    pub controller_params_generation: u64,
    pub controller_clamped_writes: u64,
    /// Locally received QUIC wire rate. This direction may have a completely
    /// different capacity and is used for RX memory/coalescing decisions.
    pub receive_rate_bytes_per_second: u64,
    pub packets_per_second: u64,
    pub tun_ingress_bytes_per_second: u64,
    pub average_record_bytes: u64,
    pub gso_ingress_ratio_ppm: u32,
    pub packet_train_queue_bytes: u64,
    pub latency_queue_bytes: u64,
    /// Incomplete PacketTrains evicted by the local receiver since the prior
    /// telemetry sample because its aggregate byte budget was exhausted.
    pub reassembly_pressure_evictions: u64,
    pub remote_expired_stripes_delta: u64,
    pub train_build_bytes_per_second: u64,
    pub bulk_preemption_delay_average_micros: u64,
    pub cpu_utilization_per_mille: u16,
    pub wasted_parity_per_mille: u16,
    pub fec_recovery_per_mille: u16,
    pub repair_hit_per_mille: u16,
    /// Cumulative matched Repair responses observed for this path epoch.
    pub repair_completed_requests: u64,
    /// Mean request-to-response latency for responses completed in the latest
    /// feedback interval. Zero means that interval had no completed request.
    pub repair_response_latency: Duration,
    pub real_traffic_bytes_per_second: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct AutoTuneBoundsV2 {
    pub minimum_train_bytes: usize,
    pub maximum_train_bytes: usize,
    pub minimum_socket_buffer_bytes: usize,
    pub minimum_receive_buffer_bytes: usize,
    pub maximum_socket_buffer_bytes: usize,
    pub maximum_receive_batch: usize,
    pub maximum_cover_overhead_per_mille: u16,
}

impl Default for AutoTuneBoundsV2 {
    fn default() -> Self {
        Self {
            minimum_train_bytes: 8 * 1024,
            maximum_train_bytes: 64 * 1024,
            // Bulk retains enough staged work to amortize connection-driver
            // wakes. Semantic latency uses a separate strict QUIC admission
            // lane and therefore does not wait behind this ordinary buffer.
            minimum_socket_buffer_bytes: 256 * 1024,
            // RX reassembly can have several interleaved PacketTrains per TUN
            // queue before QUIC delivers their end Cells. Keep the cold-start
            // floor independent from the much smaller TX admission floor.
            minimum_receive_buffer_bytes: 8 * 1024 * 1024,
            maximum_socket_buffer_bytes: 32 * 1024 * 1024,
            maximum_receive_batch: 64,
            maximum_cover_overhead_per_mille: 50,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuneReasonV2 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverTrafficProfileV2 {
    Idle,
    LiveBroadcast,
    InteractiveVideo,
    GenericH3Bulk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bbr3PresetV2 {
    SharedConservative,
    PrivateAggressive,
    LossyRadio,
    Policer,
    LongFat,
    RelayReliable,
    LowRttHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bbr3ProposalV2 {
    pub preset: Bbr3PresetV2,
    pub up_gain_milli: u32,
    pub headroom_milli: u32,
    pub cwnd_gain_milli: u32,
    pub pacing_cap_bytes_per_second: u64,
    pub loss_is_congestion: bool,
}

impl Bbr3ProposalV2 {
    fn shared_conservative() -> Self {
        Self {
            preset: Bbr3PresetV2::SharedConservative,
            up_gain_milli: 1_150,
            headroom_milli: 250,
            cwnd_gain_milli: 2_000,
            pacing_cap_bytes_per_second: 0,
            loss_is_congestion: false,
        }
    }

    pub fn for_preset(preset: Bbr3PresetV2, controller_bw: u64) -> Self {
        match preset {
            Bbr3PresetV2::SharedConservative => Self::shared_conservative(),
            Bbr3PresetV2::PrivateAggressive => Self {
                preset,
                up_gain_milli: 1_350,
                headroom_milli: 100,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV2::LossyRadio => Self {
                preset,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV2::Policer => Self {
                preset,
                up_gain_milli: 1_100,
                headroom_milli: 250,
                cwnd_gain_milli: 2_000,
                pacing_cap_bytes_per_second: controller_bw.saturating_mul(970) / 1_000,
                loss_is_congestion: true,
            },
            Bbr3PresetV2::LongFat => Self {
                preset,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 3_000,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV2::RelayReliable => Self {
                preset,
                up_gain_milli: 1_100,
                headroom_milli: 300,
                cwnd_gain_milli: 1_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV2::LowRttHost => Self {
                preset,
                up_gain_milli: 1_350,
                headroom_milli: 100,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
        }
    }
}

/// When the receiver requests Repair for a gap. Mirrors the ABI's
/// `RepairWaitPolicyV1`; `HostDefault` keeps the RTT-derived host wait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RepairWaitPolicyV2 {
    /// Host baseline behaviour (RTT-derived wait).
    #[default]
    HostDefault,
    /// Request as soon as a gap is detected (half the host wait).
    Eager,
    /// Wait for the FEC stripe to close before requesting (the host wait).
    AfterFecWindow,
    /// Wait an extra RTT for late reordering before requesting (double the
    /// host wait).
    Patient,
}

impl RepairWaitPolicyV2 {
    /// Compact wire-free encoding for the shared metrics atomics.
    pub fn to_metrics_code(self) -> u8 {
        match self {
            Self::HostDefault => 0,
            Self::Eager => 1,
            Self::AfterFecWindow => 2,
            Self::Patient => 3,
        }
    }

    /// Inverse of [`Self::to_metrics_code`]; unknown codes degrade to the
    /// host default.
    pub fn from_metrics_code(code: u8) -> Self {
        match code {
            1 => Self::Eager,
            2 => Self::AfterFecWindow,
            3 => Self::Patient,
            _ => Self::HostDefault,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuneDecisionV2 {
    pub reason: TuneReasonV2,
    pub path_epoch: u64,
    pub sample_count: u32,
    pub train_target_bytes: usize,
    pub bulk_quantum_cells: usize,
    pub fec: Option<FecGeometryV2>,
    pub repair_cache_bytes: usize,
    /// How long transmitted Cells stay repairable (0 = host default).
    pub repair_retention_millis: u32,
    /// When the receiver requests Repair for a gap.
    pub repair_wait_policy: RepairWaitPolicyV2,
    /// Local outgoing producer-admission window.
    pub send_buffer_bytes: usize,
    /// Local incoming reassembly window, independently sized from RX rate.
    pub receive_buffer_bytes: usize,
    /// Aggregate reassembly byte budget (0 = follow `receive_buffer_bytes`).
    pub reassembly_budget_bytes: usize,
    /// Maximum concurrently open PacketTrains (0 = negotiated wire limit).
    pub active_train_budget: u16,
    pub receive_batch: usize,
    pub cover_profile: CoverTrafficProfileV2,
    pub cover_overhead_per_mille: u16,
    pub cover_padding_bytes_per_second: u64,
    pub bbr: Bbr3ProposalV2,
}

/// Experiment-only application-layer action override. Every field is
/// optional, and `fec = Some(None)` explicitly requests FEC off. Overrides
/// are applied after the baseline policy and smoothing, then constrained by
/// the same runtime guardrails; they cannot enable protection on a reliable
/// relay/CPU-limited path, suppress emergency protection, exceed geometry or
/// cover bounds, or let Bulk overtake queued latency traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForcedActionV2 {
    pub bbr_preset: Option<Bbr3PresetV2>,
    pub fec: Option<Option<FecGeometryV2>>,
    pub train_target_bytes: Option<usize>,
    pub bulk_quantum_cells: Option<usize>,
    pub cover_profile: Option<CoverTrafficProfileV2>,
    pub cover_overhead_per_mille: Option<u16>,
}

impl TuneDecisionV2 {
    fn conservative(epoch: u64, bounds: AutoTuneBoundsV2) -> Self {
        Self {
            reason: TuneReasonV2::ColdStart,
            path_epoch: epoch,
            sample_count: 0,
            train_target_bytes: 16 * 1024,
            bulk_quantum_cells: 1,
            fec: None,
            repair_cache_bytes: 2 * 1024 * 1024,
            repair_retention_millis: 0,
            repair_wait_policy: RepairWaitPolicyV2::HostDefault,
            // Start large enough to avoid an artificial cold-start lock/wake
            // bottleneck on a fast local path. The first trustworthy sample
            // may shrink this immediately to the min-RTT BDP target.
            send_buffer_bytes: INITIAL_SEND_BUFFER_BYTES_V2.clamp(
                bounds.minimum_socket_buffer_bytes,
                bounds.maximum_socket_buffer_bytes,
            ),
            receive_buffer_bytes: bounds.minimum_receive_buffer_bytes,
            reassembly_budget_bytes: 0,
            active_train_budget: 0,
            receive_batch: bounds.maximum_receive_batch.max(1),
            cover_profile: CoverTrafficProfileV2::Idle,
            cover_overhead_per_mille: 0,
            cover_padding_bytes_per_second: 0,
            bbr: Bbr3ProposalV2::shared_conservative(),
        }
    }
}

/// Filtered view of one telemetry sample: the EWMA/min-RTT state of
/// [`TelemetryFilterV1`] after folding in `raw`, plus the receive-pressure
/// floor the filter currently holds. The policy, the guardrails and the
/// transition controller only read this snapshot; none of them sees filter
/// internals or mutates path history.
#[derive(Debug, Clone, Copy)]
pub struct FilteredTelemetryV1 {
    /// The unfiltered sample this snapshot was produced from. Some host rules
    /// (protection evidence, live loss emergency, queued latency traffic,
    /// cover padding) deliberately act on the live sample, not the EWMA.
    pub raw: PathTelemetryV2,
    /// Samples folded into the filter since the last reset.
    pub sample_count: u32,
    pub rtt_micros: u64,
    pub min_rtt_micros: u64,
    pub queue_delay_micros: u64,
    /// Outgoing loss EWMA; only updated by samples with protection evidence.
    pub loss_ppm: u64,
    pub burst_loss_cells: u64,
    pub delivery_rate_bytes_per_second: u64,
    pub receive_rate_bytes_per_second: u64,
    pub packets_per_second: u64,
    pub tun_ingress_bytes_per_second: u64,
    pub average_record_bytes: u64,
    pub gso_ingress_ratio_ppm: u64,
    pub cpu_per_mille: u64,
    pub wasted_parity_per_mille: u64,
    pub recovery_per_mille: u64,
    pub repair_hit_per_mille: u64,
    pub repair_latency_micros: u64,
    /// Matched Repair completions folded into the hit/latency EWMAs.
    pub repair_observations: u64,
    /// Samples that carried protection evidence since the last reset.
    pub protection_samples: u64,
    /// Receive-buffer floor currently held after reassembly pressure; zero
    /// when no pressure hold is active.
    pub receive_pressure_floor_bytes: usize,
}

impl FilteredTelemetryV1 {
    pub fn reliable(&self) -> bool {
        self.raw.reliability == PathReliability::ReliableRelay
    }

    /// Smoothed host CPU at or above 90%: protection and cover are
    /// suppressed and the native rules fall back to minimum batching.
    pub fn cpu_limited(&self) -> bool {
        self.cpu_per_mille >= 900
    }

    /// Live host CPU at or above 90%: a learned action may not raise
    /// scheduler batching above the host baseline.
    pub fn cpu_emergency(&self) -> bool {
        self.raw.cpu_utilization_per_mille >= 900
    }

    /// Absolute delay alone is not comparable across path classes: 6 ms is a
    /// real queue on Ethernet but ordinary jitter on an 85 ms radio or
    /// cross-carrier path. Require queue delay to exceed the larger of 5 ms
    /// and half the learned propagation RTT. This matches the BBR queue guard
    /// and prevents random-loss WANs from being mislabeled as congested, which
    /// would otherwise disable exactly the FEC/Repair they need.
    pub fn queue_delay_budget_micros(&self) -> u64 {
        5_000.max(self.min_rtt_micros / 2)
    }

    pub fn queue_inflated(&self) -> bool {
        let budget = self.queue_delay_budget_micros();
        self.queue_delay_micros > budget
            && self.rtt_micros > self.min_rtt_micros.saturating_add(budget)
    }

    /// A credible sample arms the directional classifier. Once armed, keep
    /// protection stable through a loss-induced goodput collapse while the
    /// application still has any real/queued work; otherwise the old
    /// threshold toggled FEC off exactly when a lossy WAN stalled below
    /// 64 KiB/s. A completely idle direction still retires protection.
    pub fn protection_evidence(&self) -> bool {
        self.protection_samples != 0
            && (self.raw.real_traffic_bytes_per_second != 0
                || self.raw.tun_ingress_bytes_per_second != 0
                || self.raw.packet_train_queue_bytes != 0)
    }

    /// A shallow token-bucket/policer can drop at line rate without retaining
    /// a queue long enough to inflate RTT. Sustained >=2% loss below 20 ms is
    /// therefore congestion-like; BBR's matching automatic pacing loop backs
    /// off the total QUIC wire rate. Random-loss WANs are excluded by the RTT
    /// bound and continue to use FEC/Repair.
    pub fn policer_limited(&self) -> bool {
        self.protection_evidence()
            && self.rtt_micros <= 20_000
            && self.min_rtt_micros <= 20_000
            && self.loss_ppm >= 20_000
    }

    pub fn congested(&self) -> bool {
        self.queue_inflated() || self.policer_limited()
    }

    /// The live sample carries protection evidence and crosses the 0.1%
    /// loss (or two-Cell burst) threshold: protection is installed without
    /// hysteresis and a candidate may not switch it off.
    pub fn protection_emergency(&self) -> bool {
        has_protection_evidence(self.raw)
            && (self.raw.loss_ppm >= 1_000 || self.raw.burst_loss_cells >= 2)
    }

    /// Latency traffic is queued: Bulk may not overtake it.
    pub fn latency_queue_active(&self) -> bool {
        self.raw.latency_queue_bytes != 0
    }

    /// The live sample reported reassembly-pressure evictions.
    pub fn receive_pressure(&self) -> bool {
        self.raw.reassembly_pressure_evictions != 0
    }

    /// Host-authoritative path classification carried on every effective
    /// action.
    pub fn classify(&self) -> TuneReasonV2 {
        if self.reliable() {
            TuneReasonV2::ReliablePath
        } else if self.cpu_limited() {
            TuneReasonV2::CpuLimited
        } else if self.congested() {
            TuneReasonV2::Congested
        } else if self.burst_loss_cells >= 2 {
            TuneReasonV2::BurstLoss
        } else if self.loss_ppm >= 1_000 {
            TuneReasonV2::RandomLoss
        } else {
            TuneReasonV2::HealthyLowLoss
        }
    }

    /// Directional cover profile derived from the smoothed TX/RX rates.
    pub fn cover_profile(&self) -> CoverTrafficProfileV2 {
        classify_cover_profile(
            self.delivery_rate_bytes_per_second,
            self.receive_rate_bytes_per_second,
        )
    }
}

/// Stateful telemetry smoothing: EWMAs, min RTT, Repair evidence and the
/// reassembly-pressure hold. It is the only component of the auto-tuner
/// that carries per-sample history about the path itself; everything
/// downstream consumes the [`FilteredTelemetryV1`] snapshot it emits.
#[derive(Debug, Clone, Copy)]
pub struct TelemetryFilterV1 {
    bounds: AutoTuneBoundsV2,
    samples: u32,
    rtt_micros: u64,
    min_rtt_micros: u64,
    queue_delay_micros: u64,
    loss_ppm: u64,
    burst_loss_cells: u64,
    delivery_rate: u64,
    receive_rate: u64,
    packets_per_second: u64,
    tun_ingress_rate: u64,
    average_record_bytes: u64,
    gso_ingress_ratio_ppm: u64,
    cpu_per_mille: u64,
    wasted_parity_per_mille: u64,
    recovery_per_mille: u64,
    repair_hit_per_mille: u64,
    repair_latency_micros: u64,
    repair_observations: u64,
    last_repair_completed_requests: u64,
    repair_counter_initialized: bool,
    protection_samples: u64,
    receive_pressure_floor_bytes: usize,
    receive_pressure_hold_samples: u8,
}

impl TelemetryFilterV1 {
    pub fn new(bounds: AutoTuneBoundsV2) -> Self {
        Self {
            bounds,
            samples: 0,
            rtt_micros: 0,
            min_rtt_micros: 0,
            queue_delay_micros: 0,
            loss_ppm: 0,
            burst_loss_cells: 0,
            delivery_rate: 0,
            receive_rate: 0,
            packets_per_second: 0,
            tun_ingress_rate: 0,
            average_record_bytes: 0,
            gso_ingress_ratio_ppm: 0,
            cpu_per_mille: 0,
            wasted_parity_per_mille: 0,
            recovery_per_mille: 0,
            repair_hit_per_mille: 0,
            repair_latency_micros: 0,
            repair_observations: 0,
            last_repair_completed_requests: 0,
            repair_counter_initialized: false,
            protection_samples: 0,
            receive_pressure_floor_bytes: 0,
            receive_pressure_hold_samples: 0,
        }
    }

    /// Forget all path history (path change or missing telemetry).
    pub fn reset(&mut self) {
        *self = Self::new(self.bounds);
    }

    pub fn sample_count(&self) -> u32 {
        self.samples
    }

    /// Fold one live sample into the filter. `current_receive_buffer_bytes`
    /// is the receive window currently in effect; reassembly pressure raises
    /// a floor relative to it that is then held for a bounded number of
    /// samples without any operator configuration.
    pub fn update(
        &mut self,
        sample: PathTelemetryV2,
        current_receive_buffer_bytes: usize,
    ) -> FilteredTelemetryV1 {
        if sample.reassembly_pressure_evictions != 0 {
            self.receive_pressure_floor_bytes = current_receive_buffer_bytes
                .saturating_mul(2)
                .max(
                    current_receive_buffer_bytes.saturating_add(RECEIVE_PRESSURE_GROWTH_STEP_BYTES),
                )
                .clamp(
                    self.bounds.minimum_receive_buffer_bytes,
                    self.bounds.maximum_socket_buffer_bytes,
                );
            self.receive_pressure_hold_samples = RECEIVE_PRESSURE_HOLD_SAMPLES;
        } else if self.receive_pressure_hold_samples != 0 {
            self.receive_pressure_hold_samples -= 1;
            if self.receive_pressure_hold_samples == 0 {
                self.receive_pressure_floor_bytes = 0;
            }
        }
        self.samples = self.samples.saturating_add(1);
        self.smooth(sample);
        self.view(sample)
    }

    /// Non-mutating snapshot of the current filter state paired with
    /// `sample`. Used when a learned action is constrained against an
    /// already-observed sample without advancing the sample clock again.
    pub fn view(&self, sample: PathTelemetryV2) -> FilteredTelemetryV1 {
        FilteredTelemetryV1 {
            raw: sample,
            sample_count: self.samples,
            rtt_micros: self.rtt_micros,
            min_rtt_micros: self.min_rtt_micros,
            queue_delay_micros: self.queue_delay_micros,
            loss_ppm: self.loss_ppm,
            burst_loss_cells: self.burst_loss_cells,
            delivery_rate_bytes_per_second: self.delivery_rate,
            receive_rate_bytes_per_second: self.receive_rate,
            packets_per_second: self.packets_per_second,
            tun_ingress_bytes_per_second: self.tun_ingress_rate,
            average_record_bytes: self.average_record_bytes,
            gso_ingress_ratio_ppm: self.gso_ingress_ratio_ppm,
            cpu_per_mille: self.cpu_per_mille,
            wasted_parity_per_mille: self.wasted_parity_per_mille,
            recovery_per_mille: self.recovery_per_mille,
            repair_hit_per_mille: self.repair_hit_per_mille,
            repair_latency_micros: self.repair_latency_micros,
            repair_observations: self.repair_observations,
            protection_samples: self.protection_samples,
            receive_pressure_floor_bytes: self.receive_pressure_floor_bytes,
        }
    }

    fn smooth(&mut self, sample: PathTelemetryV2) {
        self.rtt_micros = ewma(self.rtt_micros, micros(sample.rtt), 3, 8);
        self.min_rtt_micros = match self.min_rtt_micros {
            0 => micros(sample.min_rtt),
            current => current.min(micros(sample.min_rtt)),
        };
        self.queue_delay_micros = ewma(self.queue_delay_micros, micros(sample.queue_delay), 3, 8);
        // QUIC keepalives and PMTU probes make an idle interval's loss ratio
        // statistically meaningless: losing one of only a handful of packets
        // previously pre-armed FEC at 8+1 before the first real byte arrived.
        // Update protection classifiers only when this outgoing direction has
        // enough real Cells and packets to form a useful sample.
        if has_protection_evidence(sample) {
            self.protection_samples = self.protection_samples.saturating_add(1);
            self.loss_ppm = ewma(self.loss_ppm, u64::from(sample.loss_ppm), 3, 8);
            self.burst_loss_cells = ewma(
                self.burst_loss_cells,
                u64::from(sample.burst_loss_cells),
                1,
                2,
            );
        }
        self.delivery_rate = ewma(
            self.delivery_rate,
            sample.delivery_rate_bytes_per_second,
            1,
            4,
        );
        self.receive_rate = ewma(
            self.receive_rate,
            sample.receive_rate_bytes_per_second,
            1,
            4,
        );
        self.packets_per_second = ewma(self.packets_per_second, sample.packets_per_second, 1, 4);
        self.tun_ingress_rate = ewma(
            self.tun_ingress_rate,
            sample.tun_ingress_bytes_per_second,
            1,
            4,
        );
        self.average_record_bytes =
            ewma(self.average_record_bytes, sample.average_record_bytes, 1, 4);
        self.gso_ingress_ratio_ppm = ewma(
            self.gso_ingress_ratio_ppm,
            u64::from(sample.gso_ingress_ratio_ppm),
            1,
            4,
        );
        self.cpu_per_mille = ewma(
            self.cpu_per_mille,
            u64::from(sample.cpu_utilization_per_mille),
            1,
            4,
        );
        self.wasted_parity_per_mille = ewma(
            self.wasted_parity_per_mille,
            u64::from(sample.wasted_parity_per_mille),
            1,
            4,
        );
        self.recovery_per_mille = ewma(
            self.recovery_per_mille,
            u64::from(sample.fec_recovery_per_mille),
            1,
            4,
        );
        // A zero completion delta means "no new evidence", not a zero-hit or
        // zero-latency response. Preserve the last EWMA until another matched
        // request completes.
        let completed_delta = if self.repair_counter_initialized {
            sample
                .repair_completed_requests
                .saturating_sub(self.last_repair_completed_requests)
        } else {
            self.repair_counter_initialized = true;
            0
        };
        if completed_delta != 0 && !sample.repair_response_latency.is_zero() {
            self.repair_hit_per_mille = ewma(
                self.repair_hit_per_mille,
                u64::from(sample.repair_hit_per_mille),
                1,
                4,
            );
            self.repair_latency_micros = ewma(
                self.repair_latency_micros,
                micros(sample.repair_response_latency),
                1,
                4,
            );
            self.repair_observations = self.repair_observations.saturating_add(completed_delta);
        }
        self.last_repair_completed_requests = sample.repair_completed_requests;
    }
}

/// The deterministic native rule set: a pure function from filtered
/// telemetry (plus the host limits that define the action space) to a
/// [`CandidateActionV1`]. It proposes every V1 domain it has an opinion on
/// and leaves host-derived fields (Repair cache, cover padding, egress)
/// unset. Like any other policy output it is untrusted: reliable-underlay,
/// CPU, queue, memory and wire-overhead limits are enforced afterwards by
/// [`GuardrailsV1`], not here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativePolicyV1;

impl NativePolicyV1 {
    pub fn propose(
        &self,
        filtered: &FilteredTelemetryV1,
        limits: &HostLimitsV1,
    ) -> CandidateActionV1 {
        let raw = &filtered.raw;
        let queue_inflated = filtered.queue_inflated();
        let protection_evidence = filtered.protection_evidence();
        let policer_limited = filtered.policer_limited();
        let congested = filtered.congested();
        let cpu_limited = filtered.cpu_limited();
        let reliable = filtered.reliable();
        let reason = filtered.classify();

        // Repair runs behind authenticated control scheduling and can take
        // several path RTTs even when it is healthy. Requiring <100 ms made
        // sparse 0.1-0.5% loss randomly pin 8+1 FEC depending on whether the
        // first few repairs landed just above or below that cliff. Eight RTTs
        // with a 200 ms floor is still comfortably ahead of an inner TCP RTO
        // while giving stable evidence enough time to retire wasted parity.
        let repair_latency_budget_micros = filtered.rtt_micros.saturating_mul(8).max(200_000);
        let repair_effective = filtered.repair_observations >= 3
            && filtered.repair_hit_per_mille >= 800
            && filtered.repair_latency_micros != 0
            && filtered.repair_latency_micros <= repair_latency_budget_micros;
        // On a low-RTT shallow policer, loss is the congestion signal itself.
        // Adding parity raises the same bottleneck's offered load and creates
        // a positive feedback loop (loss -> FEC -> more loss -> Repair). QUIC
        // and the inner transport already retransmit; retain FEC only when an
        // actual queue or non-policer loss signature disproves this case.
        let unqueued_shallow_policer = policer_limited && !queue_inflated;
        let proven_wasteful_short_path = filtered.rtt_micros < 20_000
            && repair_effective
            && filtered.wasted_parity_per_mille >= 750
            && filtered.recovery_per_mille <= 250;
        // QUIC's lost-packet counter includes congestion loss. Suppressing all
        // FEC merely because a shallow policer also built a queue amplified
        // one lost outer Cell into a complete 16-64 KiB PacketTrain loss.
        // Under queue congestion retain exactly one sparse parity Cell; BBR
        // accounts for those wire bytes and converges on the usable
        // bottleneck rate. (Reliable-underlay and CPU suppression are host
        // guardrails applied after this proposal.)
        let fec = if !protection_evidence
            || filtered.loss_ppm < 1_000
            || unqueued_shallow_policer
            || proven_wasteful_short_path
        {
            None
        } else if congested {
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            })
        } else if repair_effective
            && filtered.loss_ppm < 10_000
            && filtered.wasted_parity_per_mille > 800
            && filtered.recovery_per_mille < 50
        {
            // A short path may report a multi-Cell burst even when absolute
            // loss is below 1%. Once authenticated feedback proves that
            // almost every parity Cell is wasted and Repair reliably closes
            // the rare hole, the burst classifier must not pin 8+1 forever.
            // This check deliberately precedes the burst branches below.
            None
        } else if filtered.loss_ppm < 10_000
            && filtered.wasted_parity_per_mille > 900
            && filtered.recovery_per_mille < 50
        {
            // Receiver evidence already proves dense parity is wasteful, but
            // Repair has not accumulated enough completed requests to turn
            // protection fully off. Widen the stripe instead of holding 8+1
            // at ~12.5% wire cost for tens of seconds on a lightly lossy
            // short path.
            Some(FecGeometryV2 {
                data_cells: 16,
                parity_cells: 1,
            })
        } else if filtered.burst_loss_cells >= 3 || filtered.loss_ppm >= 30_000 {
            Some(if filtered.rtt_micros < 80_000 {
                // A shallow policer can report a large instantaneous loss
                // percentage without retaining an RTT queue. On such
                // short-feedback paths 4+2 parity raises wire load by 50%,
                // causing still more policer loss. One 8+1 stripe plus
                // fast Repair bounds redundancy and breaks that loop.
                FecGeometryV2 {
                    data_cells: 8,
                    parity_cells: 1,
                }
            } else if repair_effective
                && filtered.wasted_parity_per_mille > 800
                && filtered.recovery_per_mille < 100
            {
                // Start severe/unclassified loss at 4+2, but do not keep
                // spending two parity Cells after directional receiver
                // evidence proves nearly all parity is wasted and Repair
                // returns within the RTT-derived budget. A 6+1 stripe
                // retains immediate isolated-loss recovery while halving
                // wire redundancy and leaves burst tails to proven Repair.
                FecGeometryV2 {
                    data_cells: 6,
                    parity_cells: 1,
                }
            } else {
                FecGeometryV2 {
                    data_cells: 4,
                    parity_cells: 2,
                }
            })
        } else if filtered.burst_loss_cells >= 2 || filtered.loss_ppm >= 10_000 {
            Some(if filtered.rtt_micros < 80_000 {
                FecGeometryV2 {
                    data_cells: 8,
                    parity_cells: 1,
                }
            } else if filtered.wasted_parity_per_mille > 800 && filtered.recovery_per_mille < 100 {
                if repair_effective {
                    // Matched feedback proves reliable Repair arrives
                    // within its RTT-derived budget. Spread the remaining
                    // single parity symbol over eight data Cells; this
                    // preserves immediate recovery for isolated loss while
                    // leaving the rare miss to Repair.
                    FecGeometryV2 {
                        data_cells: 8,
                        parity_cells: 1,
                    }
                } else {
                    // Until Repair is proven, retain the denser six-Cell
                    // stripe but halve parity from two symbols to one.
                    FecGeometryV2 {
                        data_cells: 6,
                        parity_cells: 1,
                    }
                }
            } else {
                FecGeometryV2 {
                    data_cells: 6,
                    parity_cells: 2,
                }
            })
        } else {
            Some(FecGeometryV2 {
                data_cells: if filtered.rtt_micros >= 80_000 { 6 } else { 8 },
                parity_cells: 1,
            })
        };

        let minimum_train = usize_from_u64(u64::from(limits.train_target_floor_bytes));
        let maximum_train = usize_from_u64(u64::from(limits.train_target_cap_bytes));
        let train_target = if cpu_limited || congested {
            16 * 1024
        } else if filtered.delivery_rate_bytes_per_second >= 50 * 1024 * 1024
            && raw.packet_train_queue_bytes >= 64 * 1024
        {
            maximum_train
        } else if filtered.delivery_rate_bytes_per_second >= 5 * 1024 * 1024 {
            32 * 1024
        } else {
            minimum_train
        }
        .clamp(minimum_train, maximum_train);

        // QUIC still paces every datagram, so admitting a four-Cell Bulk
        // quantum does not create a wire burst. Under Bulk-only
        // congestion/CPU pressure, batching amortizes the connection lock;
        // the one-Cell bound while latency traffic is queued is a host
        // guardrail.
        let bulk_quantum_cells = if cpu_limited
            || congested
            || filtered.delivery_rate_bytes_per_second >= 20 * 1024 * 1024
        {
            4
        } else {
            2
        };

        // Size producer admission from propagation BDP, never from the
        // currently inflated RTT. Using smoothed RTT here made queueing
        // self-reinforcing: a deeper QUIC DATAGRAM queue raised RTT, which in
        // turn requested an even deeper queue. min_rtt is the controller's
        // path baseline and therefore excludes our own queue delay.
        let bdp = filtered
            .delivery_rate_bytes_per_second
            .saturating_mul(filtered.min_rtt_micros)
            / 1_000_000;
        // A pure BDP target collapses to the minimum on very-low-RTT links,
        // even when hundreds of thousands of DATAGRAMs/s are competing for
        // the connection lock. Under Bulk-only CPU pressure retain roughly an
        // 8 ms producer window so the native QUIC admission queue amortizes
        // wakes/locks; queued latency traffic disables this extra window.
        let processing_window =
            if cpu_limited && raw.latency_queue_bytes == 0 && raw.packet_train_queue_bytes > 0 {
                filtered.delivery_rate_bytes_per_second / 125
            } else {
                0
            };
        let send_buffer = usize_from_u64(bdp.saturating_mul(2).max(processing_window)).clamp(
            usize_from_u64(limits.send_buffer_floor_bytes),
            usize_from_u64(limits.send_buffer_cap_bytes),
        );
        // TX and RX capacity are independent. In particular, a 1000/100
        // household path must not size the 1 Gbit/s receive window from its
        // 100 Mbit/s uplink estimate, nor let the downlink inflate producer
        // admission on that uplink. Each endpoint learns its local outgoing
        // and incoming directions separately; no symmetric tier is inferred.
        let receive_bdp = filtered
            .receive_rate_bytes_per_second
            .saturating_mul(filtered.min_rtt_micros)
            / 1_000_000;
        let receive_buffer = usize_from_u64(receive_bdp.saturating_mul(2))
            .clamp(
                usize_from_u64(limits.receive_buffer_floor_bytes),
                usize_from_u64(limits.receive_buffer_cap_bytes),
            )
            .max(filtered.receive_pressure_floor_bytes);
        // TUN records are drained without waiting. Bound one aggregation
        // opportunity to roughly eight maximum-size records (512 KiB): small
        // packets still amortize channel wakeups at the negotiated maximum,
        // while GSO super-packets do not create multi-megabyte deferred bursts.
        let maximum_receive_batch = usize::from(limits.receive_batch_cap.max(1));
        let record_bytes = filtered.average_record_bytes.max(1);
        let batch_by_bytes = (512 * 1024_u64)
            .checked_div(record_bytes)
            .unwrap_or(1)
            .clamp(1, maximum_receive_batch as u64) as usize;
        let receive_batch = if filtered.tun_ingress_bytes_per_second == 0 {
            maximum_receive_batch
        } else if filtered.gso_ingress_ratio_ppm >= 500_000 {
            batch_by_bytes.min(8)
        } else {
            batch_by_bytes
        };
        let cover_profile = filtered.cover_profile();
        // Cover suppression under queue, loss, CPU, idle or queued Bulk is a
        // host guardrail; the rule only proposes its nominal overhead.
        let cover_overhead = 30.min(limits.cover_overhead_cap_per_mille);

        let bbr = if reliable {
            Bbr3ProposalV2 {
                preset: Bbr3PresetV2::RelayReliable,
                up_gain_milli: 1_100,
                headroom_milli: 300,
                cwnd_gain_milli: 1_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            }
        } else if filtered.min_rtt_micros < 2_000 {
            Bbr3ProposalV2 {
                preset: Bbr3PresetV2::LowRttHost,
                up_gain_milli: 1_350,
                headroom_milli: 100,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            }
        } else if policer_limited {
            Bbr3ProposalV2 {
                preset: Bbr3PresetV2::Policer,
                up_gain_milli: 1_100,
                headroom_milli: 250,
                cwnd_gain_milli: 2_000,
                pacing_cap_bytes_per_second: raw.controller_bw_bytes_per_second.saturating_mul(970)
                    / 1_000,
                loss_is_congestion: true,
            }
        } else if filtered.min_rtt_micros >= 120_000 {
            Bbr3ProposalV2 {
                preset: Bbr3PresetV2::LongFat,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 3_000,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            }
        } else if matches!(reason, TuneReasonV2::RandomLoss | TuneReasonV2::BurstLoss) {
            Bbr3ProposalV2 {
                preset: Bbr3PresetV2::LossyRadio,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            }
        } else {
            Bbr3ProposalV2::shared_conservative()
        };

        CandidateActionV1 {
            bbr: Some(bbr_candidate(&bbr)),
            scheduler: Some(SchedulerCandidateV1 {
                train_target_bytes: Some(u32::try_from(train_target).unwrap_or(u32::MAX)),
                bulk_quantum_cells: Some(bulk_quantum_cells),
                bulk_admission_window_bytes: None,
                preset_hint: None,
            }),
            fec: Some(fec_candidate(fec)),
            repair: None,
            tx: Some(TxCandidateV1 {
                send_buffer_bytes: Some(u64::try_from(send_buffer).unwrap_or(u64::MAX)),
                datagram_admission_bytes: None,
                producer_window_bytes: None,
            }),
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: Some(u64::try_from(receive_buffer).unwrap_or(u64::MAX)),
                receive_batch: Some(u16::try_from(receive_batch).unwrap_or(u16::MAX)),
                reassembly_budget_bytes: None,
                active_train_budget: None,
            }),
            cover: Some(CoverCandidateV1 {
                profile: Some(cover_profile.into()),
                overhead_per_mille: Some(cover_overhead),
                padding_bytes_per_second: None,
            }),
            egress_request: None,
            extensions: Vec::new(),
        }
    }
}

fn bbr_candidate(proposal: &Bbr3ProposalV2) -> BbrCandidateV1 {
    BbrCandidateV1 {
        preset: Some(proposal.preset.into()),
        probe_bw_up_pacing_gain_milli: Some(proposal.up_gain_milli),
        default_cwnd_gain_milli: Some(proposal.cwnd_gain_milli),
        headroom_milli: Some(proposal.headroom_milli),
        loss_is_congestion: Some(proposal.loss_is_congestion),
        pacing_cap_bytes_per_second: Some(proposal.pacing_cap_bytes_per_second),
        ..BbrCandidateV1::default()
    }
}

fn fec_candidate(geometry: Option<FecGeometryV2>) -> FecCandidateV1 {
    match geometry {
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
    }
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

impl ForcedActionV2 {
    /// Express an experiment/learned override as an untrusted candidate.
    /// Only the fields the override sets are filled; `bbr_preset` expands to
    /// the preset's full proposal (the Policer pacing cap is derived from the
    /// live `controller_bw_bytes_per_second`).
    pub fn to_candidate(self, controller_bw_bytes_per_second: u64) -> CandidateActionV1 {
        let scheduler = (self.train_target_bytes.is_some() || self.bulk_quantum_cells.is_some())
            .then(|| SchedulerCandidateV1 {
                train_target_bytes: self
                    .train_target_bytes
                    .map(|bytes| u32::try_from(bytes).unwrap_or(u32::MAX)),
                bulk_quantum_cells: self
                    .bulk_quantum_cells
                    .map(|cells| u16::try_from(cells).unwrap_or(u16::MAX)),
                bulk_admission_window_bytes: None,
                preset_hint: None,
            });
        let cover =
            (self.cover_profile.is_some() || self.cover_overhead_per_mille.is_some()).then(|| {
                CoverCandidateV1 {
                    profile: self.cover_profile.map(Into::into),
                    overhead_per_mille: self.cover_overhead_per_mille,
                    padding_bytes_per_second: None,
                }
            });
        CandidateActionV1 {
            bbr: self.bbr_preset.map(|preset| {
                bbr_candidate(&Bbr3ProposalV2::for_preset(
                    preset,
                    controller_bw_bytes_per_second,
                ))
            }),
            scheduler,
            fec: self.fec.map(fec_candidate),
            repair: None,
            tx: None,
            rx: None,
            cover,
            egress_request: None,
            extensions: Vec::new(),
        }
    }
}

/// Thin composition of the auto-tune pipeline (plan section 6.2):
///
/// ```text
/// raw telemetry
/// -> TelemetryFilterV1        (EWMA, min RTT, Repair evidence, pressure hold)
/// -> NativePolicyV1           (rule candidate)
/// -> GuardrailsV1             (host hard limits)
/// -> TransitionControllerV1   (FEC hysteresis, buffer steps)
/// -> [forced override, through GuardrailsV1]
/// -> GuardrailsV1 final pass
/// -> EffectiveActionV1 -> TuneDecisionV2
/// ```
///
/// An explicit [`ForcedActionV2`] enters the same pipeline as an untrusted
/// candidate; by contract its values are exact inside the guardrails, so it
/// is merged after the transition controller (which only smooths the native
/// rule's proposal) and before the final guardrail pass.
#[derive(Debug)]
pub struct AutoTunerV2 {
    bounds: AutoTuneBoundsV2,
    epoch: u64,
    smoothed: TelemetryFilterV1,
    policy: NativePolicyV1,
    guardrails: GuardrailsV1,
    transition: TransitionControllerV1,
    current: EffectiveActionV1,
    last_clamps: ClampReportV1,
}

impl AutoTunerV2 {
    pub fn new(bounds: AutoTuneBoundsV2, path_epoch: u64) -> Self {
        Self {
            bounds,
            epoch: path_epoch,
            smoothed: TelemetryFilterV1::new(bounds),
            policy: NativePolicyV1,
            guardrails: GuardrailsV1::from_bounds(&bounds),
            transition: TransitionControllerV1::new(Instant::now()),
            current: Self::conservative(path_epoch, bounds, TuneReasonV2::ColdStart),
            last_clamps: ClampReportV1::default(),
        }
    }

    fn conservative(
        epoch: u64,
        bounds: AutoTuneBoundsV2,
        reason: TuneReasonV2,
    ) -> EffectiveActionV1 {
        let mut decision = TuneDecisionV2::conservative(epoch, bounds);
        decision.reason = reason;
        EffectiveActionV1::from_tune_decision(&decision)
    }

    pub fn observe(&mut self, sample: PathTelemetryV2) -> TuneDecisionV2 {
        self.observe_at_with_force(sample, Instant::now(), None)
    }

    pub fn observe_forced(
        &mut self,
        sample: PathTelemetryV2,
        forced: ForcedActionV2,
    ) -> TuneDecisionV2 {
        self.observe_at_with_force(sample, Instant::now(), Some(forced))
    }

    pub fn observe_at(&mut self, sample: PathTelemetryV2, now: Instant) -> TuneDecisionV2 {
        self.observe_at_with_force(sample, now, None)
    }

    pub fn observe_at_with_force(
        &mut self,
        sample: PathTelemetryV2,
        now: Instant,
        forced: Option<ForcedActionV2>,
    ) -> TuneDecisionV2 {
        if sample.path_epoch != self.epoch {
            self.epoch = sample.path_epoch;
            self.smoothed.reset();
            self.transition.reset(now);
            self.current = Self::conservative(self.epoch, self.bounds, TuneReasonV2::PathChanged);
        }
        let previous = self.current.clone();
        let mut clamps = ClampReportV1::default();

        // 1. raw -> filtered telemetry.
        let filtered = self
            .smoothed
            .update(sample, usize_from_u64(previous.rx.receive_buffer_bytes));
        let ctx = GuardrailContextV1::from_filtered(&filtered);

        // 2. native candidate. The rule set is the host baseline of this
        //    tick, so it is constrained against its own values over the
        //    previous effective action: the relative guardrails ("not above
        //    the baseline") are identities here and the absolute ones bind.
        let candidate = self.policy.propose(&filtered, self.guardrails.limits());
        let native_base = candidate.apply_over(&previous);

        // 3. guardrails.
        let (mut native, report) = self.guardrails.apply(&candidate, &native_base, &ctx);
        clamps.entries.extend(report.entries);
        native.reason = filtered.classify().into();
        native.path_epoch = self.epoch;
        native.sample_count = filtered.sample_count;

        // 4. transition controller.
        let transition_ctx = TransitionContextV1::from_filtered(&filtered);
        let (smoothed, report) = self
            .transition
            .smooth(&native, &previous, now, &transition_ctx);
        clamps.entries.extend(report.entries);

        // 5. forced experiment override as a candidate over the smoothed
        //    baseline. The override is exact inside the absolute guardrails;
        //    the relative CPU-emergency clamp against the rule baseline is
        //    reserved for learned actions (`constrain_action`).
        let overridden = match forced {
            Some(forced) => {
                let experiment_ctx = GuardrailContextV1 {
                    cpu_emergency: false,
                    ..ctx
                };
                let (overridden, report) = self.guardrails.apply(
                    &forced.to_candidate(sample.controller_bw_bytes_per_second),
                    &smoothed,
                    &experiment_ctx,
                );
                clamps.entries.extend(report.entries);
                overridden
            }
            None => smoothed,
        };

        // 6. final guardrail pass -> effective.
        let (effective, report) = self.guardrails.reapply(&overridden, &ctx);
        clamps.entries.extend(report.entries);
        self.last_clamps = clamps;
        self.current = effective;
        self.current.to_tune_decision()
    }

    pub fn current(&self) -> TuneDecisionV2 {
        self.current.to_tune_decision()
    }

    /// The latest effective action in its ABI shape.
    pub fn current_effective(&self) -> &EffectiveActionV1 {
        &self.current
    }

    /// Every clamp and hold applied while deriving the latest effective
    /// action (native pass, transition, forced override and final pass).
    pub fn last_clamp_report(&self) -> &ClampReportV1 {
        &self.last_clamps
    }

    /// Host limits this tuner enforces.
    pub fn limits(&self) -> &HostLimitsV1 {
        self.guardrails.limits()
    }

    /// Drop all learned state when the runtime cannot obtain a trustworthy
    /// path sample. The logical path epoch is deliberately retained: a
    /// transient gap while QUIC validates or migrates a path must not look
    /// like a topology change to the dataplane.
    pub fn fallback_for_missing_telemetry(&mut self) -> TuneDecisionV2 {
        self.smoothed.reset();
        self.transition.reset(Instant::now());
        self.current =
            Self::conservative(self.epoch, self.bounds, TuneReasonV2::TelemetryUnavailable);
        self.last_clamps = ClampReportV1::default();
        self.current.to_tune_decision()
    }

    /// Guardrail context of the last observation paired with `sample`, i.e.
    /// the live facts a learned/guest candidate is constrained against
    /// without advancing the sample clock again.
    pub fn guardrail_context(&self, sample: PathTelemetryV2) -> GuardrailContextV1 {
        GuardrailContextV1::from_filtered(&self.smoothed.view(sample))
    }

    /// Constrain an untrusted candidate (learned action, policy guest) over
    /// `base` with this tuner's guardrails and the filtered view of
    /// `sample`. This is `constrain_action` for the ABI candidate shape: one
    /// [`GuardrailsV1::apply`] pass, no transition smoothing, no clock
    /// advance.
    pub fn constrain_candidate(
        &self,
        sample: PathTelemetryV2,
        candidate: &CandidateActionV1,
        base: &EffectiveActionV1,
    ) -> (EffectiveActionV1, ClampReportV1) {
        let ctx = self.guardrail_context(sample);
        self.guardrails.apply(candidate, base, &ctx)
    }

    /// Apply a learned application action to an already-observed rule
    /// baseline without advancing the sample clock a second time. This is the
    /// single guardrail boundary shared by fixed-action experiments and the
    /// online learner: one [`GuardrailsV1::apply`] over the filtered
    /// telemetry of the last observation. The BBR arm of a learned action is
    /// materialised by the caller on `baseline`; `bbr_preset` is not
    /// consulted here.
    pub fn constrain_action(
        &self,
        sample: PathTelemetryV2,
        baseline: TuneDecisionV2,
        action: ForcedActionV2,
    ) -> TuneDecisionV2 {
        let filtered = self.smoothed.view(sample);
        let ctx = GuardrailContextV1::from_filtered(&filtered);
        let base = EffectiveActionV1::from_tune_decision(&baseline);
        let candidate = ForcedActionV2 {
            bbr_preset: None,
            ..action
        }
        .to_candidate(sample.controller_bw_bytes_per_second);
        let (effective, _) = self.guardrails.apply(&candidate, &base, &ctx);
        effective.to_tune_decision()
    }
}

pub(crate) fn repair_cache_target_bytes(
    reliability: PathReliability,
    fec: Option<FecGeometryV2>,
    rtt_micros: u64,
    delivery_rate: u64,
    offered_rate: u64,
) -> usize {
    if reliability == PathReliability::ReliableRelay {
        1024 * 1024
    } else if fec.is_none() {
        0
    } else {
        // A missing Cell is detected only after the receiver has waited for
        // the remainder of its stripe, then a reliable request/response must
        // make another round trip. The old high-RTT branch shrank this cache
        // to 1 MiB, guaranteeing empty Repair responses on an 85 ms / 50 Mbit
        // path: the requested stripe had already been evicted before the
        // request arrived. Retain roughly ten propagation RTTs of the larger
        // observed/offered TX rate and use an RTT tier as a cold/collapsed-rate
        // floor. The byte cap bounds memory without another operator setting.
        const MIB: u64 = 1024 * 1024;
        let rate = delivery_rate.max(offered_rate);
        let rate_target = rate.saturating_mul(rtt_micros).saturating_mul(10) / 1_000_000;
        let rtt_floor = if rtt_micros >= 150_000 {
            24 * MIB
        } else if rtt_micros >= 80_000 {
            16 * MIB
        } else {
            4 * MIB
        };
        usize::try_from(rate_target.max(rtt_floor).min(32 * MIB)).unwrap_or(32 * MIB as usize)
    }
}

fn classify_cover_profile(
    tx_bytes_per_second: u64,
    rx_bytes_per_second: u64,
) -> CoverTrafficProfileV2 {
    const ACTIVE_RATE: u64 = 128 * 1024;
    if tx_bytes_per_second.max(rx_bytes_per_second) < ACTIVE_RATE {
        CoverTrafficProfileV2::Idle
    } else if tx_bytes_per_second >= ACTIVE_RATE
        && tx_bytes_per_second >= rx_bytes_per_second.saturating_mul(4)
    {
        CoverTrafficProfileV2::LiveBroadcast
    } else if tx_bytes_per_second >= ACTIVE_RATE && rx_bytes_per_second >= ACTIVE_RATE {
        CoverTrafficProfileV2::InteractiveVideo
    } else {
        CoverTrafficProfileV2::GenericH3Bulk
    }
}

fn ewma(current: u64, sample: u64, numerator: u64, denominator: u64) -> u64 {
    if current == 0 {
        sample
    } else {
        current
            .saturating_mul(denominator - numerator)
            .saturating_add(sample.saturating_mul(numerator))
            / denominator
    }
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
pub(crate) mod tests_fixture {
    use super::*;

    pub(crate) fn sample(epoch: u64) -> PathTelemetryV2 {
        PathTelemetryV2 {
            path_epoch: epoch,
            reliability: PathReliability::Datagram,
            rtt: Duration::from_millis(30),
            min_rtt: Duration::from_millis(25),
            queue_delay: Duration::from_millis(1),
            loss_ppm: 100,
            burst_loss_cells: 0,
            reorder_ppm: 0,
            receiver_goodput_bytes_per_second: 20 * 1024 * 1024,
            residual_loss_ppm: 0,
            latency_sojourn_p95_micros: 0,
            latency_sojourn_p50_micros: 0,
            latency_sojourn_p99_micros: 0,
            latency_queue_recently_nonempty: false,
            delivery_rate_bytes_per_second: 20 * 1024 * 1024,
            controller_pacing_rate_bytes_per_second: 0,
            controller_send_quantum_bytes: 0,
            controller_state: 0,
            controller_bw_bytes_per_second: 0,
            controller_inflight_longterm_bytes: 0,
            controller_guard_transitions_delta: 0,
            controller_app_limited: false,
            controller_tunables_generation: 0,
            controller_params_generation: 0,
            controller_clamped_writes: 0,
            receive_rate_bytes_per_second: 128 * 1024,
            packets_per_second: 20_000,
            tun_ingress_bytes_per_second: 20 * 1024 * 1024,
            average_record_bytes: 1_500,
            gso_ingress_ratio_ppm: 0,
            packet_train_queue_bytes: 128 * 1024,
            latency_queue_bytes: 0,
            reassembly_pressure_evictions: 0,
            remote_expired_stripes_delta: 0,
            train_build_bytes_per_second: 0,
            bulk_preemption_delay_average_micros: 0,
            cpu_utilization_per_mille: 500,
            wasted_parity_per_mille: 0,
            fec_recovery_per_mille: 0,
            repair_hit_per_mille: 0,
            repair_completed_requests: 0,
            repair_response_latency: Duration::ZERO,
            real_traffic_bytes_per_second: 20 * 1024 * 1024,
        }
    }

    #[test]
    fn forced_application_action_is_exact_inside_guardrails() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.packet_train_queue_bytes = 0;
        let forced = ForcedActionV2 {
            bbr_preset: None,
            fec: Some(Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            })),
            train_target_bytes: Some(64 * 1024),
            bulk_quantum_cells: Some(4),
            cover_profile: Some(CoverTrafficProfileV2::GenericH3Bulk),
            cover_overhead_per_mille: Some(50),
        };

        let decision = tuner.observe_forced(telemetry, forced);
        assert_eq!(decision.fec, forced.fec.unwrap());
        assert_eq!(decision.train_target_bytes, 64 * 1024);
        assert_eq!(decision.bulk_quantum_cells, 4);
        assert_eq!(decision.cover_profile, CoverTrafficProfileV2::GenericH3Bulk);
        assert_eq!(decision.cover_overhead_per_mille, 50);
        assert_eq!(
            decision.cover_padding_bytes_per_second,
            telemetry.real_traffic_bytes_per_second * 50 / 1_000
        );
    }

    #[test]
    fn forced_bbr_preset_is_exact_at_the_experiment_boundary() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.controller_bw_bytes_per_second = 10_000_000;
        let decision = tuner.observe_forced(
            telemetry,
            ForcedActionV2 {
                bbr_preset: Some(Bbr3PresetV2::Policer),
                ..ForcedActionV2::default()
            },
        );
        assert_eq!(decision.bbr.preset, Bbr3PresetV2::Policer);
        assert_eq!(decision.bbr.pacing_cap_bytes_per_second, 9_700_000);
    }

    #[test]
    fn forced_action_cannot_cross_emergency_reliable_or_latency_guards() {
        let force_off_and_burst = ForcedActionV2 {
            fec: Some(None),
            bulk_quantum_cells: Some(4),
            ..ForcedActionV2::default()
        };
        let mut emergency = sample(1);
        emergency.loss_ppm = 50_000;
        emergency.burst_loss_cells = 3;
        emergency.latency_queue_bytes = 1;
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let decision = tuner.observe_forced(emergency, force_off_and_burst);
        assert!(
            decision.fec.is_some(),
            "emergency FEC must win over force-off"
        );
        assert_eq!(decision.bulk_quantum_cells, 1);

        let mut reliable = sample(1);
        reliable.reliability = PathReliability::ReliableRelay;
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let decision = tuner.observe_forced(
            reliable,
            ForcedActionV2 {
                fec: Some(Some(FecGeometryV2 {
                    data_cells: 4,
                    parity_cells: 2,
                })),
                ..ForcedActionV2::default()
            },
        );
        assert_eq!(decision.fec, None);
    }

    #[test]
    fn learned_action_reuses_guardrails_without_advancing_sample_clock() {
        let mut telemetry = sample(1);
        telemetry.loss_ppm = 50_000;
        telemetry.burst_loss_cells = 3;
        telemetry.latency_queue_bytes = 1;
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let baseline = tuner.observe(telemetry);
        assert!(baseline.fec.is_some());
        let constrained = tuner.constrain_action(
            telemetry,
            baseline,
            ForcedActionV2 {
                fec: Some(None),
                bulk_quantum_cells: Some(4),
                ..ForcedActionV2::default()
            },
        );
        assert_eq!(constrained.sample_count, baseline.sample_count);
        assert_eq!(constrained.fec, baseline.fec);
        assert_eq!(constrained.bulk_quantum_cells, 1);
        assert_ne!(constrained.repair_cache_bytes, 0);

        let mut cpu_limited = sample(2);
        cpu_limited.cpu_utilization_per_mille = 950;
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 2);
        let baseline = tuner.observe(cpu_limited);
        let constrained = tuner.constrain_action(
            cpu_limited,
            baseline,
            ForcedActionV2 {
                train_target_bytes: Some(64 * 1024),
                bulk_quantum_cells: Some(4),
                ..ForcedActionV2::default()
            },
        );
        assert!(constrained.train_target_bytes <= baseline.train_target_bytes);
        assert!(constrained.bulk_quantum_cells <= baseline.bulk_quantum_cells);
    }

    #[test]
    fn receive_pressure_grows_and_holds_bounded_memory_without_configuration() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        assert_eq!(
            tuner.observe(telemetry).receive_buffer_bytes,
            8 * 1024 * 1024
        );

        telemetry.reassembly_pressure_evictions = 1;
        assert_eq!(
            tuner.observe(telemetry).receive_buffer_bytes,
            16 * 1024 * 1024
        );

        telemetry.reassembly_pressure_evictions = 0;
        for _ in 0..RECEIVE_PRESSURE_HOLD_SAMPLES - 1 {
            assert_eq!(
                tuner.observe(telemetry).receive_buffer_bytes,
                16 * 1024 * 1024
            );
        }
        assert_eq!(
            tuner.observe(telemetry).receive_buffer_bytes,
            16 * 1024 * 1024 - 512 * 1024
        );
    }

    #[test]
    fn live_media_profile_is_selected_from_directional_rate_without_configuration() {
        assert_eq!(classify_cover_profile(0, 0), CoverTrafficProfileV2::Idle);
        assert_eq!(
            classify_cover_profile(20 * 1024 * 1024, 256 * 1024),
            CoverTrafficProfileV2::LiveBroadcast
        );
        assert_eq!(
            classify_cover_profile(20 * 1024 * 1024, 10 * 1024 * 1024),
            CoverTrafficProfileV2::InteractiveVideo
        );
        assert_eq!(
            classify_cover_profile(64 * 1024, 10 * 1024 * 1024),
            CoverTrafficProfileV2::GenericH3Bulk
        );
    }

    #[test]
    fn nonblocking_tun_drain_adapts_to_record_geometry_without_waiting() {
        let mut telemetry = sample(1);
        telemetry.packets_per_second = 200_000;
        telemetry.cpu_utilization_per_mille = 200;
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let decision = tuner.observe(telemetry);
        assert_eq!(decision.receive_batch, 64);

        telemetry.average_record_bytes = 60 * 1024;
        telemetry.gso_ingress_ratio_ppm = 1_000_000;
        let decision = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(telemetry);
        assert_eq!(decision.receive_batch, 8);

        telemetry.tun_ingress_bytes_per_second = 0;
        let decision = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(telemetry);
        assert_eq!(decision.receive_batch, 64);
    }

    #[test]
    fn shallow_policer_with_an_actual_queue_keeps_bounded_sparse_fec() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(5);
        telemetry.rtt = Duration::from_millis(12);
        telemetry.queue_delay = Duration::from_millis(7);
        telemetry.loss_ppm = 80_000;
        telemetry.burst_loss_cells = 4;
        let decision = tuner.observe_at(telemetry, start);
        assert_eq!(
            decision.fec,
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1
            })
        );
        assert_eq!(decision.reason, TuneReasonV2::Congested);
    }

    #[test]
    fn high_rtt_jitter_does_not_suppress_loss_protection() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(85);
        telemetry.rtt = Duration::from_millis(93);
        telemetry.queue_delay = Duration::from_millis(8);
        telemetry.loss_ppm = 80_000;
        telemetry.burst_loss_cells = 4;

        let decision = tuner.observe(telemetry);
        assert_eq!(decision.reason, TuneReasonV2::BurstLoss);
        assert_eq!(
            decision.fec,
            Some(FecGeometryV2 {
                data_cells: 4,
                parity_cells: 2,
            })
        );
        assert!((16 * 1024 * 1024..=32 * 1024 * 1024).contains(&decision.repair_cache_bytes));
    }

    #[test]
    fn fec_hysteresis_never_emits_protected_cells_with_zero_repair_cache() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.loss_ppm = 80_000;
        telemetry.burst_loss_cells = 4;
        let enabled = tuner.observe_at(telemetry, start);
        assert!(enabled.fec.is_some());
        assert!(enabled.repair_cache_bytes > 0);

        telemetry.loss_ppm = 0;
        telemetry.burst_loss_cells = 0;
        let settling = tuner.observe_at(telemetry, start + Duration::from_millis(100));
        assert!(
            settling.fec.is_some(),
            "FEC transition should still be held"
        );
        assert!(
            settling.repair_cache_bytes > 0,
            "the held FEC geometry must retain its dependent Repair cache"
        );
    }

    #[test]
    fn reliable_relay_disables_fec_and_shrinks_repair_cache() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.reliability = PathReliability::ReliableRelay;
        telemetry.loss_ppm = 100_000;
        telemetry.burst_loss_cells = 5;
        let decision = tuner.observe(telemetry);
        assert_eq!(decision.fec, None);
        assert_eq!(decision.reason, TuneReasonV2::ReliablePath);
        assert_eq!(decision.repair_cache_bytes, 1024 * 1024);
    }

    #[test]
    fn repair_cache_covers_high_rtt_request_response_horizon() {
        let geometry = Some(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 2,
        });
        assert_eq!(
            repair_cache_target_bytes(
                PathReliability::Datagram,
                geometry,
                85_000,
                6_250_000,
                6_250_000,
            ),
            16 * 1024 * 1024
        );
        assert_eq!(
            repair_cache_target_bytes(
                PathReliability::Datagram,
                geometry,
                180_000,
                62_500_000,
                62_500_000,
            ),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn first_loss_sample_installs_sparse_fec_without_waiting_for_inner_rto() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(18);
        telemetry.rtt = Duration::from_millis(20);
        telemetry.loss_ppm = 5_000;
        assert_eq!(
            tuner.observe_at(telemetry, start).fec,
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1
            })
        );
    }

    #[test]
    fn idle_probe_loss_does_not_prearm_fec_or_policer_state() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(5);
        telemetry.rtt = Duration::from_millis(6);
        telemetry.loss_ppm = 250_000;
        telemetry.packets_per_second = 8;
        telemetry.real_traffic_bytes_per_second = 0;
        telemetry.tun_ingress_bytes_per_second = 0;

        for offset in 0..5 {
            let decision = tuner.observe_at(telemetry, start + Duration::from_secs(offset));
            assert_eq!(decision.fec, None);
            assert_eq!(decision.reason, TuneReasonV2::HealthyLowLoss);
        }
        assert_eq!(tuner.smoothed.loss_ppm, 0);
    }

    #[test]
    fn saturated_loss_stall_arms_protection_below_normal_traffic_floor() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(80);
        telemetry.rtt = Duration::from_millis(85);
        telemetry.loss_ppm = 100_000;
        telemetry.real_traffic_bytes_per_second = 32 * 1024;
        telemetry.packets_per_second = 64;
        telemetry.packet_train_queue_bytes = 256 * 1024;

        let decision = tuner.observe_at(telemetry, start);
        assert_eq!(decision.reason, TuneReasonV2::RandomLoss);
        assert!(decision.fec.is_some());
    }

    #[test]
    fn unqueued_shallow_policer_never_adds_loss_amplifying_parity() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(5);
        telemetry.rtt = Duration::from_millis(6);
        telemetry.queue_delay = Duration::from_millis(1);
        telemetry.loss_ppm = 200_000;

        for offset in 0..5 {
            let decision = tuner.observe_at(telemetry, start + Duration::from_secs(offset));
            assert_eq!(decision.reason, TuneReasonV2::Congested);
            assert_eq!(decision.fec, None);
        }
    }

    #[test]
    fn receiver_feedback_reduces_medium_loss_redundancy() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(85);
        telemetry.rtt = Duration::from_millis(90);
        telemetry.queue_delay = Duration::from_millis(5);
        telemetry.loss_ppm = 15_000;
        telemetry.burst_loss_cells = 2;
        for offset in 0..=3 {
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(
            tuner.current().fec,
            Some(FecGeometryV2 {
                data_cells: 6,
                parity_cells: 2
            })
        );

        telemetry.wasted_parity_per_mille = 950;
        telemetry.fec_recovery_per_mille = 50;
        for offset in 4..=7 {
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(
            tuner.current().fec,
            Some(FecGeometryV2 {
                data_cells: 6,
                parity_cells: 1
            })
        );

        telemetry.repair_hit_per_mille = 1_000;
        telemetry.repair_response_latency = Duration::from_millis(150);
        for offset in 8..=13 {
            telemetry.repair_completed_requests += 1;
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(
            tuner.current().fec,
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1
            }),
            "proven fast Repair should thin medium-loss parity without disabling protection"
        );
    }

    #[test]
    fn proven_repair_halves_wasteful_severe_loss_redundancy() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(85);
        telemetry.rtt = Duration::from_millis(90);
        telemetry.queue_delay = Duration::from_millis(5);
        telemetry.loss_ppm = 80_000;
        telemetry.burst_loss_cells = 4;
        assert_eq!(
            tuner.observe_at(telemetry, start).fec,
            Some(FecGeometryV2 {
                data_cells: 4,
                parity_cells: 2
            })
        );

        telemetry.wasted_parity_per_mille = 995;
        telemetry.fec_recovery_per_mille = 5;
        telemetry.repair_hit_per_mille = 1_000;
        telemetry.repair_response_latency = Duration::from_millis(25);
        let mut decision = tuner.current();
        for offset in 1..=4 {
            telemetry.repair_completed_requests += 4;
            decision = tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(
            decision.fec,
            Some(FecGeometryV2 {
                data_cells: 6,
                parity_cells: 1
            })
        );
        assert!(decision.repair_cache_bytes > 0);
    }

    #[test]
    fn proven_fast_repair_retires_wasteful_short_rtt_severe_fec() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(5);
        telemetry.rtt = Duration::from_millis(12);
        telemetry.queue_delay = Duration::from_millis(7);
        telemetry.loss_ppm = 80_000;
        telemetry.burst_loss_cells = 4;
        assert_eq!(
            tuner.observe_at(telemetry, start).fec,
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            })
        );

        telemetry.wasted_parity_per_mille = 1_000;
        telemetry.fec_recovery_per_mille = 0;
        telemetry.repair_hit_per_mille = 1_000;
        telemetry.repair_response_latency = Duration::from_millis(20);
        let mut decision = tuner.current();
        for offset in 1..=10 {
            telemetry.repair_completed_requests += 4;
            decision = tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(decision.fec, None);
        assert_eq!(decision.reason, TuneReasonV2::Congested);
    }

    #[test]
    fn light_loss_keeps_fec_until_repair_is_proven_fast_and_effective() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.min_rtt = Duration::from_millis(18);
        telemetry.rtt = Duration::from_millis(20);
        telemetry.loss_ppm = 5_000;
        telemetry.burst_loss_cells = 4;
        telemetry.wasted_parity_per_mille = 950;
        telemetry.fec_recovery_per_mille = 0;

        for offset in 0..=3 {
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(
            tuner.current().fec,
            Some(FecGeometryV2 {
                data_cells: 16,
                parity_cells: 1
            }),
            "unused parity should become sparse while Repair is still unproven"
        );

        telemetry.repair_hit_per_mille = 1_000;
        telemetry.repair_response_latency = Duration::from_millis(150);
        for offset in 4..=8 {
            telemetry.repair_completed_requests += 1;
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert_eq!(
            tuner.current().fec,
            None,
            "three stable sub-RTO Repair observations should retire wasteful light-loss FEC"
        );
    }

    #[test]
    fn slow_or_low_hit_repair_does_not_displace_light_loss_fec() {
        let start = Instant::now();
        for (hit, latency) in [
            (500, Duration::from_millis(20)),
            (1_000, Duration::from_secs(1)),
        ] {
            let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
            let mut telemetry = sample(1);
            telemetry.loss_ppm = 5_000;
            telemetry.wasted_parity_per_mille = 950;
            telemetry.repair_hit_per_mille = hit;
            telemetry.repair_response_latency = latency;
            for offset in 0..=7 {
                telemetry.repair_completed_requests = offset;
                tuner.observe_at(telemetry, start + Duration::from_secs(offset));
            }
            assert_eq!(
                tuner.current().fec,
                Some(FecGeometryV2 {
                    data_cells: 16,
                    parity_cells: 1
                })
            );
        }
    }

    #[test]
    fn path_change_resets_repair_effectiveness_confidence() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.loss_ppm = 5_000;
        telemetry.wasted_parity_per_mille = 950;
        telemetry.repair_hit_per_mille = 1_000;
        telemetry.repair_response_latency = Duration::from_millis(10);
        for offset in 0..=4 {
            telemetry.repair_completed_requests = offset;
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert!(tuner.smoothed.repair_observations >= 3);

        telemetry.path_epoch = 2;
        let decision = tuner.observe_at(telemetry, start + Duration::from_secs(5));
        assert_eq!(decision.path_epoch, 2);
        assert_eq!(tuner.smoothed.repair_observations, 0);
    }

    #[test]
    fn path_change_resets_to_conservative_cold_start() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.delivery_rate_bytes_per_second = 200 * 1024 * 1024;
        for offset in 1..=4 {
            tuner.observe_at(telemetry, start + Duration::from_secs(offset));
        }
        assert!(tuner.current().train_target_bytes > 16 * 1024);
        telemetry.path_epoch = 2;
        telemetry.delivery_rate_bytes_per_second = 0;
        let decision = tuner.observe_at(telemetry, start + Duration::from_secs(5));
        assert_eq!(decision.path_epoch, 2);
        assert_eq!(decision.train_target_bytes, 8 * 1024);
    }

    #[test]
    fn missing_telemetry_resets_every_adaptive_output_without_changing_epoch() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 7);
        let mut telemetry = sample(7);
        telemetry.delivery_rate_bytes_per_second = 200 * 1024 * 1024;
        for _ in 0..4 {
            tuner.observe(telemetry);
        }
        assert!(tuner.current().train_target_bytes > 16 * 1024);

        let decision = tuner.fallback_for_missing_telemetry();
        assert_eq!(decision.reason, TuneReasonV2::TelemetryUnavailable);
        assert_eq!(decision.path_epoch, 7);
        assert_eq!(decision.sample_count, 0);
        assert_eq!(decision.train_target_bytes, 16 * 1024);
        assert_eq!(decision.bulk_quantum_cells, 1);
        assert_eq!(decision.fec, None);
        assert_eq!(decision.cover_profile, CoverTrafficProfileV2::Idle);
        assert_eq!(decision.cover_padding_bytes_per_second, 0);
    }

    #[test]
    fn congestion_zeroes_cover_and_minimizes_bulk_quantum() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.rtt = Duration::from_millis(60);
        telemetry.queue_delay = Duration::from_millis(30);
        telemetry.latency_queue_bytes = 1024;
        let decision = tuner.observe(telemetry);
        assert_eq!(decision.reason, TuneReasonV2::Congested);
        assert_eq!(decision.bulk_quantum_cells, 1);
        assert_eq!(decision.cover_overhead_per_mille, 0);

        let mut cpu_limited = sample(1);
        cpu_limited.cpu_utilization_per_mille = 1_000;
        let decision = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(cpu_limited);
        assert_eq!(decision.reason, TuneReasonV2::CpuLimited);
        assert_eq!(decision.cover_overhead_per_mille, 0);
        assert_eq!(decision.cover_padding_bytes_per_second, 0);
    }

    #[test]
    fn congestion_loss_keeps_one_sparse_parity_cell_to_avoid_train_loss_amplification() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.rtt = Duration::from_millis(60);
        telemetry.queue_delay = Duration::from_millis(30);
        telemetry.loss_ppm = 100_000;
        telemetry.burst_loss_cells = 4;
        let mut decision = tuner.observe_at(telemetry, start);
        for seconds in 1..=4 {
            decision = tuner.observe_at(telemetry, start + Duration::from_secs(seconds));
        }
        assert_eq!(decision.reason, TuneReasonV2::Congested);
        assert_eq!(
            decision.fec,
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            })
        );
        assert!((4 * 1024 * 1024..=32 * 1024 * 1024).contains(&decision.repair_cache_bytes));
    }

    #[test]
    fn severe_fec_is_reduced_immediately_when_live_evidence_proves_congestion() {
        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut loss = sample(1);
        loss.loss_ppm = 100_000;
        loss.burst_loss_cells = 4;
        let enabled = tuner.observe_at(loss, start);
        assert!(enabled.fec.is_some());

        let mut congested = loss;
        congested.queue_delay = Duration::from_millis(30);
        congested.rtt = Duration::from_millis(60);
        congested.min_rtt = Duration::from_millis(20);
        let disabled = tuner.observe_at(congested, start + Duration::from_secs(1));
        assert_eq!(disabled.reason, TuneReasonV2::Congested);
        assert_eq!(
            disabled.fec,
            Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            })
        );
        assert!((4 * 1024 * 1024..=32 * 1024 * 1024).contains(&disabled.repair_cache_bytes));
    }

    #[test]
    fn bulk_only_congestion_keeps_a_batchable_bounded_quantum() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.rtt = Duration::from_millis(60);
        telemetry.queue_delay = Duration::from_millis(30);
        telemetry.latency_queue_bytes = 0;
        let decision = tuner.observe(telemetry);
        assert_eq!(decision.reason, TuneReasonV2::Congested);
        assert_eq!(decision.bulk_quantum_cells, 4);
    }

    #[test]
    fn low_rtt_cpu_limited_bulk_grows_native_admission_window() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.rtt = Duration::from_micros(50);
        telemetry.min_rtt = Duration::from_micros(40);
        telemetry.queue_delay = Duration::from_micros(10);
        telemetry.delivery_rate_bytes_per_second = 300 * 1024 * 1024;
        telemetry.real_traffic_bytes_per_second = telemetry.delivery_rate_bytes_per_second;
        telemetry.packets_per_second = 220_000;
        telemetry.packet_train_queue_bytes = 1024 * 1024;
        telemetry.cpu_utilization_per_mille = 1_000;

        let mut decision = tuner.observe(telemetry);
        for _ in 0..8 {
            decision = tuner.observe(telemetry);
        }
        assert_eq!(decision.reason, TuneReasonV2::CpuLimited);
        assert!(decision.send_buffer_bytes >= 2 * 1024 * 1024);

        telemetry.latency_queue_bytes = 1;
        let reduced = tuner.observe(telemetry);
        assert!(reduced.send_buffer_bytes < decision.send_buffer_bytes);
    }

    #[test]
    fn asymmetric_capacity_sizes_outgoing_and_incoming_windows_independently() {
        fn settle(mut telemetry: PathTelemetryV2) -> TuneDecisionV2 {
            telemetry.rtt = Duration::from_millis(105);
            telemetry.min_rtt = Duration::from_millis(100);
            telemetry.queue_delay = Duration::from_millis(5);
            telemetry.cpu_utilization_per_mille = 200;
            let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
            let mut decision = tuner.observe(telemetry);
            for _ in 0..80 {
                decision = tuner.observe(telemetry);
            }
            decision
        }

        let mut symmetric_slow = sample(1);
        symmetric_slow.delivery_rate_bytes_per_second = 12_500_000;
        symmetric_slow.receive_rate_bytes_per_second = 12_500_000;
        let symmetric_slow = settle(symmetric_slow);

        let mut fast_downlink = sample(1);
        fast_downlink.delivery_rate_bytes_per_second = 12_500_000;
        fast_downlink.receive_rate_bytes_per_second = 125_000_000;
        let fast_downlink = settle(fast_downlink);

        assert_eq!(
            fast_downlink.send_buffer_bytes, symmetric_slow.send_buffer_bytes,
            "incoming downlink capacity must not inflate uplink admission"
        );
        assert!(fast_downlink.receive_buffer_bytes > symmetric_slow.receive_buffer_bytes);
        assert_eq!(fast_downlink.receive_buffer_bytes, 25_000_000);

        let mut fast_uplink = sample(1);
        fast_uplink.delivery_rate_bytes_per_second = 125_000_000;
        fast_uplink.receive_rate_bytes_per_second = 12_500_000;
        let fast_uplink = settle(fast_uplink);
        assert!(fast_uplink.send_buffer_bytes > fast_downlink.send_buffer_bytes);
        assert_eq!(
            fast_uplink.receive_buffer_bytes, symmetric_slow.receive_buffer_bytes,
            "outgoing uplink capacity must not inflate the receive window"
        );
    }

    #[test]
    fn queue_inflated_rtt_does_not_inflate_quic_admission_buffer() {
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.delivery_rate_bytes_per_second = 1_500_000;
        telemetry.real_traffic_bytes_per_second = telemetry.delivery_rate_bytes_per_second;
        telemetry.min_rtt = Duration::from_millis(12);
        telemetry.rtt = Duration::from_millis(220);
        telemetry.queue_delay = telemetry.rtt - telemetry.min_rtt;
        telemetry.packet_train_queue_bytes = 6 * 1024 * 1024;
        telemetry.latency_queue_bytes = 0;
        telemetry.cpu_utilization_per_mille = 200;

        let decision = tuner.observe(telemetry);
        assert_eq!(decision.reason, TuneReasonV2::Congested);
        assert_eq!(decision.send_buffer_bytes, 256 * 1024);

        // Raising only the queue-inflated RTT must not feed back into the
        // native DATAGRAM admission target.
        telemetry.rtt = Duration::from_secs(2);
        let inflated = tuner.observe(telemetry);
        assert_eq!(inflated.send_buffer_bytes, decision.send_buffer_bytes);
    }

    #[test]
    fn native_rule_candidate_is_only_smoothed_on_a_healthy_path_and_guarded_under_pressure() {
        use crate::protocol::v2::policy::api::{ClampFieldV1, ClampReasonV1};

        let start = Instant::now();
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.packet_train_queue_bytes = 0;
        for offset in 0..=5 {
            let decision = tuner.observe_at(telemetry, start + Duration::from_secs(offset));
            // The rule set is the host baseline: on a healthy path only the
            // transition controller holds its values back, never a guardrail.
            assert!(
                tuner
                    .last_clamp_report()
                    .entries
                    .iter()
                    .all(|entry| entry.reason == ClampReasonV1::TransitionHold),
                "{:?}",
                tuner.last_clamp_report()
            );
            assert_eq!(decision.cover_overhead_per_mille, 30);
        }
        assert_eq!(
            tuner.current_effective().to_tune_decision(),
            tuner.current()
        );

        // Queued Bulk is a host guardrail on the rule's nominal cover
        // proposal, not part of the rule itself.
        telemetry.packet_train_queue_bytes = 128 * 1024;
        let decision = tuner.observe_at(telemetry, start + Duration::from_secs(6));
        assert_eq!(decision.cover_overhead_per_mille, 0);
        assert!(tuner.last_clamp_report().entries.iter().any(|entry| {
            entry.field == ClampFieldV1::CoverOverheadPerMille
                && entry.requested == 30
                && entry.effective == 0
                && entry.reason == ClampReasonV1::QueuePressure
        }));
    }

    #[test]
    fn forced_override_clamps_are_reported() {
        use crate::protocol::v2::policy::api::{ClampFieldV1, ClampReasonV1};

        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.packet_train_queue_bytes = 0;
        let decision = tuner.observe_forced(
            telemetry,
            ForcedActionV2 {
                cover_profile: Some(CoverTrafficProfileV2::GenericH3Bulk),
                cover_overhead_per_mille: Some(200),
                train_target_bytes: Some(1024 * 1024),
                ..ForcedActionV2::default()
            },
        );
        assert_eq!(decision.cover_overhead_per_mille, 50);
        assert_eq!(decision.train_target_bytes, 64 * 1024);
        let report = tuner.last_clamp_report();
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::CoverOverheadPerMille
                && entry.requested == 200
                && entry.effective == 50
                && entry.reason == ClampReasonV1::AboveCap
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::SchedulerTrainTargetBytes
                && entry.reason == ClampReasonV1::AboveCap
        }));
    }

    #[test]
    fn constrain_action_is_one_guardrail_pass_over_the_filtered_sample() {
        use crate::protocol::v2::policy::{
            api::{EffectiveActionV1, EffectiveHostExt},
            guardrails::{GuardrailContextV1, GuardrailsV1},
        };

        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut telemetry = sample(1);
        telemetry.loss_ppm = 20_000;
        telemetry.burst_loss_cells = 2;
        telemetry.cpu_utilization_per_mille = 950;
        let baseline = tuner.observe(telemetry);
        let action = ForcedActionV2 {
            fec: Some(Some(FecGeometryV2 {
                data_cells: 4,
                parity_cells: 2,
            })),
            train_target_bytes: Some(64 * 1024),
            bulk_quantum_cells: Some(4),
            cover_overhead_per_mille: Some(50),
            ..ForcedActionV2::default()
        };
        let through_tuner = tuner.constrain_action(telemetry, baseline, action);

        let filtered = tuner.smoothed.view(telemetry);
        let ctx = GuardrailContextV1::from_filtered(&filtered);
        assert!(ctx.cpu_emergency && ctx.cpu_limited);
        let (direct, report) = GuardrailsV1::from_bounds(&AutoTuneBoundsV2::default()).apply(
            &action.to_candidate(telemetry.controller_bw_bytes_per_second),
            &EffectiveActionV1::from_tune_decision(&baseline),
            &ctx,
        );
        assert_eq!(direct.to_tune_decision(), through_tuner);
        assert!(!report.is_empty());
        assert_eq!(through_tuner.fec, None, "CPU pressure suppresses parity");
        assert!(through_tuner.train_target_bytes <= baseline.train_target_bytes);
        assert_eq!(through_tuner.cover_overhead_per_mille, 0);
    }
}
