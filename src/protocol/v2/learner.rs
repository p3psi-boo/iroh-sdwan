//! Slow-path contextual learner for V2 transport actions.
//!
//! The learner itself lives in `ironet-policy-core` (single source for the
//! native backend and the builtin WASM guest). This module is the host-side
//! adapter that keeps the legacy API (`BanditLearnerV2`, `ContextKeyV2`,
//! `LearnerMemoryV2`, ...) for `v2_runtime.rs`, `replay.rs` and `memory.rs`
//! while routing every step through the ABI: runtime telemetry, utility and
//! the baseline decision are projected onto `PolicyInputV1`, the core's
//! `PolicyOutputV1` is projected back onto `TuneDecisionV2`, and the learner
//! state travels as the opaque `state`/`next_state` blob.
//!
//! Time: the core counts logical ticks (one tick == one second). The adapter
//! maps `Instant`s to ticks with the first `Instant` it sees as tick 0 and
//! `floor(seconds since that origin)` afterwards.

use std::{sync::Arc, time::Instant};

use ironet_policy_core::{
    ActionSpecV1, ArmMemoryV1, BbrProposalSpecV1, ContextKeyV1, ContextMemoryV1,
    ContextSchemaSpecV1, CorePolicy, EXTENSION_TAG_HOST_UTILITY_F64_V1, ExplorationSpecV1,
    FineMemoryV1, LearnerMemoryV1, LearnerModeV1, LearnerStateV1, LearnerTraceV1, PolicySpecV1,
    PosteriorSpecV1, PresetSpecV1, UtilityWeightsSpecV1, host_utility_extension,
};
use serde::{Deserialize, Serialize};

use super::{
    policy::{
        ContextSchemaV2, PolicyArtifactV2,
        api::{
            BbrHostExt, EffectiveActionV1, EffectiveHostExt, HostCapabilitiesV1, HostLimitsV1,
            HostUtilityV1, PolicyInputV1, PolicyTelemetryV1, TelemetryHostExt, UtilityHostExt,
        },
        builtin as builtin_policy,
    },
    tuning::{AutoTunerV2, Bbr3PresetV2, Bbr3ProposalV2, PathTelemetryV2, TuneDecisionV2},
    utility::UtilitySample,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnerModeV2 {
    Off,
    Shadow,
    On,
}

impl From<LearnerModeV2> for LearnerModeV1 {
    fn from(mode: LearnerModeV2) -> Self {
        match mode {
            LearnerModeV2::Off => Self::Off,
            LearnerModeV2::Shadow => Self::Shadow,
            LearnerModeV2::On => Self::On,
        }
    }
}

impl From<LearnerModeV1> for LearnerModeV2 {
    fn from(mode: LearnerModeV1) -> Self {
        match mode {
            LearnerModeV1::Off => Self::Off,
            LearnerModeV1::Shadow => Self::Shadow,
            LearnerModeV1::On => Self::On,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContextKeyV2 {
    pub rtt_class: u8,
    pub rate_class: u8,
    pub loss_class: u8,
    pub reliable: bool,
    /// True only for a genuinely host-local path below 2 ms. The
    /// ordinary `rtt_class == 0` bucket spans up to 10 ms and is too broad
    /// for the low-RTT cwnd-floor preset. The 2 ms bound includes the
    /// userspace QUIC/TUN scheduling floor measured by the netns harness.
    #[serde(default)]
    pub host_rtt: bool,
}

impl ContextKeyV2 {
    pub fn classify(t: &PathTelemetryV2) -> Self {
        Self::classify_with(
            t,
            &ContextSchemaV2 {
                rtt_millis: vec![10, 40, 120],
                rate_mbps: vec![10, 100, 500],
                loss_ppm: vec![1_000, 10_000, 30_000],
            },
        )
    }

    #[cfg(test)]
    fn policy_key(self) -> String {
        ContextKeyV1::from(self).policy_key()
    }

    pub fn classify_with(t: &PathTelemetryV2, schema: &ContextSchemaV2) -> Self {
        ContextKeyV1::classify(
            &PolicyTelemetryV1::from_runtime(t),
            t.reliability.into(),
            &context_schema_to_core(schema),
        )
        .into()
    }
}

impl From<ContextKeyV1> for ContextKeyV2 {
    fn from(key: ContextKeyV1) -> Self {
        Self {
            rtt_class: key.rtt_class,
            rate_class: key.rate_class,
            loss_class: key.loss_class,
            reliable: key.reliable,
            host_rtt: key.host_rtt,
        }
    }
}

impl From<ContextKeyV2> for ContextKeyV1 {
    fn from(key: ContextKeyV2) -> Self {
        Self {
            rtt_class: key.rtt_class,
            rate_class: key.rate_class,
            loss_class: key.loss_class,
            reliable: key.reliable,
            host_rtt: key.host_rtt,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LearnerTraceV2 {
    pub mode: LearnerModeV2,
    pub context: ContextKeyV2,
    pub baseline_preset: Bbr3PresetV2,
    pub proposed_preset: Bbr3PresetV2,
    pub applied_preset: Bbr3PresetV2,
    pub predicted_advantage: f64,
    pub exploring: bool,
    pub rollback: bool,
    pub rollbacks: u64,
    pub fine_up_gain_delta_milli: i16,
    pub fine_headroom_delta_milli: i16,
    pub fine_cwnd_gain_delta_milli: i16,
}

impl From<LearnerTraceV1> for LearnerTraceV2 {
    fn from(trace: LearnerTraceV1) -> Self {
        Self {
            mode: trace.mode.into(),
            context: trace.context.into(),
            baseline_preset: trace.baseline_preset.into(),
            proposed_preset: trace.proposed_preset.into(),
            applied_preset: trace.applied_preset.into(),
            predicted_advantage: trace.predicted_advantage,
            exploring: trace.exploring,
            rollback: trace.rollback,
            rollbacks: trace.rollbacks,
            fine_up_gain_delta_milli: trace.fine_up_gain_delta_milli,
            fine_headroom_delta_milli: trace.fine_headroom_delta_milli,
            fine_cwnd_gain_delta_milli: trace.fine_cwnd_gain_delta_milli,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ArmMemoryV2 {
    pub observations: u32,
    pub mean: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextMemoryV2 {
    pub key: ContextKeyV2,
    pub arms: [ArmMemoryV2; 7],
    pub active: Bbr3PresetV2,
    pub max_bw_bytes_per_second: u64,
    pub min_rtt_micros: u64,
    #[serde(default)]
    pub fine: FineMemoryV2,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FineMemoryV2 {
    pub up_gain_delta_milli: i16,
    pub headroom_delta_milli: i16,
    pub cwnd_gain_delta_milli: i16,
    pub direction: i8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LearnerMemoryV2 {
    pub contexts: Vec<ContextMemoryV2>,
}

impl From<FineMemoryV1> for FineMemoryV2 {
    fn from(fine: FineMemoryV1) -> Self {
        Self {
            up_gain_delta_milli: fine.up_gain_delta_milli,
            headroom_delta_milli: fine.headroom_delta_milli,
            cwnd_gain_delta_milli: fine.cwnd_gain_delta_milli,
            direction: fine.direction,
        }
    }
}

impl From<FineMemoryV2> for FineMemoryV1 {
    fn from(fine: FineMemoryV2) -> Self {
        Self {
            up_gain_delta_milli: fine.up_gain_delta_milli,
            headroom_delta_milli: fine.headroom_delta_milli,
            cwnd_gain_delta_milli: fine.cwnd_gain_delta_milli,
            direction: fine.direction,
        }
    }
}

impl From<&LearnerMemoryV1> for LearnerMemoryV2 {
    fn from(memory: &LearnerMemoryV1) -> Self {
        Self {
            contexts: memory
                .contexts
                .iter()
                .map(|context| ContextMemoryV2 {
                    key: context.key.into(),
                    arms: context.arms.map(|arm| ArmMemoryV2 {
                        observations: arm.observations,
                        mean: arm.mean,
                    }),
                    active: context.active.into(),
                    max_bw_bytes_per_second: context.max_bw_bytes_per_second,
                    min_rtt_micros: context.min_rtt_micros,
                    fine: context.fine.into(),
                })
                .collect(),
        }
    }
}

impl From<&LearnerMemoryV2> for LearnerMemoryV1 {
    fn from(memory: &LearnerMemoryV2) -> Self {
        Self {
            contexts: memory
                .contexts
                .iter()
                .map(|context| ContextMemoryV1 {
                    key: context.key.into(),
                    arms: context.arms.map(|arm| ArmMemoryV1 {
                        observations: arm.observations,
                        mean: arm.mean,
                    }),
                    active: context.active.into(),
                    max_bw_bytes_per_second: context.max_bw_bytes_per_second,
                    min_rtt_micros: context.min_rtt_micros,
                    fine: context.fine.into(),
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact -> core spec
// ---------------------------------------------------------------------------

fn context_schema_to_core(schema: &ContextSchemaV2) -> ContextSchemaSpecV1 {
    ContextSchemaSpecV1 {
        rtt_millis: schema.rtt_millis.clone(),
        rate_mbps: schema.rate_mbps.clone(),
        loss_ppm: schema.loss_ppm.clone(),
    }
}

fn proposal_to_core(proposal: Bbr3ProposalV2) -> BbrProposalSpecV1 {
    BbrProposalSpecV1 {
        preset: proposal.preset.into(),
        up_gain_milli: proposal.up_gain_milli,
        headroom_milli: proposal.headroom_milli,
        cwnd_gain_milli: proposal.cwnd_gain_milli,
        pacing_cap_bytes_per_second: proposal.pacing_cap_bytes_per_second,
        loss_is_congestion: proposal.loss_is_congestion,
    }
}

fn proposal_to_runtime(proposal: BbrProposalSpecV1) -> Bbr3ProposalV2 {
    Bbr3ProposalV2 {
        preset: proposal.preset.into(),
        up_gain_milli: proposal.up_gain_milli,
        headroom_milli: proposal.headroom_milli,
        cwnd_gain_milli: proposal.cwnd_gain_milli,
        pacing_cap_bytes_per_second: proposal.pacing_cap_bytes_per_second,
        loss_is_congestion: proposal.loss_is_congestion,
    }
}

/// Project the host's JSON artifact onto the core's pure-data spec (the
/// schema version, digest, source and trained-on list stay host-only).
pub fn policy_spec_from_artifact(policy: &PolicyArtifactV2) -> PolicySpecV1 {
    PolicySpecV1 {
        id: policy.id.clone(),
        algorithm: policy.algorithm.clone(),
        version: policy.built_at.clone(),
        objective: policy.objective.map(Into::into),
        contexts: context_schema_to_core(&policy.contexts),
        presets: policy
            .presets
            .iter()
            .map(|preset| PresetSpecV1 {
                name: preset.name.clone(),
                proposal: proposal_to_core(preset.proposal),
                action: ActionSpecV1 {
                    fec_data_cells: preset.action.fec_data_cells,
                    fec_parity_cells: preset.action.fec_parity_cells,
                    train_target_bytes: preset
                        .action
                        .train_target_bytes
                        .map(|value| u32::try_from(value).unwrap_or(u32::MAX)),
                    bulk_quantum_cells: preset
                        .action
                        .bulk_quantum_cells
                        .map(|value| u16::try_from(value).unwrap_or(u16::MAX)),
                    cover_overhead_per_mille: preset.action.cover_overhead_per_mille,
                },
            })
            .collect(),
        priors: policy
            .priors
            .iter()
            .map(|(context, priors)| {
                (
                    context.clone(),
                    priors
                        .iter()
                        .map(|(name, prior)| {
                            (
                                name.clone(),
                                PosteriorSpecV1 {
                                    observations: prior.observations,
                                    mean: prior.mean,
                                },
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
        weights: policy
            .weights
            .iter()
            .map(|(name, weights)| {
                (
                    name.clone(),
                    UtilityWeightsSpecV1 {
                        throughput: weights.throughput,
                        queue_delay: weights.queue_delay,
                        latency_sojourn: weights.latency_sojourn,
                        residual_loss: weights.residual_loss,
                        jitter: weights.jitter,
                        cpu: weights.cpu,
                        wire_overhead: weights.wire_overhead,
                        memory: weights.memory,
                    },
                )
            })
            .collect(),
        exploration: ExplorationSpecV1 {
            minimum_dwell_millis: policy.exploration.minimum_dwell_millis,
            minimum_rtt_rounds: policy.exploration.minimum_rtt_rounds,
            minimum_samples: policy.exploration.minimum_samples,
            maximum_cpu_per_mille: policy.exploration.maximum_cpu_per_mille,
            rollback_regression_per_mille: policy.exploration.rollback_regression_per_mille,
        },
    }
}

// ---------------------------------------------------------------------------
// Instant -> logical tick
// ---------------------------------------------------------------------------

/// Maps host `Instant`s onto the core's logical ticks: the first `Instant`
/// seen is tick 0, later ones are `floor(seconds since origin)`. One tick is
/// one second, matching the one-second tuner loop.
#[derive(Debug, Default, Clone, Copy)]
struct TickClock {
    origin: Option<Instant>,
}

impl TickClock {
    fn tick(&mut self, now: Instant) -> u64 {
        let origin = *self.origin.get_or_insert(now);
        now.saturating_duration_since(origin).as_secs()
    }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct BanditLearnerV2 {
    mode: LearnerModeV2,
    seed: u64,
    policy: Arc<PolicyArtifactV2>,
    core: CorePolicy,
    /// Encoded `ironet_policy_core` learner state; empty until the first
    /// step (cold start).
    state: Vec<u8>,
    clock: TickClock,
}

impl BanditLearnerV2 {
    pub fn new(mode: LearnerModeV2, seed: u64) -> Self {
        Self::with_policy(
            mode,
            seed,
            Arc::new(builtin_policy().expect("embedded autotune policy must validate")),
        )
    }

    pub fn with_policy(mode: LearnerModeV2, seed: u64, policy: Arc<PolicyArtifactV2>) -> Self {
        Self {
            mode,
            seed,
            core: CorePolicy::new(policy_spec_from_artifact(&policy), mode.into()),
            policy,
            state: Vec::new(),
            clock: TickClock::default(),
        }
    }

    pub fn replace_policy(&mut self, policy: Arc<PolicyArtifactV2>, now: Instant) {
        if self.policy.digest == policy.digest {
            return;
        }
        let tick = self.clock.tick(now);
        let same_algorithm = self.policy.algorithm == policy.algorithm;
        if let Ok(mut state) = LearnerStateV1::decode_or_cold_start(&self.state, self.seed) {
            state.reset_for_policy_change(same_algorithm, tick);
            self.state = state.encode().unwrap_or_default();
        }
        self.core = CorePolicy::new(policy_spec_from_artifact(&policy), self.mode.into());
        self.policy = policy;
    }

    pub fn export_memory(&self) -> LearnerMemoryV2 {
        LearnerStateV1::decode_or_cold_start(&self.state, self.seed)
            .map(|state| LearnerMemoryV2::from(&state.export_memory()))
            .unwrap_or_default()
    }

    pub fn warm_start(&mut self, memory: &LearnerMemoryV2, now: Instant) {
        let tick = self.clock.tick(now);
        if let Ok(mut state) = LearnerStateV1::decode_or_cold_start(&self.state, self.seed) {
            state.warm_start(&LearnerMemoryV1::from(memory), tick);
            self.state = state.encode().unwrap_or_default();
        }
    }

    pub fn step(
        &mut self,
        now: Instant,
        telemetry: &PathTelemetryV2,
        utility: &UtilitySample,
        baseline: TuneDecisionV2,
    ) -> (TuneDecisionV2, LearnerTraceV2) {
        let tick = self.clock.tick(now);
        let objective = self.policy.objective.unwrap_or_default();
        let input = PolicyInputV1 {
            logical_tick: tick,
            deterministic_seed: self.seed,
            peer_hash: [0; 32],
            path_epoch: telemetry.path_epoch,
            reliability: telemetry.reliability.into(),
            telemetry: PolicyTelemetryV1::from_runtime(telemetry),
            previous: EffectiveActionV1::from_tune_decision(&baseline),
            previous_utility: HostUtilityV1::from_sample(objective, utility),
            limits: HostLimitsV1::default(),
            capabilities: HostCapabilitiesV1 {
                // Not set: this adapter materializes the shadow
                // counterfactual itself (`materialize_policy_action`) and
                // needs `decide` to return the *applied* arm's candidate
                // (the baseline in shadow mode). The flag would switch the
                // core to the proposed arm's counterfactual candidate.
                shadow: false,
                extension_tags: vec![EXTENSION_TAG_HOST_UTILITY_F64_V1],
                ..HostCapabilitiesV1::default()
            },
            egress: Default::default(),
            extensions: vec![host_utility_extension(utility.total)],
            state: std::mem::take(&mut self.state),
        };
        match self.core.decide_traced(&input) {
            Ok((output, trace)) => {
                self.state = output.next_state;
                let effective = output.candidate.apply_over(&input.previous);
                let mut decision = baseline;
                decision.bbr = effective.bbr.to_proposal();
                (decision, trace.into())
            }
            Err(fault) => {
                // The carried state could not be decoded or re-encoded; the
                // adapter never produces such a blob, so this is defensive.
                // Restart from an empty state and publish the baseline.
                tracing::warn!(%fault, "V2 autotune learner restarted from an empty state");
                self.state.clear();
                let context = ContextKeyV2::classify_with(telemetry, &self.policy.contexts);
                (
                    baseline,
                    LearnerTraceV2 {
                        mode: self.mode,
                        context,
                        baseline_preset: baseline.bbr.preset,
                        proposed_preset: baseline.bbr.preset,
                        applied_preset: baseline.bbr.preset,
                        predicted_advantage: 0.0,
                        exploring: false,
                        rollback: false,
                        rollbacks: 0,
                        fine_up_gain_delta_milli: 0,
                        fine_headroom_delta_milli: 0,
                        fine_cwnd_gain_delta_milli: 0,
                    },
                )
            }
        }
    }
}

/// Materialize a shadow arm as a complete, guarded counterfactual action.
/// The returned decision is never published by this helper; callers decide
/// whether it is observability-only or an on-mode action.
pub fn materialize_policy_action(
    policy: &PolicyArtifactV2,
    tuner: &AutoTunerV2,
    telemetry: PathTelemetryV2,
    baseline: TuneDecisionV2,
    preset: Bbr3PresetV2,
) -> TuneDecisionV2 {
    let mut decision = baseline;
    decision.bbr = proposal_to_runtime(ironet_policy_core::resolve_preset_proposal(
        policy.preset(preset).map(proposal_to_core),
        preset.into(),
        telemetry.controller_bw_bytes_per_second,
    ));
    policy.action(preset).map_or(decision, |action| {
        tuner.constrain_action(telemetry, decision, action)
    })
}

pub fn preset_is_eligible(context: ContextKeyV2, preset: Bbr3PresetV2) -> bool {
    ironet_policy_core::preset_is_eligible(context.into(), preset.into())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::protocol::v2::{
        tuning::{AutoTuneBoundsV2, AutoTunerV2},
        utility::{Objective, UtilityEstimator, WireCostV2},
    };

    fn telemetry() -> PathTelemetryV2 {
        super::super::tuning::tests_fixture::sample(1)
    }

    #[test]
    fn builtin_spec_matches_the_embedded_host_artifact() {
        let host = policy_spec_from_artifact(&builtin_policy().unwrap());
        assert_eq!(host, PolicySpecV1::builtin());
        host.validate().unwrap();
    }

    #[test]
    fn context_separates_asymmetric_rate_loss_and_rtt_classes() {
        let mut t = telemetry();
        t.min_rtt = Duration::from_millis(150);
        t.delivery_rate_bytes_per_second = 80_000_000;
        t.burst_loss_cells = 3;
        let key = ContextKeyV2::classify(&t);
        assert_eq!(key.rtt_class, 3);
        assert_eq!(key.rate_class, 3);
        assert_eq!(key.loss_class, 2);
    }

    #[test]
    fn severe_loss_takes_precedence_over_low_rtt_for_candidate_selection() {
        let context = ContextKeyV2 {
            rtt_class: 0,
            rate_class: 2,
            loss_class: 3,
            reliable: false,
            host_rtt: true,
        };
        assert!(preset_is_eligible(context, Bbr3PresetV2::Policer));
        assert!(preset_is_eligible(context, Bbr3PresetV2::LossyRadio));
        assert!(!preset_is_eligible(context, Bbr3PresetV2::LowRttHost));
    }

    #[test]
    fn low_rtt_host_is_not_eligible_on_an_ordinary_lan_rtt() {
        let mut t = telemetry();
        t.min_rtt = Duration::from_millis(4);
        let context = ContextKeyV2::classify(&t);
        assert_eq!(context.rtt_class, 0);
        assert!(!context.host_rtt);
        assert!(!preset_is_eligible(context, Bbr3PresetV2::LowRttHost));

        t.min_rtt = Duration::from_micros(800);
        let context = ContextKeyV2::classify(&t);
        assert!(context.host_rtt);
        assert!(preset_is_eligible(context, Bbr3PresetV2::LowRttHost));

        t.min_rtt = Duration::from_micros(1_500);
        assert!(ContextKeyV2::classify(&t).host_rtt);
    }

    #[test]
    fn shadow_never_applies_its_candidate() {
        let t = telemetry();
        let baseline = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(t);
        let mut estimator = UtilityEstimator::new(Objective::Balanced);
        let utility = estimator.observe(&t, &baseline, &WireCostV2::default());
        let start = Instant::now();
        let mut learner = BanditLearnerV2::new(LearnerModeV2::Shadow, 7);
        let (decision, trace) =
            learner.step(start + Duration::from_secs(20), &t, &utility, baseline);
        assert_eq!(decision.bbr, baseline.bbr);
        assert_eq!(trace.applied_preset, baseline.bbr.preset);
    }

    #[test]
    fn shadow_policy_uses_offline_context_priors_for_counterfactual_action() {
        let t = telemetry();
        let mut baseline = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(t);
        baseline.sample_count = 8;
        let utility = UtilitySample {
            total: 1.0,
            components: [0.0; 8],
            goodput_bytes_per_second: 1,
        };
        let mut policy = builtin_policy().unwrap();
        policy.priors.insert(
            ContextKeyV2::classify_with(&t, &policy.contexts).policy_key(),
            std::collections::BTreeMap::from([(
                "private-aggressive".to_owned(),
                crate::protocol::v2::policy::PosteriorSpecV2 {
                    observations: 100,
                    mean: 100.0,
                },
            )]),
        );
        policy.digest = policy.calculated_digest().unwrap();
        let mut learner = BanditLearnerV2::with_policy(LearnerModeV2::Shadow, 7, Arc::new(policy));
        let start = Instant::now();
        learner.step(start, &t, &utility, baseline);
        let (decision, trace) =
            learner.step(start + Duration::from_secs(20), &t, &utility, baseline);
        assert_eq!(trace.proposed_preset, Bbr3PresetV2::PrivateAggressive);
        assert_eq!(trace.applied_preset, baseline.bbr.preset);
        assert_eq!(decision.bbr, baseline.bbr);
        assert!(trace.predicted_advantage > 90.0);
    }

    #[test]
    fn path_epoch_discards_inflight_exploration_state() {
        let mut t = telemetry();
        let baseline = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(t);
        let utility = UtilitySample {
            total: 1.0,
            components: [0.0; 8],
            goodput_bytes_per_second: 1,
        };
        let now = Instant::now();
        let mut learner = BanditLearnerV2::new(LearnerModeV2::On, 3);
        learner.step(now, &t, &utility, baseline);
        assert_eq!(learner.export_memory().contexts.len(), 1);
        t.path_epoch = 2;
        let baseline = AutoTunerV2::new(AutoTuneBoundsV2::default(), 2).observe(t);
        learner.step(now + Duration::from_secs(1), &t, &utility, baseline);
        let state = LearnerStateV1::decode(&learner.state).unwrap();
        assert_eq!(state.path_epoch(), 2);
        assert_eq!(learner.export_memory().contexts.len(), 1);
    }

    #[test]
    fn same_algorithm_policy_hot_swap_preserves_posteriors_and_resets_probe() {
        let telemetry = telemetry();
        let baseline = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(telemetry);
        let utility = UtilitySample {
            total: 1.0,
            components: [0.0; 8],
            goodput_bytes_per_second: 1,
        };
        let now = Instant::now();
        let mut learner = BanditLearnerV2::new(LearnerModeV2::On, 9);
        learner.step(now, &telemetry, &utility, baseline);
        let mut memory = learner.export_memory();
        memory.contexts[0].arms[0] = ArmMemoryV2 {
            observations: 1,
            mean: 0.75,
        };
        memory.contexts[0].fine.up_gain_delta_milli = 100;
        learner.warm_start(&memory, now);
        assert_eq!(
            learner.export_memory().contexts[0].fine.up_gain_delta_milli,
            100
        );

        let mut next = builtin_policy().unwrap();
        next.id = "bandit-vivace@2".to_owned();
        next.digest = next.calculated_digest().unwrap();
        learner.replace_policy(Arc::new(next), now + Duration::from_secs(1));
        let memory = learner.export_memory();
        assert_eq!(memory.contexts[0].arms[0].observations, 1);
        assert_eq!(memory.contexts[0].arms[0].mean, 0.75);
        assert_eq!(memory.contexts[0].fine.up_gain_delta_milli, 0);
    }

    #[test]
    fn tick_clock_starts_at_zero_and_truncates_to_whole_seconds() {
        let mut clock = TickClock::default();
        let origin = Instant::now();
        assert_eq!(clock.tick(origin + Duration::from_secs(5)), 0);
        assert_eq!(clock.tick(origin + Duration::from_millis(6_999)), 1);
        assert_eq!(clock.tick(origin + Duration::from_secs(15)), 10);
        assert_eq!(clock.tick(origin), 0);
    }

    #[test]
    fn dwell_through_the_adapter_matches_the_legacy_ten_second_gate() {
        let t = telemetry();
        let mut baseline = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(t);
        baseline.sample_count = 8;
        let utility = UtilitySample {
            total: 1.0,
            components: [0.0; 8],
            goodput_bytes_per_second: 1,
        };
        let start = Instant::now();
        let mut learner = BanditLearnerV2::new(LearnerModeV2::Shadow, 7);
        learner.step(start, &t, &utility, baseline);
        learner.step(start + Duration::from_millis(9_999), &t, &utility, baseline);
        let before = learner.export_memory();
        assert!(
            before.contexts[0]
                .arms
                .iter()
                .all(|arm| arm.observations == 0)
        );
        learner.step(start + Duration::from_secs(10), &t, &utility, baseline);
        let after = learner.export_memory();
        assert_eq!(
            after.contexts[0]
                .arms
                .iter()
                .map(|arm| arm.observations)
                .sum::<u32>(),
            1
        );
    }

    #[test]
    fn memory_round_trips_through_the_core_types() {
        let memory = LearnerMemoryV2 {
            contexts: vec![ContextMemoryV2 {
                key: ContextKeyV2 {
                    rtt_class: 1,
                    rate_class: 2,
                    loss_class: 3,
                    reliable: true,
                    host_rtt: false,
                },
                arms: [ArmMemoryV2 {
                    observations: 4,
                    mean: 0.25,
                }; 7],
                active: Bbr3PresetV2::RelayReliable,
                max_bw_bytes_per_second: 9,
                min_rtt_micros: 8,
                fine: FineMemoryV2 {
                    up_gain_delta_milli: 25,
                    headroom_delta_milli: -10,
                    cwnd_gain_delta_milli: 50,
                    direction: -1,
                },
            }],
        };
        let core = LearnerMemoryV1::from(&memory);
        assert_eq!(LearnerMemoryV2::from(&core), memory);
        assert_eq!(
            serde_json::to_string(&core).unwrap(),
            serde_json::to_string(&memory).unwrap()
        );
    }
}
