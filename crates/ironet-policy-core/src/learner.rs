//! The contextual-bandit learner: per-context Thompson sampling over BBR
//! presets with a continuous fine-tuning walk, driven purely by
//! [`PolicyInputV1`].
//!
//! Time: every quantity that used to be a `Duration`/`Instant` is a count of
//! logical ticks. One tick is one telemetry interval, i.e. one second; dwell
//! requirements expressed in milliseconds/RTTs are satisfied once
//! `elapsed_ticks * 1_000_000 µs >= minimum_dwell_micros`.

use std::collections::BTreeMap;

use ironet_policy_abi::{Bbr3PresetV1, PolicyExtensionV1, PolicyInputV1};
use serde::{Deserialize, Serialize};

use crate::{
    BbrProposalSpecV1, ContextKeyV1, PolicySpecV1, preset_index, resolve_preset_proposal,
    rng::DeterministicRng,
};

/// TLV tag of the optional full-precision previous utility
/// (`HostUtilityV1` total as `f64::to_bits().to_le_bytes()`, 8 bytes). The
/// host adds it so the learner's `f64` reward path stays bit-identical to the
/// pre-ABI implementation; guests without it fall back to
/// `previous_utility.utility_milli / 1000`.
pub const EXTENSION_TAG_HOST_UTILITY_F64_V1: u16 = 1;

/// Build the [`EXTENSION_TAG_HOST_UTILITY_F64_V1`] entry for `total`.
pub fn host_utility_extension(total: f64) -> PolicyExtensionV1 {
    PolicyExtensionV1 {
        tag: EXTENSION_TAG_HOST_UTILITY_F64_V1,
        payload: total.to_bits().to_le_bytes().to_vec(),
    }
}

/// The reward the learner observes this tick: `None` when the host marked
/// the previous utility invalid (first tick of an epoch), otherwise the
/// full-precision extension value when present, else the fixed-point total.
pub fn host_utility_total(input: &PolicyInputV1) -> Option<f64> {
    if !input.previous_utility.valid {
        return None;
    }
    let precise = input
        .extensions
        .iter()
        .find(|extension| extension.tag == EXTENSION_TAG_HOST_UTILITY_F64_V1)
        .and_then(|extension| <[u8; 8]>::try_from(extension.payload.as_slice()).ok())
        .map(|bytes| f64::from_bits(u64::from_le_bytes(bytes)));
    Some(precise.unwrap_or(f64::from(input.previous_utility.utility_milli) / 1_000.0))
}

/// Learner operating mode. `Off` never evaluates arms, `Shadow` evaluates
/// but always applies the host baseline, `On` applies its own choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LearnerModeV1 {
    Off,
    Shadow,
    On,
}

/// Exported posterior of one arm.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ArmMemoryV1 {
    pub observations: u32,
    pub mean: f64,
}

/// Exported fine-tuning walk of one context.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FineMemoryV1 {
    pub up_gain_delta_milli: i16,
    pub headroom_delta_milli: i16,
    pub cwnd_gain_delta_milli: i16,
    pub direction: i8,
}

/// Exported memory of one context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextMemoryV1 {
    pub key: ContextKeyV1,
    pub arms: [ArmMemoryV1; 7],
    pub active: Bbr3PresetV1,
    pub max_bw_bytes_per_second: u64,
    pub min_rtt_micros: u64,
    #[serde(default)]
    pub fine: FineMemoryV1,
}

/// Portable learner memory (what the host persists as JSON); sorted by key.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LearnerMemoryV1 {
    pub contexts: Vec<ContextMemoryV1>,
}

/// Full-precision trace of one step (the bounded `PolicyDiagnosticsV1` is
/// derived from it).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LearnerTraceV1 {
    pub mode: LearnerModeV1,
    pub context: ContextKeyV1,
    pub baseline_preset: Bbr3PresetV1,
    pub proposed_preset: Bbr3PresetV1,
    pub applied_preset: Bbr3PresetV1,
    pub predicted_advantage: f64,
    pub exploring: bool,
    pub rollback: bool,
    pub rollbacks: u64,
    pub fine_up_gain_delta_milli: i16,
    pub fine_headroom_delta_milli: i16,
    pub fine_cwnd_gain_delta_milli: i16,
}

/// Result of one [`LearnerStateV1::step`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StepOutcomeV1 {
    /// The BBR proposal to publish (spec preset, fallback table, policer cap
    /// and fine deltas already applied).
    pub proposal: BbrProposalSpecV1,
    pub trace: LearnerTraceV1,
    /// The context was seen for the first time this tick.
    pub created_context: bool,
    /// The dwell interval closed and arms were (re)sampled this tick.
    pub evaluated: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Posterior {
    pub(crate) observations: u32,
    pub(crate) mean: f64,
}

impl Posterior {
    fn observe(&mut self, reward: f64) {
        self.observations = self.observations.saturating_add(1);
        self.mean += (reward - self.mean) / f64::from(self.observations);
    }

    fn sample(self, rng: &mut DeterministicRng) -> f64 {
        let uncertainty = 1.0 / f64::from(self.observations.saturating_add(1)).sqrt();
        self.mean + rng.standard_normal() * uncertainty
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ContextState {
    pub(crate) posteriors: [Posterior; 7],
    pub(crate) active: Bbr3PresetV1,
    pub(crate) active_since_tick: u64,
    pub(crate) reward_sum: f64,
    pub(crate) reward_samples: u32,
    pub(crate) max_bw_bytes_per_second: u64,
    pub(crate) min_rtt_micros: u64,
    pub(crate) fine: FineMemoryV1,
    pub(crate) last_fine_reward: Option<f64>,
}

impl ContextState {
    pub(crate) fn new(tick: u64, baseline: Bbr3PresetV1) -> Self {
        Self {
            posteriors: [Posterior::default(); 7],
            active: baseline,
            active_since_tick: tick,
            reward_sum: 0.0,
            reward_samples: 0,
            max_bw_bytes_per_second: 0,
            min_rtt_micros: u64::MAX,
            fine: FineMemoryV1 {
                direction: 1,
                ..FineMemoryV1::default()
            },
            last_fine_reward: None,
        }
    }

    fn record(&mut self, reward: f64) {
        if reward.is_finite() {
            self.reward_sum += reward;
            self.reward_samples = self.reward_samples.saturating_add(1);
        }
    }

    fn finish_interval(&mut self) -> Option<f64> {
        if self.reward_samples != 0 {
            let reward = self.reward_sum / f64::from(self.reward_samples);
            self.posteriors[preset_index(self.active)].observe(reward);
            self.reward_sum = 0.0;
            self.reward_samples = 0;
            return Some(reward);
        }
        self.reward_sum = 0.0;
        self.reward_samples = 0;
        None
    }

    pub(crate) fn refine(&mut self, reward: Option<f64>) {
        let Some(reward) = reward else {
            return;
        };
        if self
            .last_fine_reward
            .is_some_and(|previous| reward < previous)
        {
            self.fine.direction = -self.fine.direction;
        }
        let direction = i16::from(self.fine.direction.signum());
        self.fine.up_gain_delta_milli = self
            .fine
            .up_gain_delta_milli
            .saturating_add(direction * 25)
            .clamp(-100, 150);
        self.fine.headroom_delta_milli = self
            .fine
            .headroom_delta_milli
            .saturating_sub(direction * 10)
            .clamp(-50, 50);
        self.fine.cwnd_gain_delta_milli = self
            .fine
            .cwnd_gain_delta_milli
            .saturating_add(direction * 50)
            .clamp(-300, 300);
        self.last_fine_reward = Some(reward);
    }

    fn reset_fine(&mut self) {
        self.fine = FineMemoryV1 {
            direction: 1,
            ..FineMemoryV1::default()
        };
        self.last_fine_reward = None;
    }

    fn total_observations(&self) -> u64 {
        self.posteriors
            .iter()
            .map(|posterior| u64::from(posterior.observations))
            .sum()
    }
}

/// In-memory learner state: everything that travels in
/// `PolicyInputV1::state` / `PolicyOutputV1::next_state`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearnerStateV1 {
    pub(crate) contexts: BTreeMap<ContextKeyV1, ContextState>,
    pub(crate) rng: DeterministicRng,
    pub(crate) path_epoch: u64,
    pub(crate) rollbacks: u64,
}

impl LearnerStateV1 {
    /// Cold-start state; `seed` is `PolicyInputV1::deterministic_seed`
    /// (zero is lifted to one, as the legacy learner did).
    pub fn new(seed: u64) -> Self {
        Self {
            contexts: BTreeMap::new(),
            rng: DeterministicRng::seeded(seed),
            path_epoch: 0,
            rollbacks: 0,
        }
    }

    /// Cold-start state warmed from persisted memory at `tick`.
    pub fn from_memory(memory: &LearnerMemoryV1, seed: u64, tick: u64) -> Self {
        let mut state = Self::new(seed);
        state.warm_start(memory, tick);
        state
    }

    pub fn path_epoch(&self) -> u64 {
        self.path_epoch
    }

    pub fn rollbacks(&self) -> u64 {
        self.rollbacks
    }

    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Export the portable memory, sorted by context key.
    pub fn export_memory(&self) -> LearnerMemoryV1 {
        LearnerMemoryV1 {
            contexts: self
                .contexts
                .iter()
                .map(|(key, state)| ContextMemoryV1 {
                    key: *key,
                    arms: state.posteriors.map(|posterior| ArmMemoryV1 {
                        observations: posterior.observations,
                        mean: posterior.mean,
                    }),
                    active: state.active,
                    max_bw_bytes_per_second: state.max_bw_bytes_per_second,
                    min_rtt_micros: state.min_rtt_micros,
                    fine: state.fine,
                })
                .collect(),
        }
    }

    /// Replace all contexts with `memory` (contexts with a non-finite arm
    /// mean are dropped); every restored context starts a fresh dwell at
    /// `tick`.
    pub fn warm_start(&mut self, memory: &LearnerMemoryV1, tick: u64) {
        self.contexts.clear();
        for context in &memory.contexts {
            if context.arms.iter().any(|arm| !arm.mean.is_finite()) {
                continue;
            }
            self.contexts.insert(
                context.key,
                ContextState {
                    posteriors: context.arms.map(|arm| Posterior {
                        observations: arm.observations,
                        mean: arm.mean,
                    }),
                    active: context.active,
                    active_since_tick: tick,
                    reward_sum: 0.0,
                    reward_samples: 0,
                    max_bw_bytes_per_second: context.max_bw_bytes_per_second,
                    min_rtt_micros: context.min_rtt_micros,
                    fine: FineMemoryV1 {
                        direction: if context.fine.direction == 0 {
                            1
                        } else {
                            context.fine.direction.signum()
                        },
                        ..context.fine
                    },
                    last_fine_reward: None,
                },
            );
        }
    }

    /// The policy spec changed at `tick`: abort in-flight intervals and the
    /// fine walk; additionally forget posteriors and fall back to the
    /// conservative arm when the algorithm family changed.
    pub fn reset_for_policy_change(&mut self, same_algorithm: bool, tick: u64) {
        for state in self.contexts.values_mut() {
            state.active_since_tick = tick;
            state.reward_sum = 0.0;
            state.reward_samples = 0;
            state.reset_fine();
            if !same_algorithm {
                state.posteriors = [Posterior::default(); 7];
                state.active = Bbr3PresetV1::SharedConservative;
            }
        }
    }

    /// Drop the `count` contexts with the fewest observations (ties: smallest
    /// key first). Returns how many were removed.
    pub(crate) fn evict_contexts(&mut self, count: usize) -> usize {
        let mut victims: Vec<(u64, ContextKeyV1)> = self
            .contexts
            .iter()
            .map(|(key, state)| (state.total_observations(), *key))
            .collect();
        victims.sort_unstable();
        let mut removed = 0;
        for (_, key) in victims.into_iter().take(count) {
            self.contexts.remove(&key);
            removed += 1;
        }
        removed
    }

    /// One learner tick. Mirrors the legacy `BanditLearnerV2::step`
    /// operation for operation (same `f64` evaluation order) with
    /// `input.logical_tick` as the clock and `input.previous` as the host
    /// baseline.
    pub fn step(
        &mut self,
        spec: &PolicySpecV1,
        mode: LearnerModeV1,
        input: &PolicyInputV1,
    ) -> StepOutcomeV1 {
        let telemetry = &input.telemetry;
        let now = input.logical_tick;
        let baseline_preset = input.previous.bbr.preset;
        let context = ContextKeyV1::classify_input(input, &spec.contexts);
        let epoch_changed = self.path_epoch != input.path_epoch;
        if epoch_changed {
            if self.path_epoch != 0 {
                // Abort an in-flight exploration, but retain per-context
                // posteriors as priors for a path that later returns.
                for state in self.contexts.values_mut() {
                    state.active_since_tick = now;
                    state.reward_sum = 0.0;
                    state.reward_samples = 0;
                }
            }
            self.path_epoch = input.path_epoch;
        }
        let created_context = !self.contexts.contains_key(&context);
        if created_context {
            let mut state = ContextState::new(now, baseline_preset);
            if let Some(priors) = spec.priors.get(&context.policy_key()) {
                for preset in &spec.presets {
                    if let Some(prior) = priors.get(&preset.name) {
                        state.posteriors[preset_index(preset.proposal.preset)] = Posterior {
                            observations: prior.observations,
                            mean: prior.mean,
                        };
                    }
                }
            }
            self.contexts.insert(context, state);
        }
        let state = self.contexts.get_mut(&context).expect("inserted above");
        if epoch_changed {
            state.active = baseline_preset;
            state.active_since_tick = now;
            state.reset_fine();
        }
        state.max_bw_bytes_per_second = state
            .max_bw_bytes_per_second
            .max(telemetry.local_tx_controller_bw_bytes_per_second);
        state.min_rtt_micros = state.min_rtt_micros.min(telemetry.path_min_rtt_micros);

        // Shadow observations belong to the baseline actually on the wire,
        // not to an unapplied candidate.
        if mode != LearnerModeV1::On {
            state.active = baseline_preset;
        }
        let utility = host_utility_total(input);
        if let Some(total) = utility {
            state.record(total);
        }

        let minimum_dwell_micros = spec
            .exploration
            .minimum_dwell_millis
            .saturating_mul(1_000)
            .max(
                telemetry
                    .path_rtt_micros
                    .saturating_mul(u64::from(spec.exploration.minimum_rtt_rounds)),
            );
        let emergency = telemetry.local_tx_loss_ppm >= 30_000
            || telemetry.remote_residual_loss_ppm >= 10_000
            || telemetry.remote_expired_stripes_delta > 0;
        let elapsed_micros = u128::from(now.saturating_sub(state.active_since_tick)) * 1_000_000;
        let stable = input.previous.sample_count >= spec.exploration.minimum_samples
            && telemetry.host_cpu_utilization_per_mille < spec.exploration.maximum_cpu_per_mille
            && !emergency
            && elapsed_micros >= u128::from(minimum_dwell_micros);
        let mut proposed = if mode == LearnerModeV1::On {
            state.active
        } else {
            baseline_preset
        };
        let mut exploring = false;
        let mut evaluated = false;
        if mode != LearnerModeV1::Off && stable {
            evaluated = true;
            let interval_reward = state.finish_interval();
            if mode == LearnerModeV1::On
                && !matches!(
                    state.active,
                    Bbr3PresetV1::Policer | Bbr3PresetV1::RelayReliable
                )
            {
                state.refine(interval_reward);
            }
            let candidates = candidate_presets(context);
            proposed = candidates[0];
            let mut best_sample = f64::NEG_INFINITY;
            for candidate in candidates {
                let sample = state.posteriors[preset_index(*candidate)].sample(&mut self.rng);
                if sample > best_sample {
                    best_sample = sample;
                    proposed = *candidate;
                }
            }
            exploring = proposed != baseline_preset;
            state.active_since_tick = now;
            let next_active = if mode == LearnerModeV1::On {
                proposed
            } else {
                baseline_preset
            };
            if next_active != state.active {
                state.reset_fine();
            }
            state.active = next_active;
        }

        let baseline_mean = state.posteriors[preset_index(baseline_preset)].mean;
        let proposed_mean = state.posteriors[preset_index(proposed)].mean;
        let predicted_advantage = proposed_mean - baseline_mean;
        let rollback_fraction = f64::from(spec.exploration.rollback_regression_per_mille) / 1_000.0;
        let rollback = mode == LearnerModeV1::On
            && state.active != baseline_preset
            && baseline_mean.is_finite()
            && baseline_mean != 0.0
            && utility.is_some_and(|total| {
                total < baseline_mean - baseline_mean.abs() * rollback_fraction
            });
        if rollback {
            self.rollbacks = self.rollbacks.saturating_add(1);
            state.active = baseline_preset;
            state.active_since_tick = now;
            state.reset_fine();
            proposed = baseline_preset;
        }

        let applied = if mode == LearnerModeV1::On {
            proposed
        } else {
            baseline_preset
        };
        let mut proposal = resolve_preset_proposal(
            spec.preset(applied),
            applied,
            telemetry.local_tx_controller_bw_bytes_per_second,
        );
        if mode == LearnerModeV1::On
            && !matches!(applied, Bbr3PresetV1::Policer | Bbr3PresetV1::RelayReliable)
        {
            proposal.up_gain_milli = add_signed_u32(
                proposal.up_gain_milli,
                state.fine.up_gain_delta_milli,
                1_050,
                1_500,
            );
            proposal.headroom_milli = add_signed_u32(
                proposal.headroom_milli,
                state.fine.headroom_delta_milli,
                50,
                400,
            );
            proposal.cwnd_gain_milli = add_signed_u32(
                proposal.cwnd_gain_milli,
                state.fine.cwnd_gain_delta_milli,
                1_200,
                3_500,
            );
        }
        StepOutcomeV1 {
            proposal,
            trace: LearnerTraceV1 {
                mode,
                context,
                baseline_preset,
                proposed_preset: proposed,
                applied_preset: applied,
                predicted_advantage,
                exploring,
                rollback,
                rollbacks: self.rollbacks,
                fine_up_gain_delta_milli: state.fine.up_gain_delta_milli,
                fine_headroom_delta_milli: state.fine.headroom_delta_milli,
                fine_cwnd_gain_delta_milli: state.fine.cwnd_gain_delta_milli,
            },
            created_context,
            evaluated,
        }
    }
}

fn add_signed_u32(value: u32, delta: i16, minimum: u32, maximum: u32) -> u32 {
    value
        .saturating_add_signed(i32::from(delta))
        .clamp(minimum, maximum)
}

/// Arms the learner may sample in `context`, most conservative first.
pub fn candidate_presets(context: ContextKeyV1) -> &'static [Bbr3PresetV1] {
    use Bbr3PresetV1::*;
    if context.reliable {
        &[RelayReliable]
    } else if context.loss_class == 3 {
        &[Policer, SharedConservative, LossyRadio]
    } else if context.loss_class != 0 {
        &[LossyRadio, SharedConservative, LongFat]
    } else if context.host_rtt {
        &[LowRttHost, SharedConservative, PrivateAggressive]
    } else if context.rtt_class == 3 {
        &[LongFat, SharedConservative, PrivateAggressive]
    } else {
        &[SharedConservative, PrivateAggressive, LossyRadio]
    }
}

/// Whether `preset` is one of the arms of `context`.
pub fn preset_is_eligible(context: ContextKeyV1, preset: Bbr3PresetV1) -> bool {
    candidate_presets(context).contains(&preset)
}

#[cfg(test)]
mod tests {
    use ironet_policy_abi::{
        BbrEffectiveV1, EffectiveActionV1, HostUtilityV1, PathReliabilityV1, PolicyTelemetryV1,
    };

    use super::*;
    use crate::PosteriorSpecV1;

    pub(crate) fn telemetry() -> PolicyTelemetryV1 {
        PolicyTelemetryV1 {
            path_rtt_micros: 42_000,
            path_min_rtt_micros: 40_000,
            path_queue_delay_micros: 2_000,
            local_tx_wire_rate_bytes_per_second: 10_000_000,
            local_tx_controller_bw_bytes_per_second: 10_500_000,
            local_tx_loss_ppm: 18_000,
            local_tx_burst_loss_cells: 1,
            remote_residual_loss_ppm: 1_500,
            host_cpu_utilization_per_mille: 260,
            ..PolicyTelemetryV1::default()
        }
    }

    pub(crate) fn input(tick: u64, utility: f64, sample_count: u32) -> PolicyInputV1 {
        let previous = EffectiveActionV1 {
            path_epoch: 1,
            sample_count,
            bbr: BbrEffectiveV1 {
                preset: Bbr3PresetV1::LossyRadio,
                ..BbrEffectiveV1::default()
            },
            ..EffectiveActionV1::default()
        };
        PolicyInputV1 {
            logical_tick: tick,
            deterministic_seed: 7,
            path_epoch: 1,
            reliability: PathReliabilityV1::Datagram,
            telemetry: telemetry(),
            previous,
            previous_utility: HostUtilityV1 {
                valid: true,
                utility_milli: (utility * 1_000.0) as i32,
                ..HostUtilityV1::default()
            },
            extensions: vec![host_utility_extension(utility)],
            ..PolicyInputV1::default()
        }
    }

    #[test]
    fn utility_prefers_the_full_precision_extension() {
        let mut sample = input(0, 3.7145432210031473, 8);
        assert_eq!(host_utility_total(&sample), Some(3.7145432210031473));
        sample.extensions.clear();
        assert_eq!(host_utility_total(&sample), Some(3.714));
        sample.previous_utility.valid = false;
        assert_eq!(host_utility_total(&sample), None);
    }

    #[test]
    fn severe_loss_takes_precedence_over_low_rtt_for_candidate_selection() {
        let candidates = candidate_presets(ContextKeyV1 {
            rtt_class: 0,
            rate_class: 2,
            loss_class: 3,
            reliable: false,
            host_rtt: true,
        });
        assert_eq!(candidates[0], Bbr3PresetV1::Policer);
        assert!(candidates.contains(&Bbr3PresetV1::LossyRadio));
        assert!(!candidates.contains(&Bbr3PresetV1::LowRttHost));
        assert!(preset_is_eligible(
            ContextKeyV1 {
                rtt_class: 0,
                rate_class: 1,
                loss_class: 0,
                reliable: false,
                host_rtt: true,
            },
            Bbr3PresetV1::LowRttHost
        ));
    }

    #[test]
    fn shadow_never_applies_its_candidate_and_records_baseline_reward() {
        let spec = PolicySpecV1::builtin();
        let mut state = LearnerStateV1::new(7);
        for tick in 0..12 {
            let outcome = state.step(&spec, LearnerModeV1::Shadow, &input(tick, 1.0, 8));
            assert_eq!(outcome.trace.applied_preset, Bbr3PresetV1::LossyRadio);
            assert_eq!(outcome.proposal.preset, Bbr3PresetV1::LossyRadio);
            // The dwell closes once at tick 10 and then restarts.
            assert_eq!(outcome.evaluated, tick == 10);
        }
        let memory = state.export_memory();
        assert_eq!(memory.contexts.len(), 1);
        let lossy = memory.contexts[0].arms[preset_index(Bbr3PresetV1::LossyRadio)];
        assert_eq!(lossy.observations, 1);
        assert_eq!(lossy.mean, 1.0);
    }

    #[test]
    fn dwell_counts_whole_ticks_as_seconds() {
        let spec = PolicySpecV1::builtin();
        let mut state = LearnerStateV1::new(7);
        // minimum_dwell = max(10 s, 8 * 42 ms) = 10 s = 10 ticks.
        assert!(
            !state
                .step(&spec, LearnerModeV1::Shadow, &input(0, 1.0, 8))
                .evaluated
        );
        assert!(
            !state
                .step(&spec, LearnerModeV1::Shadow, &input(9, 1.0, 8))
                .evaluated
        );
        assert!(
            state
                .step(&spec, LearnerModeV1::Shadow, &input(10, 1.0, 8))
                .evaluated
        );
        // An RTT-dominated dwell rounds up to whole ticks.
        let mut state = LearnerStateV1::new(7);
        let mut long = input(0, 1.0, 8);
        long.telemetry.path_rtt_micros = 1_500_000; // 8 * 1.5 s = 12 s
        state.step(&spec, LearnerModeV1::Shadow, &long);
        long.logical_tick = 11;
        assert!(!state.step(&spec, LearnerModeV1::Shadow, &long).evaluated);
        long.logical_tick = 12;
        assert!(state.step(&spec, LearnerModeV1::Shadow, &long).evaluated);
    }

    #[test]
    fn offline_priors_drive_the_counterfactual_proposal() {
        let mut spec = PolicySpecV1::builtin();
        let key = ContextKeyV1::classify_input(&input(0, 1.0, 8), &spec.contexts);
        spec.priors.insert(
            key.policy_key(),
            BTreeMap::from([(
                "long-fat".to_owned(),
                PosteriorSpecV1 {
                    observations: 100,
                    mean: 100.0,
                },
            )]),
        );
        let mut state = LearnerStateV1::new(7);
        state.step(&spec, LearnerModeV1::Shadow, &input(0, 1.0, 8));
        let outcome = state.step(&spec, LearnerModeV1::Shadow, &input(20, 1.0, 8));
        assert_eq!(outcome.trace.proposed_preset, Bbr3PresetV1::LongFat);
        assert_eq!(outcome.trace.applied_preset, Bbr3PresetV1::LossyRadio);
        assert!(outcome.trace.exploring);
        assert!(outcome.trace.predicted_advantage > 90.0);
    }

    #[test]
    fn path_epoch_change_resets_the_interval_but_keeps_contexts() {
        let spec = PolicySpecV1::builtin();
        let mut state = LearnerStateV1::new(3);
        state.step(&spec, LearnerModeV1::On, &input(0, 1.0, 8));
        assert_eq!(state.context_count(), 1);
        let mut next = input(1, 1.0, 0);
        next.path_epoch = 2;
        next.previous.path_epoch = 2;
        state.step(&spec, LearnerModeV1::On, &next);
        assert_eq!(state.path_epoch(), 2);
        assert_eq!(state.context_count(), 1);
    }

    #[test]
    fn on_mode_applies_fine_deltas_and_rolls_back_regressions() {
        let spec = PolicySpecV1::builtin();
        let mut state = LearnerStateV1::new(11);
        // Build a strong baseline posterior for the lossy-radio arm.
        for tick in 0..60 {
            state.step(&spec, LearnerModeV1::On, &input(tick, 2.0, 8));
        }
        let memory = state.export_memory();
        let arms = memory.contexts[0].arms;
        assert!(arms.iter().any(|arm| arm.observations > 0));
        // A sharp regression while a non-baseline arm is active rolls back.
        let mut rolled_back = false;
        for tick in 60..400 {
            let outcome = state.step(&spec, LearnerModeV1::On, &input(tick, -50.0, 8));
            if outcome.trace.rollback {
                rolled_back = true;
                assert_eq!(outcome.trace.applied_preset, Bbr3PresetV1::LossyRadio);
                assert!(outcome.trace.rollbacks >= 1);
                break;
            }
        }
        assert!(rolled_back || state.rollbacks() == 0);
    }

    #[test]
    fn continuous_refinement_reverses_on_regression_and_stays_bounded() {
        let mut state = ContextState::new(0, Bbr3PresetV1::SharedConservative);
        state.refine(Some(1.0));
        assert_eq!(state.fine.up_gain_delta_milli, 25);
        assert_eq!(state.fine.headroom_delta_milli, -10);
        state.refine(Some(0.5));
        assert_eq!(state.fine.direction, -1);
        assert_eq!(state.fine.up_gain_delta_milli, 0);
        for _ in 0..100 {
            state.refine(Some(0.5));
        }
        assert_eq!(state.fine.up_gain_delta_milli, -100);
        assert_eq!(state.fine.headroom_delta_milli, 50);
        assert_eq!(state.fine.cwnd_gain_delta_milli, -300);
    }

    #[test]
    fn policy_change_resets_probe_and_optionally_posteriors() {
        let spec = PolicySpecV1::builtin();
        let mut state = LearnerStateV1::new(9);
        state.step(&spec, LearnerModeV1::On, &input(0, 1.0, 8));
        let context = state.contexts.values_mut().next().unwrap();
        context.posteriors[0].observe(0.75);
        context.fine.up_gain_delta_milli = 100;
        state.reset_for_policy_change(true, 1);
        let context = state.contexts.values().next().unwrap();
        assert_eq!(context.posteriors[0].observations, 1);
        assert_eq!(context.posteriors[0].mean, 0.75);
        assert_eq!(context.fine.up_gain_delta_milli, 0);
        state.reset_for_policy_change(false, 2);
        let context = state.contexts.values().next().unwrap();
        assert_eq!(context.posteriors[0].observations, 0);
        assert_eq!(context.active, Bbr3PresetV1::SharedConservative);
    }

    #[test]
    fn warm_start_normalises_direction_and_drops_non_finite_arms() {
        let mut memory = LearnerStateV1::new(1).export_memory();
        let key = ContextKeyV1 {
            rtt_class: 1,
            rate_class: 1,
            loss_class: 0,
            reliable: false,
            host_rtt: false,
        };
        let arms = [ArmMemoryV1 {
            observations: 2,
            mean: 0.5,
        }; 7];
        memory.contexts.push(ContextMemoryV1 {
            key,
            arms,
            active: Bbr3PresetV1::LongFat,
            max_bw_bytes_per_second: 5,
            min_rtt_micros: 6,
            fine: FineMemoryV1 {
                direction: 0,
                ..FineMemoryV1::default()
            },
        });
        let mut broken = memory.contexts[0].clone();
        broken.key.rtt_class = 2;
        broken.arms[3].mean = f64::NAN;
        memory.contexts.push(broken);
        let state = LearnerStateV1::from_memory(&memory, 1, 4);
        assert_eq!(state.context_count(), 1);
        let exported = state.export_memory();
        assert_eq!(exported.contexts[0].fine.direction, 1);
        assert_eq!(exported.contexts[0].active, Bbr3PresetV1::LongFat);
        assert_eq!(exported.contexts[0].arms, arms);
    }
}
