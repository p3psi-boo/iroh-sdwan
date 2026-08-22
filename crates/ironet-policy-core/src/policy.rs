//! [`CorePolicy`]: the learner packaged as an ABI `PolicyBackend`.

use ironet_policy_abi::{
    BbrCandidateV1, BbrEffectiveV1, CandidateActionV1, CoverCandidateV1, FecCandidateV1,
    POLICY_STATE_MAX_BYTES, PolicyBackend, PolicyBackendKindV1, PolicyDecisionKindV1,
    PolicyDiagnosticsV1, PolicyFaultV1, PolicyIdentityV1, PolicyInputV1, PolicyLabelV1,
    PolicyOutputV1, SchedulerCandidateV1,
};

use crate::{
    ActionSpecV1, BbrProposalSpecV1, LearnerModeV1, LearnerStateV1, LearnerTraceV1, PolicySpecV1,
    STATE_SCHEMA_V1, StateCodecError, StepOutcomeV1, preset_name, resolve_preset_proposal,
};

/// The bandit learner as a stateless-per-call backend: every `decide`
/// decodes `input.state`, runs one [`LearnerStateV1::step`] and re-encodes
/// the state into `next_state`. Identity is
/// `PolicyBackendKindV1::Native` with `policy_id`/`policy_version` taken
/// from the spec.
#[derive(Debug, Clone)]
pub struct CorePolicy {
    spec: PolicySpecV1,
    mode: LearnerModeV1,
    identity: PolicyIdentityV1,
}

impl CorePolicy {
    /// Wrap `spec` in `mode`. The spec is not validated here; call
    /// [`PolicySpecV1::validate`] first when it comes from an untrusted file.
    pub fn new(spec: PolicySpecV1, mode: LearnerModeV1) -> Self {
        let mut identity = PolicyIdentityV1::native(spec.id.clone(), spec.version.clone());
        identity.backend = PolicyBackendKindV1::Native;
        identity.state_schema = STATE_SCHEMA_V1;
        Self {
            spec,
            mode,
            identity,
        }
    }

    /// The embedded `bandit-vivace@1` policy in `mode`.
    pub fn builtin(mode: LearnerModeV1) -> Self {
        Self::new(PolicySpecV1::builtin(), mode)
    }

    pub fn spec(&self) -> &PolicySpecV1 {
        &self.spec
    }

    pub fn mode(&self) -> LearnerModeV1 {
        self.mode
    }

    /// `PolicyBackend::decide` plus the full-precision learner trace. The
    /// output's diagnostics are the bounded projection of that trace.
    pub fn decide_traced(
        &self,
        input: &PolicyInputV1,
    ) -> Result<(PolicyOutputV1, LearnerTraceV1), PolicyFaultV1> {
        let mut state =
            LearnerStateV1::decode_or_cold_start(&input.state, input.deterministic_seed)
                .map_err(fault_from_codec)?;
        let outcome = state.step(&self.spec, self.mode, input);
        let cap = if input.limits.state_cap_bytes == 0 {
            POLICY_STATE_MAX_BYTES
        } else {
            input.limits.state_cap_bytes.min(POLICY_STATE_MAX_BYTES)
        };
        let next_state = state
            .encode_bounded(cap as usize)
            .map_err(fault_from_codec)?;
        // Host-parity materialisation (the pre-ABI runtime's
        // `materialize_policy_action`): a shadow call publishes the
        // counterfactual of the *proposed* arm — its raw spec proposal plus
        // its application action — while an On call merges the *applied*
        // arm's application action (train target, Bulk quantum, FEC geometry,
        // cover overhead) into the candidate.
        let controller_bw = input.telemetry.local_tx_controller_bw_bytes_per_second;
        let candidate = if input.capabilities.shadow {
            let mut candidate = candidate_from_proposal(resolve_preset_proposal(
                self.spec.preset(outcome.trace.proposed_preset),
                outcome.trace.proposed_preset,
                controller_bw,
            ));
            merge_action(
                &mut candidate,
                self.spec.action(outcome.trace.proposed_preset),
            );
            candidate
        } else {
            let mut candidate = candidate_from_proposal(outcome.proposal);
            if outcome.trace.mode == LearnerModeV1::On {
                merge_action(
                    &mut candidate,
                    self.spec.action(outcome.trace.applied_preset),
                );
            }
            candidate
        };
        Ok((
            PolicyOutputV1 {
                candidate,
                next_state,
                diagnostics: diagnostics_from_outcome(&outcome),
            },
            outcome.trace,
        ))
    }
}

impl PolicyBackend for CorePolicy {
    fn identity(&self) -> &PolicyIdentityV1 {
        &self.identity
    }

    fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        self.decide_traced(input).map(|(output, _)| output)
    }
}

fn fault_from_codec(error: StateCodecError) -> PolicyFaultV1 {
    match error {
        StateCodecError::TooLarge { .. } => PolicyFaultV1::StateTooLarge,
        // V1 has no dedicated "state rejected" fault; a corrupt state is
        // reported as an internal fault so the host restarts from an empty
        // state (plan §8.2) instead of silently resetting.
        StateCodecError::Truncated
        | StateCodecError::BadMagic
        | StateCodecError::UnsupportedSchema(_)
        | StateCodecError::LengthMismatch { .. }
        | StateCodecError::Malformed => PolicyFaultV1::Internal,
    }
}

/// Expand the learner's five-knob proposal into a fully explicit BBR
/// candidate (every tunable set) so `apply_over` yields exactly
/// `BbrEffectiveV1::expand_preset(..)` regardless of the previous action.
pub fn candidate_from_proposal(proposal: BbrProposalSpecV1) -> CandidateActionV1 {
    let bbr = BbrEffectiveV1::expand_preset(
        proposal.preset,
        proposal.up_gain_milli,
        proposal.headroom_milli,
        proposal.cwnd_gain_milli,
        proposal.pacing_cap_bytes_per_second,
        proposal.loss_is_congestion,
    );
    CandidateActionV1 {
        bbr: Some(BbrCandidateV1 {
            preset: Some(bbr.preset),
            probe_bw_up_pacing_gain_milli: Some(bbr.probe_bw_up_pacing_gain_milli),
            probe_bw_down_pacing_gain_milli: Some(bbr.probe_bw_down_pacing_gain_milli),
            cruise_pacing_gain_milli: Some(bbr.cruise_pacing_gain_milli),
            default_cwnd_gain_milli: Some(bbr.default_cwnd_gain_milli),
            probe_bw_up_cwnd_gain_milli: Some(bbr.probe_bw_up_cwnd_gain_milli),
            headroom_milli: Some(bbr.headroom_milli),
            beta_milli: Some(bbr.beta_milli),
            loss_threshold_milli: Some(bbr.loss_threshold_milli),
            loss_is_congestion: Some(bbr.loss_is_congestion),
            queue_guard_inflation_milli: Some(bbr.queue_guard_inflation_milli),
            queue_guard_slack_micros: Some(bbr.queue_guard_slack_micros),
            probe_rtt_interval_millis: Some(bbr.probe_rtt_interval_millis),
            probe_rtt_duration_millis: Some(bbr.probe_rtt_duration_millis),
            probe_rtt_cwnd_gain_milli: Some(bbr.probe_rtt_cwnd_gain_milli),
            min_probe_wait_millis: Some(bbr.min_probe_wait_millis),
            max_added_probe_wait_millis: Some(bbr.max_added_probe_wait_millis),
            pacing_cap_bytes_per_second: Some(bbr.pacing_cap_bytes_per_second),
            cwnd_floor_bytes: Some(bbr.cwnd_floor_bytes),
            cwnd_cap_bytes: Some(bbr.cwnd_cap_bytes),
            startup_bw_hint_bytes_per_second: Some(bbr.startup_bw_hint_bytes_per_second),
        }),
        ..CandidateActionV1::default()
    }
}

/// Project the learner proposal back out of an effective action (the five
/// knobs the learner controls).
pub fn proposal_from_effective(bbr: &BbrEffectiveV1) -> BbrProposalSpecV1 {
    BbrProposalSpecV1 {
        preset: bbr.preset,
        up_gain_milli: bbr.probe_bw_up_pacing_gain_milli,
        headroom_milli: bbr.headroom_milli,
        cwnd_gain_milli: bbr.default_cwnd_gain_milli,
        pacing_cap_bytes_per_second: bbr.pacing_cap_bytes_per_second,
        loss_is_congestion: bbr.loss_is_congestion,
    }
}

/// Merge a preset's application action into the candidate the way the host
/// expresses learned-action overlays (BBR excluded: the arm's proposal is
/// already in the candidate). FEC `Some(0)`/`Some(0)` explicitly disables
/// parity. Fields the action does not set are cleared to `None`, matching
/// the host overlay assignment exactly.
fn merge_action(candidate: &mut CandidateActionV1, action: Option<ActionSpecV1>) {
    let Some(action) = action else {
        return;
    };
    candidate.scheduler = (action.train_target_bytes.is_some()
        || action.bulk_quantum_cells.is_some())
    .then(|| SchedulerCandidateV1 {
        train_target_bytes: action.train_target_bytes,
        bulk_quantum_cells: action.bulk_quantum_cells,
        ..SchedulerCandidateV1::default()
    });
    candidate.fec = action
        .fec_data_cells
        .zip(action.fec_parity_cells)
        .map(|(data, parity)| {
            if data == 0 && parity == 0 {
                FecCandidateV1 {
                    enabled: Some(false),
                    ..FecCandidateV1::default()
                }
            } else {
                FecCandidateV1 {
                    enabled: Some(true),
                    data_cells: Some(data),
                    parity_cells: Some(parity),
                    preset_family: None,
                }
            }
        });
    candidate.cover = action
        .cover_overhead_per_mille
        .map(|overhead| CoverCandidateV1 {
            profile: None,
            overhead_per_mille: Some(overhead),
            padding_bytes_per_second: None,
        });
}

fn diagnostics_from_outcome(outcome: &StepOutcomeV1) -> PolicyDiagnosticsV1 {
    let trace = &outcome.trace;
    let decision_kind = if trace.rollback {
        PolicyDecisionKindV1::Rollback
    } else if trace.exploring {
        PolicyDecisionKindV1::Explore
    } else if trace.mode == LearnerModeV1::Off {
        PolicyDecisionKindV1::Hold
    } else if outcome.created_context {
        PolicyDecisionKindV1::ColdStart
    } else if outcome.evaluated {
        PolicyDecisionKindV1::Exploit
    } else {
        PolicyDecisionKindV1::Hold
    };
    PolicyDiagnosticsV1 {
        decision_kind,
        context_label: PolicyLabelV1::truncated(&trace.context.policy_key()),
        applied_arm_label: PolicyLabelV1::truncated(preset_name(trace.applied_preset)),
        baseline_arm_label: PolicyLabelV1::truncated(preset_name(trace.baseline_preset)),
        predicted_advantage_milli: milli_i32(trace.predicted_advantage),
        // Confidence is not modelled by the bandit; reported as unknown.
        confidence_per_mille: 0,
        exploring: trace.exploring,
        rollback: trace.rollback,
        rollbacks: u32::try_from(trace.rollbacks).unwrap_or(u32::MAX),
        // The core computes no utility of its own; the host value is the
        // only reward it uses.
        guest_utility_milli: 0,
        state_schema: STATE_SCHEMA_V1,
    }
}

fn milli_i32(value: f64) -> i32 {
    if value.is_nan() {
        return 0;
    }
    // `as` saturates for finite and infinite floats.
    (value * 1_000.0).round() as i32
}

#[cfg(test)]
mod tests {
    use ironet_policy_abi::{
        Bbr3PresetV1, EffectiveActionV1, HostUtilityV1, PathReliabilityV1, PolicyTelemetryV1,
    };

    use super::*;
    use crate::host_utility_extension;

    fn input(tick: u64, utility: f64, state: Vec<u8>) -> PolicyInputV1 {
        let previous = EffectiveActionV1 {
            path_epoch: 1,
            sample_count: 8,
            bbr: BbrEffectiveV1 {
                preset: Bbr3PresetV1::LossyRadio,
                ..BbrEffectiveV1::default()
            },
            ..EffectiveActionV1::default()
        };
        PolicyInputV1 {
            logical_tick: tick,
            deterministic_seed: 1,
            path_epoch: 1,
            reliability: PathReliabilityV1::Datagram,
            telemetry: PolicyTelemetryV1 {
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
            },
            previous,
            previous_utility: HostUtilityV1 {
                valid: true,
                utility_milli: (utility * 1_000.0) as i32,
                ..HostUtilityV1::default()
            },
            extensions: vec![host_utility_extension(utility)],
            state,
            ..PolicyInputV1::default()
        }
    }

    fn run(policy: &mut CorePolicy, ticks: u64) -> (Vec<PolicyOutputV1>, Vec<LearnerTraceV1>) {
        let mut state = Vec::new();
        let mut outputs = Vec::new();
        let mut traces = Vec::new();
        for tick in 0..ticks {
            let (output, trace) = policy
                .decide_traced(&input(tick, 3.5 + tick as f64 * 0.01, state.clone()))
                .unwrap();
            state.clone_from(&output.next_state);
            outputs.push(output);
            traces.push(trace);
        }
        (outputs, traces)
    }

    #[test]
    fn identity_is_native_with_spec_id_and_state_schema() {
        let policy = CorePolicy::builtin(LearnerModeV1::Shadow);
        let identity = policy.identity();
        assert_eq!(identity.backend, PolicyBackendKindV1::Native);
        assert_eq!(identity.policy_id, "bandit-vivace@1");
        assert_eq!(identity.policy_version, "2026-08-20T00:00:00Z");
        assert_eq!(identity.state_schema, STATE_SCHEMA_V1);
        assert!(identity.digest.is_none());
    }

    #[test]
    fn same_input_and_seed_produce_identical_output_and_state() {
        let mut first = CorePolicy::builtin(LearnerModeV1::On);
        let mut second = CorePolicy::builtin(LearnerModeV1::On);
        let (left, left_traces) = run(&mut first, 40);
        let (right, right_traces) = run(&mut second, 40);
        assert_eq!(left, right);
        assert_eq!(left_traces, right_traces);
        assert!(left.iter().all(|output| !output.next_state.is_empty()));
        assert!(
            left.iter()
                .all(|output| output.diagnostics.state_schema == 1)
        );
        // A different seed diverges once arms are sampled.
        let other = CorePolicy::builtin(LearnerModeV1::On);
        let mut state = Vec::new();
        let mut different = false;
        for tick in 0..40 {
            let mut sample = input(tick, 3.5 + tick as f64 * 0.01, state.clone());
            sample.deterministic_seed = 2;
            let (output, trace) = other.decide_traced(&sample).unwrap();
            state.clone_from(&output.next_state);
            different |= trace != left_traces[tick as usize];
        }
        assert!(different || left_traces.iter().all(|trace| !trace.exploring));
    }

    #[test]
    fn candidate_is_a_fully_explicit_bbr_overlay() {
        let mut policy = CorePolicy::builtin(LearnerModeV1::Shadow);
        let sample = input(0, 1.0, Vec::new());
        let output = policy.decide(&sample).unwrap();
        let bbr = output.candidate.bbr.as_ref().unwrap();
        assert_eq!(bbr.preset, Some(Bbr3PresetV1::LossyRadio));
        assert_eq!(bbr.probe_bw_up_pacing_gain_milli, Some(1_250));
        assert_eq!(bbr.cruise_pacing_gain_milli, Some(1_000));
        assert!(output.candidate.scheduler.is_none());
        assert!(output.candidate.fec.is_none());
        let effective = output.candidate.apply_over(&sample.previous);
        assert_eq!(
            proposal_from_effective(&effective.bbr),
            BbrProposalSpecV1 {
                preset: Bbr3PresetV1::LossyRadio,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            }
        );
        assert_eq!(
            output.diagnostics.decision_kind,
            PolicyDecisionKindV1::ColdStart
        );
        assert_eq!(output.diagnostics.context_label.text(), "r2-b1-l2-datagra");
        assert_eq!(output.diagnostics.applied_arm_label.text(), "lossy-radio");
    }

    #[test]
    fn oversized_or_corrupt_state_is_a_fault() {
        let mut policy = CorePolicy::builtin(LearnerModeV1::Shadow);
        let huge = input(0, 1.0, vec![0; POLICY_STATE_MAX_BYTES as usize + 1]);
        assert_eq!(policy.decide(&huge), Err(PolicyFaultV1::StateTooLarge));
        let corrupt = input(0, 1.0, b"IPLS\x01\x00\x00\x00\x03\x00\x00\x00abc".to_vec());
        assert_eq!(policy.decide(&corrupt), Err(PolicyFaultV1::Internal));
        let foreign = input(0, 1.0, vec![1, 2, 3]);
        assert_eq!(policy.decide(&foreign), Err(PolicyFaultV1::Internal));
        // Host limits below the ABI cap are honoured.
        let mut small = input(0, 1.0, Vec::new());
        small.limits.state_cap_bytes = 8;
        assert_eq!(policy.decide(&small), Err(PolicyFaultV1::StateTooLarge));
    }

    #[test]
    fn backend_is_object_safe_and_state_flows_through_decide() {
        let mut backend: Box<dyn PolicyBackend> = Box::new(CorePolicy::builtin(LearnerModeV1::On));
        let first = backend.decide(&input(0, 1.0, Vec::new())).unwrap();
        let second = backend
            .decide(&input(1, 1.0, first.next_state.clone()))
            .unwrap();
        assert_eq!(
            LearnerStateV1::decode(&second.next_state)
                .unwrap()
                .context_count(),
            1
        );
    }
}
