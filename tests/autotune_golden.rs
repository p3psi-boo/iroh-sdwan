//! Per-sample golden gate for the production V2 policy replay pipeline.
//!
//! The checked-in fixture captures the baseline, learner trace, effective
//! action and learner memory for each tap sample.  Replay is executed through
//! `PolicyTickV1`, the same host pipeline used by `ironet policy replay`.

use std::{fs, path::Path};

use ironet::protocol::v2::{
    learner::{LearnerModeV2, policy_utility_weights},
    policy::canonical_spec_digest,
    policy_tick::core_slot_from_spec,
    replay::{ReplayGoldenV2, ReplayTapSampleV2, replay_ticks},
    utility::Objective,
};
use ironet_policy_core::PolicySpecV1;

const FIXTURE: &str = "tests/fixtures/autotune-replay-v1.json";
const GOLDEN: &str = "tests/fixtures/autotune-golden-v1.json";

fn load_samples() -> Vec<ReplayTapSampleV2> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    serde_json::from_str(&fs::read_to_string(path).expect("read replay fixture"))
        .expect("decode replay fixture")
}

fn load_golden() -> ReplayGoldenV2 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    serde_json::from_str(&fs::read_to_string(path).expect("read golden fixture"))
        .expect("decode golden fixture")
}

fn replay_builtin(
    samples: &[ReplayTapSampleV2],
    seed: u64,
) -> ironet::protocol::v2::replay::TickReplayReportV2 {
    let policy = PolicySpecV1::builtin();
    replay_ticks(
        samples,
        core_slot_from_spec(&policy, LearnerModeV2::Shadow),
        policy_utility_weights(&policy, Objective::Balanced),
        Objective::Balanced,
        LearnerModeV2::Shadow,
        seed,
    )
    .expect("replay")
}

#[test]
fn canonical_builtin_policy_replay_matches_golden_sample_by_sample() {
    let samples = load_samples();
    let expected = load_golden();
    let policy = PolicySpecV1::builtin();
    let canonical_digest = canonical_spec_digest(&policy).expect("canonical builtin digest");
    let report = replay_builtin(&samples, 1);

    assert_eq!(expected.fixture, FIXTURE);
    assert_eq!(expected.policy_id, policy.id);
    assert_eq!(expected.policy_digest, canonical_digest);
    assert_eq!(expected.source_policy_digest, canonical_digest);
    assert_eq!(report.module_digest, canonical_digest);
    assert_eq!(expected.objective, "balanced");
    assert_eq!(expected.seed, 1);
    assert_eq!(expected.learner_mode, "shadow");
    assert_eq!(expected.sample_count, samples.len());
    assert_eq!(report.samples, samples.len());
    assert_eq!(report.policy_id, expected.policy_id);
    assert_eq!(report.faults, 0);

    for (actual, expected) in report.trace.iter().zip(&expected.samples) {
        assert_eq!(actual.index, expected.index);
        assert_eq!(actual.offset_micros, expected.offset_micros);
        assert_eq!(actual.utility_total_bits, expected.utility.total_bits);
        assert_eq!(actual.baseline, expected.baseline);
        assert_eq!(actual.effective, expected.effective);
        assert!(actual.candidate.is_some());
        assert_eq!(actual.fault, None);
    }
}

#[test]
fn identical_seed_and_input_produce_identical_production_replay() {
    let samples = load_samples();
    let first = replay_builtin(&samples, 1);
    let second = replay_builtin(&samples, 1);
    assert_eq!(first, second);
    assert_eq!(first.trace_digest, second.trace_digest);
}
