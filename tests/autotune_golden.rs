//! Per-sample golden gate for the V2 autotune policy chain.
//!
//! `tests/fixtures/autotune-golden-v1.json` records, for every sample of
//! `tests/fixtures/autotune-replay-v1.json`, the telemetry input, the
//! host-computed utility, the native baseline, the learner trace, the
//! effective and candidate `TuneDecisionV2`, and a digest of the learner
//! memory. Any policy-chain change that alters a single bit of that trace
//! must regenerate the golden on purpose (the `generated_by` header holds the
//! exact command).

use std::{fs, path::Path};

use ironet::protocol::v2::{
    policy::builtin,
    replay::{REPLAY_GOLDEN_SCHEMA_V2, ReplayGoldenV2, ReplayTapSampleV2, replay_with_golden},
    utility::Objective,
};

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

#[test]
fn builtin_policy_replay_matches_golden_sample_by_sample() {
    let samples = load_samples();
    let expected = load_golden();
    let policy = builtin().expect("builtin policy");

    assert_eq!(expected.schema_version, REPLAY_GOLDEN_SCHEMA_V2);
    assert_eq!(expected.fixture, FIXTURE);
    assert_eq!(expected.policy_id, policy.id);
    assert_eq!(expected.policy_digest, policy.digest);
    assert_eq!(expected.source_policy_digest, policy.digest);
    assert_eq!(expected.objective, "balanced");
    assert_eq!(expected.seed, 1);
    assert_eq!(expected.learner_mode, "shadow");
    assert_eq!(expected.sample_count, samples.len());
    assert_eq!(expected.samples.len(), samples.len());
    assert!(
        expected.generated_by.contains("--golden-output"),
        "golden header must record its generator command"
    );

    let (report, mut actual) =
        replay_with_golden(&samples, &policy, policy.clone(), Objective::Balanced, 1)
            .expect("replay");
    actual.generated_by = expected.generated_by.clone();
    actual.fixture = expected.fixture.clone();

    for (actual, expected) in actual.samples.iter().zip(&expected.samples) {
        assert_eq!(
            actual.input, expected.input,
            "sample {} input diverged",
            expected.index
        );
        assert_eq!(
            actual.utility, expected.utility,
            "sample {} utility diverged",
            expected.index
        );
        assert_eq!(
            actual.baseline, expected.baseline,
            "sample {} baseline diverged",
            expected.index
        );
        assert_eq!(
            actual.learner, expected.learner,
            "sample {} learner trace diverged",
            expected.index
        );
        assert_eq!(
            actual.effective, expected.effective,
            "sample {} effective decision diverged",
            expected.index
        );
        assert_eq!(
            actual.candidate, expected.candidate,
            "sample {} candidate decision diverged",
            expected.index
        );
        assert_eq!(
            actual.memory, expected.memory,
            "sample {} learner memory diverged",
            expected.index
        );
        assert_eq!(
            actual.memory_digest, expected.memory_digest,
            "sample {} learner memory digest diverged",
            expected.index
        );
        assert_eq!(actual, expected, "sample {} diverged", expected.index);
    }
    assert_eq!(actual, expected);
    assert_eq!(report.trace_digest, expected.trace_digest);
    assert_eq!(report.policy_digest, expected.policy_digest);
}

#[test]
fn identical_seed_and_input_produce_identical_golden() {
    let samples = load_samples();
    let policy = builtin().expect("builtin policy");
    let (first_report, first) =
        replay_with_golden(&samples, &policy, policy.clone(), Objective::Balanced, 1)
            .expect("first replay");
    let (second_report, second) =
        replay_with_golden(&samples, &policy, policy.clone(), Objective::Balanced, 1)
            .expect("second replay");
    assert_eq!(first, second);
    assert_eq!(first_report.trace_digest, second_report.trace_digest);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
}
