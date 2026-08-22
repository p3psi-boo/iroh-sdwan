use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, ValueEnum};
use ironet::protocol::v2::{
    learner::{ContextKeyV2, ensure_policy_objective, preset_is_eligible},
    policy::{canonical_spec_digest, load_canonical_spec},
    policy_train::{OracleActionV2, context_name, oracle_action_matches_preset},
    promotion::{HoldoutMeasurementV2, PromotionThresholdsV2, evaluate_promotion},
    tuning::Bbr3PresetV2,
    utility::Objective,
};
use ironet_policy_core::PolicySpecV1;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(about = "Gate an Ironet V2 autotune policy against independent profiled holdouts")]
struct Args {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long, value_enum)]
    preset: PresetArg,
    #[arg(long, required = true)]
    holdout: Vec<PathBuf>,
    #[arg(long, default_value_t = 0.0)]
    minimum_utility_delta: f64,
    #[arg(long, default_value_t = 50)]
    maximum_throughput_regression_per_mille: u16,
    #[arg(long, default_value_t = 100)]
    maximum_ping_p95_regression_per_mille: u16,
    #[arg(long, default_value_t = 800)]
    minimum_context_coverage_per_mille: u16,
    #[arg(long, default_value_t = 3)]
    minimum_independent_runs_per_scenario: u16,
    #[arg(long, default_value_t = 1_000)]
    minimum_pass_rate_per_mille: u16,
    #[arg(long, default_value_t = 500)]
    maximum_utility_delta_dispersion_per_mille: u16,
    #[arg(long, default_value_t = 250)]
    maximum_throughput_ratio_dispersion_per_mille: u16,
    #[arg(long, default_value_t = 250)]
    maximum_ping_p95_ratio_dispersion_per_mille: u16,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PresetArg {
    SharedConservative,
    PrivateAggressive,
    LossyRadio,
    Policer,
    LongFat,
    RelayReliable,
    LowRttHost,
}

impl From<PresetArg> for Bbr3PresetV2 {
    fn from(value: PresetArg) -> Self {
        match value {
            PresetArg::SharedConservative => Self::SharedConservative,
            PresetArg::PrivateAggressive => Self::PrivateAggressive,
            PresetArg::LossyRadio => Self::LossyRadio,
            PresetArg::Policer => Self::Policer,
            PresetArg::LongFat => Self::LongFat,
            PresetArg::RelayReliable => Self::RelayReliable,
            PresetArg::LowRttHost => Self::LowRttHost,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OracleV1 {
    schema_version: u32,
    #[serde(default)]
    objective: Option<Objective>,
    scenarios: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CandidateV1 {
    candidate_id: String,
    action: Option<OracleActionV2>,
    utility_last10_mean: f64,
    overlay_mbit: f64,
    overlay_ping_p95_ms: f64,
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.policy.is_absolute(), "policy path must be absolute");
    ensure!(args.output.is_absolute(), "output path must be absolute");
    ensure!(
        args.minimum_independent_runs_per_scenario > 0,
        "minimum independent runs must be positive"
    );
    for (name, value) in [
        ("minimum pass rate", args.minimum_pass_rate_per_mille),
        (
            "maximum utility delta dispersion",
            args.maximum_utility_delta_dispersion_per_mille,
        ),
        (
            "maximum throughput ratio dispersion",
            args.maximum_throughput_ratio_dispersion_per_mille,
        ),
        (
            "maximum ping p95 ratio dispersion",
            args.maximum_ping_p95_ratio_dispersion_per_mille,
        ),
    ] {
        ensure!(value <= 1_000, "{name} must be in 0..=1000 per mille");
    }
    let policy = load_canonical_spec(&args.policy)?;
    let preset = Bbr3PresetV2::from(args.preset);
    let preset_name = policy
        .presets
        .iter()
        .find(|candidate| candidate.proposal.preset == preset.into())
        .map(|candidate| candidate.name.clone())
        .context("policy does not contain requested preset")?;
    let measurements = load_measurements(&args.holdout, &policy, preset, &preset_name)?;
    let report = evaluate_promotion(
        policy.id.clone(),
        canonical_spec_digest(&policy)?,
        preset_name,
        PromotionThresholdsV2 {
            minimum_utility_delta: args.minimum_utility_delta,
            maximum_throughput_regression_per_mille: args.maximum_throughput_regression_per_mille,
            maximum_ping_p95_regression_per_mille: args.maximum_ping_p95_regression_per_mille,
            minimum_context_coverage_per_mille: args.minimum_context_coverage_per_mille,
            require_zero_perf_lost_samples: true,
            minimum_independent_runs_per_scenario: args.minimum_independent_runs_per_scenario,
            minimum_pass_rate_per_mille: args.minimum_pass_rate_per_mille,
            maximum_utility_delta_dispersion_per_mille: args
                .maximum_utility_delta_dispersion_per_mille,
            maximum_throughput_ratio_dispersion_per_mille: args
                .maximum_throughput_ratio_dispersion_per_mille,
            maximum_ping_p95_ratio_dispersion_per_mille: args
                .maximum_ping_p95_ratio_dispersion_per_mille,
        },
        &measurements,
    );
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut encoded = serde_json::to_vec_pretty(&report)?;
    encoded.push(b'\n');
    fs::write(&args.output, encoded)?;
    println!("{}", serde_json::to_string(&report)?);
    if !report.passed {
        bail!("autotune policy promotion gate failed");
    }
    Ok(())
}

fn load_measurements(
    paths: &[PathBuf],
    policy: &PolicySpecV1,
    preset: Bbr3PresetV2,
    preset_name: &str,
) -> Result<Vec<HoldoutMeasurementV2>> {
    let mut measurements = Vec::new();
    let mut seen_holdouts = BTreeSet::new();
    let mut seen_runs = BTreeSet::new();
    let mut measured_objective = None;
    for path in paths {
        let canonical_path =
            fs::canonicalize(path).with_context(|| format!("canonicalizing {}", path.display()))?;
        ensure!(
            seen_holdouts.insert(canonical_path.clone()),
            "holdout was supplied more than once: {}",
            canonical_path.display()
        );
        let oracle: OracleV1 = serde_json::from_slice(
            &fs::read(&canonical_path)
                .with_context(|| format!("reading {}", canonical_path.display()))?,
        )?;
        ensure!(oracle.schema_version == 1, "unsupported oracle schema");
        let oracle_objective = oracle.objective.unwrap_or(Objective::Balanced);
        ensure!(
            measured_objective.is_none_or(|current| current == oracle_objective),
            "holdouts mix autotune objectives"
        );
        measured_objective = Some(oracle_objective);
        ensure_policy_objective(policy, oracle_objective)?;
        for (scenario, value) in oracle.scenarios {
            let candidates: Vec<CandidateV1> = serde_json::from_value(
                value
                    .get("candidates")
                    .cloned()
                    .context("oracle scenario has no candidates")?,
            )?;
            let baseline = candidates
                .iter()
                .find(|candidate| candidate.candidate_id == "baseline")
                .with_context(|| format!("scenario {scenario} has no baseline"))?;
            let matching = candidates
                .iter()
                .filter(|candidate| {
                    candidate
                        .action
                        .as_ref()
                        .is_some_and(|action| oracle_action_matches_preset(policy, preset, action))
                })
                .collect::<Vec<_>>();
            ensure!(
                matching.len() == 1,
                "scenario {scenario} must contain exactly one action matching the policy preset"
            );
            let candidate = matching[0];
            let baseline_output = fs::canonicalize(&baseline.output).with_context(|| {
                format!(
                    "canonicalizing baseline output {}",
                    baseline.output.display()
                )
            })?;
            let candidate_output = fs::canonicalize(&candidate.output).with_context(|| {
                format!(
                    "canonicalizing candidate output {}",
                    candidate.output.display()
                )
            })?;
            ensure!(
                seen_runs.insert((
                    scenario.clone(),
                    baseline_output.clone(),
                    candidate_output.clone()
                )),
                "scenario {scenario} reuses the same profiled baseline/candidate run"
            );
            let baseline_summary = read_summary(&baseline_output)?;
            let candidate_summary = read_summary(&candidate_output)?;
            ensure!(
                baseline_summary.binary_sha256 == candidate_summary.binary_sha256,
                "scenario {scenario} compares different binaries"
            );
            ensure!(
                baseline_summary.perf_enabled && candidate_summary.perf_enabled,
                "scenario {scenario} was not profiled"
            );
            measurements.push(HoldoutMeasurementV2 {
                run_id: canonical_path.display().to_string(),
                scenario,
                candidate_utility: candidate.utility_last10_mean,
                baseline_utility: baseline.utility_last10_mean,
                candidate_throughput_mbit: candidate.overlay_mbit,
                baseline_throughput_mbit: baseline.overlay_mbit,
                candidate_ping_p95_ms: candidate.overlay_ping_p95_ms,
                baseline_ping_p95_ms: baseline.overlay_ping_p95_ms,
                context_coverage_per_mille: context_coverage(
                    &baseline_summary.raw,
                    policy,
                    preset,
                    preset_name,
                )?,
                candidate_perf_lost_samples: candidate_summary
                    .a_perf_lost_samples
                    .saturating_add(candidate_summary.b_perf_lost_samples),
                baseline_perf_lost_samples: baseline_summary
                    .a_perf_lost_samples
                    .saturating_add(baseline_summary.b_perf_lost_samples),
            });
        }
    }
    Ok(measurements)
}

struct SummaryV2 {
    binary_sha256: String,
    perf_enabled: bool,
    a_perf_lost_samples: u64,
    b_perf_lost_samples: u64,
    raw: serde_json::Value,
}

fn read_summary(output: &Path) -> Result<SummaryV2> {
    let path = output.join("summary.json");
    let raw: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    Ok(SummaryV2 {
        binary_sha256: required_str(&raw, "binary_sha256")?.to_owned(),
        perf_enabled: raw
            .get("perf_enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        a_perf_lost_samples: required_u64(&raw, "a_perf_lost_samples")?,
        b_perf_lost_samples: required_u64(&raw, "b_perf_lost_samples")?,
        raw,
    })
}

fn context_coverage(
    summary: &serde_json::Value,
    policy: &PolicySpecV1,
    preset: Bbr3PresetV2,
    preset_name: &str,
) -> Result<u16> {
    let direction = required_str(summary, "direction")?;
    let side = if direction == "reverse" { "b" } else { "a" };
    let samples = summary
        .get("autotune_tap")
        .and_then(|tap| tap.get(side))
        .and_then(serde_json::Value::as_array)
        .context("summary has no sender autotune tap")?;
    let mut total = 0_u64;
    let mut covered = 0_u64;
    for sample in samples {
        if sample
            .get("offset_seconds")
            .and_then(serde_json::Value::as_f64)
            .is_some_and(|offset| offset < 0.0)
        {
            continue;
        }
        let context = sample
            .get("learner")
            .and_then(|learner| learner.get("context"))
            .context("tap sample has no learner context")?;
        let context = ContextKeyV2 {
            rtt_class: u8::try_from(required_u64(context, "rtt_class")?)?,
            rate_class: u8::try_from(required_u64(context, "rate_class")?)?,
            loss_class: u8::try_from(required_u64(context, "loss_class")?)?,
            reliable: context
                .get("reliable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            host_rtt: context
                .get("host_rtt")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        };
        if !preset_is_eligible(context, preset) {
            continue;
        }
        let key = context_name(context);
        total += 1;
        covered += u64::from(
            policy
                .priors
                .get(&key)
                .is_some_and(|priors| priors.contains_key(preset_name)),
        );
    }
    ensure!(total != 0, "summary has no saturation tap samples");
    Ok(((covered.saturating_mul(1_000) / total).min(1_000)) as u16)
}

fn required_str<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("missing string {key}"))
}

fn required_u64(value: &serde_json::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .with_context(|| format!("missing integer {key}"))
}
