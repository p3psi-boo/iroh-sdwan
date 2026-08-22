use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use chrono::{SecondsFormat, Utc};
use clap::Parser;
use ironet::protocol::v2::{
    learner::ContextKeyV2,
    policy::{canonical_spec_digest, load_canonical_spec},
    policy_train::{OracleActionV2, TrainingObservationV2, train_policy},
    replay::ReplayTelemetryV2,
    utility::Objective,
};
use ironet_policy_core::PolicySpecV1;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(about = "Build a validated canonical Ironet PolicySpecV1 from oracle results")]
struct Args {
    /// One or more oracle.json files produced by scripts/autotune-oracle.sh.
    #[arg(long, required = true)]
    oracle: Vec<PathBuf>,
    /// Base canonical PolicySpecV1 JSON, or 'builtin'.
    #[arg(long, default_value = "builtin")]
    base_policy: String,
    /// Unique ID written into the trained canonical spec.
    #[arg(long)]
    id: String,
    /// RFC3339 timestamp; defaults to the current UTC second.
    #[arg(long)]
    built_at: Option<String>,
    /// Posterior confidence assigned to each independent candidate run.
    #[arg(long, default_value_t = 8)]
    prior_observations_per_run: u32,
    /// Destination canonical PolicySpecV1 JSON.
    #[arg(long)]
    output: PathBuf,
    /// Optional mapping/audit report destination.
    #[arg(long)]
    report: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct OracleFileV1 {
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
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.output.is_absolute(), "output path must be absolute");
    if let Some(report) = &args.report {
        ensure!(report.is_absolute(), "report path must be absolute");
    }
    let base = load_base(&args.base_policy)?;
    let (observations, objective) = load_observations(&args.oracle, &base)?;
    let built_at = args
        .built_at
        .unwrap_or_else(|| Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    let (mut policy, report) = train_policy(
        base,
        args.id,
        built_at,
        &observations,
        args.prior_observations_per_run,
    )?;
    policy.objective = Some(objective.into());
    policy.validate()?;
    let digest = canonical_spec_digest(&policy)?;
    write_json(&args.output, &policy)?;
    if let Some(path) = args.report {
        write_json(&path, &report)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "policy": args.output,
            "id": policy.id,
            "digest": digest,
            "contexts": policy.priors.len(),
            "objective": objective,
            "input_observations": report.input_observations,
            "accepted_observations": report.accepted_observations,
            "skipped_observations": report.skipped_observations,
        })
    );
    Ok(())
}

fn load_base(selection: &str) -> Result<PolicySpecV1> {
    if selection == "builtin" {
        Ok(PolicySpecV1::builtin())
    } else {
        let path = PathBuf::from(selection);
        ensure!(path.is_absolute(), "base policy path must be absolute");
        load_canonical_spec(&path)
    }
}

fn load_observations(
    oracle_paths: &[PathBuf],
    policy: &PolicySpecV1,
) -> Result<(Vec<TrainingObservationV2>, Objective)> {
    let mut observations = Vec::new();
    let mut objectives = BTreeSet::new();
    for oracle_path in oracle_paths {
        let oracle: OracleFileV1 = serde_json::from_slice(
            &fs::read(oracle_path).with_context(|| format!("reading {}", oracle_path.display()))?,
        )
        .with_context(|| format!("decoding {}", oracle_path.display()))?;
        ensure!(oracle.schema_version == 1, "unsupported oracle schema");
        objectives.insert(oracle.objective.unwrap_or(Objective::Balanced));
        for (scenario, value) in oracle.scenarios {
            let candidates: Vec<CandidateV1> = serde_json::from_value(
                value
                    .get("candidates")
                    .cloned()
                    .with_context(|| format!("scenario {scenario} has no candidates"))?,
            )?;
            // Context is an environmental input to the action choice. Derive
            // it from the unforced baseline, never from the candidate whose
            // action may itself move RTT/rate/loss across a bucket boundary.
            let baseline = candidates
                .iter()
                .find(|candidate| candidate.candidate_id == "baseline")
                .with_context(|| format!("scenario {scenario} has no baseline"))?;
            let contexts = load_contexts(&baseline.output.join("summary.json"), policy)?;
            for candidate in candidates {
                let Some(action) = candidate.action else {
                    continue;
                };
                ensure!(
                    candidate.utility_last10_mean.is_finite(),
                    "candidate utility is non-finite"
                );
                for context in &contexts {
                    observations.push(TrainingObservationV2 {
                        context: *context,
                        action: action.clone(),
                        utility: candidate.utility_last10_mean,
                        source: format!(
                            "{}#{scenario}/{}",
                            oracle_path.display(),
                            candidate.candidate_id
                        ),
                    });
                }
            }
        }
    }
    ensure!(
        objectives.len() == 1,
        "training inputs mix autotune objectives"
    );
    Ok((
        observations,
        objectives
            .into_iter()
            .next()
            .expect("one objective checked"),
    ))
}

fn load_contexts(summary_path: &Path, policy: &PolicySpecV1) -> Result<BTreeSet<ContextKeyV2>> {
    let summary: serde_json::Value = serde_json::from_slice(
        &fs::read(summary_path).with_context(|| format!("reading {}", summary_path.display()))?,
    )?;
    let side = match summary.get("direction").and_then(serde_json::Value::as_str) {
        Some("reverse") => "b",
        _ => "a",
    };
    let taps = summary
        .get("autotune_tap")
        .and_then(|tap| tap.get(side))
        .and_then(serde_json::Value::as_array)
        .with_context(|| format!("{} has no {side} autotune tap", summary_path.display()))?;
    let mut contexts = BTreeSet::new();
    for tap in taps {
        if tap
            .get("offset_seconds")
            .and_then(serde_json::Value::as_f64)
            .is_some_and(|offset| offset < 0.0)
        {
            continue;
        }
        let telemetry: ReplayTelemetryV2 = serde_json::from_value(
            tap.get("telemetry")
                .cloned()
                .context("tap has no telemetry")?,
        )?;
        contexts.insert(ContextKeyV2::classify_with(
            &telemetry.into_runtime(),
            &policy.contexts,
        ));
    }
    ensure!(!contexts.is_empty(), "baseline has no saturation contexts");
    Ok(contexts)
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    fs::write(path, encoded).with_context(|| format!("writing {}", path.display()))
}
