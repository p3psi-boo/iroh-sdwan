use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use ironet::protocol::v2::{
    policy::{PolicyArtifactV2, builtin, load},
    replay::{ReplayTapSampleV2, replay_with_golden},
    utility::Objective,
};

#[derive(Debug, Parser)]
#[command(about = "Deterministically replay Ironet V2 autotune telemetry")]
struct Args {
    /// Tap JSON array, profile summary.json, or JSONL file; '-' reads stdin.
    #[arg(long)]
    input: PathBuf,
    /// Candidate PolicyArtifact JSON, or 'builtin'.
    #[arg(long, default_value = "builtin")]
    policy: String,
    /// Policy that produced schema-3 utility components, or 'builtin'.
    #[arg(long, default_value = "builtin")]
    source_policy: String,
    /// Side selected from a profile summary's autotune_tap object.
    #[arg(long, default_value = "a")]
    side: String,
    #[arg(long, value_enum, default_value_t = ObjectiveArg::Balanced)]
    objective: ObjectiveArg,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Report path; '-' writes stdout.
    #[arg(long, default_value = "-")]
    output: PathBuf,
    /// Optional per-sample golden trace path (bit-exact learner inputs,
    /// outputs and state digests); '-' writes stdout.
    #[arg(long)]
    golden_output: Option<PathBuf>,
}

impl Args {
    /// Canonical command line recorded in the golden header so the file can
    /// be regenerated verbatim.
    fn generator_command(&self) -> String {
        let objective = match self.objective {
            ObjectiveArg::Balanced => "balanced",
            ObjectiveArg::Throughput => "throughput",
            ObjectiveArg::Latency => "latency",
        };
        let mut command = format!(
            "cargo run --example autotune_replay -- --input {} --policy {} --source-policy {} --objective {objective} --seed {}",
            self.input.display(),
            self.policy,
            self.source_policy,
            self.seed,
        );
        if self.side != "a" {
            command.push_str(&format!(" --side {}", self.side));
        }
        if let Some(path) = &self.golden_output {
            command.push_str(&format!(" --golden-output {}", path.display()));
        }
        command
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ObjectiveArg {
    Balanced,
    Throughput,
    Latency,
}

impl From<ObjectiveArg> for Objective {
    fn from(value: ObjectiveArg) -> Self {
        match value {
            ObjectiveArg::Balanced => Self::Balanced,
            ObjectiveArg::Throughput => Self::Throughput,
            ObjectiveArg::Latency => Self::Latency,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input = read_input(&args.input)?;
    let samples = decode_samples(&input, &args.side)?;
    let source = load_selection(&args.source_policy).context("loading source policy")?;
    let candidate = load_selection(&args.policy).context("loading candidate policy")?;
    let (report, mut golden) = replay_with_golden(
        &samples,
        &source,
        candidate,
        args.objective.into(),
        args.seed,
    )?;
    if let Some(path) = &args.golden_output {
        golden.generated_by = args.generator_command();
        golden.fixture = args.input.display().to_string();
        let mut encoded = serde_json::to_vec_pretty(&golden)?;
        encoded.push(b'\n');
        write_output(path, &encoded)?;
    }
    let mut encoded = serde_json::to_vec_pretty(&report)?;
    encoded.push(b'\n');
    write_output(&args.output, &encoded)
}

fn load_selection(selection: &str) -> Result<PolicyArtifactV2> {
    if selection == "builtin" {
        builtin()
    } else {
        let path = Path::new(selection);
        if !path.is_absolute() {
            bail!("policy path must be absolute: {}", path.display());
        }
        load(path)
    }
}

fn read_input(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    } else {
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    }
}

fn decode_samples(input: &str, side: &str) -> Result<Vec<ReplayTapSampleV2>> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input) {
        let selected = if let Some(samples) = value.as_array() {
            serde_json::Value::Array(samples.clone())
        } else if let Some(samples) = value.get("samples") {
            samples.clone()
        } else if let Some(samples) = value.get("autotune_tap").and_then(|tap| tap.get(side)) {
            samples.clone()
        } else {
            serde_json::Value::Array(vec![value])
        };
        return serde_json::from_value(selected).context("decoding replay samples");
    }

    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("decoding JSONL replay sample on line {}", index + 1))
        })
        .collect()
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    if path == Path::new("-") {
        io::stdout().write_all(bytes)?;
    } else {
        fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}
