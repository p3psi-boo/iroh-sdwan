//! Versioned, integrity-checked adaptive-control policy artifacts.

pub mod api;
pub mod egress;
pub mod guardrails;
pub mod state;
pub mod transition;

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    fec::FecGeometryV2,
    tuning::{Bbr3PresetV2, Bbr3ProposalV2, ForcedActionV2},
    utility::{Objective, UtilityWeights},
};

pub const POLICY_SCHEMA_VERSION_V2: u32 = 1;
pub const BUILTIN_POLICY_SOURCE_V2: &str = "builtin";
const BUILTIN_POLICY_JSON_V2: &str = include_str!("../../../config/autotune-policy-v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSchemaV2 {
    pub rtt_millis: Vec<u32>,
    pub rate_mbps: Vec<u32>,
    pub loss_ppm: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetSpecV2 {
    pub name: String,
    pub proposal: Bbr3ProposalV2,
    #[serde(default)]
    pub action: ActionSpecV2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActionSpecV2 {
    /// `None` inherits the rule baseline; `0+0` explicitly disables FEC.
    pub fec_data_cells: Option<u8>,
    pub fec_parity_cells: Option<u8>,
    pub train_target_bytes: Option<usize>,
    pub bulk_quantum_cells: Option<usize>,
    pub cover_overhead_per_mille: Option<u16>,
}

impl ActionSpecV2 {
    fn validate(self) -> Result<()> {
        ensure!(
            self.fec_data_cells.is_some() == self.fec_parity_cells.is_some(),
            "autotune FEC action must specify both data and parity"
        );
        if let (Some(data), Some(parity)) = (self.fec_data_cells, self.fec_parity_cells)
            && (data != 0 || parity != 0)
        {
            let geometry = FecGeometryV2 {
                data_cells: usize::from(data),
                parity_cells: usize::from(parity),
            };
            geometry.validate()?;
            ensure!(
                geometry.parity_cells.saturating_mul(1_000)
                    <= geometry.data_cells.saturating_mul(500),
                "autotune FEC action exceeds the 50% overhead guard"
            );
        }
        if let Some(train) = self.train_target_bytes {
            ensure!(
                (8 * 1024..=64 * 1024).contains(&train),
                "autotune train action outside safe bounds"
            );
        }
        if let Some(quantum) = self.bulk_quantum_cells {
            ensure!(
                (1..=4).contains(&quantum),
                "autotune quantum outside safe bounds"
            );
        }
        if let Some(overhead) = self.cover_overhead_per_mille {
            ensure!(
                overhead <= 50,
                "autotune cover overhead outside safe bounds"
            );
        }
        Ok(())
    }

    pub fn forced(self) -> ForcedActionV2 {
        ForcedActionV2 {
            bbr_preset: None,
            fec: self
                .fec_data_cells
                .zip(self.fec_parity_cells)
                .map(|(data, parity)| {
                    if data == 0 && parity == 0 {
                        None
                    } else {
                        Some(FecGeometryV2 {
                            data_cells: usize::from(data),
                            parity_cells: usize::from(parity),
                        })
                    }
                }),
            train_target_bytes: self.train_target_bytes,
            bulk_quantum_cells: self.bulk_quantum_cells,
            cover_profile: None,
            cover_overhead_per_mille: self.cover_overhead_per_mille,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosteriorSpecV2 {
    pub observations: u32,
    pub mean: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtilityWeightsSpecV2 {
    pub throughput: f64,
    pub queue_delay: f64,
    pub latency_sojourn: f64,
    pub residual_loss: f64,
    pub jitter: f64,
    pub cpu: f64,
    pub wire_overhead: f64,
    pub memory: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorationSpecV2 {
    pub minimum_dwell_millis: u64,
    pub minimum_rtt_rounds: u32,
    pub minimum_samples: u32,
    pub maximum_cpu_per_mille: u16,
    pub rollback_regression_per_mille: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifactV2 {
    pub schema_version: u32,
    pub id: String,
    pub algorithm: String,
    pub built_at: String,
    #[serde(default)]
    pub trained_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective: Option<Objective>,
    pub contexts: ContextSchemaV2,
    pub presets: Vec<PresetSpecV2>,
    #[serde(default)]
    pub priors: BTreeMap<String, BTreeMap<String, PosteriorSpecV2>>,
    pub weights: BTreeMap<String, UtilityWeightsSpecV2>,
    pub exploration: ExplorationSpecV2,
    pub digest: String,
}

impl PolicyArtifactV2 {
    pub fn ensure_objective(&self, objective: Objective) -> Result<()> {
        ensure!(
            self.objective.is_none_or(|trained| trained == objective),
            "autotune policy objective {:?} does not match runtime objective {:?}",
            self.objective,
            objective
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == POLICY_SCHEMA_VERSION_V2,
            "unsupported autotune policy schema {}",
            self.schema_version
        );
        ensure!(!self.id.trim().is_empty(), "autotune policy id is empty");
        ensure!(
            self.algorithm == "bandit-vivace",
            "unsupported autotune policy algorithm {}",
            self.algorithm
        );
        validate_thresholds(&self.contexts.rtt_millis, "rtt_millis")?;
        validate_thresholds(&self.contexts.rate_mbps, "rate_mbps")?;
        validate_thresholds(&self.contexts.loss_ppm, "loss_ppm")?;
        ensure!(!self.presets.is_empty(), "autotune policy has no presets");
        let mut names = std::collections::BTreeSet::new();
        let mut kinds = std::collections::BTreeSet::new();
        for preset in &self.presets {
            ensure!(
                !preset.name.trim().is_empty(),
                "autotune preset name is empty"
            );
            ensure!(names.insert(&preset.name), "duplicate autotune preset name");
            ensure!(
                kinds.insert(preset.proposal.preset as u8),
                "duplicate autotune preset kind"
            );
            validate_proposal(preset.proposal)?;
            preset.action.validate()?;
        }
        ensure!(
            kinds.len() == 7,
            "autotune policy must define every BBR preset exactly once"
        );
        ensure!(
            self.weights.contains_key("balanced")
                && self.weights.contains_key("throughput")
                && self.weights.contains_key("latency"),
            "autotune policy must define all utility objectives"
        );
        ensure!(
            self.weights.values().all(|weights| [
                weights.throughput,
                weights.queue_delay,
                weights.latency_sojourn,
                weights.residual_loss,
                weights.jitter,
                weights.cpu,
                weights.wire_overhead,
                weights.memory,
            ]
            .into_iter()
            .all(|value| value.is_finite() && (0.0..=10.0).contains(&value))),
            "autotune policy contains invalid utility weights"
        );
        for (context, priors) in &self.priors {
            validate_context_key(context)?;
            for (preset, posterior) in priors {
                ensure!(
                    names.iter().any(|name| name.as_str() == preset),
                    "autotune prior references unknown preset {preset}"
                );
                ensure!(
                    posterior.mean.is_finite(),
                    "autotune prior contains non-finite reward"
                );
                ensure!(
                    posterior.observations <= 1_000_000_000,
                    "autotune prior observation count is unreasonable"
                );
            }
        }
        ensure!(
            (1_000..=300_000).contains(&self.exploration.minimum_dwell_millis),
            "autotune dwell is outside safe bounds"
        );
        ensure!(
            (1..=64).contains(&self.exploration.minimum_rtt_rounds),
            "autotune RTT dwell is outside safe bounds"
        );
        ensure!(
            (4..=600).contains(&self.exploration.minimum_samples),
            "autotune minimum samples is outside safe bounds"
        );
        ensure!(
            (100..=1_000).contains(&self.exploration.maximum_cpu_per_mille),
            "autotune CPU guard is outside safe bounds"
        );
        ensure!(
            (10..=500).contains(&self.exploration.rollback_regression_per_mille),
            "autotune rollback threshold is outside safe bounds"
        );
        let calculated_digest = self.calculated_digest()?;
        ensure!(
            self.digest == calculated_digest,
            "autotune policy digest mismatch: expected {}, calculated {calculated_digest}",
            self.digest
        );
        Ok(())
    }

    pub fn calculated_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.digest.clear();
        Ok(blake3::hash(&serde_json::to_vec(&unsigned)?)
            .to_hex()
            .to_string())
    }

    pub fn preset(&self, preset: Bbr3PresetV2) -> Option<Bbr3ProposalV2> {
        self.presets
            .iter()
            .find(|candidate| candidate.proposal.preset == preset)
            .map(|candidate| candidate.proposal)
    }

    pub fn action(&self, preset: Bbr3PresetV2) -> Option<ForcedActionV2> {
        self.presets
            .iter()
            .find(|candidate| candidate.proposal.preset == preset)
            .map(|candidate| candidate.action.forced())
    }

    pub fn utility_weights(&self, objective: Objective) -> UtilityWeights {
        let key = match objective {
            Objective::Balanced => "balanced",
            Objective::Throughput => "throughput",
            Objective::Latency => "latency",
        };
        let weights = self
            .weights
            .get(key)
            .expect("validated policy defines every objective");
        UtilityWeights {
            throughput: weights.throughput,
            queue_delay: weights.queue_delay,
            latency_sojourn: weights.latency_sojourn,
            residual_loss: weights.residual_loss,
            jitter: weights.jitter,
            cpu: weights.cpu,
            wire_overhead: weights.wire_overhead,
            memory: weights.memory,
        }
    }
}

fn validate_thresholds(values: &[u32], name: &str) -> Result<()> {
    ensure!(values.len() <= 16, "too many autotune {name} thresholds");
    ensure!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "autotune {name} thresholds must be strictly increasing"
    );
    Ok(())
}

fn validate_context_key(value: &str) -> Result<()> {
    let mut parts = value.split('-');
    for prefix in ['r', 'b', 'l'] {
        let part = parts
            .next()
            .context("autotune prior context is incomplete")?;
        let class = part
            .strip_prefix(prefix)
            .context("autotune prior context has invalid class prefix")?
            .parse::<u8>()
            .context("autotune prior context class is invalid")?;
        ensure!(class <= 3, "autotune prior context class exceeds 3");
    }
    ensure!(
        matches!(parts.next(), Some("datagram" | "reliable")),
        "autotune prior context has invalid reliability"
    );
    let suffix = parts.next();
    ensure!(
        suffix.is_none() || suffix == Some("host"),
        "autotune prior context has invalid RTT specialization"
    );
    ensure!(
        parts.next().is_none(),
        "autotune prior context has trailing data"
    );
    Ok(())
}

fn validate_proposal(proposal: Bbr3ProposalV2) -> Result<()> {
    ensure!(
        (1_050..=1_500).contains(&proposal.up_gain_milli),
        "BBR up gain outside safe bounds"
    );
    ensure!(
        (50..=400).contains(&proposal.headroom_milli),
        "BBR headroom outside safe bounds"
    );
    ensure!(
        (1_200..=3_500).contains(&proposal.cwnd_gain_milli),
        "BBR cwnd gain outside safe bounds"
    );
    ensure!(
        proposal.pacing_cap_bytes_per_second == 0
            || proposal.pacing_cap_bytes_per_second >= 64 * 1024,
        "BBR pacing cap outside safe bounds"
    );
    Ok(())
}

pub fn builtin() -> Result<PolicyArtifactV2> {
    decode(BUILTIN_POLICY_JSON_V2.as_bytes(), BUILTIN_POLICY_SOURCE_V2)
}

pub fn load(path: &Path) -> Result<PolicyArtifactV2> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decode(&bytes, &path.display().to_string())
}

fn decode(bytes: &[u8], source: &str) -> Result<PolicyArtifactV2> {
    let artifact: PolicyArtifactV2 = serde_json::from_slice(bytes)
        .with_context(|| format!("decoding autotune policy {source}"))?;
    artifact
        .validate()
        .with_context(|| format!("validating autotune policy {source}"))?;
    Ok(artifact)
}

/// File policies are operational inputs: corruption or an unsupported future
/// schema degrades to the embedded policy rather than taking down forwarding.
pub fn load_or_builtin(selection: &str) -> Result<(PolicyArtifactV2, String, Option<String>)> {
    if selection == BUILTIN_POLICY_SOURCE_V2 {
        return Ok((builtin()?, BUILTIN_POLICY_SOURCE_V2.to_owned(), None));
    }
    match load(Path::new(selection)) {
        Ok(policy) => Ok((policy, selection.to_owned(), None)),
        Err(error) => Ok((
            builtin()?,
            BUILTIN_POLICY_SOURCE_V2.to_owned(),
            Some(format!("{error:#}")),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_integrity_checked_and_complete() {
        let policy = builtin().unwrap();
        assert_eq!(policy.id, "bandit-vivace@1");
        assert_eq!(policy.presets.len(), 7);
        for preset in [
            Bbr3PresetV2::SharedConservative,
            Bbr3PresetV2::PrivateAggressive,
            Bbr3PresetV2::LossyRadio,
            Bbr3PresetV2::Policer,
            Bbr3PresetV2::LongFat,
            Bbr3PresetV2::RelayReliable,
            Bbr3PresetV2::LowRttHost,
        ] {
            assert!(policy.preset(preset).is_some());
            assert!(policy.action(preset).is_some());
        }
        let lossy = policy.action(Bbr3PresetV2::LossyRadio).unwrap();
        assert_eq!(lossy.train_target_bytes, Some(32 * 1024));
        assert_eq!(lossy.fec.unwrap().unwrap().parity_cells, 2);
    }

    #[test]
    fn rejects_tampering_schema_and_out_of_range_proposal() {
        let policy = builtin().unwrap();
        let mut tampered = policy.clone();
        tampered.presets[0].proposal.up_gain_milli = 2_000;
        tampered.digest = tampered.calculated_digest().unwrap();
        assert!(tampered.validate().is_err());

        let mut wrong_schema = policy.clone();
        wrong_schema.schema_version = 99;
        wrong_schema.digest = wrong_schema.calculated_digest().unwrap();
        assert!(wrong_schema.validate().is_err());

        let mut wrong_digest = policy;
        wrong_digest.built_at.push('x');
        assert!(wrong_digest.validate().is_err());
    }

    #[test]
    fn objective_specific_artifacts_reject_cross_objective_use() {
        let mut policy = builtin().unwrap();
        policy.objective = Some(Objective::Throughput);
        policy.digest = policy.calculated_digest().unwrap();
        policy.validate().unwrap();
        policy.ensure_objective(Objective::Throughput).unwrap();
        assert!(policy.ensure_objective(Objective::Balanced).is_err());
        let encoded = serde_json::to_vec(&policy).unwrap();
        let decoded: PolicyArtifactV2 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.objective, Some(Objective::Throughput));
        assert_eq!(decoded.digest, policy.digest);
    }

    #[test]
    fn missing_file_falls_back_to_builtin() {
        let (_, source, error) = load_or_builtin("/definitely/missing/policy.json").unwrap();
        assert_eq!(source, BUILTIN_POLICY_SOURCE_V2);
        assert!(error.is_some());
    }
}

pub mod package;
pub mod runtime;
pub mod signature;
pub mod status;
