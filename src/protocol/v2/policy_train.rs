//! Offline construction of versioned policy priors from measured oracle runs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use super::{
    learner::{ContextKeyV2, preset_is_eligible},
    policy::{PolicyArtifactV2, PosteriorSpecV2, PresetSpecV2},
    tuning::Bbr3PresetV2,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleActionV2 {
    #[serde(default)]
    pub bbr_preset: Option<Bbr3PresetV2>,
    pub fec: Option<String>,
    pub train_target_bytes: usize,
    pub bulk_quantum_cells: usize,
    pub cover_overhead_per_mille: u16,
    #[serde(default)]
    pub cover_profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrainingObservationV2 {
    pub context: ContextKeyV2,
    pub action: OracleActionV2,
    pub utility: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrainingReportV2 {
    pub schema_version: u32,
    pub policy_id: String,
    pub input_observations: usize,
    pub accepted_observations: usize,
    pub skipped_observations: usize,
    pub contexts: usize,
    pub mappings: Vec<ActionMappingV2>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionMappingV2 {
    pub source: String,
    pub context: String,
    pub preset: Option<String>,
    pub distance: u64,
    pub utility: f64,
}

#[derive(Debug, Default)]
struct AggregateV2 {
    samples: u32,
    utility_sum: f64,
}

pub fn train_policy(
    mut base: PolicyArtifactV2,
    id: String,
    built_at: String,
    observations: &[TrainingObservationV2],
    prior_observations_per_run: u32,
) -> Result<(PolicyArtifactV2, TrainingReportV2)> {
    base.validate()?;
    ensure!(!id.trim().is_empty(), "trained policy id is empty");
    ensure!(
        !built_at.trim().is_empty(),
        "trained policy built_at is empty"
    );
    ensure!(!observations.is_empty(), "training set has no observations");
    ensure!(
        (1..=10_000).contains(&prior_observations_per_run),
        "prior observations per run is outside 1..=10000"
    );

    let mut aggregates: BTreeMap<(String, String), AggregateV2> = BTreeMap::new();
    let mut mappings = Vec::with_capacity(observations.len());
    let mut trained_on = BTreeSet::new();
    let mut accepted_observations = 0_usize;
    for observation in observations {
        ensure!(
            observation.utility.is_finite(),
            "training utility is non-finite"
        );
        validate_action(&observation.action)?;
        let context = context_name(observation.context);
        if observation.action.bbr_preset.is_none() || observation.action.cover_profile.is_some() {
            mappings.push(ActionMappingV2 {
                source: observation.source.clone(),
                context,
                preset: None,
                distance: u64::MAX,
                utility: observation.utility,
            });
            continue;
        }
        let Some((preset, distance)) =
            closest_preset(&base, observation.context, &observation.action)?
        else {
            mappings.push(ActionMappingV2 {
                source: observation.source.clone(),
                context,
                preset: None,
                distance: u64::MAX,
                utility: observation.utility,
            });
            continue;
        };
        if distance >= 100 {
            mappings.push(ActionMappingV2 {
                source: observation.source.clone(),
                context,
                preset: None,
                distance,
                utility: observation.utility,
            });
            continue;
        }
        accepted_observations += 1;
        let aggregate = aggregates
            .entry((context.clone(), preset.name.clone()))
            .or_default();
        aggregate.samples = aggregate.samples.saturating_add(1);
        aggregate.utility_sum += observation.utility;
        trained_on.insert(observation.source.clone());
        mappings.push(ActionMappingV2 {
            source: observation.source.clone(),
            context,
            preset: Some(preset.name.clone()),
            distance,
            utility: observation.utility,
        });
    }

    base.id = id;
    base.built_at = built_at;
    base.trained_on = trained_on.into_iter().collect();
    base.priors.clear();
    ensure!(
        accepted_observations != 0,
        "no oracle action maps to a policy arm with matching FEC geometry"
    );
    for ((context, preset), aggregate) in aggregates {
        base.priors.entry(context).or_default().insert(
            preset,
            PosteriorSpecV2 {
                observations: aggregate.samples.saturating_mul(prior_observations_per_run),
                mean: aggregate.utility_sum / f64::from(aggregate.samples),
            },
        );
    }
    base.digest = base.calculated_digest()?;
    base.validate()?;
    mappings.sort_by(|left, right| {
        (&left.context, &left.preset, &left.source).cmp(&(
            &right.context,
            &right.preset,
            &right.source,
        ))
    });
    let report = TrainingReportV2 {
        schema_version: 1,
        policy_id: base.id.clone(),
        input_observations: observations.len(),
        accepted_observations,
        skipped_observations: observations.len() - accepted_observations,
        contexts: base.priors.len(),
        mappings,
    };
    Ok((base, report))
}

fn validate_action(action: &OracleActionV2) -> Result<()> {
    ensure!(
        (8 * 1024..=64 * 1024).contains(&action.train_target_bytes),
        "training action train size is outside safe bounds"
    );
    ensure!(
        (1..=4).contains(&action.bulk_quantum_cells),
        "training action quantum is outside safe bounds"
    );
    ensure!(
        action.cover_overhead_per_mille <= 50,
        "training action cover overhead is outside safe bounds"
    );
    parse_fec(action.fec.as_deref())?;
    Ok(())
}

fn closest_preset<'a>(
    policy: &'a PolicyArtifactV2,
    context: ContextKeyV2,
    action: &OracleActionV2,
) -> Result<Option<(&'a PresetSpecV2, u64)>> {
    let requested_preset = action
        .bbr_preset
        .ok_or_else(|| anyhow::anyhow!("oracle action has no measured BBR preset"))?;
    let mut best: Option<(&PresetSpecV2, u64)> = None;
    for preset in &policy.presets {
        if preset.proposal.preset != requested_preset
            || !preset_is_eligible(context, preset.proposal.preset)
            || !is_complete(preset)
        {
            continue;
        }
        let distance = action_distance(action, preset)?;
        if best.is_none_or(|(_, best_distance)| distance < best_distance) {
            best = Some((preset, distance));
        }
    }
    Ok(best)
}

fn is_complete(preset: &PresetSpecV2) -> bool {
    preset.action.fec_data_cells.is_some()
        && preset.action.fec_parity_cells.is_some()
        && preset.action.train_target_bytes.is_some()
        && preset.action.bulk_quantum_cells.is_some()
        && preset.action.cover_overhead_per_mille.is_some()
}

fn action_distance(action: &OracleActionV2, preset: &PresetSpecV2) -> Result<u64> {
    let requested_fec = parse_fec(action.fec.as_deref())?;
    let preset_fec = preset
        .action
        .fec_data_cells
        .zip(preset.action.fec_parity_cells)
        .expect("complete action checked");
    let fec_distance = if requested_fec == preset_fec { 0 } else { 100 };
    let train_distance = action.train_target_bytes.abs_diff(
        preset
            .action
            .train_target_bytes
            .expect("complete action checked"),
    ) / (8 * 1024);
    let quantum_distance = action.bulk_quantum_cells.abs_diff(
        preset
            .action
            .bulk_quantum_cells
            .expect("complete action checked"),
    ) * 4;
    let cover_distance = usize::from(
        action.cover_overhead_per_mille.abs_diff(
            preset
                .action
                .cover_overhead_per_mille
                .expect("complete action checked"),
        ),
    ) / 10;
    Ok(fec_distance + train_distance as u64 + quantum_distance as u64 + cover_distance as u64)
}

pub fn oracle_action_matches_preset(
    policy: &PolicyArtifactV2,
    preset: Bbr3PresetV2,
    action: &OracleActionV2,
) -> bool {
    if action.bbr_preset != Some(preset) || action.cover_profile.is_some() {
        return false;
    }
    policy
        .presets
        .iter()
        .find(|candidate| candidate.proposal.preset == preset)
        .filter(|candidate| is_complete(candidate))
        .and_then(|candidate| action_distance(action, candidate).ok())
        == Some(0)
}

fn parse_fec(value: Option<&str>) -> Result<(u8, u8)> {
    let Some(value) = value else {
        return Ok((0, 0));
    };
    let Some((data, parity)) = value.split_once('+') else {
        bail!("training action FEC must be null or DATA+PARITY");
    };
    let data = data.parse::<u8>()?;
    let parity = parity.parse::<u8>()?;
    ensure!((2..=16).contains(&data), "training FEC data is invalid");
    ensure!(parity <= 8, "training FEC parity is invalid");
    Ok((data, parity))
}

pub fn context_name(context: ContextKeyV2) -> String {
    let base = format!(
        "r{}-b{}-l{}-{}",
        context.rtt_class,
        context.rate_class,
        context.loss_class,
        if context.reliable {
            "reliable"
        } else {
            "datagram"
        }
    );
    if context.host_rtt {
        format!("{base}-host")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::policy::builtin;

    #[test]
    fn oracle_actions_train_valid_deterministic_priors() {
        let observation = TrainingObservationV2 {
            context: ContextKeyV2 {
                rtt_class: 2,
                rate_class: 1,
                loss_class: 2,
                reliable: false,
                host_rtt: false,
            },
            action: OracleActionV2 {
                bbr_preset: Some(Bbr3PresetV2::LossyRadio),
                fec: Some("8+2".to_owned()),
                train_target_bytes: 32 * 1024,
                bulk_quantum_cells: 2,
                cover_overhead_per_mille: 0,
                cover_profile: None,
            },
            utility: 2.5,
            source: "fixture/lossy".to_owned(),
        };
        let (first, report) = train_policy(
            builtin().unwrap(),
            "fixture@1".to_owned(),
            "2026-08-20T00:00:00Z".to_owned(),
            std::slice::from_ref(&observation),
            16,
        )
        .unwrap();
        let (second, _) = train_policy(
            builtin().unwrap(),
            "fixture@1".to_owned(),
            "2026-08-20T00:00:00Z".to_owned(),
            &[observation],
            16,
        )
        .unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(report.mappings[0].preset.as_deref(), Some("lossy-radio"));
        assert_eq!(
            first.priors["r2-b1-l2-datagram"]["lossy-radio"].observations,
            16
        );
        assert_eq!(first.priors["r2-b1-l2-datagram"]["lossy-radio"].mean, 2.5);
    }

    #[test]
    fn mixed_action_grid_skips_presets_ineligible_for_a_context() {
        let context = ContextKeyV2 {
            rtt_class: 2,
            rate_class: 1,
            loss_class: 2,
            reliable: false,
            host_rtt: false,
        };
        let observations = [
            TrainingObservationV2 {
                context,
                action: OracleActionV2 {
                    bbr_preset: Some(Bbr3PresetV2::LossyRadio),
                    fec: Some("8+2".to_owned()),
                    train_target_bytes: 32 * 1024,
                    bulk_quantum_cells: 2,
                    cover_overhead_per_mille: 0,
                    cover_profile: None,
                },
                utility: 2.5,
                source: "grid/lossy".to_owned(),
            },
            TrainingObservationV2 {
                context,
                action: OracleActionV2 {
                    bbr_preset: Some(Bbr3PresetV2::Policer),
                    fec: Some("8+1".to_owned()),
                    train_target_bytes: 16 * 1024,
                    bulk_quantum_cells: 1,
                    cover_overhead_per_mille: 0,
                    cover_profile: None,
                },
                utility: 1.0,
                source: "grid/policer".to_owned(),
            },
        ];
        let (_, report) = train_policy(
            builtin().unwrap(),
            "grid@1".to_owned(),
            "2026-08-20T00:00:00Z".to_owned(),
            &observations,
            8,
        )
        .unwrap();
        assert_eq!(report.accepted_observations, 1);
        assert_eq!(report.skipped_observations, 1);
        assert_eq!(
            report
                .mappings
                .iter()
                .find(|mapping| mapping.source == "grid/policer")
                .unwrap()
                .preset,
            None
        );
    }

    #[test]
    fn low_rtt_severe_loss_can_train_the_policer_arm() {
        let observation = TrainingObservationV2 {
            context: ContextKeyV2 {
                rtt_class: 0,
                rate_class: 2,
                loss_class: 3,
                reliable: false,
                host_rtt: false,
            },
            action: OracleActionV2 {
                bbr_preset: Some(Bbr3PresetV2::Policer),
                fec: Some("8+1".to_owned()),
                train_target_bytes: 16 * 1024,
                bulk_quantum_cells: 1,
                cover_overhead_per_mille: 0,
                cover_profile: None,
            },
            utility: 3.0,
            source: "shallow-policer".to_owned(),
        };
        let (policy, report) = train_policy(
            builtin().unwrap(),
            "policer@1".to_owned(),
            "2026-08-20T00:00:00Z".to_owned(),
            &[observation],
            8,
        )
        .unwrap();
        assert_eq!(report.accepted_observations, 1);
        assert_eq!(policy.priors["r0-b2-l3-datagram"]["policer"].mean, 3.0);
    }

    #[test]
    fn application_only_oracle_cannot_claim_a_complete_bbr_arm() {
        let observation = TrainingObservationV2 {
            context: ContextKeyV2 {
                rtt_class: 2,
                rate_class: 1,
                loss_class: 2,
                reliable: false,
                host_rtt: false,
            },
            action: OracleActionV2 {
                bbr_preset: None,
                fec: Some("8+2".to_owned()),
                train_target_bytes: 32 * 1024,
                bulk_quantum_cells: 2,
                cover_overhead_per_mille: 0,
                cover_profile: None,
            },
            utility: 2.5,
            source: "legacy-grid".to_owned(),
        };
        assert!(
            train_policy(
                builtin().unwrap(),
                "invalid@1".to_owned(),
                "2026-08-20T00:00:00Z".to_owned(),
                &[observation],
                8,
            )
            .is_err()
        );
    }

    #[test]
    fn forced_cover_profile_cannot_train_an_arm_that_only_controls_overhead() {
        let observation = TrainingObservationV2 {
            context: ContextKeyV2 {
                rtt_class: 2,
                rate_class: 1,
                loss_class: 2,
                reliable: false,
                host_rtt: false,
            },
            action: OracleActionV2 {
                bbr_preset: Some(Bbr3PresetV2::LossyRadio),
                fec: Some("8+2".to_owned()),
                train_target_bytes: 32 * 1024,
                bulk_quantum_cells: 2,
                cover_overhead_per_mille: 0,
                cover_profile: Some("idle".to_owned()),
            },
            utility: 2.5,
            source: "cover-mismatch".to_owned(),
        };
        assert!(
            train_policy(
                builtin().unwrap(),
                "invalid@2".to_owned(),
                "2026-08-20T00:00:00Z".to_owned(),
                &[observation],
                8,
            )
            .is_err()
        );
    }
}
