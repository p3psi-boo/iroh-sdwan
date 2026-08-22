//! Deterministic promotion gates for candidate autotune policies.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct PromotionThresholdsV2 {
    pub minimum_utility_delta: f64,
    pub maximum_throughput_regression_per_mille: u16,
    pub maximum_ping_p95_regression_per_mille: u16,
    pub minimum_context_coverage_per_mille: u16,
    pub require_zero_perf_lost_samples: bool,
    pub minimum_independent_runs_per_scenario: u16,
    pub minimum_pass_rate_per_mille: u16,
    pub maximum_utility_delta_dispersion_per_mille: u16,
    pub maximum_throughput_ratio_dispersion_per_mille: u16,
    pub maximum_ping_p95_ratio_dispersion_per_mille: u16,
}

#[derive(Debug, Clone)]
pub struct HoldoutMeasurementV2 {
    pub run_id: String,
    pub scenario: String,
    pub candidate_utility: f64,
    pub baseline_utility: f64,
    pub candidate_throughput_mbit: f64,
    pub baseline_throughput_mbit: f64,
    pub candidate_ping_p95_ms: f64,
    pub baseline_ping_p95_ms: f64,
    pub context_coverage_per_mille: u16,
    pub candidate_perf_lost_samples: u64,
    pub baseline_perf_lost_samples: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromotionReportV2 {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_digest: String,
    pub preset: String,
    pub passed: bool,
    pub thresholds: PromotionThresholdReportV2,
    pub scenarios: Vec<PromotionScenarioV2>,
    pub stability: Vec<PromotionStabilityV2>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromotionThresholdReportV2 {
    pub minimum_utility_delta: f64,
    pub maximum_throughput_regression_per_mille: u16,
    pub maximum_ping_p95_regression_per_mille: u16,
    pub minimum_context_coverage_per_mille: u16,
    pub require_zero_perf_lost_samples: bool,
    pub minimum_independent_runs_per_scenario: u16,
    pub minimum_pass_rate_per_mille: u16,
    pub maximum_utility_delta_dispersion_per_mille: u16,
    pub maximum_throughput_ratio_dispersion_per_mille: u16,
    pub maximum_ping_p95_ratio_dispersion_per_mille: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromotionScenarioV2 {
    pub run_id: String,
    pub scenario: String,
    pub passed: bool,
    pub utility_delta: f64,
    pub throughput_regression_per_mille: u16,
    pub ping_p95_regression_per_mille: u16,
    pub context_coverage_per_mille: u16,
    pub candidate_perf_lost_samples: u64,
    pub baseline_perf_lost_samples: u64,
    pub failed_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromotionStabilityV2 {
    pub scenario: String,
    pub independent_runs: u16,
    pub passed_runs: u16,
    pub pass_rate_per_mille: u16,
    pub utility_delta_dispersion_per_mille: u16,
    pub throughput_ratio_dispersion_per_mille: u16,
    pub ping_p95_ratio_dispersion_per_mille: u16,
    pub failed_checks: Vec<String>,
    pub passed: bool,
}

pub fn evaluate_promotion(
    policy_id: String,
    policy_digest: String,
    preset: String,
    thresholds: PromotionThresholdsV2,
    measurements: &[HoldoutMeasurementV2],
) -> PromotionReportV2 {
    let scenarios = measurements
        .iter()
        .map(|measurement| {
            let utility_delta = measurement.candidate_utility - measurement.baseline_utility;
            let throughput_regression_per_mille = regression_per_mille(
                measurement.candidate_throughput_mbit,
                measurement.baseline_throughput_mbit,
            );
            let ping_p95_regression_per_mille = growth_per_mille(
                measurement.candidate_ping_p95_ms,
                measurement.baseline_ping_p95_ms,
            );
            let mut failed_checks = Vec::new();
            if !utility_delta.is_finite() || utility_delta < thresholds.minimum_utility_delta {
                failed_checks.push("utility-delta".to_owned());
            }
            if throughput_regression_per_mille > thresholds.maximum_throughput_regression_per_mille
            {
                failed_checks.push("throughput-regression".to_owned());
            }
            if ping_p95_regression_per_mille > thresholds.maximum_ping_p95_regression_per_mille {
                failed_checks.push("ping-p95-regression".to_owned());
            }
            if measurement.context_coverage_per_mille
                < thresholds.minimum_context_coverage_per_mille
            {
                failed_checks.push("context-coverage".to_owned());
            }
            if thresholds.require_zero_perf_lost_samples
                && (measurement.candidate_perf_lost_samples != 0
                    || measurement.baseline_perf_lost_samples != 0)
            {
                failed_checks.push("perf-lost-samples".to_owned());
            }
            PromotionScenarioV2 {
                run_id: measurement.run_id.clone(),
                scenario: measurement.scenario.clone(),
                passed: failed_checks.is_empty(),
                utility_delta,
                throughput_regression_per_mille,
                ping_p95_regression_per_mille,
                context_coverage_per_mille: measurement.context_coverage_per_mille,
                candidate_perf_lost_samples: measurement.candidate_perf_lost_samples,
                baseline_perf_lost_samples: measurement.baseline_perf_lost_samples,
                failed_checks,
            }
        })
        .collect::<Vec<_>>();
    let stability = evaluate_stability(&scenarios, measurements, thresholds);
    PromotionReportV2 {
        schema_version: 2,
        policy_id,
        policy_digest,
        preset,
        passed: !scenarios.is_empty()
            && scenarios.iter().all(|scenario| scenario.passed)
            && stability.iter().all(|group| group.passed),
        thresholds: PromotionThresholdReportV2 {
            minimum_utility_delta: thresholds.minimum_utility_delta,
            maximum_throughput_regression_per_mille: thresholds
                .maximum_throughput_regression_per_mille,
            maximum_ping_p95_regression_per_mille: thresholds.maximum_ping_p95_regression_per_mille,
            minimum_context_coverage_per_mille: thresholds.minimum_context_coverage_per_mille,
            require_zero_perf_lost_samples: thresholds.require_zero_perf_lost_samples,
            minimum_independent_runs_per_scenario: thresholds.minimum_independent_runs_per_scenario,
            minimum_pass_rate_per_mille: thresholds.minimum_pass_rate_per_mille,
            maximum_utility_delta_dispersion_per_mille: thresholds
                .maximum_utility_delta_dispersion_per_mille,
            maximum_throughput_ratio_dispersion_per_mille: thresholds
                .maximum_throughput_ratio_dispersion_per_mille,
            maximum_ping_p95_ratio_dispersion_per_mille: thresholds
                .maximum_ping_p95_ratio_dispersion_per_mille,
        },
        scenarios,
        stability,
    }
}

fn evaluate_stability(
    scenarios: &[PromotionScenarioV2],
    measurements: &[HoldoutMeasurementV2],
    thresholds: PromotionThresholdsV2,
) -> Vec<PromotionStabilityV2> {
    let mut groups = BTreeMap::<&str, Vec<usize>>::new();
    for (index, scenario) in scenarios.iter().enumerate() {
        groups.entry(&scenario.scenario).or_default().push(index);
    }
    groups
        .into_iter()
        .map(|(scenario, indices)| {
            let independent_runs = indices.len().min(usize::from(u16::MAX)) as u16;
            let passed_runs = indices
                .iter()
                .filter(|index| scenarios[**index].passed)
                .count()
                .min(usize::from(u16::MAX)) as u16;
            let pass_rate_per_mille = if independent_runs == 0 {
                0
            } else {
                (u32::from(passed_runs) * 1_000 / u32::from(independent_runs)) as u16
            };
            let utility_deltas = indices
                .iter()
                .map(|index| scenarios[*index].utility_delta)
                .collect::<Vec<_>>();
            let throughput_ratios = indices
                .iter()
                .map(|index| {
                    ratio_per_mille(
                        measurements[*index].candidate_throughput_mbit,
                        measurements[*index].baseline_throughput_mbit,
                    )
                })
                .collect::<Vec<_>>();
            let ping_ratios = indices
                .iter()
                .map(|index| {
                    ratio_per_mille(
                        measurements[*index].candidate_ping_p95_ms,
                        measurements[*index].baseline_ping_p95_ms,
                    )
                })
                .collect::<Vec<_>>();
            let utility_delta_dispersion_per_mille = dispersion_per_mille(&utility_deltas);
            let throughput_ratio_dispersion_per_mille = dispersion_per_mille(&throughput_ratios);
            let ping_p95_ratio_dispersion_per_mille = dispersion_per_mille(&ping_ratios);
            let mut failed_checks = Vec::new();
            if independent_runs < thresholds.minimum_independent_runs_per_scenario {
                failed_checks.push("minimum-independent-runs".to_owned());
            }
            if pass_rate_per_mille < thresholds.minimum_pass_rate_per_mille {
                failed_checks.push("pass-rate".to_owned());
            }
            if utility_delta_dispersion_per_mille
                > thresholds.maximum_utility_delta_dispersion_per_mille
            {
                failed_checks.push("utility-delta-dispersion".to_owned());
            }
            if throughput_ratio_dispersion_per_mille
                > thresholds.maximum_throughput_ratio_dispersion_per_mille
            {
                failed_checks.push("throughput-ratio-dispersion".to_owned());
            }
            if ping_p95_ratio_dispersion_per_mille
                > thresholds.maximum_ping_p95_ratio_dispersion_per_mille
            {
                failed_checks.push("ping-p95-ratio-dispersion".to_owned());
            }
            PromotionStabilityV2 {
                scenario: scenario.to_owned(),
                independent_runs,
                passed_runs,
                pass_rate_per_mille,
                utility_delta_dispersion_per_mille,
                throughput_ratio_dispersion_per_mille,
                ping_p95_ratio_dispersion_per_mille,
                passed: failed_checks.is_empty(),
                failed_checks,
            }
        })
        .collect()
}

fn ratio_per_mille(value: f64, baseline: f64) -> f64 {
    if !value.is_finite() || !baseline.is_finite() || baseline <= 0.0 {
        return f64::NAN;
    }
    value / baseline * 1_000.0
}

fn dispersion_per_mille(values: &[f64]) -> u16 {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return u16::MAX;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    ((variance.sqrt() / mean.abs().max(1.0)) * 1_000.0)
        .round()
        .min(f64::from(u16::MAX)) as u16
}

fn regression_per_mille(candidate: f64, baseline: f64) -> u16 {
    if !candidate.is_finite() || !baseline.is_finite() || baseline <= 0.0 {
        return u16::MAX;
    }
    (((baseline - candidate).max(0.0) / baseline) * 1_000.0)
        .round()
        .min(f64::from(u16::MAX)) as u16
}

fn growth_per_mille(candidate: f64, baseline: f64) -> u16 {
    if !candidate.is_finite() || !baseline.is_finite() || baseline <= 0.0 {
        return u16::MAX;
    }
    (((candidate - baseline).max(0.0) / baseline) * 1_000.0)
        .round()
        .min(f64::from(u16::MAX)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> PromotionThresholdsV2 {
        PromotionThresholdsV2 {
            minimum_utility_delta: 0.0,
            maximum_throughput_regression_per_mille: 50,
            maximum_ping_p95_regression_per_mille: 100,
            minimum_context_coverage_per_mille: 800,
            require_zero_perf_lost_samples: true,
            minimum_independent_runs_per_scenario: 1,
            minimum_pass_rate_per_mille: 1_000,
            maximum_utility_delta_dispersion_per_mille: 500,
            maximum_throughput_ratio_dispersion_per_mille: 250,
            maximum_ping_p95_ratio_dispersion_per_mille: 250,
        }
    }

    #[test]
    fn promotion_requires_every_independent_guard() {
        let passing = HoldoutMeasurementV2 {
            run_id: "run-1".to_owned(),
            scenario: "passing".to_owned(),
            candidate_utility: 2.0,
            baseline_utility: 1.0,
            candidate_throughput_mbit: 98.0,
            baseline_throughput_mbit: 100.0,
            candidate_ping_p95_ms: 105.0,
            baseline_ping_p95_ms: 100.0,
            context_coverage_per_mille: 900,
            candidate_perf_lost_samples: 0,
            baseline_perf_lost_samples: 0,
        };
        let report = evaluate_promotion(
            "p@1".to_owned(),
            "digest".to_owned(),
            "lossy-radio".to_owned(),
            thresholds(),
            std::slice::from_ref(&passing),
        );
        assert!(report.passed);

        let failing = HoldoutMeasurementV2 {
            scenario: "failing".to_owned(),
            candidate_utility: 0.0,
            candidate_throughput_mbit: 80.0,
            candidate_ping_p95_ms: 150.0,
            context_coverage_per_mille: 700,
            candidate_perf_lost_samples: 1,
            ..passing
        };
        let report = evaluate_promotion(
            "p@1".to_owned(),
            "digest".to_owned(),
            "lossy-radio".to_owned(),
            thresholds(),
            &[failing],
        );
        assert!(!report.passed);
        assert_eq!(report.scenarios[0].failed_checks.len(), 5);
    }

    #[test]
    fn promotion_requires_repeated_stable_measurements() {
        let measurement = HoldoutMeasurementV2 {
            run_id: "run-1".to_owned(),
            scenario: "r2".to_owned(),
            candidate_utility: 2.0,
            baseline_utility: 1.0,
            candidate_throughput_mbit: 100.0,
            baseline_throughput_mbit: 100.0,
            candidate_ping_p95_ms: 100.0,
            baseline_ping_p95_ms: 100.0,
            context_coverage_per_mille: 1_000,
            candidate_perf_lost_samples: 0,
            baseline_perf_lost_samples: 0,
        };
        let mut strict = thresholds();
        strict.minimum_independent_runs_per_scenario = 3;
        let report = evaluate_promotion(
            "p@2".to_owned(),
            "digest".to_owned(),
            "lossy-radio".to_owned(),
            strict,
            std::slice::from_ref(&measurement),
        );
        assert!(!report.passed);
        assert_eq!(
            report.stability[0].failed_checks,
            ["minimum-independent-runs"]
        );

        let mut runs = vec![measurement.clone(); 3];
        for (index, run) in runs.iter_mut().enumerate() {
            run.run_id = format!("run-{index}");
        }
        let report = evaluate_promotion(
            "p@2".to_owned(),
            "digest".to_owned(),
            "lossy-radio".to_owned(),
            strict,
            &runs,
        );
        assert!(report.passed);

        runs[2].candidate_utility = 20.0;
        runs[2].candidate_throughput_mbit = 300.0;
        runs[2].candidate_ping_p95_ms = 300.0;
        let report = evaluate_promotion(
            "p@2".to_owned(),
            "digest".to_owned(),
            "lossy-radio".to_owned(),
            strict,
            &runs,
        );
        assert!(!report.passed);
        assert!(
            report.stability[0]
                .failed_checks
                .contains(&"utility-delta-dispersion".to_owned())
        );
        assert!(
            report.stability[0]
                .failed_checks
                .contains(&"throughput-ratio-dispersion".to_owned())
        );
        assert!(
            report.stability[0]
                .failed_checks
                .contains(&"ping-p95-ratio-dispersion".to_owned())
        );
    }
}
