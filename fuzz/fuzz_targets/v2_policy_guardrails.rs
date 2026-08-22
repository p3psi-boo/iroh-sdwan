#![no_main]

//! Fuzz the policy guardrails: an arbitrary `CandidateActionV1` over a fixed
//! enabled base must never escape the host hard bounds, and re-applying the
//! result must be a fixed point with an empty clamp report.

use ironet::protocol::v2::{
    fec::FecGeometryV2,
    policy::{
        api::{
            BbrEffectiveV1, BbrHostExt, CandidateActionV1, ClampReasonV1, EffectiveActionV1,
            EffectiveHostExt, FecEffectiveV1, FecHostExt,
        },
        guardrails::{
            ACTIVE_TRAIN_BUDGET_CAP, GuardrailContextV1, GuardrailsV1,
            REASSEMBLY_BUDGET_FLOOR_BYTES, REPAIR_RETENTION_CAP_MILLIS,
        },
    },
    tuning::{
        AutoTuneBoundsV2, CoverTrafficProfileV2, RepairWaitPolicyV2, TuneDecisionV2, TuneReasonV2,
    },
};
use libfuzzer_sys::fuzz_target;

/// Trailing bytes drive the guardrail context; everything before is the
/// postcard-encoded candidate.
const CONTEXT_BYTES: usize = 40;
const MAX_CANDIDATE_BYTES: usize = 4_096;

fn base() -> EffectiveActionV1 {
    EffectiveActionV1::from_tune_decision(&TuneDecisionV2 {
        reason: TuneReasonV2::HealthyLowLoss,
        path_epoch: 3,
        sample_count: 9,
        train_target_bytes: 32 * 1024,
        bulk_quantum_cells: 2,
        fec: Some(FecGeometryV2 {
            data_cells: 8,
            parity_cells: 1,
        }),
        repair_cache_bytes: 4 * 1024 * 1024,
        send_buffer_bytes: 1024 * 1024,
        receive_buffer_bytes: 16 * 1024 * 1024,
        receive_batch: 32,
        cover_profile: CoverTrafficProfileV2::InteractiveVideo,
        cover_overhead_per_mille: 30,
        cover_padding_bytes_per_second: 300_000,
        repair_retention_millis: 0,
        repair_wait_policy: RepairWaitPolicyV2::HostDefault,
        reassembly_budget_bytes: 0,
        active_train_budget: 0,
        bbr: BbrEffectiveV1::default().to_proposal(),
    })
}

fn context(tail: &[u8]) -> GuardrailContextV1 {
    let flag = |index: usize| tail[index] & 1 == 1;
    let number = |index: usize| {
        u64::from_be_bytes(tail[index..index + 8].try_into().expect("8-byte window"))
            % 200_000_000
    };
    let cpu_limited = flag(0);
    // `GuardrailContextV1::from_filtered` always suppresses cover under CPU
    // pressure; keep the fuzzed contexts inside that invariant.
    let cover_suppression = if cpu_limited {
        Some(ClampReasonV1::CpuPressure)
    } else if flag(1) {
        Some(ClampReasonV1::QueuePressure)
    } else {
        None
    };
    GuardrailContextV1 {
        reliable: flag(2),
        cpu_limited,
        cpu_emergency: flag(3),
        protection_emergency: flag(4),
        latency_queue_active: flag(5),
        cover_suppression,
        real_traffic_bytes_per_second: number(8),
        rtt_micros: number(16) % 400_000,
        delivery_rate_bytes_per_second: number(16),
        offered_rate_bytes_per_second: number(24),
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() < CONTEXT_BYTES {
        return;
    }
    let (candidate_bytes, tail) = input.split_at(input.len() - CONTEXT_BYTES);
    let candidate_bytes = &candidate_bytes[..candidate_bytes.len().min(MAX_CANDIDATE_BYTES)];
    let Ok(candidate) = postcard::from_bytes::<CandidateActionV1>(candidate_bytes) else {
        return;
    };
    let ctx = context(tail);
    let limits = AutoTuneBoundsV2::default();
    let guardrails = GuardrailsV1::from_bounds(&limits);
    let host = guardrails.limits().clone();
    let base = base();
    let (effective, _) = guardrails.apply(&candidate, &base, &ctx);

    // BBR: every numeric knob stays inside the range the controller accepts.
    let bbr = &effective.bbr;
    assert!((1_050..=1_500).contains(&bbr.probe_bw_up_pacing_gain_milli));
    assert!((700..=950).contains(&bbr.probe_bw_down_pacing_gain_milli));
    assert!((950..=1_020).contains(&bbr.cruise_pacing_gain_milli));
    assert!((1_200..=3_000).contains(&bbr.default_cwnd_gain_milli));
    assert!((1_500..=3_500).contains(&bbr.probe_bw_up_cwnd_gain_milli));
    assert!((50..=400).contains(&bbr.headroom_milli));
    assert!((500..=900).contains(&bbr.beta_milli));
    assert!((5..=100).contains(&bbr.loss_threshold_milli));
    assert!((200..=1_500).contains(&bbr.queue_guard_inflation_milli));
    assert!((2_000..=50_000).contains(&bbr.queue_guard_slack_micros));
    assert!((2_000..=30_000).contains(&bbr.probe_rtt_interval_millis));
    assert!((100..=500).contains(&bbr.probe_rtt_duration_millis));
    assert!((100..=3_500).contains(&bbr.probe_rtt_cwnd_gain_milli));
    assert!((1_000..=10_000).contains(&bbr.min_probe_wait_millis));
    assert!(bbr.max_added_probe_wait_millis <= 5_000);
    assert!(bbr.pacing_cap_bytes_per_second == 0 || bbr.pacing_cap_bytes_per_second >= 64 * 1024);
    assert!(bbr.cwnd_cap_bytes == 0 || bbr.cwnd_cap_bytes >= 4 * 1_200);
    assert!(bbr.cwnd_cap_bytes == 0 || bbr.cwnd_floor_bytes <= bbr.cwnd_cap_bytes);

    // FEC: a reliable underlay or host CPU pressure forces protection off,
    // and any enabled geometry is valid and within the wire-overhead cap.
    if ctx.reliable || ctx.cpu_limited {
        assert!(!effective.fec.enabled);
    }
    if let Some(geometry) = effective.fec.to_geometry() {
        assert!(geometry.validate().is_ok());
        assert!(geometry.data_cells <= usize::from(host.fec_data_cells_cap));
        assert!(geometry.parity_cells <= usize::from(host.fec_parity_cells_cap));
        assert!(
            geometry.parity_cells * 1_000
                <= geometry.data_cells * usize::from(host.fec_parity_per_mille_cap)
        );
    } else {
        assert_eq!(effective.fec, FecEffectiveV1::default());
    }

    // Scheduler: latency traffic keeps its strict lane, and a CPU emergency
    // never batches above the baseline.
    if ctx.latency_queue_active {
        assert_eq!(effective.scheduler.bulk_quantum_cells, 1);
    }
    if ctx.cpu_emergency {
        assert!(effective.scheduler.train_target_bytes <= base.scheduler.train_target_bytes);
        assert!(effective.scheduler.bulk_quantum_cells <= base.scheduler.bulk_quantum_cells);
    }

    // Memory: the RX budget can only shrink, never grow past the receive
    // buffer, and every buffer stays inside the host budget.
    assert!(effective.rx.receive_buffer_bytes >= host.receive_buffer_floor_bytes);
    assert!(effective.rx.receive_buffer_bytes <= host.receive_buffer_cap_bytes);
    let budget = effective.rx.reassembly_budget_bytes;
    if budget != 0 {
        assert!(budget >= REASSEMBLY_BUDGET_FLOOR_BYTES.min(effective.rx.receive_buffer_bytes));
        assert!(budget <= effective.rx.receive_buffer_bytes);
    }
    assert!(effective.rx.active_train_budget <= ACTIVE_TRAIN_BUDGET_CAP);
    assert!(effective.repair.cache_bytes <= host.repair_cache_cap_bytes);
    assert!(effective.repair.retention_target_millis <= REPAIR_RETENTION_CAP_MILLIS);

    // Cover: suppressed paths carry no overhead and the padding is derived.
    if ctx.cover_suppression.is_some() {
        assert_eq!(effective.cover.overhead_per_mille, 0);
        assert_eq!(effective.cover.padding_bytes_per_second, 0);
    }
    assert_eq!(
        effective.cover.padding_bytes_per_second,
        ctx.real_traffic_bytes_per_second
            .saturating_mul(u64::from(effective.cover.overhead_per_mille))
            / 1_000
    );

    // Egress: the priority cap and the minimum/desired relation hold.
    assert!(effective.egress.priority <= host.egress_priority_cap);
    assert!(
        effective.egress.desired_rate_bytes_per_second == 0
            || effective.egress.minimum_rate_bytes_per_second
                <= effective.egress.desired_rate_bytes_per_second
    );

    // Idempotence: re-running every guardrail over the effective action is
    // the identity and reports nothing.
    let (again, again_report) = guardrails.reapply(&effective, &ctx);
    assert_eq!(again, effective);
    assert!(again_report.is_empty());
});
