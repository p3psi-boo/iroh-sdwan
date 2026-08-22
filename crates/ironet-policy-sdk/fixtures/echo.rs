//! Reference guest: propose exactly the previous effective action and carry
//! opaque state through unchanged.

#![deny(unsafe_code)]

use ironet_policy_abi::{
    BbrCandidateV1, CandidateActionV1, CoverCandidateV1, EgressRequestV1, FecCandidateV1,
    PolicyFaultV1, PolicyInputV1, PolicyOutputV1, RepairCandidateV1, RxCandidateV1,
    SchedulerCandidateV1, TxCandidateV1,
};
use ironet_policy_sdk::GuestPolicy;

struct Echo;

fn candidate_from_previous(input: &PolicyInputV1) -> CandidateActionV1 {
    let previous = &input.previous;
    CandidateActionV1 {
        bbr: Some(BbrCandidateV1 {
            preset: Some(previous.bbr.preset),
            probe_bw_up_pacing_gain_milli: Some(previous.bbr.probe_bw_up_pacing_gain_milli),
            probe_bw_down_pacing_gain_milli: Some(previous.bbr.probe_bw_down_pacing_gain_milli),
            cruise_pacing_gain_milli: Some(previous.bbr.cruise_pacing_gain_milli),
            default_cwnd_gain_milli: Some(previous.bbr.default_cwnd_gain_milli),
            probe_bw_up_cwnd_gain_milli: Some(previous.bbr.probe_bw_up_cwnd_gain_milli),
            headroom_milli: Some(previous.bbr.headroom_milli),
            beta_milli: Some(previous.bbr.beta_milli),
            loss_threshold_milli: Some(previous.bbr.loss_threshold_milli),
            loss_is_congestion: Some(previous.bbr.loss_is_congestion),
            queue_guard_inflation_milli: Some(previous.bbr.queue_guard_inflation_milli),
            queue_guard_slack_micros: Some(previous.bbr.queue_guard_slack_micros),
            probe_rtt_interval_millis: Some(previous.bbr.probe_rtt_interval_millis),
            probe_rtt_duration_millis: Some(previous.bbr.probe_rtt_duration_millis),
            probe_rtt_cwnd_gain_milli: Some(previous.bbr.probe_rtt_cwnd_gain_milli),
            min_probe_wait_millis: Some(previous.bbr.min_probe_wait_millis),
            max_added_probe_wait_millis: Some(previous.bbr.max_added_probe_wait_millis),
            pacing_cap_bytes_per_second: Some(previous.bbr.pacing_cap_bytes_per_second),
            cwnd_floor_bytes: Some(previous.bbr.cwnd_floor_bytes),
            cwnd_cap_bytes: Some(previous.bbr.cwnd_cap_bytes),
            startup_bw_hint_bytes_per_second: Some(previous.bbr.startup_bw_hint_bytes_per_second),
        }),
        scheduler: Some(SchedulerCandidateV1 {
            train_target_bytes: Some(previous.scheduler.train_target_bytes),
            bulk_quantum_cells: Some(previous.scheduler.bulk_quantum_cells),
            bulk_admission_window_bytes: Some(previous.scheduler.bulk_admission_window_bytes),
            preset_hint: Some(previous.scheduler.preset_hint),
        }),
        fec: Some(FecCandidateV1 {
            enabled: Some(previous.fec.enabled),
            data_cells: Some(previous.fec.data_cells),
            parity_cells: Some(previous.fec.parity_cells),
            preset_family: Some(previous.fec.preset_family),
        }),
        repair: Some(RepairCandidateV1 {
            cache_bytes: Some(previous.repair.cache_bytes),
            retention_target_millis: Some(previous.repair.retention_target_millis),
            wait_policy: Some(previous.repair.wait_policy),
            responsibility: Some(previous.repair.responsibility),
        }),
        tx: Some(TxCandidateV1 {
            send_buffer_bytes: Some(previous.tx.send_buffer_bytes),
            datagram_admission_bytes: Some(previous.tx.datagram_admission_bytes),
            producer_window_bytes: Some(previous.tx.producer_window_bytes),
        }),
        rx: Some(RxCandidateV1 {
            receive_buffer_bytes: Some(previous.rx.receive_buffer_bytes),
            receive_batch: Some(previous.rx.receive_batch),
            reassembly_budget_bytes: Some(previous.rx.reassembly_budget_bytes),
            active_train_budget: Some(previous.rx.active_train_budget),
        }),
        cover: Some(CoverCandidateV1 {
            profile: Some(previous.cover.profile),
            overhead_per_mille: Some(previous.cover.overhead_per_mille),
            padding_bytes_per_second: Some(previous.cover.padding_bytes_per_second),
        }),
        egress_request: Some(EgressRequestV1 {
            desired_rate_bytes_per_second: previous.egress.desired_rate_bytes_per_second,
            minimum_rate_bytes_per_second: previous.egress.minimum_rate_bytes_per_second,
            priority: previous.egress.priority,
            exploring: previous.egress.exploring,
        }),
        extensions: Vec::new(),
    }
}

impl GuestPolicy for Echo {
    fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        Ok(PolicyOutputV1 {
            candidate: candidate_from_previous(input),
            next_state: input.state.clone(),
            ..PolicyOutputV1::default()
        })
    }
}

ironet_policy_sdk::export_policy!(Echo);
