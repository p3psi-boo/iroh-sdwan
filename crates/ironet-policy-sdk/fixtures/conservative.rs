//! Reference guest: propose no optional action fields and carry state through.

#![deny(unsafe_code)]

use ironet_policy_abi::{CandidateActionV1, PolicyFaultV1, PolicyInputV1, PolicyOutputV1};
use ironet_policy_sdk::GuestPolicy;

struct Conservative;

impl GuestPolicy for Conservative {
    fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        Ok(PolicyOutputV1 {
            // Every optional domain and field is None; the host keeps its
            // current effective action and applies its normal guardrails.
            candidate: CandidateActionV1::default(),
            next_state: input.state.clone(),
            ..PolicyOutputV1::default()
        })
    }
}

ironet_policy_sdk::export_policy!(Conservative);
