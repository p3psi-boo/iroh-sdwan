//! Built-in policy guest.
//!
//! The guest is deliberately a thin wrapper around `ironet-policy-core` so
//! the native and WASM policy paths execute the same learner.  All per-peer
//! state remains in the ABI records (`input.state` and `output.next_state`);
//! the wrapper creates a call-local core value and therefore has no clock,
//! random source, environment access or process state.

#![deny(unsafe_code)]

use ironet_policy_abi::{PolicyBackend, PolicyFaultV1, PolicyInputV1, PolicyOutputV1};
use ironet_policy_core::{CorePolicy, LearnerModeV1};
use ironet_policy_sdk::GuestPolicy;

struct BuiltinPolicy;

impl GuestPolicy for BuiltinPolicy {
    fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        // Shadow calls evaluate the learner but preserve the host baseline;
        // normal calls apply the learner's selected action.  The host passes
        // this mode explicitly through the ABI capability bit so the same
        // component can be used for both paths.
        let mode = if input.capabilities.shadow {
            LearnerModeV1::Shadow
        } else {
            LearnerModeV1::On
        };
        let mut policy = CorePolicy::builtin(mode);
        policy.decide(input)
    }
}

ironet_policy_sdk::export_policy!(BuiltinPolicy);
