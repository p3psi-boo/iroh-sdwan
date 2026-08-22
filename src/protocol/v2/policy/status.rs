//! Runtime status DTOs for a loaded WASM policy.

use serde::{Deserialize, Serialize};

use super::api::{PolicyBackendKindV1, PolicyFaultV1, PolicyHealthV1, PolicyIdentityV1};

/// Bounded, transport-neutral status for one policy backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuntimeStatusV1 {
    pub backend: PolicyBackendKindV1,
    pub policy_id: String,
    pub policy_version: String,
    pub module_digest: Option<[u8; 32]>,
    pub signer_id: Option<String>,
    pub abi_world: String,
    pub state_schema: u32,
    pub module_generation: u64,
    pub health: PolicyHealthV1,
    pub faults_total: u64,
    pub timeouts_total: u64,
    pub quarantines_total: u64,
    pub last_call_micros: u64,
    pub fuel_consumed: u64,
    pub last_fault: Option<PolicyFaultV1>,
}

impl PolicyRuntimeStatusV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_backend(
        identity: &PolicyIdentityV1,
        health: PolicyHealthV1,
        faults_total: u64,
        timeouts_total: u64,
        quarantines_total: u64,
        last_call_micros: u64,
        fuel_consumed: u64,
        last_fault: Option<PolicyFaultV1>,
    ) -> Self {
        Self {
            backend: identity.backend,
            policy_id: identity.policy_id.clone(),
            policy_version: identity.policy_version.clone(),
            module_digest: identity.digest,
            signer_id: identity.signer_id.clone(),
            abi_world: identity.abi_world.clone(),
            state_schema: identity.state_schema,
            module_generation: identity.module_generation,
            health,
            faults_total,
            timeouts_total,
            quarantines_total,
            last_call_micros,
            fuel_consumed,
            last_fault,
        }
    }
}
