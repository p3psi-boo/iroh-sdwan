//! Backend trait, faults and identity.

use serde::{Deserialize, Serialize};

use crate::{POLICY_ABI_WORLD_V1, PolicyInputV1, PolicyOutputV1};

/// Backend flavour that produced an identity/output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyBackendKindV1 {
    /// Deterministic conservative host rules, no learner, no WASM.
    #[default]
    Native,
    /// Built-in or external WASM component.
    Wasm,
}

impl PolicyBackendKindV1 {
    pub const ALL: [Self; 2] = [Self::Native, Self::Wasm];
}

/// Fault state machine of a backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyHealthV1 {
    #[default]
    Healthy,
    Degraded,
    Quarantined,
    ShadowWarmup,
}

impl PolicyHealthV1 {
    pub const ALL: [Self; 4] = [
        Self::Healthy,
        Self::Degraded,
        Self::Quarantined,
        Self::ShadowWarmup,
    ];
}

/// Failure of one `decide` call. Every variant makes the host fall back to the
/// native conservative baseline for the tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyFaultV1 {
    /// Guest trapped (unreachable, OOB, stack overflow, ...).
    Trap,
    /// Wall-clock/epoch deadline expired.
    Timeout,
    /// Fuel budget exhausted (deterministic infinite loop guard).
    FuelExhausted,
    /// Linear memory limiter refused growth.
    OutOfMemory,
    /// Encoded input exceeded `POLICY_INPUT_BUDGET_BYTES`.
    InputTooLarge,
    /// Encoded output exceeded `POLICY_OUTPUT_BUDGET_BYTES`.
    OutputTooLarge,
    /// Output could not be decoded or failed `CandidateActionV1::validate`.
    InvalidOutput,
    /// `next_state` exceeded `POLICY_STATE_MAX_BYTES`.
    StateTooLarge,
    /// Guest exports a different world/version than the host expects.
    AbiMismatch,
    /// Backend is quarantined or not loaded.
    Unavailable,
    /// Host-side error unrelated to the guest.
    Internal,
}

impl PolicyFaultV1 {
    pub const ALL: [Self; 11] = [
        Self::Trap,
        Self::Timeout,
        Self::FuelExhausted,
        Self::OutOfMemory,
        Self::InputTooLarge,
        Self::OutputTooLarge,
        Self::InvalidOutput,
        Self::StateTooLarge,
        Self::AbiMismatch,
        Self::Unavailable,
        Self::Internal,
    ];
}

impl std::fmt::Display for PolicyFaultV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Trap => "guest trap",
            Self::Timeout => "deadline exceeded",
            Self::FuelExhausted => "fuel exhausted",
            Self::OutOfMemory => "out of memory",
            Self::InputTooLarge => "input too large",
            Self::OutputTooLarge => "output too large",
            Self::InvalidOutput => "invalid output",
            Self::StateTooLarge => "state too large",
            Self::AbiMismatch => "abi mismatch",
            Self::Unavailable => "backend unavailable",
            Self::Internal => "internal error",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PolicyFaultV1 {}

/// Identity of a loaded backend. Host metadata, not ABI payload, hence the
/// `String` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIdentityV1 {
    pub backend: PolicyBackendKindV1,
    /// Stable policy identifier (persistence key component).
    pub policy_id: String,
    /// Human-readable policy version from the manifest.
    pub policy_version: String,
    /// BLAKE3 digest of the module/package, `None` for native.
    pub digest: Option<[u8; 32]>,
    /// Signer identifier from the package signature, if any.
    pub signer_id: Option<String>,
    /// WIT world the backend implements.
    pub abi_world: String,
    /// State schema the backend reads/writes.
    pub state_schema: u32,
    /// Incremented on every hot swap of this backend slot.
    pub module_generation: u64,
}

impl PolicyIdentityV1 {
    /// Identity of the built-in native conservative backend.
    pub fn native(policy_id: impl Into<String>, policy_version: impl Into<String>) -> Self {
        Self {
            backend: PolicyBackendKindV1::Native,
            policy_id: policy_id.into(),
            policy_version: policy_version.into(),
            digest: None,
            signer_id: None,
            abi_world: POLICY_ABI_WORLD_V1.to_string(),
            state_schema: 0,
            module_generation: 0,
        }
    }
}

/// A policy engine the host can query once per peer per tick.
///
/// State is carried explicitly in `input.state`/`output.next_state`, so the
/// backend is free of per-peer state. `decide` still takes `&mut self`
/// because a WASM backend owns a `Store` whose fuel, epoch deadline and
/// linear memory must be reset per call, and a native backend may keep
/// call-local scratch buffers; sharing one backend across peers is done by
/// the caller (one instance per worker or a mutex), not by this trait.
pub trait PolicyBackend: Send {
    /// Identity reported in status and used for persistence keys.
    fn identity(&self) -> &PolicyIdentityV1;

    /// Produce a candidate for one tick. Must be deterministic in `input`.
    fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1>;

    /// Fuel consumed by the most recent `decide` call (0 for backends without
    /// a fuel meter, e.g. native ones). Observability only.
    fn fuel_consumed(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateActionV1, POLICY_STATE_MAX_BYTES};

    struct EchoBackend {
        identity: PolicyIdentityV1,
    }

    impl PolicyBackend for EchoBackend {
        fn identity(&self) -> &PolicyIdentityV1 {
            &self.identity
        }

        fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
            if input.state.len() > POLICY_STATE_MAX_BYTES as usize {
                return Err(PolicyFaultV1::StateTooLarge);
            }
            Ok(PolicyOutputV1 {
                candidate: CandidateActionV1::default(),
                next_state: input.state.clone(),
                ..PolicyOutputV1::default()
            })
        }
    }

    #[test]
    fn backend_trait_is_object_safe() {
        let mut backend: Box<dyn PolicyBackend> = Box::new(EchoBackend {
            identity: PolicyIdentityV1::native("echo", "0"),
        });
        assert_eq!(backend.identity().backend, PolicyBackendKindV1::Native);
        let input = PolicyInputV1 {
            state: vec![1, 2, 3],
            ..PolicyInputV1::default()
        };
        let output = backend.decide(&input).unwrap();
        assert_eq!(output.next_state, vec![1, 2, 3]);
        assert_eq!(output.candidate.apply_over(&input.previous), input.previous);
        let huge = PolicyInputV1 {
            state: vec![0; POLICY_STATE_MAX_BYTES as usize + 1],
            ..PolicyInputV1::default()
        };
        assert_eq!(backend.decide(&huge), Err(PolicyFaultV1::StateTooLarge));
        assert_eq!(format!("{}", PolicyFaultV1::Timeout), "deadline exceeded");
    }
}
