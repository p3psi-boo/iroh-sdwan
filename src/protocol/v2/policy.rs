//! Host integrations for the canonical V1 policy specification.
//!
//! The policy data model lives exclusively in `ironet-policy-core` as
//! [`PolicySpecV1`].  This module owns only host concerns: package loading,
//! runtime adapters, and the canonical JSON helpers used by offline tools.

pub mod api;
pub mod egress;
pub mod guardrails;
pub mod state;
pub mod transition;

use std::path::Path;

use anyhow::{Context, Result};
use ironet_policy_core::PolicySpecV1;

/// Configuration spelling for the embedded policy component.
pub const BUILTIN_POLICY_SOURCE_V2: &str = "builtin";

/// Decode the canonical `PolicySpecV1` JSON form used by offline training and
/// promotion tools. Production configuration intentionally accepts policy
/// components (`.wasm`) only; this helper is not a runtime policy loader.
pub fn decode_canonical_spec(bytes: &[u8], source: &str) -> Result<PolicySpecV1> {
    let spec: PolicySpecV1 = serde_json::from_slice(bytes)
        .with_context(|| format!("decoding canonical policy spec {source}"))?;
    spec.validate()
        .with_context(|| format!("validating canonical policy spec {source}"))?;
    Ok(spec)
}

/// Load an offline canonical policy specification from an absolute or
/// workspace-local path. Callers decide their own path policy.
pub fn load_canonical_spec(path: &Path) -> Result<PolicySpecV1> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decode_canonical_spec(&bytes, &path.display().to_string())
}

/// Stable content digest of the canonical JSON form. This identifies a spec
/// for offline reports only; deployed WASM components use package digests.
pub fn canonical_spec_digest(spec: &PolicySpecV1) -> Result<String> {
    spec.validate()
        .context("validating canonical policy spec")?;
    Ok(blake3::hash(&serde_json::to_vec(spec)?)
        .to_hex()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_canonical_and_not_a_builtin_source() {
        let fixture = decode_canonical_spec(
            include_bytes!("../../../config/autotune-policy-v1.json"),
            "config/autotune-policy-v1.json",
        )
        .unwrap();
        assert_eq!(fixture, PolicySpecV1::builtin());
        assert!(!canonical_spec_digest(&fixture).unwrap().is_empty());
    }

    #[test]
    fn canonical_decoder_rejects_legacy_envelope_fields() {
        let legacy = br#"{
            \"schema_version\": 1,
            \"id\": \"bandit-vivace@1\",
            \"algorithm\": \"bandit-vivace\",
            \"version\": \"fixture\",
            \"contexts\": {\"rtt_millis\": [], \"rate_mbps\": [], \"loss_ppm\": []},
            \"presets\": [],
            \"weights\": {},
            \"exploration\": {
                \"minimum_dwell_millis\": 1000,
                \"minimum_rtt_rounds\": 1,
                \"minimum_samples\": 4,
                \"maximum_cpu_per_mille\": 100,
                \"rollback_regression_per_mille\": 10
            }
        }"#;
        assert!(decode_canonical_spec(legacy, "legacy").is_err());
    }
}

pub mod package;
pub mod runtime;
pub mod signature;
pub mod status;
