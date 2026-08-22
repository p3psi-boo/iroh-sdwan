//! Print the builtin policy metadata consumed by the reproducible packaging
//! script.  Keeping this tiny host-side helper beside the guest makes the
//! manifest's identity come from `PolicySpecV1::builtin()` rather than from a
//! duplicated shell constant.

use ironet_policy_core::{EXTENSION_TAG_HOST_UTILITY_F64_V1, PolicySpecV1, STATE_SCHEMA_V1};

fn main() {
    let spec = PolicySpecV1::builtin();
    let policy_version = spec
        .id
        .rsplit_once('@')
        .and_then(|(_, version)| version.parse::<u64>().ok())
        .unwrap_or(1);
    println!("policy_id={}", spec.id);
    println!("policy_version={policy_version}");
    println!("built_at={}", spec.version);
    println!("state_schema={STATE_SCHEMA_V1}");
    println!("extension_tag={EXTENSION_TAG_HOST_UTILITY_F64_V1}");
}
