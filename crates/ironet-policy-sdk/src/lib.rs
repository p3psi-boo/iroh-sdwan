//! Guest SDK for Ironet adaptive-control policy components.
//!
//! A policy component implements the `ironet:policy/policy@1.0.0` WIT world
//! (`crates/ironet-policy-abi/wit/ironet-policy.wit`): one pure export,
//! `decide`, no imports. This crate gives a guest everything it needs to do
//! that in Rust without touching the component ABI by hand:
//!
//! - [`bindings`]: the `wit-bindgen` guest bindings generated from the ABI
//!   crate's WIT (the WIT is referenced by path, not copied);
//! - two-way conversions between the generated binding types and the
//!   `ironet-policy-abi` types (`From`/`TryFrom`; the fallible direction maps
//!   shape errors to [`PolicyFaultV1::AbiMismatch`] for host-supplied input
//!   and [`PolicyFaultV1::InvalidOutput`] for guest-produced output);
//! - [`GuestPolicy`] + [`export_policy!`]: implement one trait over the ABI
//!   types and export it as the component's `decide` in one line;
//! - [`fixed`]: `milli`/`per-mille`/`ppm` fixed-point helpers, saturating
//!   arithmetic and a tiny deterministic RNG seeded from
//!   `PolicyInputV1::deterministic_seed`.
//!
//! Guests must stay deterministic: no wall clock, no randomness other than
//! the seed, no environment, no I/O. Build with
//! `--target wasm32-unknown-unknown` and the `wasm-guest` profile of the
//! workspace (`opt-level = "s"`, `panic = "abort"`, `lto = true`,
//! `codegen-units = 1`), then turn the core module into a component with
//! `wasm-tools component new`. See `README.md` for the full walkthrough and
//! `scripts/build-policy-guest.sh` for the reproducible build used by the
//! repository.

#![deny(unsafe_code)]

pub mod fixed;

pub mod convert;

/// Generated guest bindings for the `ironet:policy/policy@1.0.0` world.
///
/// Types live in [`bindings::ironet::policy::types`]; the world-level aliases
/// [`bindings::PolicyInput`], [`bindings::PolicyOutput`] and
/// [`bindings::PolicyFault`] point at them. [`bindings::Guest`] is the raw
/// export trait; prefer [`GuestPolicy`] + [`export_policy!`], which work on
/// the `ironet-policy-abi` types and perform the conversions for you.
///
/// This module is the only place in the crate that contains `unsafe` code
/// (the generated canonical-ABI lifting/lowering); hence the module-level
/// allow. Everything else is `#![deny(unsafe_code)]`.
#[allow(unsafe_code, missing_docs)]
pub mod bindings {
    wit_bindgen::generate!({
        path: "../ironet-policy-abi/wit",
        world: "policy",
        pub_export_macro: true,
        export_macro_name: "export_policy_bindings",
        default_bindings_module: "ironet_policy_sdk::bindings",
        generate_unused_types: true,
        additional_derives: [PartialEq, Eq],
    });
}

pub use convert::{label_from_wit, label_to_wit};
pub use ironet_policy_abi as abi;
pub use ironet_policy_abi::{
    POLICY_ABI_MAJOR_V1, POLICY_ABI_MINOR_V1, POLICY_ABI_WORLD_V1, POLICY_STATE_MAX_BYTES,
    PolicyFaultV1, PolicyInputV1, PolicyOutputV1,
};

/// A policy written against the ABI types. Implement it for a unit struct
/// and hand that struct to [`export_policy!`].
///
/// `decide` is an associated function, not a method: a component has no
/// ambient instance, all state travels in `input.state` / `next_state`.
/// Implementations must be deterministic in `input` (same input, same
/// output, bit for bit) and must not exceed `input.limits.state_cap_bytes`
/// in `next_state`.
pub trait GuestPolicy {
    /// Produce the candidate for one tick.
    fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1>;
}

/// Glue between the generated [`bindings::Guest`] and a [`GuestPolicy`]:
/// converts the input, runs the policy, checks the state budget and converts
/// the output. Used by [`export_policy!`]; public so tests and the builtin
/// guest can run the exact exported path natively.
pub fn run_decide<P: GuestPolicy>(
    input: bindings::PolicyInput,
) -> Result<bindings::PolicyOutput, bindings::PolicyFault> {
    let input = PolicyInputV1::try_from(input).map_err(bindings::PolicyFault::from)?;
    let output = P::decide(&input).map_err(bindings::PolicyFault::from)?;
    if output.next_state.len() > state_cap_bytes(&input) as usize {
        return Err(bindings::PolicyFault::StateTooLarge);
    }
    Ok(output.into())
}

/// The `next_state` budget that applies to `input`: the host's
/// `limits.state_cap_bytes`, or [`POLICY_STATE_MAX_BYTES`] when the host
/// sent `0`, never more than [`POLICY_STATE_MAX_BYTES`].
pub fn state_cap_bytes(input: &PolicyInputV1) -> u32 {
    match input.limits.state_cap_bytes {
        0 => POLICY_STATE_MAX_BYTES,
        cap => cap.min(POLICY_STATE_MAX_BYTES),
    }
}

/// Export a [`GuestPolicy`] implementation as the component's `decide`.
///
/// ```ignore
/// use ironet_policy_sdk::{GuestPolicy, PolicyFaultV1, PolicyInputV1, PolicyOutputV1};
///
/// struct Conservative;
///
/// impl GuestPolicy for Conservative {
///     fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
///         Ok(PolicyOutputV1 { next_state: input.state.clone(), ..PolicyOutputV1::default() })
///     }
/// }
///
/// ironet_policy_sdk::export_policy!(Conservative);
/// ```
///
/// The expansion contains the generated `#[unsafe(export_name = "decide")]`
/// trampolines, so it carries its own `#[allow(unsafe_code)]`; the invoking
/// crate can keep `#![deny(unsafe_code)]` (but not `forbid`).
#[macro_export]
macro_rules! export_policy {
    ($policy:ty) => {
        #[allow(unsafe_code)]
        const _: () = {
            struct __IronetPolicyComponent;

            impl $crate::bindings::Guest for __IronetPolicyComponent {
                fn decide(
                    input: $crate::bindings::PolicyInput,
                ) -> ::core::result::Result<
                    $crate::bindings::PolicyOutput,
                    $crate::bindings::PolicyFault,
                > {
                    $crate::run_decide::<$policy>(input)
                }
            }

            $crate::bindings::export_policy_bindings!(
                __IronetPolicyComponent with_types_in $crate::bindings
            );
        };
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironet_policy_abi::{CandidateActionV1, HostLimitsV1};

    struct Echo;

    impl GuestPolicy for Echo {
        fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
            Ok(PolicyOutputV1 {
                candidate: CandidateActionV1::default(),
                next_state: input.state.clone(),
                ..PolicyOutputV1::default()
            })
        }
    }

    struct Faulty;

    impl GuestPolicy for Faulty {
        fn decide(_: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
            Err(PolicyFaultV1::Internal)
        }
    }

    #[test]
    fn run_decide_round_trips_through_the_bindings() {
        let input = PolicyInputV1 {
            state: vec![1, 2, 3],
            ..PolicyInputV1::default()
        };
        let output = run_decide::<Echo>(input.into()).unwrap();
        assert_eq!(output.next_state, vec![1, 2, 3]);
        assert_eq!(
            PolicyOutputV1::try_from(output).unwrap().candidate,
            CandidateActionV1::default()
        );
    }

    #[test]
    fn run_decide_maps_faults_and_state_budget() {
        assert_eq!(
            run_decide::<Faulty>(PolicyInputV1::default().into()),
            Err(bindings::PolicyFault::Internal)
        );
        let too_big = PolicyInputV1 {
            limits: HostLimitsV1 {
                state_cap_bytes: 2,
                ..HostLimitsV1::default()
            },
            state: vec![0; 3],
            ..PolicyInputV1::default()
        };
        assert_eq!(
            run_decide::<Echo>(too_big.into()),
            Err(bindings::PolicyFault::StateTooLarge)
        );
        let mut bad_hash: bindings::PolicyInput = PolicyInputV1::default().into();
        bad_hash.peer_hash.pop();
        assert_eq!(
            run_decide::<Echo>(bad_hash),
            Err(bindings::PolicyFault::AbiMismatch)
        );
    }

    #[test]
    fn state_cap_defaults_and_saturates() {
        let mut input = PolicyInputV1::default();
        input.limits.state_cap_bytes = 0;
        assert_eq!(state_cap_bytes(&input), POLICY_STATE_MAX_BYTES);
        input.limits.state_cap_bytes = u32::MAX;
        assert_eq!(state_cap_bytes(&input), POLICY_STATE_MAX_BYTES);
        input.limits.state_cap_bytes = 512;
        assert_eq!(state_cap_bytes(&input), 512);
    }
}
