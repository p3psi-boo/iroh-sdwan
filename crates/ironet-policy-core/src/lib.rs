//! Policy core: the Ironet adaptive-control learner as pure logic over the
//! ABI V1 types.
//!
//! This crate is the single source of the contextual-bandit learner that used
//! to live in `ironet::protocol::v2::learner`. It is compiled twice:
//!
//! - natively, wrapped by the host (`ironet`) as the `native` policy backend
//!   and as the reference implementation the golden tests are generated from;
//! - for `wasm32-unknown-unknown`, wrapped by the builtin policy guest.
//!
//! To make that possible the crate depends on nothing but
//! `ironet-policy-abi`, `serde` and `postcard` (compact state encoding), and
//! it never touches `std::time`, randomness, threads, files or the host's
//! runtime structs. All inputs arrive as [`PolicyInputV1`]: telemetry as
//! [`PolicyTelemetryV1`], the previous action as [`EffectiveActionViewV1`],
//! the reward as [`HostUtilityV1`], time as `logical_tick` (one tick per
//! telemetry interval, i.e. one second) and randomness as
//! `deterministic_seed`. All outputs leave as [`PolicyOutputV1`] whose
//! `next_state` carries the learner memory encoded with
//! [`STATE_SCHEMA_V1`].
//!
//! Two deliberate extensions of the plain ABI exist for bit-exact parity with
//! the host's historical `f64` learner:
//!
//! - [`EXTENSION_TAG_HOST_UTILITY_F64_V1`]: an optional TLV entry in
//!   `PolicyInputV1.extensions` carrying the full-precision previous utility
//!   (`f64::to_bits`, little endian). When absent the fixed-point
//!   `previous_utility.utility_milli` is used instead.
//! - [`CorePolicy::decide_traced`]: a native-only companion of
//!   `PolicyBackend::decide` that also returns the full-precision
//!   [`LearnerTraceV1`] the bounded [`PolicyDiagnosticsV1`] is derived from.

#![forbid(unsafe_code)]

mod context;
mod learner;
mod policy;
mod rng;
mod spec;
mod state;

pub use context::*;
pub use learner::*;
pub use policy::*;
pub use spec::*;
pub use state::*;

pub use ironet_policy_abi as abi;
