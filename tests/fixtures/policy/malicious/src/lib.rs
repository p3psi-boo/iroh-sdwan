#![allow(unreachable_code, unused_variables)]

extern crate alloc;

use ironet_policy_sdk::abi::{PolicyInputV1, PolicyOutputV1};
#[cfg(any(
    feature = "invalid-enum",
    feature = "oversized-output",
    feature = "overflow-action",
    feature = "all-maximums"
))]
use ironet_policy_sdk::abi::CandidateActionV1;
#[cfg(feature = "oversized-output")]
use ironet_policy_sdk::abi::PolicyExtensionV1;
#[cfg(any(feature = "overflow-action", feature = "all-maximums"))]
use ironet_policy_sdk::abi::BbrCandidateV1;
#[cfg(feature = "invalid-enum")]
use ironet_policy_sdk::abi::FecCandidateV1;
use ironet_policy_sdk::{GuestPolicy, PolicyFaultV1};

struct Fixture;

impl GuestPolicy for Fixture {
    fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        #[cfg(feature = "loop")]
        loop {
            core::hint::spin_loop();
        }

        #[cfg(feature = "fuel-burn")]
        {
            let mut accumulator = 0u64;
            loop {
                accumulator = core::hint::black_box(
                    accumulator.wrapping_add(0x9e37_79b9_7f4a_7c15),
                );
            }
        }

        #[cfg(feature = "memory-grow")]
        {
            let mut bytes = alloc::vec![0u8; 16 * 1024 * 1024];
            for (index, byte) in bytes.iter_mut().step_by(4096).enumerate() {
                *byte = index as u8;
            }
            core::hint::black_box(bytes);
        }

        #[cfg(feature = "trap")]
        panic!("fixture trap");

        #[cfg(feature = "oversized-state")]
        return Ok(PolicyOutputV1 {
            next_state: alloc::vec![0; 65 * 1024],
            ..PolicyOutputV1::default()
        });

        #[cfg(feature = "oversized-output")]
        return Ok(PolicyOutputV1 {
            candidate: CandidateActionV1 {
                extensions: alloc::vec![PolicyExtensionV1 {
                    tag: 0xffff,
                    payload: alloc::vec![0; 63 * 1024],
                }],
                ..CandidateActionV1::default()
            },
            ..PolicyOutputV1::default()
        });

        #[cfg(feature = "invalid-enum")]
        return Ok(PolicyOutputV1 {
            candidate: CandidateActionV1 {
                fec: Some(FecCandidateV1 {
                    enabled: Some(true),
                    data_cells: Some(1),
                    parity_cells: Some(255),
                    ..FecCandidateV1::default()
                }),
                ..CandidateActionV1::default()
            },
            ..PolicyOutputV1::default()
        });

        #[cfg(feature = "overflow-action")]
        return Ok(PolicyOutputV1 {
            candidate: CandidateActionV1 {
                bbr: Some(BbrCandidateV1 {
                    headroom_milli: Some(u32::MAX),
                    beta_milli: Some(u32::MAX),
                    cwnd_floor_bytes: Some(u64::MAX),
                    ..BbrCandidateV1::default()
                }),
                ..CandidateActionV1::default()
            },
            ..PolicyOutputV1::default()
        });

        #[cfg(feature = "all-maximums")]
        return Ok(PolicyOutputV1 {
            candidate: CandidateActionV1 {
                bbr: Some(BbrCandidateV1 {
                    probe_bw_up_pacing_gain_milli: Some(u32::MAX),
                    probe_bw_down_pacing_gain_milli: Some(u32::MAX),
                    cruise_pacing_gain_milli: Some(u32::MAX),
                    default_cwnd_gain_milli: Some(u32::MAX),
                    probe_bw_up_cwnd_gain_milli: Some(u32::MAX),
                    headroom_milli: Some(u32::MAX),
                    beta_milli: Some(u32::MAX),
                    loss_threshold_milli: Some(u32::MAX),
                    queue_guard_inflation_milli: Some(u32::MAX),
                    queue_guard_slack_micros: Some(u64::MAX),
                    probe_rtt_interval_millis: Some(u64::MAX),
                    probe_rtt_duration_millis: Some(u64::MAX),
                    pacing_cap_bytes_per_second: Some(u64::MAX),
                    cwnd_floor_bytes: Some(u64::MAX),
                    cwnd_cap_bytes: Some(u64::MAX),
                    startup_bw_hint_bytes_per_second: Some(u64::MAX),
                    ..BbrCandidateV1::default()
                }),
                ..CandidateActionV1::default()
            },
            ..PolicyOutputV1::default()
        });

        #[cfg(feature = "non-deterministic-attempt")]
        {
            // This executes a floating-point NaN operation.  The host engine
            // enables Cranelift NaN canonicalisation; the value never enters
            // the ABI, so the resulting output remains bit-for-bit stable.
            let nan = 0.0f64 / 0.0f64;
            let mut output = PolicyOutputV1::default();
            output.diagnostics.guest_utility_milli = nan.to_bits() as i32;
            return Ok(output);
        }

        Ok(PolicyOutputV1 {
            next_state: input.state.clone(),
            ..PolicyOutputV1::default()
        })
    }
}

ironet_policy_sdk::export_policy!(Fixture);
