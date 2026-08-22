//! Binary encoding of [`LearnerStateV1`] for `PolicyInputV1::state` /
//! `PolicyOutputV1::next_state`.
//!
//! Layout (`STATE_SCHEMA_V1`), all integers little endian:
//!
//! ```text
//! offset  size  field
//! 0       4     magic  b"IPLS"  (Ironet PoLicy State)
//! 4       4     u32    state schema (== 1)
//! 8       4     u32    payload length in bytes
//! 12      n     postcard-encoded LearnerStateV1
//! ```
//!
//! The payload is `postcard` (varint integers, 8-byte IEEE `f64`, length
//! prefixed map/sequences, zig-zag signed integers); the struct layout is
//! `{ contexts: map<ContextKeyV1, ContextState>, rng: u64, path_epoch: u64,
//! rollbacks: u64 }`. Encoding is deterministic for equal states. The total
//! encoded size never exceeds `POLICY_STATE_MAX_BYTES`: when a state would
//! not fit, contexts with the fewest observations are evicted first.

use ironet_policy_abi::POLICY_STATE_MAX_BYTES;

use crate::LearnerStateV1;

/// Schema of the state encoding implemented by this crate; reported in
/// `PolicyDiagnosticsV1::state_schema` and `PolicyIdentityV1::state_schema`.
pub const STATE_SCHEMA_V1: u32 = 1;
/// Magic prefix of an encoded state.
pub const STATE_MAGIC_V1: [u8; 4] = *b"IPLS";
/// Fixed header size preceding the payload.
pub const STATE_HEADER_BYTES: usize = 12;

/// Why a state blob could not be decoded or encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateCodecError {
    /// The blob (or the smallest encodable state) exceeds the cap.
    TooLarge { len: usize, cap: usize },
    /// Fewer bytes than the fixed header.
    Truncated,
    /// Magic prefix mismatch.
    BadMagic,
    /// The blob was written by another state schema.
    UnsupportedSchema(u32),
    /// Header length does not match the payload length.
    LengthMismatch { declared: u32, actual: usize },
    /// The payload is not a valid `LearnerStateV1`.
    Malformed,
}

impl std::fmt::Display for StateCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len, cap } => write!(f, "policy state of {len} bytes exceeds {cap}"),
            Self::Truncated => f.write_str("policy state shorter than its header"),
            Self::BadMagic => f.write_str("policy state magic mismatch"),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported policy state schema {schema}")
            }
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "policy state declares {declared} payload bytes but carries {actual}"
            ),
            Self::Malformed => f.write_str("policy state payload is malformed"),
        }
    }
}

impl std::error::Error for StateCodecError {}

impl LearnerStateV1 {
    /// Decode a state produced by [`Self::encode_bounded`]. Blobs longer than
    /// `POLICY_STATE_MAX_BYTES` are rejected before parsing.
    pub fn decode(bytes: &[u8]) -> Result<Self, StateCodecError> {
        let cap = POLICY_STATE_MAX_BYTES as usize;
        if bytes.len() > cap {
            return Err(StateCodecError::TooLarge {
                len: bytes.len(),
                cap,
            });
        }
        if bytes.len() < STATE_HEADER_BYTES {
            return Err(StateCodecError::Truncated);
        }
        if bytes[..4] != STATE_MAGIC_V1 {
            return Err(StateCodecError::BadMagic);
        }
        let schema = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if schema != STATE_SCHEMA_V1 {
            return Err(StateCodecError::UnsupportedSchema(schema));
        }
        let declared = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let payload = &bytes[STATE_HEADER_BYTES..];
        if usize::try_from(declared).ok() != Some(payload.len()) {
            return Err(StateCodecError::LengthMismatch {
                declared,
                actual: payload.len(),
            });
        }
        let (state, rest): (Self, &[u8]) =
            postcard::take_from_bytes(payload).map_err(|_| StateCodecError::Malformed)?;
        if !rest.is_empty() {
            return Err(StateCodecError::Malformed);
        }
        Ok(state)
    }

    /// [`Self::decode`], treating an empty blob as a cold start seeded with
    /// `seed`.
    pub fn decode_or_cold_start(bytes: &[u8], seed: u64) -> Result<Self, StateCodecError> {
        if bytes.is_empty() {
            return Ok(Self::new(seed));
        }
        Self::decode(bytes)
    }

    /// Encode without any size bound (header + payload).
    pub fn encode_unbounded(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("learner state is always encodable");
        let mut out = Vec::with_capacity(STATE_HEADER_BYTES + payload.len());
        out.extend_from_slice(&STATE_MAGIC_V1);
        out.extend_from_slice(&STATE_SCHEMA_V1.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Encode to at most `cap_bytes` (itself capped at
    /// `POLICY_STATE_MAX_BYTES`), evicting the least-observed contexts from
    /// `self` until the blob fits, so the in-memory state always equals what
    /// was emitted. Fails only when even a context-free state does not fit.
    pub fn encode_bounded(&mut self, cap_bytes: usize) -> Result<Vec<u8>, StateCodecError> {
        let cap = cap_bytes.min(POLICY_STATE_MAX_BYTES as usize);
        loop {
            let encoded = self.encode_unbounded();
            if encoded.len() <= cap {
                return Ok(encoded);
            }
            // Evict in proportion to the overshoot (at least one context per
            // round) so a badly oversized state converges in a few rounds.
            let contexts = self.context_count().max(1);
            let per_context = (encoded.len() / contexts).max(1);
            let count = ((encoded.len() - cap) / per_context).max(1);
            if self.evict_contexts(count) == 0 {
                return Err(StateCodecError::TooLarge {
                    len: encoded.len(),
                    cap,
                });
            }
        }
    }

    /// [`Self::encode_bounded`] with the ABI-wide cap.
    pub fn encode(&mut self) -> Result<Vec<u8>, StateCodecError> {
        self.encode_bounded(POLICY_STATE_MAX_BYTES as usize)
    }
}

#[cfg(test)]
mod tests {
    use ironet_policy_abi::Bbr3PresetV1;

    use super::*;
    use crate::{ArmMemoryV1, ContextKeyV1, ContextMemoryV1, FineMemoryV1, LearnerMemoryV1};

    fn memory_with_contexts(count: u32) -> LearnerMemoryV1 {
        let mut memory = LearnerMemoryV1::default();
        for index in 0..count {
            let mut arms = [ArmMemoryV1 {
                observations: 0,
                mean: 0.0,
            }; 7];
            for (arm, slot) in arms.iter_mut().zip(0_u32..) {
                arm.observations = index % 5 + slot;
                arm.mean = f64::from(index) * 0.1 + f64::from(slot);
            }
            memory.contexts.push(ContextMemoryV1 {
                key: ContextKeyV1 {
                    rtt_class: (index % 16) as u8,
                    rate_class: ((index / 16) % 16) as u8,
                    loss_class: ((index / 256) % 4) as u8,
                    reliable: (index / 1024) % 2 == 1,
                    host_rtt: (index / 2048) % 2 == 1,
                },
                arms,
                active: Bbr3PresetV1::ALL[(index % 7) as usize],
                max_bw_bytes_per_second: u64::from(index) * 1_000_003,
                min_rtt_micros: u64::from(index) * 17,
                fine: FineMemoryV1 {
                    up_gain_delta_milli: 25,
                    headroom_delta_milli: -10,
                    cwnd_gain_delta_milli: 50,
                    direction: -1,
                },
            });
        }
        memory
    }

    #[test]
    fn state_round_trips_bit_exactly() {
        let mut state = LearnerStateV1::from_memory(&memory_with_contexts(40), 99, 5);
        state.path_epoch = 3;
        state.rollbacks = 2;
        let encoded = state.encode().unwrap();
        assert_eq!(&encoded[..4], b"IPLS");
        assert_eq!(encoded[4..8], 1_u32.to_le_bytes());
        let decoded = LearnerStateV1::decode(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(decoded.encode_unbounded(), encoded);
        assert_eq!(decoded.export_memory(), state.export_memory());
        let cold = LearnerStateV1::decode_or_cold_start(&[], 4).unwrap();
        assert_eq!(cold, LearnerStateV1::new(4));
    }

    #[test]
    fn decode_rejects_corrupt_or_foreign_blobs() {
        let mut state = LearnerStateV1::from_memory(&memory_with_contexts(2), 1, 0);
        let encoded = state.encode().unwrap();
        assert_eq!(
            LearnerStateV1::decode(&encoded[..8]),
            Err(StateCodecError::Truncated)
        );
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            LearnerStateV1::decode(&bad_magic),
            Err(StateCodecError::BadMagic)
        );
        let mut future = encoded.clone();
        future[4] = 2;
        assert_eq!(
            LearnerStateV1::decode(&future),
            Err(StateCodecError::UnsupportedSchema(2))
        );
        let mut short = encoded.clone();
        short.pop();
        assert!(matches!(
            LearnerStateV1::decode(&short),
            Err(StateCodecError::LengthMismatch { .. })
        ));
        let mut garbage = encoded.clone();
        let len = garbage.len();
        garbage[STATE_HEADER_BYTES..].fill(0xff);
        garbage[8..12].copy_from_slice(&((len - STATE_HEADER_BYTES) as u32).to_le_bytes());
        assert_eq!(
            LearnerStateV1::decode(&garbage),
            Err(StateCodecError::Malformed)
        );
        let oversized = vec![0_u8; POLICY_STATE_MAX_BYTES as usize + 1];
        assert_eq!(
            LearnerStateV1::decode(&oversized),
            Err(StateCodecError::TooLarge {
                len: POLICY_STATE_MAX_BYTES as usize + 1,
                cap: POLICY_STATE_MAX_BYTES as usize,
            })
        );
    }

    #[test]
    fn encode_evicts_least_observed_contexts_to_stay_under_the_cap() {
        let mut state = LearnerStateV1::from_memory(&memory_with_contexts(4_000), 1, 0);
        assert!(state.encode_unbounded().len() > POLICY_STATE_MAX_BYTES as usize);
        let encoded = state.encode().unwrap();
        assert!(encoded.len() <= POLICY_STATE_MAX_BYTES as usize);
        assert!(state.context_count() < 4_000);
        assert!(state.context_count() > 100);
        assert_eq!(LearnerStateV1::decode(&encoded).unwrap(), state);
        // Survivors are the most observed contexts.
        let min_survivor = state
            .contexts
            .values()
            .map(|context| {
                context
                    .posteriors
                    .iter()
                    .map(|p| u64::from(p.observations))
                    .sum::<u64>()
            })
            .min()
            .unwrap();
        assert!(min_survivor >= 21);

        let mut tiny = LearnerStateV1::from_memory(&memory_with_contexts(3), 1, 0);
        let encoded = tiny.encode_bounded(64).unwrap();
        assert!(encoded.len() <= 64);
        assert_eq!(tiny.context_count(), 0);
        assert!(matches!(
            tiny.encode_bounded(8),
            Err(StateCodecError::TooLarge { .. })
        ));
    }
}
