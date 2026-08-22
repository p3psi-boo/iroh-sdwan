//! Deterministic xorshift64 generator; the only randomness of the learner.
//! Seeded from `PolicyInputV1::deterministic_seed` on cold start and carried
//! in the state afterwards.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeterministicRng(pub(crate) u64);

impl DeterministicRng {
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub(crate) fn uniform(&mut self) -> f64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        (value as f64 + 1.0) / (u64::MAX as f64 + 2.0)
    }

    pub(crate) fn standard_normal(&mut self) -> f64 {
        let u1 = self.uniform().max(f64::MIN_POSITIVE);
        let u2 = self.uniform();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_seed_is_lifted_and_sequence_is_reproducible() {
        let mut a = DeterministicRng::seeded(0);
        let mut b = DeterministicRng::seeded(1);
        assert_eq!(a, b);
        let left: Vec<f64> = (0..8).map(|_| a.standard_normal()).collect();
        let right: Vec<f64> = (0..8).map(|_| b.standard_normal()).collect();
        assert_eq!(left, right);
        assert!(left.iter().all(|value| value.is_finite()));
        let mut c = DeterministicRng::seeded(2);
        assert_ne!(c.uniform(), DeterministicRng::seeded(1).uniform());
    }
}
