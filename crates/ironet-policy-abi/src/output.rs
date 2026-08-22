//! What a policy returns from one `decide` call.

use serde::{Deserialize, Serialize};

use crate::{CandidateActionV1, POLICY_LABEL_BYTES, PolicyDecisionKindV1};

/// Fixed-length, zero-padded UTF-8 label used in diagnostics. Never used as a
/// metrics label; it exists so guests can attach a short context or arm name
/// without opening an arbitrary-string channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyLabelV1(pub [u8; POLICY_LABEL_BYTES]);

impl PolicyLabelV1 {
    /// Build a label from text, truncating to [`POLICY_LABEL_BYTES`] at a
    /// UTF-8 character boundary.
    pub fn truncated(text: &str) -> Self {
        let mut bytes = [0u8; POLICY_LABEL_BYTES];
        let mut end = text.len().min(POLICY_LABEL_BYTES);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        bytes[..end].copy_from_slice(&text.as_bytes()[..end]);
        Self(bytes)
    }

    /// Text content without the zero padding. Invalid UTF-8 (only possible
    /// from an untrusted guest) is replaced lossily.
    pub fn text(&self) -> String {
        let end = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(POLICY_LABEL_BYTES);
        String::from_utf8_lossy(&self.0[..end]).into_owned()
    }
}

/// Bounded diagnostics a policy may attach to its output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDiagnosticsV1 {
    /// Kind of decision taken this tick.
    pub decision_kind: PolicyDecisionKindV1,
    /// Context bucket label (e.g. `r1-b2-l0-dg`).
    pub context_label: PolicyLabelV1,
    /// Arm/preset the policy applied.
    pub applied_arm_label: PolicyLabelV1,
    /// Arm/preset the policy would apply without exploration.
    pub baseline_arm_label: PolicyLabelV1,
    /// Predicted utility advantage of the candidate over baseline x 1000.
    pub predicted_advantage_milli: i32,
    /// Policy confidence in the candidate (0..=1000).
    pub confidence_per_mille: u16,
    /// Candidate is an exploration.
    pub exploring: bool,
    /// Candidate is a rollback of a previous exploration.
    pub rollback: bool,
    /// Cumulative rollbacks in this path epoch.
    pub rollbacks: u32,
    /// Guest-side utility estimate x 1000; informational only, never used
    /// by promotion or rollback.
    pub guest_utility_milli: i32,
    /// Schema of `next_state`; the host keys state persistence on it.
    pub state_schema: u32,
}

/// Result of one `decide` call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutputV1 {
    pub candidate: CandidateActionV1,
    /// Opaque state for the next tick, at most `POLICY_STATE_MAX_BYTES`.
    pub next_state: Vec<u8>,
    pub diagnostics: PolicyDiagnosticsV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_truncates_on_char_boundary() {
        let label = PolicyLabelV1::truncated("上下文标签很长很长很长");
        assert_eq!(label.text(), "上下文标签");
        assert_eq!(PolicyLabelV1::truncated("").text(), "");
        assert_eq!(
            PolicyLabelV1::truncated("r1-b2-l0-datagram-host").text(),
            "r1-b2-l0-datagra"
        );
    }
}
