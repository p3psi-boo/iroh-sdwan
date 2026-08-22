//! Phase 0 spike guest: a pure-computation `decide` with f64 arithmetic that
//! loosely mimics a learner update (EWMA + a small bandit-style scoring loop).
//! No host imports, no WASI, `panic = "abort"`, target wasm32-unknown-unknown.

wit_bindgen::generate!({
    path: "../wit",
    world: "policy",
});

struct Policy;

impl Guest for Policy {
    fn decide(input: Vec<u8>) -> Vec<u8> {
        decide_impl(&input)
    }
}

export!(Policy);

fn decide_impl(input: &[u8]) -> Vec<u8> {
    // Interpret input as pairs of f64 (rtt_ms, loss), 16 bytes per sample.
    let mut ewma_rtt = 0.0f64;
    let mut ewma_loss = 0.0f64;
    let mut n = 0u32;
    for chunk in input.chunks_exact(16) {
        let rtt = f64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let loss = f64::from_le_bytes(chunk[8..16].try_into().unwrap());
        ewma_rtt = 0.875 * ewma_rtt + 0.125 * rtt;
        ewma_loss = 0.875 * ewma_loss + 0.125 * loss;
        n += 1;
    }
    // Score 8 candidate actions (like CandidateActionV1 arms) with a tiny loop.
    let mut best = 0usize;
    let mut best_score = f64::NEG_INFINITY;
    let mut scores = [0.0f64; 8];
    for (i, s) in scores.iter_mut().enumerate() {
        let pacing = 1.0 + i as f64 * 0.25;
        let util = pacing * (1.0 - ewma_loss) - (ewma_rtt / 100.0) * pacing * pacing * 0.05;
        let mut acc = util;
        for k in 0..32 {
            acc = acc * 0.999 + (k as f64) * 1e-6;
        }
        *s = acc;
        if acc > best_score {
            best_score = acc;
            best = i;
        }
    }
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&ewma_rtt.to_le_bytes());
    out.extend_from_slice(&ewma_loss.to_le_bytes());
    out.extend_from_slice(&best_score.to_le_bytes());
    out.extend_from_slice(&(best as u32).to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out
}
