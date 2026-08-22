//! Transition controller: rate-limits how fast a guarded action may move
//! between ticks.
//!
//! The policy and the guardrails are stateless per tick; this stage owns the
//! only cross-tick smoothing state of the pipeline:
//!
//! - **FEC hysteresis** -- enabling or changing protection requires the same
//!   geometry to be proposed on [`FEC_CONFIRMATION_SAMPLES`] consecutive
//!   ticks and at least [`FEC_CHANGE_COOLDOWN`] since the last protection
//!   change, unless the live sample is a loss emergency. Turning protection
//!   off is fail-safe and always immediate.
//! - **Buffer steps** -- the PacketTrain target, the TX send buffer and the
//!   RX receive buffer move at most one step per tick towards the proposed
//!   value, so batch/buffer outputs never oscillate.
//!
//! Every value it holds back is recorded in the [`ClampReportV1`] with
//! [`ClampReasonV1::TransitionHold`]. A path change or a telemetry outage
//! resets the controller through [`TransitionControllerV1::reset`].

use std::time::{Duration, Instant};

use crate::protocol::v2::{
    fec::FecGeometryV2,
    policy::api::*,
    tuning::{FilteredTelemetryV1, RECEIVE_PRESSURE_GROWTH_STEP_BYTES},
};

/// Consecutive ticks that must propose the same protection geometry before
/// it is installed (unless the live sample is an emergency).
pub const FEC_CONFIRMATION_SAMPLES: u8 = 3;
/// Minimum time between two protection changes (unless emergency).
pub const FEC_CHANGE_COOLDOWN: Duration = Duration::from_secs(1);
/// PacketTrain target step per tick.
pub const TRAIN_TARGET_STEP_BYTES: u32 = 8 * 1024;
/// TX send-buffer step per tick.
pub const SEND_BUFFER_STEP_BYTES: u64 = 256 * 1024;
/// RX receive-buffer step per tick without reassembly pressure.
pub const RECEIVE_BUFFER_STEP_BYTES: u64 = 512 * 1024;
/// RX receive-buffer step per tick while the live sample reports
/// reassembly pressure.
pub const RECEIVE_PRESSURE_STEP_BYTES: u64 = RECEIVE_PRESSURE_GROWTH_STEP_BYTES as u64;

/// Live facts the controller reads from the current tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransitionContextV1 {
    /// Live loss emergency: protection changes bypass hysteresis.
    pub protection_emergency: bool,
    /// The live sample reported reassembly-pressure evictions: the receive
    /// buffer may grow by the pressure step.
    pub receive_pressure: bool,
}

impl TransitionContextV1 {
    pub fn from_filtered(filtered: &FilteredTelemetryV1) -> Self {
        Self {
            protection_emergency: filtered.protection_emergency(),
            receive_pressure: filtered.receive_pressure(),
        }
    }
}

/// Cross-tick smoothing state (see the module documentation).
#[derive(Debug, Clone, Copy)]
pub struct TransitionControllerV1 {
    candidate_fec: Option<FecGeometryV2>,
    candidate_repeats: u8,
    last_change: Instant,
}

impl TransitionControllerV1 {
    pub fn new(now: Instant) -> Self {
        Self {
            candidate_fec: None,
            candidate_repeats: 0,
            last_change: now,
        }
    }

    /// Forget the pending protection candidate and restart the cooldown.
    pub fn reset(&mut self, now: Instant) {
        *self = Self::new(now);
    }

    /// Geometry currently accumulating confirmations, if any.
    pub fn pending_fec(&self) -> Option<FecGeometryV2> {
        self.candidate_fec
    }

    /// Confirmations the pending geometry has accumulated.
    pub fn pending_repeats(&self) -> u8 {
        self.candidate_repeats
    }

    /// Smooth `proposed` against `previous`, the effective action of the
    /// prior tick. Returns the rate-limited action plus every hold applied.
    pub fn smooth(
        &mut self,
        proposed: &EffectiveActionV1,
        previous: &EffectiveActionV1,
        now: Instant,
        ctx: &TransitionContextV1,
    ) -> (EffectiveActionV1, ClampReportV1) {
        let mut out = proposed.clone();
        let mut report = ClampReportV1::default();

        // A single unprotected Cell can invalidate a much larger GSO record.
        // Once a live sample crosses the protection threshold, waiting three
        // more observations makes the inner TCP recover from repeated
        // multi-second RTOs; install sparse protection immediately and keep
        // fail-safe removal immediate as well.
        let proposed_fec = proposed.fec.to_geometry();
        let current_fec = previous.fec.to_geometry();
        if proposed_fec != current_fec {
            if proposed_fec.is_none() {
                // Protection is fail-safe-off: once the evidence no longer
                // justifies parity, stop it immediately instead of injecting
                // more observation windows of known-wasted bytes. Re-enabling
                // remains hysteretic, so a single noisy sample cannot flap
                // parity back on.
                self.candidate_fec = None;
                self.candidate_repeats = 0;
                self.last_change = now;
            } else {
                if proposed_fec == self.candidate_fec {
                    self.candidate_repeats = self.candidate_repeats.saturating_add(1);
                } else {
                    self.candidate_fec = proposed_fec;
                    self.candidate_repeats = 1;
                }
                let cooldown_complete =
                    now.saturating_duration_since(self.last_change) >= FEC_CHANGE_COOLDOWN;
                if !ctx.protection_emergency
                    && (self.candidate_repeats < FEC_CONFIRMATION_SAMPLES || !cooldown_complete)
                {
                    out.fec = FecEffectiveV1::from_geometry(current_fec);
                    report.entries.push(ClampEntryV1::new(
                        ClampFieldV1::FecEnabled,
                        i64::from(proposed.fec.enabled),
                        i64::from(out.fec.enabled),
                        ClampReasonV1::TransitionHold,
                    ));
                } else {
                    self.candidate_repeats = 0;
                    self.last_change = now;
                }
            }
        } else {
            self.candidate_repeats = 0;
        }

        // Performance outputs are intentionally smoother than the protection
        // loop: one step per observation prevents batch/buffer oscillation.
        out.scheduler.train_target_bytes = step_reported(
            ClampFieldV1::SchedulerTrainTargetBytes,
            u64::from(previous.scheduler.train_target_bytes),
            u64::from(proposed.scheduler.train_target_bytes),
            u64::from(TRAIN_TARGET_STEP_BYTES),
            &mut report,
        ) as u32;
        out.tx.send_buffer_bytes = step_reported(
            ClampFieldV1::TxSendBufferBytes,
            previous.tx.send_buffer_bytes,
            proposed.tx.send_buffer_bytes,
            SEND_BUFFER_STEP_BYTES,
            &mut report,
        );
        let receive_step = if ctx.receive_pressure {
            RECEIVE_PRESSURE_STEP_BYTES
        } else {
            RECEIVE_BUFFER_STEP_BYTES
        };
        out.rx.receive_buffer_bytes = step_reported(
            ClampFieldV1::RxReceiveBufferBytes,
            previous.rx.receive_buffer_bytes,
            proposed.rx.receive_buffer_bytes,
            receive_step,
            &mut report,
        );
        (out, report)
    }
}

/// Move `current` one `step` towards `target`, recording a hold when the
/// target was not reached.
fn step_reported(
    field: ClampFieldV1,
    current: u64,
    target: u64,
    step: u64,
    report: &mut ClampReportV1,
) -> u64 {
    let next = if target > current {
        current.saturating_add(step).min(target)
    } else {
        current.saturating_sub(step).max(target)
    };
    if next != target {
        report.entries.push(ClampEntryV1::new(
            field,
            i64::try_from(target).unwrap_or(i64::MAX),
            i64::try_from(next).unwrap_or(i64::MAX),
            ClampReasonV1::TransitionHold,
        ));
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry(data_cells: usize, parity_cells: usize) -> FecEffectiveV1 {
        FecEffectiveV1::from_geometry(Some(FecGeometryV2 {
            data_cells,
            parity_cells,
        }))
    }

    fn action(fec: FecEffectiveV1) -> EffectiveActionV1 {
        EffectiveActionV1 {
            fec,
            scheduler: SchedulerEffectiveV1 {
                train_target_bytes: 16 * 1024,
                bulk_quantum_cells: 1,
                ..SchedulerEffectiveV1::default()
            },
            tx: TxEffectiveV1 {
                send_buffer_bytes: 256 * 1024,
                ..TxEffectiveV1::default()
            },
            rx: RxEffectiveV1 {
                receive_buffer_bytes: 8 * 1024 * 1024,
                receive_batch: 64,
                ..RxEffectiveV1::default()
            },
            ..EffectiveActionV1::default()
        }
    }

    #[test]
    fn enabling_protection_needs_three_confirmations_and_a_cooldown() {
        let start = Instant::now();
        let mut controller = TransitionControllerV1::new(start);
        let previous = action(FecEffectiveV1::default());
        let proposed = action(geometry(8, 1));
        let ctx = TransitionContextV1::default();

        for tick in 0..2 {
            let (out, report) = controller.smooth(
                &proposed,
                &previous,
                start + Duration::from_secs(tick),
                &ctx,
            );
            assert!(!out.fec.enabled, "tick {tick} must still hold");
            assert!(report.entries.iter().any(|entry| {
                entry.field == ClampFieldV1::FecEnabled
                    && entry.reason == ClampReasonV1::TransitionHold
            }));
        }
        let (out, report) =
            controller.smooth(&proposed, &previous, start + Duration::from_secs(2), &ctx);
        assert_eq!(out.fec, geometry(8, 1));
        assert!(report.is_empty(), "{report:?}");
        assert_eq!(controller.pending_repeats(), 0);
    }

    #[test]
    fn cooldown_alone_holds_a_confirmed_geometry() {
        let start = Instant::now();
        let mut controller = TransitionControllerV1::new(start);
        let previous = action(FecEffectiveV1::default());
        let proposed = action(geometry(8, 1));
        let ctx = TransitionContextV1::default();
        for _ in 0..3 {
            let (out, _) = controller.smooth(&proposed, &previous, start, &ctx);
            assert!(!out.fec.enabled, "three repeats inside the cooldown hold");
        }
        let (out, _) = controller.smooth(&proposed, &previous, start + FEC_CHANGE_COOLDOWN, &ctx);
        assert!(out.fec.enabled);
    }

    #[test]
    fn emergency_bypasses_hysteresis_and_disable_is_immediate() {
        let start = Instant::now();
        let mut controller = TransitionControllerV1::new(start);
        let off = action(FecEffectiveV1::default());
        let on = action(geometry(4, 2));
        let emergency = TransitionContextV1 {
            protection_emergency: true,
            receive_pressure: false,
        };
        let (out, report) = controller.smooth(&on, &off, start, &emergency);
        assert_eq!(out.fec, geometry(4, 2));
        assert!(report.is_empty());

        let calm = TransitionContextV1::default();
        let (out, report) = controller.smooth(&off, &on, start + Duration::from_millis(10), &calm);
        assert!(!out.fec.enabled, "fail-safe off is never held");
        assert!(report.is_empty());
        assert_eq!(controller.pending_fec(), None);
    }

    #[test]
    fn a_changed_candidate_restarts_the_confirmation_count() {
        let start = Instant::now();
        let mut controller = TransitionControllerV1::new(start);
        let previous = action(FecEffectiveV1::default());
        let ctx = TransitionContextV1::default();
        controller.smooth(&action(geometry(8, 1)), &previous, start, &ctx);
        controller.smooth(
            &action(geometry(8, 1)),
            &previous,
            start + Duration::from_secs(1),
            &ctx,
        );
        assert_eq!(controller.pending_repeats(), 2);
        let (out, _) = controller.smooth(
            &action(geometry(6, 2)),
            &previous,
            start + Duration::from_secs(2),
            &ctx,
        );
        assert!(!out.fec.enabled);
        assert_eq!(
            controller.pending_fec(),
            Some(FecGeometryV2 {
                data_cells: 6,
                parity_cells: 2
            })
        );
        assert_eq!(controller.pending_repeats(), 1);
    }

    #[test]
    fn buffers_move_one_step_per_tick_and_pressure_widens_the_receive_step() {
        let start = Instant::now();
        let mut controller = TransitionControllerV1::new(start);
        let previous = action(FecEffectiveV1::default());
        let mut proposed = previous.clone();
        proposed.scheduler.train_target_bytes = 64 * 1024;
        proposed.tx.send_buffer_bytes = 4 * 1024 * 1024;
        proposed.rx.receive_buffer_bytes = 32 * 1024 * 1024;

        let (out, report) =
            controller.smooth(&proposed, &previous, start, &TransitionContextV1::default());
        assert_eq!(out.scheduler.train_target_bytes, 24 * 1024);
        assert_eq!(out.tx.send_buffer_bytes, 512 * 1024);
        assert_eq!(out.rx.receive_buffer_bytes, 8 * 1024 * 1024 + 512 * 1024);
        assert_eq!(
            report
                .entries
                .iter()
                .filter(|entry| entry.reason == ClampReasonV1::TransitionHold)
                .count(),
            3
        );

        let pressure = TransitionContextV1 {
            protection_emergency: false,
            receive_pressure: true,
        };
        let (out, _) = controller.smooth(&proposed, &previous, start, &pressure);
        assert_eq!(out.rx.receive_buffer_bytes, 16 * 1024 * 1024);

        // Shrinking is symmetric and stops exactly at the target.
        let mut shrink = previous.clone();
        shrink.scheduler.train_target_bytes = 12 * 1024;
        let (out, _) =
            controller.smooth(&shrink, &previous, start, &TransitionContextV1::default());
        assert_eq!(out.scheduler.train_target_bytes, 12 * 1024);
    }

    #[test]
    fn reset_forgets_the_pending_candidate_and_restarts_the_cooldown() {
        let start = Instant::now();
        let mut controller = TransitionControllerV1::new(start);
        let previous = action(FecEffectiveV1::default());
        let proposed = action(geometry(8, 1));
        let ctx = TransitionContextV1::default();
        controller.smooth(&proposed, &previous, start, &ctx);
        controller.smooth(&proposed, &previous, start + Duration::from_secs(1), &ctx);
        controller.reset(start + Duration::from_secs(2));
        assert_eq!(controller.pending_fec(), None);
        let (out, _) =
            controller.smooth(&proposed, &previous, start + Duration::from_secs(2), &ctx);
        assert!(
            !out.fec.enabled,
            "reset must restart the confirmation count"
        );
        assert_eq!(controller.pending_repeats(), 1);
    }
}
