mod max_filter;
mod tunables;

pub use tunables::{Bbr3Params, Bbr3Tunables};

use crate::RttEstimator;
use crate::congestion::bbr3::max_filter::MaxFilter;
use crate::congestion::{Controller, ControllerFactory, ControllerMetrics, ControllerSnapshot};
use crate::{Duration, Instant};
use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg32;
use std::any::Any;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Number of complete ProbeBW cycles retained by the maximum-delivery filter.
///
/// Two cycles are sufficient for a lossless flow, but on an 80-180 ms tunnel
/// with burst loss one low four-packet phase can expire the only capacity
/// sample before ProbeUp has time to repair it. Pacing and cwnd then shrink
/// together and recovery takes minutes. Ten cycles is still bounded, matches
/// the traditional BBR max-bandwidth horizon, and path migration constructs a
/// fresh controller so stale capacity is not carried across route changes.
const MAX_BW_FILTER_LEN: usize = 10;

/// equivalent to BBR.ExtraAckedFilterLen <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.11>
const EXTRA_ACKED_FILTER_LEN: usize = 10;

/// safety mechanism to flag packets as stale within our tracking VecDeque. rounds refer to <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1>.
/// The value of 10 rounds is picked because normally after max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity) <https://datatracker.ietf.org/doc/html/rfc9002#section-6.1.2>
/// the packet should have been declared lost already, this is just to guarantee that the VecDeque doesn't grow indefinitely.
const ROUND_COUNT_WINDOW: u64 = 10;

/// the minimum for the maximum datagram size <https://datatracker.ietf.org/doc/html/rfc9000#section-14>
const MIN_MAX_DATAGRAM_SIZE: u16 = 1200;

/// the maximum for the maximum datagram size <https://datatracker.ietf.org/doc/html/rfc9000#section-18.2>
const MAX_DATAGRAM_SIZE: u64 = 65527;

/// 1.2Mbps converted to bytes/sec, used to determine `send_quantum`.
/// this is the pacing rate used where we don't authorize a burst bigger than a full packet
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const PACING_RATE_1_2MBPS: f64 = 1_200_000.0 / 8.0;

/// 24Mbps converted to bytes/sec.
/// this is the pacing rate used where we don't authorize a burst bigger than two full packets
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const PACING_RATE_24MBPS: f64 = 24_000_000.0 / 8.0;

/// 64 Kb in bytes
/// this is the maximum size we want for a quantum in `set_send_quantum`
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const HIGH_PACE_MAX_QUANTUM: u64 = 64 * 1000;

/// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
/// the sending rate to double each round (4 * ln(2) ~= 2.77)
/// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const STARTUP_PACING_GAIN: f64 = 2.773;

/// equivalent to BBR.PacingMarginPercent: The static discount factor of 1% used to scale BBR.bw to produce C.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 1.0;

/// equivalent to BBR.DefaultCwndGain: A constant specifying the minimum gain value that allows the sending rate to double each round (2) BBRStartupCwndGain.
/// Used by default in most phases for BBR.cwnd_gain.
const DEFAULT_CWND_GAIN: f64 = 2.0;

/// equivalent to BBR.DrainPacingGain: A constant specifying the pacing gain value used in Drain mode,
/// to attempt to drain the estimated queue at the bottleneck link in one round-trip or less.
/// As noted in BBRDrainPacingGain, any value at or below 1 / BBRStartupCwndGain = 1 / 2 = 0.5 will theoretically achieve this.
/// BBR uses the value 0.5, which has been shown to offer good performance when compared with other alternatives.
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.4>
/// <https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_drain_gain.pdf>
const DRAIN_PACING_GAIN: f64 = 1.0 / DEFAULT_CWND_GAIN;

// A short-RTT shallow policer drops instead of retaining a measurable queue,
// so the RTT guard cannot distinguish it from random radio loss. Aggregate
// outcomes over 500 ms so QUIC's delayed/batched loss declarations remain in
// the same sample as their ACKs. Sustained >=2% loss below 20 ms RTT backs
// pacing off multiplicatively, while a clean window probes upward. Long-haul and
// radio paths stay on the FEC/Repair path instead of being rate-capped.
const POLICER_RTT_CEILING: Duration = Duration::from_millis(20);
const POLICER_SAMPLE_WINDOW: Duration = Duration::from_millis(500);
const POLICER_MIN_SAMPLE_BYTES: u64 = 64 * 1024;
const POLICER_LOSS_THRESHOLD: f64 = 0.02;
const POLICER_CLEAN_THRESHOLD: f64 = 0.005;
const POLICER_MIN_PACING_SCALE: f64 = 0.80;
const POLICER_MAX_SINGLE_DECREASE: f64 = 0.90;
const POLICER_ADDITIVE_RECOVERY: f64 = 0.02;

/// equivalent to BBR.MinRTTFilterLen: A constant specifying the length of the BBR.min_rtt min filter window, BBR.MinRTTFilterLen is 10 secs.
const MIN_RTT_FILTER_LEN: u64 = 10;

/// multiplier used to check growth when validating if the full bandwidth has been reached
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
const FULL_BW_GROWTH: f64 = 1.25;

/// maximum number of rounds needed before we consider that the pipe is full <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
const MAX_FULL_BW_COUNT: u64 = 3;

/// when setting `bw_probe_up_rounds` when raising our inflight long term slope we don't go above this
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
const MAX_LONG_TERM_PROBE_UP_ROUNDS: u32 = 30;

/// max number of rounds used when deciding to coexist with Reno / CUBIC <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.1>
const MAX_RENO_ROUNDS: u64 = 63;

/// Substates when probing bandwidth
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProbeBwSubstate {
    /// Deceleration: sends slower than delivery rate to reduce queue
    /// equivalent to ProbeBW_DOWN <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.1>
    Down,

    /// Cruising: sends at delivery rate to maintain high utilization
    /// equivalent to ProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.2>
    Cruise,

    /// Refill: sends at BBR.bw for one RTT to fill pipe before probing up
    /// equivalent to ProbeBW_REFILL <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.3>
    Refill,

    /// Acceleration: sends faster than delivery rate to probe for more bandwidth
    /// equivalent to ProbeBW_UP <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.4>
    Up,
}

/// State Machine description from BBR3
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BbrState {
    /// Initial state: rapidly probes for bandwidth using high pacing_gain
    /// equivalent to Startup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1>
    Startup,

    /// Drains queue created during Startup by using low pacing_gain (< 1.0)
    /// equivalent to Drain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2>
    Drain,

    /// Steady-state phase that cycles through bandwidth probing tactics
    /// equivalent to ProbeBW states <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3>
    ProbeBw(ProbeBwSubstate),

    /// Temporarily reduces inflight to measure true min_rtt
    /// equivalent to ProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4>
    ProbeRtt,
}

/// Ack phases used during ProbeBW states
/// equivalent to BBR.ack_phase states <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AckPhase {
    /// equivalent to ACKS_PROBE_STARTING
    ProbeStarting,
    /// equivalent to ACKS_PROBE_STOPPING
    ProbeStopping,
    /// equivalent to ACKS_REFILLING
    Refilling,
    /// equivalent to ACKS_PROBE_FEEDBACK
    ProbeFeedback,
}

/// Description of a packet for the purposes of analysis through BBR3
/// all volumes of data use bytes, all rates of data use bytes/sec
/// equivalent to P <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.1.2>
#[derive(Debug, Clone, Copy)]
struct BbrPacket {
    /// equivalent to P.delivered: C.delivered when the packet was sent from transport connection C.
    delivered: u64,
    /// equivalent to P.delivered_time: C.delivered_time when the packet was sent.
    delivered_time: Instant,
    /// equivalent to P.first_send_time: C.first_send_time when the packet was sent.
    first_send_time: Instant,
    /// equivalent to P.send_time: The pacing departure time selected when the packet was scheduled to be sent.
    send_time: Instant,
    /// equivalent to P.is_app_limited: true if C.app_limited was non-zero when the packet was sent, else false.
    is_app_limited: bool,
    /// equivalent to P.tx_in_flight: C.inflight immediately after the transmission of packet P.
    tx_in_flight: u64,
    /// packet number from the connection
    packet_number: u64,
    /// packet size in bytes
    size: u16,
    /// equivalent to P.lost: C.lost when the packet was sent
    lost: u64,
    /// used to flag acknowledgement within our VecDeque, a packet can be flagged lost after having been flagged acknowledged
    /// hence the necessity of this flag being set before we remove it from packets.
    acknowledged: bool,
    /// used to mark packets stale if they're far from the current round <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1>
    round_count: u64,
}

/// Description of a per-ack rate sample state that will allow us to determine a short term evolution of the connection
/// equivalent to RS <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.2>
#[derive(Debug, Clone, Copy)]
struct BbrRateSample {
    /// equivalent to RS.delivery_rate: The delivery rate (aka bandwidth) sample obtained from the packet that has just been ACKed.
    delivery_rate: f64,
    /// equivalent to RS.is_app_limited: The P.is_app_limited from the most recent packet
    ///    delivered; indicates whether the rate sample is application-limited.
    is_app_limited: bool,
    /// equivalent to RS.interval: The length of the sampling interval.
    interval: Duration,
    /// equivalent to RS.delivered: The volume of data delivered between the transmission of the packet that has just been ACKed and the current time.
    delivered: u64,
    /// equivalent to RS.prior_delivered: The P.delivered count from the most recent packet delivered.
    prior_delivered: u64,
    /// equivalent to RS.prior_time: The P.delivered_time from the most recent packet delivered.
    prior_time: Instant,
    /// equivalent to RS.send_elapsed: Send time interval calculated from the most recent
    ///    packet delivered (see the "Send Rate" section above).
    send_elapsed: Duration,
    /// equivalent to RS.ack_elapsed: ACK time interval calculated from the most recent
    ///    packet delivered (see the "ACK Rate" section above).
    ack_elapsed: Duration,
    /// equivalent to RS.rtt: The RTT sample calculated based on the most recently-sent packet of the packets that have just been ACKed.
    rtt: Duration,
    /// equivalent to RS.tx_in_flight: C.inflight at the time of the transmission of the packet that has just been ACKed
    /// (the most recently sent packet among packets ACKed by the ACK that was just received).
    tx_in_flight: u64,
    /// equivalent to RS.newly_acked: The volume of data in bytes cumulatively or selectively acknowledged upon the ACK that was just received.
    newly_acked: u64,
    /// equivalent to RS.newly_lost: The volume of data in bytes newly marked lost upon the ACK that was just received.
    newly_lost: u64,
    /// equivalent to RS.lost: The volume of data in bytes that was declared lost between the transmission
    /// and acknowledgment of the packet that has just been ACKed (the most recently sent packet among packets ACKed by the ACK that was just received).
    lost: u64,
    /// equivalent to RS.last_end_seq
    last_end_seq: u64,
    /// represents the last packet that was used in the generation of this rate sample
    last_packet: BbrPacket,
}

/// Experimental! Use at your own risk.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html>
/// equivalent to a combination of BBR and C states
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.4>
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.1>
#[derive(Debug, Clone)]
pub struct Bbr3 {
    /// Path-local runtime tuning handle. Cloned controllers intentionally
    /// share it; separately constructed paths receive separate handles.
    tunables: Arc<Bbr3Tunables>,
    /// Validated parameters refreshed only at packet-timed round boundaries.
    params: Bbr3Params,
    params_generation: u64,
    /// equivalent to C.SMSS The Sender Maximum Send Size in bytes. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.1>
    /// <https://www.rfc-editor.org/rfc/rfc9000#name-datagram-size>
    smss: u64,
    /// equivalent to C.InitialCwnd: The initial congestion window set by the transport protocol implementation for the connection at initialization time.
    initial_cwnd: u64,
    /// equivalent to C.delivered: The total amount of data delivered so far over the lifetime of the transport connection C.
    /// This MUST NOT include pure ACK packets. It SHOULD include spurious retransmissions that have been acknowledged as delivered.
    delivered: u64,
    /// equivalent to C.inflight: The connection's best estimate of the number of bytes outstanding in the network.
    /// This includes the number of bytes that have been sent and have not been acknowledged or marked as lost since their last transmission
    /// (e.g. "pipe" from RFC6675 or "bytes_in_flight" from RFC9002). This MUST NOT include pure ACK packets.
    inflight: u64,
    /// equivalent to C.is_cwnd_limited: True if the connection has fully utilized C.cwnd at any point in the last packet-timed round trip.
    is_cwnd_limited: bool,
    /// equivalent to BBR.cycle_count: The virtual time used by the BBR.max_bw filter window.
    /// since the BBR.max_bw_filter only needs to track samples from two time slots: the previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: u64,
    /// equivalent to C.cwnd: The transport sender's congestion window. When transmitting data, the sending connection ensures that C.inflight does not exceed C.cwnd.
    cwnd: u64,
    /// equivalent to C.pacing_rate: The current pacing rate for a BBR flow, which controls inter-packet spacing.
    pacing_rate: f64,
    /// equivalent to C.send_quantum: The maximum size of a data aggregate scheduled and transmitted together as a unit, e.g., to amortize per-packet transmission overheads.
    send_quantum: u64,
    /// equivalent to BBR.pacing_gain: The dynamic gain factor used to scale BBR.bw to produce C.pacing_rate.
    pacing_gain: f64,
    /// default pacing gain is 1, when cruising, probing for RTT or refilling <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    default_pacing_gain: f64,
    /// pacing gain when probing bandwidth down <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_bw_down_pacing_gain: f64,
    /// pacing gain when probing bandwidth up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_bw_up_pacing_gain: f64,
    /// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
    /// the sending rate to double each round (4 * ln(2) ~= 2.77)
    /// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    startup_pacing_gain: f64,
    /// equivalent to BBR.DrainPacingGain: A constant specifying the pacing gain value used in Drain mode,
    /// to attempt to drain the estimated queue at the bottleneck link in one round-trip or less.
    /// As noted in BBRDrainPacingGain, any value at or below 1 / BBRStartupCwndGain = 1 / 2 = 0.5 will theoretically achieve this.
    /// BBR uses the value 0.5, which has been shown to offer good performance when compared with other alternatives.
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    drain_pacing_gain: f64,
    /// equivalent to BBR.PacingMarginPercent: The static discount factor of 1% used to scale BBR.bw to produce C.pacing_rate.
    pacing_margin_percent: f64,
    /// equivalent to BBR.cwnd_gain: The dynamic gain factor used to scale the estimated BDP to produce a congestion window (C.cwnd).
    cwnd_gain: f64,
    /// equivalent to BBR.DefaultCwndGain: A constant specifying the minimum gain value that allows the sending rate to double each round (2) BBRStartupCwndGain.
    /// Used by default in most phases for BBR.cwnd_gain.
    default_cwnd_gain: f64,
    /// used to generate random numbers when deciding how long to wait before probing again
    /// using Pcg32 as it's a fast general purpose random number generator and fits our purpose here
    /// these numbers will not be security critical as they're only used to decide when to probe the connection next.
    probe_rng: Pcg32,
    /// cwnd gain used when probing up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_bw_up_cwnd_gain: f64,
    /// cwnd gain used when probing RTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_rtt_cwnd_gain: f64,
    /// equivalent to BBR.state: The current state of a BBR flow in the BBR state machine. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-3.3>
    state: BbrState,
    /// equivalent to BBR.undo_state: The state of a BBR flow in the BBR state machine saved in case a loss episode is later declared spurious. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-3.3>
    undo_state: BbrState,
    /// equivalent to BBR.round_count: Count of packet-timed round trips elapsed so far.
    round_count: u64,
    /// equivalent to BBR.round_start: A boolean that BBR sets to true once per packet-timed round trip, on ACKs that advance BBR.round_count.
    round_start: bool,
    /// equivalent to BBR.next_round_delivered: P.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: u64,
    /// equivalent to BBR.idle_restart: A boolean that is true if and only if a connection is restarting after being idle.
    idle_restart: bool,
    /// equivalent to BBR.MinPipeCwnd: The minimal C.cwnd value BBR targets, to allow pipelining with endpoints that follow an "ACK every other packet" delayed-ACK policy: 4 * C.SMSS.
    min_pipe_cwnd: u64,
    /// equivalent to BBR.max_bw: The windowed maximum recent bandwidth sample, obtained using the BBR delivery rate sampling algorithm in
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1>,
    /// measured during the current or previous bandwidth probing cycle (or during Startup, if the flow is still in that state). (Part of the long-term model.)
    max_bw: f64,
    /// equivalent to BBR.bw_shortterm: The short-term maximum sending bandwidth that the algorithm estimates is safe for matching the current network path delivery rate,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_bw. (Part of the short-term model.)
    bw_shortterm: f64,
    /// equivalent to BBR.undo_bw_shortterm: The short-term maximum sending bandwidth that the algorithm estimates is safe for matching the current network path delivery rate,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_bw. (Part of the short-term model.)
    /// saved state in case a loss episode is later declared spurious
    undo_bw_shortterm: f64,
    /// equivalent to BBR.bw: The maximum sending bandwidth that the algorithm estimates is appropriate for matching the current network path delivery rate,
    /// given all available signals in the model, at any time scale. It is the min() of max_bw and bw_shortterm.
    bw: f64,
    /// equivalent to BBR.min_rtt: The windowed minimum round-trip time sample measured over the last BBR.MinRTTFilterLen = 10 seconds.
    /// This attempts to estimate the two-way propagation delay of the network path when all connections sharing a bottleneck are using BBR,
    /// but also allows BBR to estimate the value required for a BBR.bdp estimate that allows full throughput if there are legacy loss-based Reno or CUBIC flows sharing the bottleneck.
    min_rtt: Duration,
    /// equivalent to BBR.bdp: The estimate of the network path's BDP (Bandwidth-Delay Product), computed as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: u64,
    /// equivalent to BBR.extra_acked: A volume of data that is the estimate of the recent degree of aggregation in the network path.
    extra_acked: u64,
    /// equivalent to BBR.offload_budget: The estimate of the minimum volume of data necessary to achieve full throughput when using sender
    /// (TSO/GSO) and receiver (LRO, GRO) host offload mechanisms.
    offload_budget: u64,
    /// equivalent to BBR.max_inflight: The estimate of C.inflight required to fully utilize the bottleneck bandwidth available to the flow,
    /// based on the BDP estimate (BBR.bdp), the aggregation estimate (BBR.extra_acked), the offload budget (BBR.offload_budget), and BBR.MinPipeCwnd.
    max_inflight: u64,
    /// equivalent to BBR.inflight_longterm: The long-term maximum inflight that the algorithm estimates will produce acceptable queue pressure,
    /// based on signals in the current or previous bandwidth probing cycle, as measured by loss. That is, if a flow is probing for bandwidth,
    /// and observes that sending a particular inflight causes a loss rate higher than the loss rate threshold,
    /// it sets inflight_longterm to that volume of data. (Part of the long-term model.)
    inflight_longterm: u64,
    /// equivalent to BBR.inflight_longterm: The long-term maximum inflight that the algorithm estimates will produce acceptable queue pressure,
    /// based on signals in the current or previous bandwidth probing cycle, as measured by loss. That is, if a flow is probing for bandwidth,
    /// and observes that sending a particular inflight causes a loss rate higher than the loss rate threshold,
    /// it sets inflight_longterm to that volume of data. (Part of the long-term model.)
    /// saved state in case a loss episode is later declared spurious
    undo_inflight_longterm: u64,
    /// equivalent to BBR.inflight_shortterm: Analogous to BBR.bw_shortterm,
    /// the short-term maximum inflight that the algorithm estimates is safe for matching the current network path delivery process,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_inflight or inflight_longterm. (Part of the short-term model.)
    inflight_shortterm: u64,
    /// equivalent to BBR.undo_inflight_shortterm: Analogous to BBR.bw_shortterm,
    /// the short-term maximum inflight that the algorithm estimates is safe for matching the current network path delivery process,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_inflight or inflight_longterm. (Part of the short-term model.)
    /// saved state in case a loss episode is later declared spurious
    undo_inflight_shortterm: u64,
    /// equivalent to BBR.bw_latest: a 1-round-trip max of delivered bandwidth (RS.delivery_rate).
    bw_latest: f64,
    /// equivalent to BBR.inflight_latest: a 1-round-trip max of delivered volume of data (RS.delivered).
    inflight_latest: u64,
    /// equivalent to BBR.max_bw_filter: A windowed max filter for RS.delivery_rate samples, for estimating BBR.max_bw.
    max_bw_filter: MaxFilter,
    /// equivalent to BBR.extra_acked_interval_start: The start of the time interval for estimating the excess amount of data acknowledged due to aggregation effects.
    extra_acked_interval_start: Option<Instant>,
    /// equivalent to BBR.extra_acked_delivered: The volume of data marked as delivered since BBR.extra_acked_interval_start.
    extra_acked_delivered: u64,
    /// equivalent to BBR.extra_acked_filter: A windowed max filter for tracking the degree of aggregation in the path.
    extra_acked_filter: MaxFilter,
    /// equivalent to BBR.full_bw_reached: A boolean that records whether BBR estimates that it has ever fully utilized its available bandwidth over the lifetime of the connection.
    full_bw_reached: bool,
    /// equivalent to BBR.full_bw_now: A boolean that records whether BBR estimates that it has fully utilized its available bandwidth since it most recetly started looking.
    full_bw_now: bool,
    /// equivalent to BBR.full_bw: A recent baseline BBR.max_bw to estimate if BBR has "filled the pipe" in Startup.
    full_bw: f64,
    /// equivalent to BBR.full_bw_count: The number of non-app-limited round trips without large increases in BBR.full_bw.
    full_bw_count: u64,
    /// equivalent to BBR.min_rtt_stamp: The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: Option<Instant>,
    /// equivalent to BBR.ProbeRTTDuration: A constant specifying the minimum duration for which ProbeRTT state holds C.inflight to BBR.MinPipeCwnd or fewer packets: 200 ms.
    probe_rtt_duration: Duration,
    /// equivalent to BBR.ProbeRTTInterval: A constant specifying the minimum time interval between ProbeRTT states: 5 secs.
    probe_rtt_interval: Duration,
    /// equivalent to BBR.probe_rtt_min_delay: The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: Duration,
    /// equivalent to BBR.probe_rtt_min_stamp: The wall clock time at which the current BBR.probe_rtt_min_delay sample was obtained.
    probe_rtt_min_stamp: Option<Instant>,
    /// equivalent to BBR.probe_rtt_expired: A boolean recording whether the BBR.probe_rtt_min_delay has expired and
    /// is due for a refresh with an application idle period or a transition into ProbeRTT state.
    probe_rtt_expired: bool,
    /// equivalent to C.delivered_time: The wall clock time when C.delivered was last updated. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.1.2.1>
    delivered_time: Option<Instant>,
    /// equivalent to C.first_send_time: If packets are in flight, then this holds the send time of the packet that was most recently marked as delivered.
    /// Else, if the connection was recently idle, then this holds the send time of most recently sent packet.
    first_send_time: Option<Instant>,
    /// equivalent to C.app_limited: The index of the last transmitted packet marked as application-limited, or 0 if the connection is not currently application-limited.
    app_limited: u64,
    /// equivalent to C.lost: the number of bytes that have been lost during the lifetime of this connection
    lost: u64,
    /// equivalent to C.srtt: The smoothed RTT, an exponentially weighted moving average of the observed RTT of the connection.
    srtt: Duration,
    /// collection of packets in flight or just acknowledged / lost.
    packets: VecDeque<BbrPacket>,
    /// equivalent to RS: Per-ACK Rate Sample State <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.2>
    rs: Option<BbrRateSample>,
    /// equivalent to BBR.rounds_since_bw_probe: rounds since last bw probe state.
    rounds_since_bw_probe: u64,
    /// equivalent to BBR.bw_probe_wait: random wait time before entering probing state again
    bw_probe_wait: Duration,
    /// equivalent to BBR.bw_probe_up_rounds: number of rounds that have been executed in probe up state
    bw_probe_up_rounds: u32,
    /// equivalent to BBR.bw_probe_up_acks: volume of data in bytes that has been acknowledged during probe up state
    bw_probe_up_acks: u64,
    /// equivalent to BBR.probe_up_cnt: count of the number of times we've grown the cwnd during probe up state
    probe_up_cnt: u64,
    /// equivalent to BBR.cycle_stamp: timestamp when we start probing down state
    cycle_stamp: Option<Instant>,
    /// equivalent to BBR.ack_phase: ACK phase during probing states
    ack_phase: AckPhase,
    /// equivalent to BBR.bw_probe_samples: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2>
    bw_probe_samples: bool,
    /// equivalent to BBR.loss_round_delivered: C.delivered during the first loss of the round
    loss_round_delivered: u64,
    /// equivalent to BBR.loss_in_round: flag set to true when loss occurs during the round
    loss_in_round: bool,
    /// True after the transport reports ECN in the current model-update interval. ECN is an
    /// explicit congestion signal, so it must never use the relaxed random-loss threshold.
    explicit_congestion_in_round: bool,
    /// equivalent to BBR.probe_rtt_done_stamp: timestamp when probe RTT state is finished
    probe_rtt_done_stamp: Option<Instant>,
    /// equivalent to BBR.probe_rtt_round_done: set once per round when BBR.probe_rtt_done_stamp to check if we need to switch state
    probe_rtt_round_done: bool,
    /// equivalent to BBR.prior_cwnd: cwnd from last round
    prior_cwnd: u64,
    /// equivalent to BBR.loss_round_start: flag set to true at the very beginning of a round where loss occurred
    loss_round_start: bool,
    /// equivalent to BBR.drain_start_round: The value of round_count when Drain state started.
    drain_start_round: u64,
    /// Number of ack-eliciting packets the peer may receive before sending an immediate ACK,
    /// as requested via the QUIC ACK frequency extension. Used when computing `offload_budget`
    /// per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.8.2>.
    ack_eliciting_threshold: u64,
    /// `max_ack_delay` we requested the peer to use via the QUIC ACK frequency extension.
    /// Used when computing `offload_budget` per
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.8.2>.
    max_ack_delay: Duration,
    /// Optional host/datacenter fast-path threshold. Below this measured RTT,
    /// BBR still controls inflight but lets the socket/kernel scheduler drain
    /// a complete QUIC send quantum without userspace pacing timer churn.
    pacing_bypass_below_rtt: Option<Duration>,
    low_rtt_cwnd_floor: u64,
    /// Cumulative automatic Startup/ProbeBW transitions caused by measured
    /// queue delay. Exposed read-only for tuning/profile evidence.
    queue_delay_guard_transitions: u64,
    probe_rtt_entries: u64,
    /// Time-bounded outcome window used to identify a shallow policer without
    /// treating long-haul/radio loss as congestion.
    policer_window_started: Option<Instant>,
    policer_window_acked_bytes: u64,
    policer_window_lost_bytes: u64,
    policer_pacing_scale: f64,
    policer_pacing_transitions: u64,
    pacing_bypass_armed: bool,
}

impl Bbr3 {
    fn new(config: Arc<Bbr3Config>, current_mtu: u16) -> Self {
        let probe_rng: Pcg32;
        if let Some(probe_seed) = config.probe_rng_seed {
            probe_rng = Pcg32::from_seed(probe_seed);
        } else {
            probe_rng = Pcg32::from_rng(&mut rand::rng());
        }
        let smss = min(
            max(MIN_MAX_DATAGRAM_SIZE, current_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
        let tunables = Arc::new(
            config
                .tunables_template
                .as_deref()
                .map(Bbr3Tunables::copy_from)
                .unwrap_or_default(),
        );
        // Preserve the pre-runtime-tuning builder API by applying its explicit
        // values to the path-local template before taking the first snapshot.
        if let Some(value) = config.default_pacing_gain {
            tunables
                .cruise_pacing_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_bw_down_pacing_gain {
            tunables
                .probe_bw_down_pacing_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_bw_up_pacing_gain {
            tunables
                .probe_bw_up_pacing_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.default_cwnd_gain {
            tunables
                .default_cwnd_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_bw_up_cwnd_gain {
            tunables
                .probe_bw_up_cwnd_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_rtt_cwnd_gain {
            tunables
                .probe_rtt_cwnd_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        let (mut params, mut clamped) = Bbr3Params::from_tunables(&tunables);
        let min_cwnd = 4 * smss;
        if params.cwnd_cap_bytes > 0 && params.cwnd_cap_bytes < min_cwnd {
            params.cwnd_cap_bytes = min_cwnd;
            clamped += 1;
        }
        if params.cwnd_cap_bytes > 0 && params.cwnd_floor_bytes > params.cwnd_cap_bytes {
            params.cwnd_floor_bytes = params.cwnd_cap_bytes;
            clamped += 1;
        }
        tunables
            .clamped_writes
            .fetch_add(clamped, Ordering::Relaxed);
        let params_generation = tunables.generation.load(Ordering::Relaxed);
        let hinted_cwnd = params.startup_bw_hint_bytes_per_second.saturating_mul(333) / 1_000;
        let mut initial_cwnd = config.initial_window.max(hinted_cwnd);
        if params.cwnd_cap_bytes > 0 {
            initial_cwnd = initial_cwnd.min(params.cwnd_cap_bytes);
        }
        initial_cwnd = initial_cwnd.max(4 * smss);
        if params.cwnd_floor_bytes > 0 {
            initial_cwnd = initial_cwnd.max(params.cwnd_floor_bytes);
        }
        let startup_pacing_gain = config.startup_pacing_gain.unwrap_or(STARTUP_PACING_GAIN);
        let default_pacing_gain = params.cruise_pacing_gain;
        let probe_bw_down_pacing_gain = params.probe_bw_down_pacing_gain;
        let probe_bw_up_pacing_gain = params.probe_bw_up_pacing_gain;
        let drain_pacing_gain = config.drain_pacing_gain.unwrap_or(DRAIN_PACING_GAIN);
        let pacing_margin_percent = config
            .pacing_margin_percent
            .unwrap_or(PACING_MARGIN_PERCENT);
        let default_cwnd_gain = params.default_cwnd_gain;
        let probe_bw_up_cwnd_gain = params.probe_bw_up_cwnd_gain;
        let probe_rtt_cwnd_gain = params.probe_rtt_cwnd_gain;
        // the calculation for initial pacing rate described here <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-5>
        let nominal_bandwidth = if params.startup_bw_hint_bytes_per_second > 0 {
            params.startup_bw_hint_bytes_per_second as f64
        } else {
            initial_cwnd as f64 / 0.001
        };
        let mut pacing_rate = startup_pacing_gain * nominal_bandwidth;
        if params.pacing_rate_cap_bytes_per_second > 0 {
            pacing_rate = pacing_rate.min(params.pacing_rate_cap_bytes_per_second as f64);
        }
        Self {
            tunables,
            params,
            params_generation,
            smss,
            initial_cwnd,
            delivered: 0,
            inflight: 0,
            is_cwnd_limited: false,
            cycle_count: 0,
            cwnd: initial_cwnd,
            pacing_rate,
            send_quantum: 2 * smss, // we start high, but it will be adjusted in set_send_quantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.3>
            pacing_gain: startup_pacing_gain,
            startup_pacing_gain,
            default_pacing_gain,
            probe_bw_down_pacing_gain,
            probe_bw_up_pacing_gain,
            drain_pacing_gain,
            pacing_margin_percent,
            cwnd_gain: default_cwnd_gain,
            default_cwnd_gain,
            probe_rng,
            probe_bw_up_cwnd_gain,
            state: BbrState::Startup,
            undo_state: BbrState::Startup,
            round_count: 0,
            round_start: true,
            next_round_delivered: 0,
            idle_restart: false,
            min_pipe_cwnd: 4 * smss, // 4 * C.SMSS as defined in <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.7-4>
            max_bw: 0.0,
            bw_shortterm: f64::INFINITY,
            undo_bw_shortterm: f64::INFINITY,
            bw: 0.0,
            min_rtt: Duration::from_secs(u64::MAX),
            bdp: 0,
            extra_acked: 0,
            offload_budget: 0,
            max_inflight: 0,
            inflight_longterm: u64::MAX,
            undo_inflight_longterm: u64::MAX,
            inflight_shortterm: u64::MAX,
            undo_inflight_shortterm: u64::MAX,
            bw_latest: 0.0,
            inflight_latest: 0,
            max_bw_filter: MaxFilter::new(MAX_BW_FILTER_LEN as u64),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            extra_acked_filter: MaxFilter::new(EXTRA_ACKED_FILTER_LEN as u64),
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0.0,
            full_bw_count: 0,
            min_rtt_stamp: None,
            probe_rtt_cwnd_gain,
            probe_rtt_duration: params.probe_rtt_duration,
            probe_rtt_interval: params.probe_rtt_interval,
            probe_rtt_min_delay: Duration::ZERO,
            probe_rtt_min_stamp: None,
            probe_rtt_expired: false,
            delivered_time: None,
            first_send_time: None,
            app_limited: 0,
            lost: 0,
            srtt: Duration::ZERO,
            rs: None,
            packets: VecDeque::new(),
            rounds_since_bw_probe: 0,
            bw_probe_wait: Duration::ZERO,
            bw_probe_up_rounds: 0,
            bw_probe_up_acks: 0,
            probe_up_cnt: 0,
            cycle_stamp: None,
            ack_phase: AckPhase::ProbeStarting,
            bw_probe_samples: false,
            loss_round_delivered: 0,
            loss_in_round: false,
            explicit_congestion_in_round: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            prior_cwnd: 0,
            loss_round_start: false,
            drain_start_round: 0,
            // Conservative defaults that match RFC 9000 §13.2.2 behavior (ACK every other
            // ack-eliciting packet) and the default QUIC `max_ack_delay` of 25ms. Overridden
            // when the connection supplies peer ACK-frequency parameters.
            ack_eliciting_threshold: 1,
            max_ack_delay: Duration::from_millis(25),
            pacing_bypass_below_rtt: config.pacing_bypass_below_rtt,
            low_rtt_cwnd_floor: config.low_rtt_cwnd_floor,
            queue_delay_guard_transitions: 0,
            probe_rtt_entries: 0,
            policer_window_started: None,
            policer_window_acked_bytes: 0,
            policer_window_lost_bytes: 0,
            policer_pacing_scale: 1.0,
            policer_pacing_transitions: 0,
            pacing_bypass_armed: false,
        }
    }

    /// Refresh the controller-local parameter snapshot. This is called only
    /// after `update_round` has identified a packet-timed round boundary.
    fn refresh_params(&mut self) {
        let generation = self.tunables.generation.load(Ordering::Relaxed);
        if generation == self.params_generation {
            return;
        }
        let (mut params, mut clamped) = Bbr3Params::from_tunables(&self.tunables);
        let min_cwnd = 4 * self.smss;
        if params.cwnd_cap_bytes > 0 && params.cwnd_cap_bytes < min_cwnd {
            params.cwnd_cap_bytes = min_cwnd;
            clamped += 1;
        }
        if params.cwnd_cap_bytes > 0 && params.cwnd_floor_bytes > params.cwnd_cap_bytes {
            params.cwnd_floor_bytes = params.cwnd_cap_bytes;
            clamped += 1;
        }
        self.tunables
            .clamped_writes
            .fetch_add(clamped, Ordering::Relaxed);
        self.params = params;
        self.params_generation = generation;

        self.default_pacing_gain = params.cruise_pacing_gain;
        self.probe_bw_down_pacing_gain = params.probe_bw_down_pacing_gain;
        self.probe_bw_up_pacing_gain = params.probe_bw_up_pacing_gain;
        self.default_cwnd_gain = params.default_cwnd_gain;
        self.probe_bw_up_cwnd_gain = params.probe_bw_up_cwnd_gain;
        self.probe_rtt_cwnd_gain = params.probe_rtt_cwnd_gain;
        self.probe_rtt_duration = params.probe_rtt_duration;
        self.probe_rtt_interval = params.probe_rtt_interval;

        match self.state {
            BbrState::Startup => {
                self.pacing_gain = self.startup_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::Drain => {
                self.pacing_gain = self.drain_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::ProbeBw(ProbeBwSubstate::Down) => {
                self.pacing_gain = self.probe_bw_down_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise | ProbeBwSubstate::Refill) => {
                self.pacing_gain = self.default_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) => {
                self.pacing_gain = self.probe_bw_up_pacing_gain;
                self.cwnd_gain = self.probe_bw_up_cwnd_gain;
            }
            BbrState::ProbeRtt => {
                self.pacing_gain = self.default_pacing_gain;
                self.cwnd_gain = self.probe_rtt_cwnd_gain;
            }
        }
    }

    /// equivalent to BBREnterStartup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.1-3>
    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
        self.pacing_gain = self.startup_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRResetFullBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-4>
    fn reset_full_bw(&mut self) {
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// equivalent to BBRNoteLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    fn note_loss(&mut self) {
        if !self.loss_in_round {
            self.loss_round_delivered = self.delivered;
        }
        self.save_state_upon_loss();
        self.loss_in_round = true;
    }

    /// equivalent to BBRSaveStateUponLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11.1>
    /// Save state in case a loss episode is later declared spurious
    fn save_state_upon_loss(&mut self) {
        self.undo_state = self.state;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
    }

    /// equivalent to BBRInflightAtLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    /// We check at what prefix of packet did losses exceed `loss_thresh`
    fn inflight_at_loss(&mut self, packet_size: u64) -> u64 {
        if let Some(rate_sample) = self.rs {
            let loss_thresh = self.params.loss_thresh;
            let inflight_prev = rate_sample.tx_in_flight.saturating_sub(packet_size);
            let inflight_prev_threshold = loss_thresh * inflight_prev as f64;
            let lost_prev = rate_sample.lost.saturating_sub(packet_size);
            let compared_loss = (inflight_prev_threshold.round() as u64).saturating_sub(lost_prev);
            let lost_prefix = compared_loss as f64 / (1.0 - loss_thresh);
            let inflight_at_loss = inflight_prev + lost_prefix as u64;
            return inflight_at_loss;
        }
        0
    }

    /// equivalent to BBRSaveCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.4-13>
    fn save_cwnd(&mut self) {
        if !self.loss_in_round && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = max(self.prior_cwnd, self.cwnd);
        }
    }

    /// equivalent to BBRRestoreCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.4-13>
    fn restore_cwnd(&mut self) {
        self.cwnd = max(self.cwnd, self.prior_cwnd);
    }

    /// equivalent to BBRProbeRTTCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.5-1>
    fn probe_rtt_cwnd(&mut self) -> u64 {
        let mut probe_rtt_cwnd = self.bdp_multiple(self.bw, self.probe_rtt_cwnd_gain);
        probe_rtt_cwnd = max(probe_rtt_cwnd, self.min_pipe_cwnd);
        probe_rtt_cwnd
    }

    /// equivalent to BBRBoundCwndForProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.5-1>
    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = min(self.cwnd, self.probe_rtt_cwnd());
        }
    }

    /// equivalent to BBRTargetInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn target_inflight(&self) -> u64 {
        min(self.bdp, self.cwnd)
    }

    /// equivalent to BBRHandleInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    fn handle_inflight_too_high(&mut self, now: Instant) {
        self.bw_probe_samples = false;
        if let Some(rate_sample) = self.rs
            && !rate_sample.is_app_limited
        {
            self.inflight_longterm = max(
                rate_sample.tx_in_flight,
                (self.target_inflight() as f64 * self.params.beta) as u64,
            );
        }

        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            self.start_probe_bw_down(now);
        }
    }

    /// equivalent to IsInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    fn is_inflight_too_high(&self) -> bool {
        // Packet loss alone is ambiguous on radio, Wi-Fi, long-haul and
        // shallow-policer paths. Let the delivery-rate model converge on the
        // usable capacity and let V2 FEC/repair absorb non-congestive loss.
        // Queue growth is handled independently by `check_queue_delay_guard`;
        // using the same transient loss to also cap inflight creates a positive
        // feedback loop where the cap and measured bandwidth shrink together.
        // Only authenticated ECN is authoritative enough to install a lasting
        // loss-based inflight cap.
        if !self.explicit_congestion_in_round && !self.params.loss_is_congestion {
            return false;
        }
        if let Some(rate_sample) = self.rs {
            return rate_sample.lost as f64
                > rate_sample.tx_in_flight as f64 * self.params.loss_thresh;
        }
        false
    }

    /// Whether the controller's own RTT estimator proves that the current
    /// upward probe is building a queue rather than discovering propagation
    /// delay. The dual relative/absolute allowance avoids reacting to normal
    /// timestamp noise on either short or long RTT paths.
    fn queue_delay_guard_triggered(&self) -> bool {
        if self.min_rtt == Duration::from_secs(u64::MAX)
            || self.min_rtt.is_zero()
            || self.srtt.is_zero()
            // The first RTT sample precedes the first usable delivery-rate
            // sample. Entering Drain at that point would mark full bandwidth
            // reached with a zero pacing rate and could arm an infinite pacer
            // deadline. Wait until BBR has an actual bandwidth estimate.
            || !self.bw.is_finite()
            || self.bw <= 0.0
        {
            return false;
        }

        // Startup and ProbeBW-Up are intentionally queue-building phases. On
        // a path whose policy says random loss is not congestion, applying
        // the steady-state 0.5*min_rtt guard here repeatedly aborts bandwidth
        // discovery at a fraction of capacity (especially behind a shaped
        // home uplink). Relax only these upward probes; Drain/Cruise and
        // loss-as-congestion presets retain the strict latency guard.
        let upward_loss_tolerant_probe = !self.params.loss_is_congestion
            && matches!(
                self.state,
                BbrState::Startup | BbrState::ProbeBw(ProbeBwSubstate::Up)
            );
        let guard_multiplier = if upward_loss_tolerant_probe { 4.0 } else { 1.0 };
        let relative_slack = self
            .min_rtt
            .mul_f64(self.params.queue_delay_guard_inflation * guard_multiplier);
        let absolute_slack = if upward_loss_tolerant_probe {
            max(
                self.params.queue_delay_guard_slack,
                Duration::from_millis(20),
            )
        } else {
            self.params.queue_delay_guard_slack
        };
        let slack = max(relative_slack, absolute_slack);
        self.srtt
            > self
                .min_rtt
                .checked_add(slack)
                .unwrap_or(Duration::from_secs(u64::MAX))
    }

    /// Bound queue growth without disabling BBR's later bandwidth discovery.
    /// Startup moves to Drain immediately; a ProbeBW upward phase moves to
    /// Down. Subsequent ProbeBW cycles can still test for newly available
    /// bandwidth after the queue has drained.
    fn check_queue_delay_guard(&mut self, now: Instant) {
        if !self.queue_delay_guard_triggered() {
            return;
        }

        match self.state {
            BbrState::Startup => {
                self.full_bw_now = true;
                self.full_bw_reached = true;
                self.queue_delay_guard_transitions += 1;
                self.enter_drain();
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) => {
                self.queue_delay_guard_transitions += 1;
                self.start_probe_bw_down(now);
            }
            _ => {}
        }
    }

    /// Learn the usable wire rate of a shallow policer from transport-level
    /// outcomes. This caps pacing only; it never installs a lasting cwnd or
    /// max-bandwidth bound, so capacity recovers automatically.
    fn update_policer_pacing(&mut self, now: Instant) {
        let started = self.policer_window_started.get_or_insert(now);
        if now.saturating_duration_since(*started) < POLICER_SAMPLE_WINDOW {
            return;
        }

        let acked = std::mem::take(&mut self.policer_window_acked_bytes);
        let lost = std::mem::take(&mut self.policer_window_lost_bytes);
        self.policer_window_started = Some(now);

        if self.min_rtt == Duration::from_secs(u64::MAX)
            || self.min_rtt.is_zero()
            || self.min_rtt > POLICER_RTT_CEILING
        {
            self.policer_pacing_scale = 1.0;
            self.pacing_bypass_armed = false;
            return;
        }

        let total = acked.saturating_add(lost);
        if total < POLICER_MIN_SAMPLE_BYTES {
            return;
        }
        let loss_ratio = lost as f64 / total as f64;
        if loss_ratio >= POLICER_LOSS_THRESHOLD {
            self.pacing_bypass_armed = false;
            let decrease = (1.0 - loss_ratio).clamp(POLICER_MAX_SINGLE_DECREASE, 0.98);
            self.policer_pacing_scale =
                (self.policer_pacing_scale * decrease).max(POLICER_MIN_PACING_SCALE);
            self.policer_pacing_transitions = self.policer_pacing_transitions.saturating_add(1);
        } else if loss_ratio <= POLICER_CLEAN_THRESHOLD {
            if self.policer_pacing_transitions == 0
                && self.policer_pacing_scale >= 1.0
                && self
                    .pacing_bypass_below_rtt
                    .is_some_and(|threshold| self.min_rtt < threshold)
            {
                // Do not bypass the timer from a single optimistic RTT
                // sample. One clean half-second window distinguishes a LAN or
                // Wi-Fi path from a shallow policer before allowing bursts.
                self.pacing_bypass_armed = true;
            }
            // Once this controller has proven a shallow policer, retain a 1%
            // pacing cap. Besides preserving headroom, this keeps the
            // low-latency timer bypass disabled until path migration creates
            // a fresh controller; otherwise recovery to exactly 1.0 would
            // re-enable bursts and repeat the loss cycle.
            let recovery_ceiling = if self.policer_pacing_transitions == 0 {
                1.0
            } else {
                0.99
            };
            self.policer_pacing_scale =
                (self.policer_pacing_scale + POLICER_ADDITIVE_RECOVERY).min(recovery_ceiling);
        }
    }

    fn pacing_bypass_active(&self) -> bool {
        self.pacing_bypass_armed
            && self.policer_pacing_scale >= 1.0
            && self
                .pacing_bypass_below_rtt
                .is_some_and(|threshold| self.min_rtt < threshold)
    }

    /// equivalent to BBRCheckStartupHighLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.3>
    fn check_startup_high_loss(&mut self) {
        if self.full_bw_reached {
            return;
        }

        if self.is_inflight_too_high() {
            let mut new_inflight_hi = self.bdp.max(self.inflight_latest);
            if let Some(rate_sample) = self.rs
                && new_inflight_hi < rate_sample.delivered
            {
                new_inflight_hi = rate_sample.delivered;
            }
            self.inflight_longterm = new_inflight_hi;
            self.full_bw_reached = true;
        }
    }

    /// equivalent to BBREnterProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6>
    fn enter_probe_bw(&mut self, now: Instant) {
        self.cwnd_gain = self.default_cwnd_gain;
        self.start_probe_bw_down(now);
    }

    /// equivalent to BBRPickProbeWait <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn pick_probe_wait(&mut self) {
        // 0 or 1
        self.rounds_since_bw_probe = self.probe_rng.random_bool(0.5) as u64;
        let max_added_millis = self.params.max_added_probe_wait.as_millis() as u64;
        self.bw_probe_wait = self.params.min_probe_wait
            + Duration::from_millis(self.probe_rng.random_range(0..=max_added_millis));
    }

    /// equivalent to BBRHasElapsedInPhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn has_elapsed_in_phase(&mut self, interval: Duration, now: Instant) -> bool {
        if let Some(cycle_stamp) = self.cycle_stamp {
            now > cycle_stamp.checked_add(interval).unwrap_or(cycle_stamp)
        } else {
            true
        }
    }

    /// equivalent to BBRExitProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.4>
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// equivalent to BBRCheckProbeRTTDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn check_probe_rtt_done(&mut self, now: Instant) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp
            && now > probe_rtt_done_stamp
        {
            self.probe_rtt_min_stamp = Some(now);
            self.restore_cwnd();
            self.exit_probe_rtt(now);
        }
    }

    /// equivalent to BBRIsTimeToProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn maybe_enter_probe_bw_refill(&mut self, now: Instant) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    /// equivalent to BBRIsTimeToGoDown <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-6>
    fn maybe_go_down(&mut self) -> bool {
        if self.is_cwnd_limited && self.cwnd >= self.inflight_longterm {
            self.reset_full_bw();
            if let Some(rate_sample) = self.rs {
                self.full_bw = rate_sample.delivery_rate;
            }
        } else if self.full_bw_now {
            return true;
        }
        false
    }

    /// equivalent to BBRIsRenoCoexistenceProbeTime <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self.target_inflight();
        let rounds = min(reno_rounds, MAX_RENO_ROUNDS);
        self.rounds_since_bw_probe >= rounds
    }

    /// equivalent to BBRBDPMultiple <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn bdp_multiple(&mut self, bw: f64, gain: f64) -> u64 {
        if self.min_rtt == Duration::from_secs(u64::MAX) {
            return self.initial_cwnd;
        }
        self.bdp = (bw * self.min_rtt.as_secs_f64()).round() as u64;
        (gain * self.bdp as f64) as u64
    }

    /// equivalent to BBRUpdateOffloadBudget for QUIC per
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.8.2>.
    ///
    /// The delayed-ACK term accounts for the QUIC ACK frequency extension:
    /// `min(Ack-Eliciting Threshold, Requested Max Ack Delay * BBR.max_bw)`.
    fn update_offload_budget(&mut self) {
        let base = self.send_quantum;

        // Ack-Eliciting Threshold is a packet count in the ACK_FREQUENCY frame; convert to
        // bytes using the current SMSS. A threshold of 0 requires an immediate ACK per packet,
        // so the delayed-ACK term contributes nothing in that case.
        let threshold_bytes = self.ack_eliciting_threshold.saturating_mul(self.smss);
        let delay_bytes = (self.max_ack_delay.as_secs_f64() * self.max_bw).round() as u64;
        let delayed_ack_term = min(threshold_bytes, delay_bytes);

        self.offload_budget = base.saturating_add(delayed_ack_term);
    }

    /// equivalent to BBRQuantizationBudget <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn quantization_budget(&mut self, inflight_cap: u64) -> u64 {
        self.update_offload_budget();
        let mut inflight_cap = max(inflight_cap, self.offload_budget);
        inflight_cap = max(inflight_cap, self.min_pipe_cwnd);
        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            inflight_cap += 2 * self.smss;
        }
        inflight_cap
    }

    /// equivalent to BBRInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn get_inflight(&mut self, gain: f64) -> u64 {
        let inflight_cap = self.bdp_multiple(self.max_bw, gain);
        self.quantization_budget(inflight_cap)
    }

    /// equivalent to BBRUpdateMaxInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn update_max_inflight(&mut self) {
        let mut inflight_cap = self.bdp_multiple(self.max_bw, self.cwnd_gain);
        inflight_cap += self.extra_acked;
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    /// equivalent to BBRResetCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.explicit_congestion_in_round = false;
        self.bw_latest = 0.0;
        self.inflight_latest = 0;
    }

    /// equivalent to BBRStartRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1-9>
    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
        self.is_cwnd_limited = false;
    }

    /// equivalent to BBRUpdateRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1-9>
    fn update_round(&mut self, packet: BbrPacket) {
        if packet.delivered >= self.next_round_delivered {
            self.start_round();
            self.round_count += 1;
            self.rounds_since_bw_probe += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    /// equivalent to BBRStartProbeBW_DOWN <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-4>
    fn start_probe_bw_down(&mut self, now: Instant) {
        self.reset_congestion_signals();
        self.probe_up_cnt = u64::MAX;
        self.pick_probe_wait();
        self.cycle_stamp = Some(now);
        self.ack_phase = AckPhase::ProbeStopping;
        self.start_round();
        self.pacing_gain = self.probe_bw_down_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Down);
    }

    /// equivalent to BBRInflightWithHeadroom <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == u64::MAX {
            return u64::MAX;
        }
        let total_headroom = max(
            self.smss,
            (self.params.headroom * self.inflight_longterm as f64) as u64,
        );
        if let Some(inflight_with_headroom) = self.inflight_longterm.checked_sub(total_headroom) {
            max(inflight_with_headroom, self.min_pipe_cwnd)
        } else {
            self.min_pipe_cwnd
        }
    }

    /// equivalent to BBRSetPacingRateWithGain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-7>
    fn set_pacing_rate_with_gain(&mut self, gain: f64) {
        let mut rate = gain * self.bw * (100.0 - self.pacing_margin_percent) / 100.0
            * self.policer_pacing_scale;
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            rate = rate.min(self.params.pacing_rate_cap_bytes_per_second as f64);
        }
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// equivalent to BBRRaiseInflightLongtermSlope <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn raise_inflight_long_term_slope(&mut self) {
        let growth_this_round = self
            .smss
            .checked_shl(self.bw_probe_up_rounds)
            .unwrap_or(u64::MAX);
        self.bw_probe_up_rounds = min(self.bw_probe_up_rounds + 1, MAX_LONG_TERM_PROBE_UP_ROUNDS);
        self.probe_up_cnt = max(self.cwnd / growth_this_round, 1);
    }

    /// equivalent to BBRProbeInflightLongtermUpward <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn probe_inflight_long_term_upward(&mut self) {
        if !self.is_cwnd_limited || self.cwnd < self.inflight_longterm {
            return;
        }
        if let Some(rate_sample) = self.rs {
            self.bw_probe_up_acks += rate_sample.newly_acked;
        }
        if self.bw_probe_up_acks >= self.probe_up_cnt && self.probe_up_cnt > 0 {
            let delta = self.bw_probe_up_acks / self.probe_up_cnt;
            self.bw_probe_up_acks -= delta * self.probe_up_cnt;
            self.inflight_longterm += delta;
            if self.round_start {
                self.raise_inflight_long_term_slope();
            }
        }
    }

    /// equivalent to BBRAdvanceMaxBwFilter <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.6>
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count = self.cycle_count.saturating_add(1);
    }

    /// equivalent to BBRAdaptLongTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn adapt_long_term_model(&mut self) {
        if self.ack_phase == AckPhase::ProbeStarting && self.round_start {
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        if self.ack_phase == AckPhase::ProbeStopping
            && self.round_start
            && let BbrState::ProbeBw(_) = self.state
            && let Some(rate_sample) = self.rs
            && !rate_sample.is_app_limited
        {
            self.advance_max_bw_filter();
            // `cycle_count` is virtual time in complete ProbeBW cycles, not
            // packet-timed rounds.  ProbeStopping otherwise remains set for
            // the whole Down/Cruise interval and expires the two-cycle max-bw
            // filter after only a few RTTs.  Mark this transition consumed;
            // the next Refill/Up/Down cycle will arm ProbeStopping again.
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        if !self.is_inflight_too_high() {
            if self.inflight_longterm == u64::MAX {
                return;
            }
            if let Some(rate_sample) = self.rs
                && rate_sample.tx_in_flight > self.inflight_longterm
            {
                self.inflight_longterm = rate_sample.tx_in_flight;
            }
            if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                self.probe_inflight_long_term_upward();
            }
        }
    }

    /// equivalent to BBRIsTimeToCruise <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn maybe_update_budget_and_time_to_cruise(&mut self) -> bool {
        if self.inflight > self.inflight_with_headroom() {
            return false;
        }
        if self.inflight > self.get_inflight(1.0) {
            return false;
        }
        true
    }

    /// equivalent to BBRStartProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.4-4>
    fn start_probe_bw_cruise(&mut self) {
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRResetShortTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = f64::INFINITY;
        self.inflight_shortterm = u64::MAX;
    }

    /// equivalent to BBRInitLowerBounds <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == f64::INFINITY {
            self.bw_shortterm = self.max_bw;
        }
        if self.inflight_shortterm == u64::MAX {
            self.inflight_shortterm = self.cwnd;
        }
    }

    /// equivalent to BBRLossLowerBounds <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn loss_lower_bounds(&mut self) {
        // gives max of both f64
        self.bw_shortterm = [self.bw_latest, self.params.beta * self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = max(
            self.inflight_latest,
            (self.params.beta * self.inflight_shortterm as f64) as u64,
        );
    }

    /// equivalent to BBRBoundBWForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn bound_bw_for_model(&mut self) {
        // gives min of both f64
        self.bw = [self.max_bw, self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::min);
    }

    /// equivalent to BBRStartProbeBW_REFILL <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-4>
    fn start_probe_bw_refill(&mut self) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.ack_phase = AckPhase::Refilling;
        self.start_round();
        self.cwnd_gain = self.default_cwnd_gain;
        self.pacing_gain = self.default_pacing_gain;
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Refill);
    }

    /// equivalent to BBRStartProbeBW_UP <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-4>
    fn start_probe_bw_up(&mut self) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.start_round();
        self.reset_full_bw();
        if let Some(rate_sample) = self.rs {
            self.full_bw = rate_sample.delivery_rate;
        }
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        self.pacing_gain = self.probe_bw_up_pacing_gain;
        self.cwnd_gain = self.probe_bw_up_cwnd_gain;
        self.raise_inflight_long_term_slope();
    }

    /// equivalent to BBREnterProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn enter_probe_rtt(&mut self) {
        self.probe_rtt_entries = self.probe_rtt_entries.saturating_add(1);
        self.state = BbrState::ProbeRtt;
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.probe_rtt_cwnd_gain;
    }

    /// equivalent to BBRHandleRestartFromIdle <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.4.1>
    fn handle_restart_from_idle(&mut self, now: Instant) {
        if self.inflight == 0 && self.app_limited != 0 {
            self.idle_restart = true;
            self.extra_acked_interval_start = Some(now);
            match self.state {
                BbrState::ProbeBw(_) => {
                    self.set_pacing_rate_with_gain(1.0);
                }
                BbrState::ProbeRtt => {
                    self.check_probe_rtt_done(now);
                }
                _ => {}
            }
        }
    }

    /// equivalent to BBRUpdateProbeBWCyclePhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-6>
    fn update_probe_bw_cycle_phase(&mut self, now: Instant) {
        if !self.full_bw_reached {
            return;
        }
        self.adapt_long_term_model();
        let state = self.state;
        match state {
            BbrState::ProbeBw(ProbeBwSubstate::Down) => {
                if self.maybe_enter_probe_bw_refill(now) {
                    return;
                }
                if self.maybe_update_budget_and_time_to_cruise() {
                    self.start_probe_bw_cruise();
                }
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise) if self.maybe_enter_probe_bw_refill(now) => {
            }
            BbrState::ProbeBw(ProbeBwSubstate::Refill) if self.round_start => {
                self.bw_probe_samples = true;
                self.start_probe_bw_up();
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) if self.maybe_go_down() => {
                self.start_probe_bw_down(now);
            }
            _ => {}
        }
    }

    /// equivalent to BBRUpdateLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn update_latest_delivery_signals(&mut self) {
        self.loss_round_start = false;
        if let Some(rate_sample) = self.rs {
            self.bw_latest = [self.bw_latest, rate_sample.delivery_rate]
                .iter()
                .copied()
                .fold(f64::NAN, f64::max);
            self.inflight_latest = max(self.inflight_latest, rate_sample.delivered);

            if rate_sample.prior_delivered >= self.loss_round_delivered {
                self.loss_round_delivered = self.delivered;
                self.loss_round_start = true;
            }
        }
    }

    /// equivalent to BBRAdaptLowerBoundsFromCongestion <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn adapt_lower_bounds_from_congestion(&mut self) {
        match self.state {
            BbrState::ProbeBw(ProbeBwSubstate::Refill)
            | BbrState::ProbeBw(ProbeBwSubstate::Up)
            | BbrState::Startup => {}
            _ => {
                if self.loss_in_round {
                    self.init_lower_bounds();
                    self.loss_lower_bounds();
                }
            }
        }
    }

    /// equivalent to BBRUpdateMaxBw <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.5>
    fn update_max_bw(&mut self, p: BbrPacket) {
        self.update_round(p);
        if let Some(rate_sample) = self.rs
            && rate_sample.delivery_rate > 0.0
            && (rate_sample.delivery_rate >= self.max_bw || !rate_sample.is_app_limited)
        {
            self.max_bw_filter
                .update_max(self.cycle_count, rate_sample.delivery_rate.round() as u64);

            self.max_bw = self.max_bw_filter.get_max() as f64;
        }
    }

    /// equivalent to BBRUpdateCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn update_congestion_signals(&mut self, p: BbrPacket) {
        self.update_max_bw(p);
        if !self.loss_round_start {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        self.loss_in_round = false;
    }

    /// equivalent to BBRUpdateACKAggregation <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.9>
    fn update_ack_aggregation(&mut self, now: Instant) {
        let interval;
        if let Some(extra_acked_interval_start) = self.extra_acked_interval_start {
            interval = now - extra_acked_interval_start;
        } else {
            interval = Duration::from_secs(0);
        }
        let mut expected_delivered = (self.bw * interval.as_secs_f64()) as u64;
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(now);
            expected_delivered = 0;
        }
        if let Some(rate_sample) = self.rs {
            self.extra_acked_delivered += rate_sample.newly_acked;
        }

        let mut extra = self
            .extra_acked_delivered
            .saturating_sub(expected_delivered);
        extra = min(extra, self.cwnd);
        if self.full_bw_reached {
            self.extra_acked_filter.update_max(self.round_count, extra);
            self.extra_acked = self.extra_acked_filter.get_max();
        } else {
            self.extra_acked = extra; // In startup, just remember 1 round
        }
    }

    /// equivalent to BBRCheckFullBWReached <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
    fn check_full_bw_reached(&mut self) {
        if self.full_bw_now || !self.round_start {
            return;
        }
        if let Some(rate_sample) = self.rs {
            if rate_sample.is_app_limited {
                return;
            }
            if rate_sample.delivery_rate >= self.full_bw * FULL_BW_GROWTH {
                self.reset_full_bw();
                self.full_bw = rate_sample.delivery_rate;
                return;
            }

            // On a long-RTT random-loss path, a lossy round is not evidence
            // that Startup found the bottleneck. Correlated radio/cross-
            // carrier loss can suppress three consecutive delivery samples
            // while the sender is still orders of magnitude below capacity;
            // counting those rounds exits Startup at a few packets of cwnd
            // and leaves ProbeBW to recover for minutes. Keep probing until
            // either clean plateau rounds prove full bandwidth or the
            // independent RTT queue guard proves that probing built a queue.
            // Short-RTT policers retain the normal three-round exit and are
            // subsequently bounded by the automatic policer pacing loop.
            let high_rtt_ambiguous_loss = self.min_rtt > POLICER_RTT_CEILING
                && (rate_sample.newly_lost > 0 || rate_sample.lost > 0)
                && !self.queue_delay_guard_triggered();
            if high_rtt_ambiguous_loss {
                return;
            }
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= MAX_FULL_BW_COUNT;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    /// equivalent to BBREnterDrain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2>
    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        self.pacing_gain = self.drain_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
        self.drain_start_round = self.round_count;
    }

    /// equivalent to BBRCheckStartupDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.1-6>
    fn check_startup_done(&mut self) {
        self.check_startup_high_loss();
        if self.state == BbrState::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    /// equivalent to BBRCheckDrainDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2-3>
    fn check_drain_done(&mut self, now: Instant) {
        if self.state == BbrState::Drain
            && (self.inflight <= self.get_inflight(1.0)
                || self.round_count > self.drain_start_round + 3)
        {
            self.enter_probe_bw(now);
        }
    }

    /// equivalent to BBRUpdateMinRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3>
    fn update_min_rtt(&mut self, now: Instant) {
        if let Some(probe_rtt_min_stamp) = self.probe_rtt_min_stamp {
            self.probe_rtt_expired = now
                > probe_rtt_min_stamp
                    .checked_add(self.probe_rtt_interval)
                    .unwrap_or(probe_rtt_min_stamp);
        } else {
            self.probe_rtt_expired = true;
        }
        if let Some(rate_sample) = self.rs
            && rate_sample.rtt >= Duration::from_secs(0)
            && (rate_sample.rtt < self.probe_rtt_min_delay || self.probe_rtt_expired)
        {
            self.probe_rtt_min_delay = rate_sample.rtt;
            self.probe_rtt_min_stamp = Some(now);
        }

        let min_rtt_expired;
        if let Some(min_rtt_stamp) = self.min_rtt_stamp {
            min_rtt_expired = now
                > min_rtt_stamp
                    .checked_add(Duration::from_secs(MIN_RTT_FILTER_LEN))
                    .unwrap_or(min_rtt_stamp);
        } else {
            min_rtt_expired = true;
        }
        if self.probe_rtt_min_delay < self.min_rtt || min_rtt_expired {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    /// equivalent to BBRHandleProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn handle_probe_rtt(&mut self, now: Instant) {
        if self.probe_rtt_done_stamp.is_none() && self.inflight <= self.probe_rtt_cwnd() {
            self.probe_rtt_done_stamp =
                Some(now.checked_add(self.probe_rtt_duration).unwrap_or(now));
            self.probe_rtt_round_done = false;
            self.start_round();
        } else if self.probe_rtt_done_stamp.is_some() {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }
            if self.probe_rtt_round_done {
                self.check_probe_rtt_done(now);
            }
        }
    }

    /// equivalent to BBRCheckProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn check_probe_rtt(&mut self, now: Instant) {
        match self.state {
            BbrState::ProbeRtt => {
                self.handle_probe_rtt(now);
            }
            _ => {
                if self.probe_rtt_expired && !self.idle_restart {
                    self.enter_probe_rtt();
                    self.save_cwnd();
                    self.probe_rtt_done_stamp = None;
                    self.ack_phase = AckPhase::ProbeStopping;
                    self.start_round();
                }
            }
        }
        if let Some(rate_sample) = self.rs
            && rate_sample.delivered > 0
        {
            self.idle_restart = false;
        }
    }

    /// equivalent to BBRAdvanceLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn advance_latest_delivery_signals(&mut self) {
        if self.loss_round_start
            && let Some(rate_sample) = self.rs
        {
            self.bw_latest = rate_sample.delivery_rate;
            self.inflight_latest = rate_sample.delivered;
        }
    }

    /// equivalent to BBRUpdateModelAndState <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.2.3>
    fn update_model_and_state(&mut self, p: BbrPacket, now: Instant) {
        self.update_latest_delivery_signals();
        self.reset_congestion_signals();
        self.update_congestion_signals(p);
        if self.round_start {
            self.refresh_params();
        }
        self.update_ack_aggregation(now);
        self.check_full_bw_reached();
        self.check_startup_done();
        self.check_drain_done(now);
        self.update_probe_bw_cycle_phase(now);
        self.update_min_rtt(now);
        self.check_queue_delay_guard(now);
        self.check_probe_rtt(now);
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();
    }

    /// equivalent to BBRSetPacingRate <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-7>
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// equivalent to BBRSetSendQuantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.3>
    /// this version is based on a version of bbr2 from quiche
    fn set_send_quantum(&mut self) {
        self.send_quantum = match self.pacing_rate {
            rate if rate < PACING_RATE_1_2MBPS => self.smss,
            rate if rate < PACING_RATE_24MBPS => 2 * self.smss,
            _ => min((self.pacing_rate / 1000.0) as u64, HIGH_PACE_MAX_QUANTUM),
        };
    }

    /// equivalent to BBRBoundCwndForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.7>
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = u64::MAX;
        match self.state {
            BbrState::ProbeRtt => {
                cap = self.inflight_with_headroom();
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise) => {
                cap = self.inflight_with_headroom();
            }
            BbrState::ProbeBw(_) => {
                cap = self.inflight_longterm;
            }
            _ => {}
        }
        cap = min(cap, self.inflight_shortterm);
        cap = max(cap, self.min_pipe_cwnd);
        self.cwnd = min(self.cwnd, cap);
    }

    /// equivalent to BBRSetCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.6>
    fn set_cwnd(&mut self) {
        self.update_max_inflight();
        if self.full_bw_reached {
            if let Some(rate_sample) = self.rs {
                self.cwnd = min(self.cwnd + rate_sample.newly_acked, self.max_inflight);
            } else {
                self.cwnd = min(self.cwnd, self.max_inflight);
            }
        } else if (self.cwnd < self.max_inflight || self.delivered < self.initial_cwnd)
            && let Some(rate_sample) = self.rs
        {
            self.cwnd += rate_sample.newly_acked;
        }
        self.cwnd = max(self.cwnd, self.min_pipe_cwnd);
        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
        if self.params.cwnd_floor_bytes > 0 {
            self.cwnd = self.cwnd.max(self.params.cwnd_floor_bytes);
        }
        if self.params.cwnd_cap_bytes > 0 {
            self.cwnd = self.cwnd.min(self.params.cwnd_cap_bytes);
        }
    }

    /// equivalent to BBRUpdateControlParameters <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.2.3>
    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    /// equivalent to IsNewestPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.3-3>
    fn is_newest_packet(&self, send_time: Instant, end_seq: u64) -> bool {
        if let Some(first_send_time) = self.first_send_time {
            if send_time > first_send_time {
                return true;
            }
            if let Some(rate_sample) = self.rs
                && end_seq > rate_sample.last_end_seq
            {
                return true;
            }
        }
        false
    }

    /// equivalent to BBRHandleLostPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    fn process_lost_packet(&mut self, lost_bytes: u64, packet_index: usize, now: Instant) {
        let p = self.packets[packet_index];
        self.note_loss();
        if !self.bw_probe_samples {
            self.packets.remove(packet_index);
            return;
        }
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_lost += lost_bytes;
            rate_sample.tx_in_flight = p.tx_in_flight;
            rate_sample.lost = self.lost.saturating_sub(p.lost);
            rate_sample.is_app_limited = p.is_app_limited;
            self.rs = Some(rate_sample);
            if self.is_inflight_too_high() {
                let inflight_at_loss = self.inflight_at_loss(p.size as u64);
                if let Some(rate_sample) = self.rs.as_mut() {
                    rate_sample.tx_in_flight = inflight_at_loss;
                }
                self.handle_inflight_too_high(now);
            }
        }
        self.packets.remove(packet_index);
    }
}
impl Controller for Bbr3 {
    fn on_path_activated(&mut self) {
        // Keep validated RTT history, but discard the low-rate/app-limited standby
        // operating point. Per-path keepalives are deliberately sparse and must not
        // leave a newly selected path cruising at their delivery rate.
        self.enter_startup();
        self.reset_full_bw();
        self.full_bw_reached = false;
        self.reset_congestion_signals();
        self.inflight_longterm = u64::MAX;
        self.inflight_shortterm = u64::MAX;
        self.bw_shortterm = f64::INFINITY;
        self.policer_pacing_scale = 1.0;
        self.cwnd = self.cwnd.max(self.initial_cwnd);

        let nominal_bandwidth = if self.params.startup_bw_hint_bytes_per_second > 0 {
            self.params.startup_bw_hint_bytes_per_second as f64
        } else {
            self.initial_cwnd as f64 / 0.001
        };
        self.pacing_rate = self.startup_pacing_gain * nominal_bandwidth;
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            self.pacing_rate = self
                .pacing_rate
                .min(self.params.pacing_rate_cap_bytes_per_second as f64);
        }
        self.send_quantum = 2 * self.smss;
    }

    fn on_packet_sent(&mut self, now: Instant, bytes: u16, pn: u64) {
        if self.inflight == 0 {
            self.first_send_time = Some(now);
            self.delivered_time = Some(now);
            // BBR's idle-restart predicate is defined against the pre-send inflight value.
            // Calling this after incrementing `inflight` made the predicate impossible, which
            // could leave a connection parked in ProbeRTT when bulk traffic resumed after an
            // idle/control-only interval.
            self.handle_restart_from_idle(now);
        }
        let added_bytes = bytes as u64;
        self.inflight += added_bytes;
        self.packets.push_back(BbrPacket {
            delivered: self.delivered,
            delivered_time: self.delivered_time.unwrap_or(now),
            first_send_time: self.first_send_time.unwrap_or(now),
            send_time: now,
            is_app_limited: self.app_limited != 0,
            tx_in_flight: self.inflight,
            packet_number: pn,
            size: bytes,
            lost: self.lost,
            acknowledged: false,
            round_count: self.round_count,
        });
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        pn: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.policer_window_acked_bytes = self.policer_window_acked_bytes.saturating_add(bytes);
        self.delivered = self.delivered.saturating_add(bytes);
        self.delivered_time = Some(now);
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_acked += bytes;
            self.rs = Some(rate_sample);
        }
        let p_index_result = self.packets.binary_search_by_key(&pn, |p| p.packet_number);
        let is_newest_packet = self.is_newest_packet(sent, pn);
        if let Ok(p_index) = p_index_result
            && let Some(p) = self.packets.get_mut(p_index)
        {
            p.acknowledged = true;
            if let Some(mut rate_sample) = self.rs {
                rate_sample.rtt = now - p.send_time;
                if is_newest_packet {
                    self.srtt = rtt.get();
                    rate_sample.prior_delivered = p.delivered;
                    rate_sample.prior_time = p.delivered_time;
                    rate_sample.is_app_limited = p.is_app_limited;
                    rate_sample.tx_in_flight = p.tx_in_flight;
                    rate_sample.send_elapsed = p.send_time - p.first_send_time;
                    rate_sample.ack_elapsed = self.delivered_time.unwrap_or(now) - p.delivered_time;
                    rate_sample.last_end_seq = pn;
                    self.first_send_time = Some(p.send_time);
                    rate_sample.last_packet = *p;
                    self.rs = Some(rate_sample);
                }
            } else {
                let rate_sample = BbrRateSample {
                    rtt: now.saturating_duration_since(p.send_time),
                    prior_time: p.delivered_time,
                    interval: Duration::ZERO,
                    delivery_rate: 0.0,
                    is_app_limited: p.is_app_limited,
                    delivered: 0,
                    prior_delivered: p.delivered,
                    tx_in_flight: p.tx_in_flight,
                    send_elapsed: p.send_time - p.first_send_time,
                    ack_elapsed: self.delivered_time.unwrap_or(now) - p.delivered_time,
                    newly_acked: bytes,
                    newly_lost: 0,
                    lost: 0,
                    last_end_seq: pn,
                    last_packet: *p,
                };
                self.rs = Some(rate_sample);
                self.first_send_time = Some(p.send_time);
                self.srtt = rtt.get();
            }
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inflight = in_flight;
        if let Some(largest_packet_num) = largest_packet_num_acked {
            if self.app_limited != 0 && largest_packet_num > self.app_limited {
                self.app_limited = 0;
            } else if app_limited {
                self.app_limited = self.app_limited.max(largest_packet_num);
            }
            // Packet numbers are inserted monotonically. Retire the contiguous
            // acknowledged/expired prefix instead of scanning the complete
            // inflight deque twice for every ACK batch. Out-of-order ACKed
            // entries remain behind the first live gap and are reclaimed when
            // that gap is ACKed, declared lost, or ages out. This makes the
            // normal ordered-ACK path amortized O(acked packets), independent
            // of BDP, while preserving loss lookups for unresolved packets.
            while self.packets.front().is_some_and(|packet| {
                packet.acknowledged
                    || self.round_count.saturating_sub(packet.round_count) > ROUND_COUNT_WINDOW
            }) {
                self.packets.pop_front();
            }
            if let Some(mut rate_sample) = self.rs {
                rate_sample.interval = max(rate_sample.send_elapsed, rate_sample.ack_elapsed);
                rate_sample.delivered = self.delivered.saturating_sub(rate_sample.prior_delivered);
                // ignore this condition on an initially high min rtt as per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.3-5>
                let valid_interval = rate_sample.interval >= self.min_rtt
                    || self.min_rtt == Duration::from_secs(u64::MAX);
                if rate_sample.prior_delivered != 0
                    && valid_interval
                    && rate_sample.interval != Duration::ZERO
                {
                    rate_sample.delivery_rate =
                        rate_sample.delivered as f64 / rate_sample.interval.as_secs_f64();
                } else {
                    rate_sample.delivery_rate = 0.0;
                }
                if rate_sample.delivered >= self.cwnd {
                    self.is_cwnd_limited = true;
                }
                self.rs = Some(rate_sample);
                // BBR consumes exactly one completed delivery-rate sample per ACK
                // batch. Updating the model from `on_ack` used the preceding batch's
                // stale rate and ran once per ACK range before `interval`/`delivered`
                // had even been calculated.
                self.update_model_and_state(rate_sample.last_packet, now);
                self.update_policer_pacing(now);
                self.update_control_parameters();
                rate_sample.newly_acked = 0;
                rate_sample.lost = 0;
                rate_sample.newly_lost = 0;
                self.rs = Some(rate_sample);
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
        largest_lost_pn: u64,
    ) {
        // only process ecn here, regular packet loss is detected per packet in on_packet_lost.
        if is_ecn {
            self.policer_window_lost_bytes =
                self.policer_window_lost_bytes.saturating_add(lost_bytes);
            self.explicit_congestion_in_round = true;
            self.lost += lost_bytes;
            let p_index_result = self
                .packets
                .binary_search_by_key(&largest_lost_pn, |p| p.packet_number);
            if let Ok(p_index) = p_index_result {
                self.process_lost_packet(lost_bytes, p_index, now);
            }
            if is_persistent_congestion {
                self.cwnd = self.min_pipe_cwnd;
            }
        }
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, pn: u64, now: Instant) {
        let lost_bytes_64 = lost_bytes as u64;
        self.policer_window_lost_bytes =
            self.policer_window_lost_bytes.saturating_add(lost_bytes_64);
        self.lost += lost_bytes_64;
        let p_index_result = self.packets.binary_search_by_key(&pn, |p| p.packet_number);
        if let Ok(p_index) = p_index_result {
            self.process_lost_packet(lost_bytes_64, p_index, now);
        }
    }

    /// equivalent to BBRHandleSpuriousLossDetection: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11.2>
    fn on_spurious_congestion_event(&mut self) {
        self.loss_in_round = false;
        self.reset_full_bw();
        self.bw_shortterm = [self.bw_shortterm, self.undo_bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = max(self.inflight_shortterm, self.undo_inflight_shortterm);
        self.inflight_longterm = max(self.inflight_longterm, self.undo_inflight_longterm);
        if self.state != BbrState::ProbeRtt && self.state != self.undo_state {
            if self.undo_state == BbrState::Startup {
                self.enter_startup();
            } else if self.undo_state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                self.start_probe_bw_up();
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.smss = min(
            max(MIN_MAX_DATAGRAM_SIZE, new_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
        self.set_send_quantum();
        self.set_cwnd();
    }

    fn on_ack_frequency_update(
        &mut self,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: Duration,
    ) {
        self.ack_eliciting_threshold = ack_eliciting_threshold;
        self.max_ack_delay = requested_max_ack_delay;
    }

    fn window(&self) -> u64 {
        if self.pacing_bypass_active() {
            self.cwnd.max(self.low_rtt_cwnd_floor)
        } else {
            self.cwnd
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let pacing_enabled = !self.pacing_bypass_active();
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: pacing_enabled.then_some(self.pacing_rate.round() as u64),
            send_quantum: pacing_enabled.then_some(self.send_quantum),
            queue_delay_guard_transitions: self.queue_delay_guard_transitions,
            policer_pacing_scale_per_mille: (self.policer_pacing_scale * 1_000.0)
                .round()
                .clamp(0.0, 1_000.0) as u16,
            policer_pacing_transitions: self.policer_pacing_transitions,
            snapshot: Some(ControllerSnapshot {
                state: match self.state {
                    BbrState::Startup => 0,
                    BbrState::Drain => 1,
                    BbrState::ProbeBw(ProbeBwSubstate::Down) => 2,
                    BbrState::ProbeBw(ProbeBwSubstate::Cruise) => 3,
                    BbrState::ProbeBw(ProbeBwSubstate::Refill) => 4,
                    BbrState::ProbeBw(ProbeBwSubstate::Up) => 5,
                    BbrState::ProbeRtt => 6,
                },
                bw: self.bw.max(0.0).round() as u64,
                max_bw: self.max_bw.max(0.0).round() as u64,
                min_rtt: self.min_rtt,
                srtt: self.srtt,
                bdp: self.bdp,
                inflight_longterm: self.inflight_longterm,
                inflight_shortterm: self.inflight_shortterm,
                round_count: self.round_count,
                cycle_count: self.cycle_count,
                app_limited_in_round: self.rs.is_some_and(|sample| sample.is_app_limited),
                lost_in_round: self.rs.map_or(0, |sample| sample.newly_lost),
                delivered_in_round: self.rs.map_or(0, |sample| sample.delivered),
                probe_rtt_entries: self.probe_rtt_entries,
                guard_transitions: self.queue_delay_guard_transitions,
                clamped_writes: self.tunables.clamped_writes.load(Ordering::Relaxed),
                params_generation: self.params_generation,
            }),
        }
    }

    fn tunables(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        Some(self.tunables.clone())
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_cwnd
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `Bbr3` congestion controller
///
/// Different pacing_gains can be set to modify the multiplier used to
/// increase the sending rates.
/// Different cwnd_gains can be set to modify the multiplier used to increase
/// the congestion windows.
/// All of these parameters are specific to different states of the algorithm: see `BbrState`
/// `pacing_margin_percent` is used to set a margin when calculating the `pacing_rate` in order
/// to not send at 100% capacity when calculating pacing.
#[derive(Debug, Clone)]
pub struct Bbr3Config {
    initial_window: u64,
    probe_rng_seed: Option<[u8; 16]>,
    startup_pacing_gain: Option<f64>,
    default_pacing_gain: Option<f64>,
    probe_bw_down_pacing_gain: Option<f64>,
    probe_bw_up_pacing_gain: Option<f64>,
    probe_bw_up_cwnd_gain: Option<f64>,
    probe_rtt_cwnd_gain: Option<f64>,
    drain_pacing_gain: Option<f64>,
    pacing_margin_percent: Option<f64>,
    default_cwnd_gain: Option<f64>,
    pacing_bypass_below_rtt: Option<Duration>,
    low_rtt_cwnd_floor: u64,
    tunables_template: Option<Arc<Bbr3Tunables>>,
}

impl Bbr3Config {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    /// Bypass BBR's userspace pacing timer after the measured path minimum RTT
    /// falls below `threshold`. Congestion-window accounting remains active.
    /// This is intended for host/datacenter paths where timer scheduling costs
    /// more than the sub-millisecond wire interval; Internet paths should keep
    /// the default (`None`).
    pub fn pacing_bypass_below_rtt(&mut self, threshold: Option<Duration>) -> &mut Self {
        self.pacing_bypass_below_rtt = threshold.filter(|value| !value.is_zero());
        self
    }

    /// Set the minimum congestion window used while the low-RTT pacing bypass
    /// is active. A larger window amortizes ACK scheduling and socket wakeups
    /// on host/datacenter paths without changing Internet-path BBR behavior.
    pub fn low_rtt_cwnd_floor(&mut self, bytes: u64) -> &mut Self {
        self.low_rtt_cwnd_floor = bytes;
        self
    }

    /// Set the initial runtime-tuning template. Each newly constructed path
    /// receives its own atomic handle copied from this template.
    pub fn tunables_template(&mut self, template: Option<Arc<Bbr3Tunables>>) -> &mut Self {
        self.tunables_template = template;
        self
    }
}

impl Default for Bbr3Config {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * MAX_DATAGRAM_SIZE, 10 * MAX_DATAGRAM_SIZE),
            probe_rng_seed: None,
            startup_pacing_gain: None,
            default_pacing_gain: None,
            probe_bw_down_pacing_gain: None,
            probe_bw_up_pacing_gain: None,
            probe_bw_up_cwnd_gain: None,
            probe_rtt_cwnd_gain: None,
            drain_pacing_gain: None,
            pacing_margin_percent: None,
            default_cwnd_gain: None,
            pacing_bypass_below_rtt: None,
            low_rtt_cwnd_floor: 0,
            tunables_template: None,
        }
    }
}

impl ControllerFactory for Bbr3Config {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr3::new(self, current_mtu))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_rate_sample(lost: u64, tx_in_flight: u64) -> BbrRateSample {
        let now = Instant::now();
        let packet = BbrPacket {
            delivered: 0,
            delivered_time: now,
            first_send_time: now,
            send_time: now,
            is_app_limited: false,
            tx_in_flight,
            packet_number: 0,
            size: MIN_MAX_DATAGRAM_SIZE,
            lost: 0,
            acknowledged: false,
            round_count: 0,
        };
        BbrRateSample {
            delivery_rate: 0.0,
            is_app_limited: false,
            interval: Duration::ZERO,
            delivered: 0,
            prior_delivered: 0,
            prior_time: now,
            send_elapsed: Duration::ZERO,
            ack_elapsed: Duration::ZERO,
            rtt: Duration::from_millis(28),
            tx_in_flight,
            newly_acked: 0,
            newly_lost: lost,
            lost,
            last_end_seq: 0,
            last_packet: packet,
        }
    }

    #[test]
    fn test_probe_rng() {
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            initial_window: 14720.clamp(2 * MAX_DATAGRAM_SIZE, 10 * MAX_DATAGRAM_SIZE),
            probe_rng_seed: Some(seed),
            startup_pacing_gain: None,
            default_pacing_gain: None,
            probe_bw_down_pacing_gain: None,
            probe_bw_up_pacing_gain: None,
            probe_bw_up_cwnd_gain: None,
            probe_rtt_cwnd_gain: None,
            drain_pacing_gain: None,
            pacing_margin_percent: None,
            default_cwnd_gain: None,
            pacing_bypass_below_rtt: None,
            low_rtt_cwnd_floor: 0,
            tunables_template: None,
        };
        let mut bbr3 = Bbr3::new(Arc::new(config), 2500);
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2652));
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2570));
    }

    #[test]
    fn pacing_bypass_is_automatic_only_below_configured_minimum_rtt() {
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(1)));
        config.low_rtt_cwnd_floor(512 * 1024);
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_400);

        assert!(
            bbr3.metrics().pacing_rate.is_some(),
            "pacing stays enabled until an RTT sample exists"
        );
        bbr3.min_rtt = Duration::from_micros(999);
        bbr3.cwnd = 64 * 1024;
        bbr3.pacing_bypass_armed = true;
        assert!(bbr3.metrics().pacing_rate.is_none());
        assert!(bbr3.metrics().send_quantum.is_none());
        assert_eq!(bbr3.window(), 512 * 1024);

        bbr3.policer_pacing_scale = 0.9;
        assert!(bbr3.metrics().pacing_rate.is_some());
        assert!(bbr3.metrics().send_quantum.is_some());
        assert_eq!(bbr3.window(), 64 * 1024);

        bbr3.policer_pacing_scale = 1.0;
        bbr3.min_rtt = Duration::from_millis(1);
        assert!(bbr3.metrics().pacing_rate.is_some());
        assert!(bbr3.metrics().send_quantum.is_some());
        assert_eq!(bbr3.window(), 64 * 1024);
    }

    #[test]
    fn short_rtt_sustained_loss_automatically_caps_wire_pacing() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_scale, 0.9);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert_eq!(bbr3.metrics().policer_pacing_scale_per_mille, 900);

        bbr3.full_bw_reached = true;
        bbr3.bw = 10_000_000.0;
        bbr3.set_pacing_rate_with_gain(1.0);
        assert_eq!(bbr3.pacing_rate, 8_910_000.0);
    }

    #[test]
    fn clean_window_arms_low_rtt_bypass_but_policer_loss_disarms_it() {
        let start = Instant::now();
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        config.low_rtt_cwnd_floor(512 * 1024);
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 1_000_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(bbr3.pacing_bypass_armed);
        assert!(bbr3.metrics().pacing_rate.is_none());
        assert_eq!(bbr3.window(), 512 * 1024);

        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert!(!bbr3.pacing_bypass_armed);
        assert_eq!(bbr3.policer_pacing_scale, 0.9);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert!(bbr3.metrics().pacing_rate.is_some());
    }

    #[test]
    fn clean_short_path_recovers_additively_and_long_rtt_loss_is_ignored() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.policer_pacing_scale = 0.8;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 1_000_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!((bbr3.policer_pacing_scale - 0.82).abs() < f64::EPSILON);

        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert_eq!(bbr3.policer_pacing_scale, 1.0);
        assert_eq!(bbr3.policer_pacing_transitions, 0);

        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.policer_pacing_scale = 0.98;
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_window_acked_bytes = 1_000_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 3);
        assert_eq!(bbr3.policer_pacing_scale, 0.99);
    }

    #[test]
    fn send_quantum_uses_live_smss_and_bit_rate_thresholds() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS - 1.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 1_200);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 2_400);

        bbr3.pacing_rate = PACING_RATE_24MBPS;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 3_000);

        bbr3.pacing_rate = 100_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS;
        bbr3.on_mtu_update(1_452);
        assert_eq!(bbr3.send_quantum, 2_904);
    }

    #[test]
    fn loss_caps_inflight_only_with_explicit_congestion() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.rs = Some(test_rate_sample(90_000, 100_000));

        assert!(!bbr3.is_inflight_too_high());

        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.srtt = Duration::from_millis(28);
        assert!(!bbr3.is_inflight_too_high());

        bbr3.rs = Some(test_rate_sample(3_000, 100_000));
        bbr3.srtt = Duration::from_millis(40);
        assert!(!bbr3.is_inflight_too_high());

        bbr3.srtt = Duration::from_millis(28);
        bbr3.explicit_congestion_in_round = true;
        assert!(bbr3.is_inflight_too_high());

        bbr3.explicit_congestion_in_round = false;
        bbr3.tunables.loss_is_congestion.store(1, Ordering::Relaxed);
        bbr3.tunables.generation.store(1, Ordering::Relaxed);
        bbr3.refresh_params();
        assert!(bbr3.is_inflight_too_high());
    }

    #[test]
    fn isolated_random_loss_cannot_pin_an_already_small_flight() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(21);
        bbr3.rs = Some(test_rate_sample(1_200, 4_800));

        assert!(!bbr3.is_inflight_too_high());

        bbr3.explicit_congestion_in_round = true;
        assert!(bbr3.is_inflight_too_high());
    }

    #[test]
    fn high_latency_low_queue_path_does_not_treat_radio_loss_as_congestion() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.srtt = Duration::from_millis(90);
        bbr3.rs = Some(test_rate_sample(40_000, 100_000));

        assert!(!bbr3.is_inflight_too_high());

        bbr3.srtt = Duration::from_millis(130);
        assert!(!bbr3.is_inflight_too_high());

        bbr3.explicit_congestion_in_round = true;
        assert!(bbr3.is_inflight_too_high());
    }

    #[test]
    fn high_rtt_loss_does_not_end_startup_before_capacity_is_discovered() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::Startup;
        bbr3.round_start = true;
        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.srtt = Duration::from_millis(92);
        bbr3.bw = 100_000.0;
        bbr3.full_bw = 100_000.0;
        let mut lossy_sample = test_rate_sample(12_000, 100_000);
        lossy_sample.delivery_rate = 105_000.0;
        lossy_sample.newly_lost = 12_000;
        bbr3.rs = Some(lossy_sample);

        for _ in 0..MAX_FULL_BW_COUNT + 1 {
            bbr3.check_full_bw_reached();
        }
        assert_eq!(bbr3.full_bw_count, 0);
        assert!(!bbr3.full_bw_reached);

        let mut clean_sample = lossy_sample;
        clean_sample.lost = 0;
        clean_sample.newly_lost = 0;
        bbr3.rs = Some(clean_sample);
        for _ in 0..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
        }
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn short_rtt_policer_loss_still_ends_startup_normally() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::Startup;
        bbr3.round_start = true;
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.srtt = Duration::from_millis(7);
        bbr3.bw = 100_000.0;
        bbr3.full_bw = 100_000.0;
        let mut sample = test_rate_sample(12_000, 100_000);
        sample.delivery_rate = 105_000.0;
        sample.newly_lost = 12_000;
        bbr3.rs = Some(sample);

        for _ in 0..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
        }
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn low_queue_loss_ignores_even_an_old_packets_cumulative_history() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(35);
        bbr3.srtt = Duration::from_millis(37);
        let mut sample = test_rate_sample(20_000, 10_000);
        sample.newly_lost = 1_200;
        bbr3.rs = Some(sample);

        assert!(!bbr3.is_inflight_too_high());

        bbr3.srtt = Duration::from_millis(60);
        assert!(!bbr3.is_inflight_too_high());
    }

    #[test]
    fn queue_delay_guard_uses_live_minimum_rtt_without_an_operator_threshold() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.loss_is_congestion = true;

        assert!(!bbr3.queue_delay_guard_triggered());
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.bw = 1_000_000.0;
        assert!(!bbr3.queue_delay_guard_triggered());

        bbr3.srtt = Duration::from_micros(30_001);
        assert!(bbr3.queue_delay_guard_triggered());
    }

    #[test]
    fn queue_delay_guard_drains_startup_and_stops_only_upward_probe_bw() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.loss_is_congestion = true;
        let now = Instant::now();
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.bw = 1_000_000.0;

        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::Drain);
        assert!(bbr3.full_bw_reached);
        assert_eq!(bbr3.queue_delay_guard_transitions, 1);

        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Down));
        assert_eq!(bbr3.queue_delay_guard_transitions, 2);

        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Cruise));
        assert_eq!(bbr3.queue_delay_guard_transitions, 2);
    }

    #[test]
    fn loss_tolerant_upward_probe_gets_room_to_discover_a_shaped_link() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.bw = 1_000_000.0;

        assert!(!bbr3.params.loss_is_congestion);
        assert!(!bbr3.queue_delay_guard_triggered());
        bbr3.srtt = Duration::from_micros(60_001);
        assert!(bbr3.queue_delay_guard_triggered());

        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.srtt = Duration::from_micros(30_001);
        assert!(bbr3.queue_delay_guard_triggered());
    }

    #[test]
    fn inflight_at_loss_saturates_when_sample_is_already_over_threshold() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.rs = Some(test_rate_sample(50_000, 100_000));

        assert_eq!(bbr3.inflight_at_loss(1_200), 98_800);
    }

    #[test]
    fn lost_packet_publishes_updated_sample_before_threshold_decision() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.explicit_congestion_in_round = true;
        bbr3.rs = Some(test_rate_sample(0, 1_200));
        bbr3.bw_probe_samples = true;
        bbr3.on_packet_sent(now, 1_200, 1);

        bbr3.on_packet_lost(1_200, 1, now);

        assert!(!bbr3.bw_probe_samples);
        assert_eq!(bbr3.rs.expect("rate sample").lost, 1_200);
    }

    #[test]
    fn first_packet_after_idle_exits_an_expired_probe_rtt_before_accounting_send() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.state = BbrState::ProbeRtt;
        bbr3.cwnd = bbr3.min_pipe_cwnd;
        bbr3.prior_cwnd = 64 * 1024;
        bbr3.app_limited = 1;
        bbr3.probe_rtt_done_stamp = now.checked_sub(Duration::from_millis(1));

        bbr3.on_packet_sent(now, 1_200, 1);

        assert!(bbr3.idle_restart);
        assert_eq!(bbr3.state, BbrState::Startup);
        assert_eq!(bbr3.cwnd, 64 * 1024);
        assert_eq!(bbr3.inflight, 1_200);
    }

    #[test]
    fn max_bw_virtual_time_advances_once_per_probe_bw_cycle() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Down);
        bbr3.ack_phase = AckPhase::ProbeStopping;
        bbr3.round_start = true;
        bbr3.rs = Some(test_rate_sample(1_000_000, 24_000));

        bbr3.adapt_long_term_model();
        assert_eq!(bbr3.cycle_count, 1);
        assert_eq!(bbr3.ack_phase, AckPhase::ProbeFeedback);

        // More packet-timed rounds in Down/Cruise are still part of the same
        // ProbeBW cycle and must not age the max-bw filter again.
        bbr3.adapt_long_term_model();
        assert_eq!(bbr3.cycle_count, 1);

        bbr3.start_probe_bw_down(Instant::now());
        bbr3.round_start = true;
        bbr3.rs = Some(test_rate_sample(1_100_000, 24_000));
        bbr3.adapt_long_term_model();
        assert_eq!(bbr3.cycle_count, 2);
    }

    #[test]
    fn ack_batch_publishes_its_completed_delivery_rate_before_model_update() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let rtt = RttEstimator::new(Duration::from_millis(100));
        let start = Instant::now();

        bbr3.on_packet_sent(start, 1_200, 1);
        let first_ack = start + Duration::from_millis(10);
        bbr3.on_ack(first_ack, start, 1_200, 1, false, &rtt);
        assert_eq!(bbr3.delivered, 1_200, "the first ACK is delivered data too");
        bbr3.on_end_acks(first_ack, 0, false, Some(1));

        let second_sent = start + Duration::from_millis(11);
        let third_sent = start + Duration::from_millis(12);
        bbr3.on_packet_sent(second_sent, 1_200, 2);
        bbr3.on_packet_sent(third_sent, 1_200, 3);
        let batch_ack = start + Duration::from_millis(22);
        bbr3.on_ack(batch_ack, second_sent, 1_200, 2, false, &rtt);
        bbr3.on_ack(batch_ack, third_sent, 1_200, 3, false, &rtt);

        assert_eq!(
            bbr3.rs.expect("pending rate sample").delivery_rate,
            0.0,
            "per-packet ACK callbacks must not reuse the preceding batch's rate"
        );
        bbr3.on_end_acks(batch_ack, 0, false, Some(3));

        let sample = bbr3.rs.expect("completed rate sample");
        assert_eq!(sample.delivered, 2_400);
        assert_eq!(sample.interval, Duration::from_millis(11));
        let expected_rate = 2_400.0 / 0.011;
        assert!(
            (sample.delivery_rate - expected_rate).abs() < 0.001,
            "actual={} expected={expected_rate}",
            sample.delivery_rate
        );
        assert!((bbr3.max_bw - expected_rate.round()).abs() < 0.001);
    }

    #[test]
    fn ack_history_reclaims_only_the_contiguous_resolved_prefix() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        for packet_number in 1..=3 {
            bbr3.on_packet_sent(now, 1_200, packet_number);
        }

        bbr3.packets[1].acknowledged = true;
        bbr3.on_end_acks(now, 2_400, false, Some(2));
        assert_eq!(
            bbr3.packets.len(),
            3,
            "an unresolved prefix gap is retained"
        );

        bbr3.packets[0].acknowledged = true;
        bbr3.on_end_acks(now, 1_200, false, Some(2));
        assert_eq!(bbr3.packets.len(), 1);
        assert_eq!(bbr3.packets.front().unwrap().packet_number, 3);
    }

    #[test]
    fn runtime_params_refresh_only_after_generation_and_round_boundary() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        handle
            .probe_bw_up_pacing_gain_milli
            .store(1_500, Ordering::Relaxed);

        bbr3.refresh_params();
        assert_eq!(bbr3.params.probe_bw_up_pacing_gain, 1.25);

        handle.generation.store(1, Ordering::Relaxed);
        bbr3.next_round_delivered = 10;
        let mut packet = test_rate_sample(0, 12_000).last_packet;
        packet.delivered = 9;
        bbr3.update_model_and_state(packet, Instant::now());
        assert_eq!(bbr3.params_generation, 0);

        packet.delivered = 10;
        bbr3.update_model_and_state(packet, Instant::now());
        assert_eq!(bbr3.params_generation, 1);
        assert_eq!(bbr3.params.probe_bw_up_pacing_gain, 1.5);
    }

    #[test]
    fn runtime_caps_apply_to_pacing_and_cwnd() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.tunables
            .pacing_rate_cap_bytes_per_second
            .store(200_000, Ordering::Relaxed);
        bbr3.tunables
            .cwnd_floor_bytes
            .store(20_000, Ordering::Relaxed);
        bbr3.tunables
            .cwnd_cap_bytes
            .store(24_000, Ordering::Relaxed);
        bbr3.tunables.generation.store(1, Ordering::Relaxed);
        bbr3.refresh_params();

        bbr3.full_bw_reached = true;
        bbr3.bw = 1_000_000.0;
        bbr3.pacing_rate = 1.0;
        bbr3.set_pacing_rate_with_gain(1.25);
        assert_eq!(bbr3.pacing_rate, 200_000.0);

        bbr3.cwnd = 1;
        bbr3.set_cwnd();
        assert_eq!(bbr3.cwnd, 20_000);
        bbr3.cwnd = 100_000;
        bbr3.set_cwnd();
        assert_eq!(bbr3.cwnd, 24_000);
    }

    #[test]
    fn startup_hint_warms_pacing_and_window_and_handles_are_path_local() {
        let template = Arc::new(Bbr3Tunables::default());
        template
            .startup_bw_hint_bytes_per_second
            .store(1_000_000, Ordering::Relaxed);
        template
            .pacing_rate_cap_bytes_per_second
            .store(2_000_000, Ordering::Relaxed);
        let mut config = Bbr3Config::default();
        config.tunables_template(Some(template));
        let config = Arc::new(config);
        let first = Bbr3::new(config.clone(), 1_200);
        let second = Bbr3::new(config, 1_200);

        assert_eq!(first.initial_cwnd, 333_000);
        assert_eq!(first.pacing_rate, 2_000_000.0);
        assert!(!Arc::ptr_eq(&first.tunables, &second.tunables));
        let erased = first.tunables().expect("BBR3 tuning handle");
        assert!(erased.downcast::<Bbr3Tunables>().is_ok());
    }

    #[test]
    fn activating_warm_path_restarts_capacity_discovery() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.full_bw = 50_000.0;
        bbr3.full_bw_count = 3;
        bbr3.cwnd = bbr3.min_pipe_cwnd;
        bbr3.pacing_rate = 50_000.0;
        bbr3.inflight_longterm = bbr3.min_pipe_cwnd;
        bbr3.inflight_shortterm = bbr3.min_pipe_cwnd;
        bbr3.bw_shortterm = 50_000.0;
        bbr3.policer_pacing_scale = 0.5;

        bbr3.on_path_activated();

        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.full_bw_reached);
        assert_eq!(bbr3.full_bw, 0.0);
        assert_eq!(bbr3.full_bw_count, 0);
        assert!(bbr3.cwnd >= bbr3.initial_cwnd);
        assert_eq!(bbr3.inflight_longterm, u64::MAX);
        assert_eq!(bbr3.inflight_shortterm, u64::MAX);
        assert!(bbr3.bw_shortterm.is_infinite());
        assert_eq!(bbr3.policer_pacing_scale, 1.0);
        assert!(bbr3.pacing_rate > 50_000.0);
    }

    #[test]
    fn snapshot_reports_runtime_generation_and_clamps() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.tunables
            .loss_thresh_milli
            .store(u32::MAX, Ordering::Relaxed);
        bbr3.tunables.generation.store(7, Ordering::Relaxed);
        bbr3.refresh_params();
        let snapshot = bbr3.metrics().snapshot.expect("BBR3 snapshot");
        assert_eq!(snapshot.params_generation, 7);
        assert_eq!(snapshot.clamped_writes, 1);
        assert_eq!(snapshot.state, 0);
    }
}
