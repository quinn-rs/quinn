mod max_filter;

use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;

use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg32;

use crate::RttEstimator;
use crate::congestion::bbr3::max_filter::MaxFilter;
use crate::congestion::{Controller, ControllerFactory, ControllerMetrics};
use crate::{Duration, Instant};

/// equivalent to BBR.MaxBwFilterLen <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.10>
const MAX_BW_FILTER_LEN: usize = 2;

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

/// 64 KBytes in bytes
/// one of the default high values for `set_send_quantum`
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#section-5.6.3>
const HIGH_PACE_MAX_QUANTUM: u64 = 64 * 1024;

/// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
/// the sending rate to double each round (4 * ln(2) ~= 2.77)
/// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const STARTUP_PACING_GAIN: f64 = 2.773;

/// default pacing gain is 1, when cruising, probing for RTT or refilling <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const DEFAULT_PACING_GAIN: f64 = 1.0;

/// pacing gain when probing bandwidth down <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const PROBE_BW_DOWN_PACING_GAIN: f64 = 0.9;

/// pacing gain when probing bandwidth up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const PROBE_BW_UP_PACING_GAIN: f64 = 1.25;

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

/// cwnd gain used when probing up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const PROBE_BW_UP_CWND_GAIN: f64 = 2.25;

/// cwnd gain used when probing RTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const PROBE_RTT_CWND_GAIN: f64 = 0.5;

/// equivalent to BBR.ProbeRTTDuration: A constant specifying the minimum duration for which ProbeRTT state holds C.inflight to BBR.MinPipeCwnd or fewer packets: 200 ms.
const PROBE_RTT_DURATION_MS: u64 = 200;

/// equivalent to BBR.ProbeRTTInterval: A constant specifying the minimum time interval between ProbeRTT states: 5 secs.
const PROBE_RTT_INTERVAL_SEC: u64 = 5;

/// equivalent to BBR.LossThresh: A constant specifying the maximum tolerated per-round-trip packet loss rate when probing for bandwidth (the default is 2%).
const LOSS_THRESH: f64 = 0.02;

/// equivalent to BBR.Beta: A constant specifying the default multiplicative decrease to make upon each round trip during which the connection detects packet loss (the value is 0.7).
const BETA: f64 = 0.7;

/// equivalent to BBR.Headroom: A constant specifying the multiplicative factor to apply to BBR.inflight_longterm when calculating
/// a volume of free headroom to try to leave unused in the path
/// (e.g. free space in the bottleneck buffer or free time slots in the bottleneck link) that can be used by cross traffic (the value is 0.15).
const HEADROOM: f64 = 0.15;

/// equivalent to BBR.MinRTTFilterLen: A constant specifying the length of the BBR.min_rtt min filter window, BBR.MinRTTFilterLen is 10 secs.
const MIN_RTT_FILTER_LEN: u64 = 10;

/// multiplier used to check growth when validating if the full bandwidth has been reached
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
const FULL_BW_GROWTH: f64 = 1.25;

/// maximum number of rounds needed before we consider that the pipe is full <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
const MAX_FULL_BW_COUNT: u64 = 3;

/// equivalent to BBRStartupFullLossCnt: the minimum number of discontiguous loss
/// events observed within a single round trip before the STARTUP high-loss
/// estimator is allowed to exit STARTUP.
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#section-5.3.1.3>
const STARTUP_FULL_LOSS_CNT: u64 = 6;

/// when setting `bw_probe_up_rounds` when raising our inflight long term slope we don't go above this
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
const MAX_LONG_TERM_PROBE_UP_ROUNDS: u32 = 30;

/// max number of rounds used when deciding to coexist with Reno / CUBIC <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.1>
const MAX_RENO_ROUNDS: u64 = 63;

/// minimum amount of time to wait before probing again <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-5>
const MIN_PROBE_WAIT_MS: u64 = 2000;

/// when waiting before probing again we add up to one second of added wait time
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-5>
const MAX_ADDED_PROBE_WAIT_MS: u64 = 1000;

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
    /// once a packet has been acknowledged on a given round it is marked for removal on the next round.
    stale: bool,
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
    /// Transport-provided (via `on_cwnd_limited`); snapshotted from `cwnd_limited_this_round` at each round boundary.
    is_cwnd_limited: bool,
    /// ORs every cwnd-blocked send in the current round; snapshotted into `is_cwnd_limited` and cleared when the round advances.
    cwnd_limited_this_round: bool,
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
    /// equivalent to BBR.loss_events_in_round: count of discontiguous loss events
    /// observed in the current round trip, used by the STARTUP high-loss exit
    /// (BBRStartupFullLossCnt criterion). Reset at each loss-round boundary.
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#section-5.3.1.3>
    loss_events_in_round: u64,
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
}

impl Bbr3 {
    fn new(config: Arc<Bbr3Config>, current_mtu: u16) -> Self {
        let probe_rng: Pcg32;
        if let Some(probe_seed) = config.probe_rng_seed {
            probe_rng = Pcg32::from_seed(probe_seed);
        } else {
            probe_rng = Pcg32::from_rng(&mut rand::rng());
        }
        let smss = Ord::min(
            Ord::max(MIN_MAX_DATAGRAM_SIZE, current_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
        let initial_cwnd = config.initial_window;
        let startup_pacing_gain = config.startup_pacing_gain.unwrap_or(STARTUP_PACING_GAIN);
        let default_pacing_gain = config.default_pacing_gain.unwrap_or(DEFAULT_PACING_GAIN);
        let probe_bw_down_pacing_gain = config
            .probe_bw_down_pacing_gain
            .unwrap_or(PROBE_BW_DOWN_PACING_GAIN);
        let probe_bw_up_pacing_gain = config
            .probe_bw_up_pacing_gain
            .unwrap_or(PROBE_BW_UP_PACING_GAIN);
        let drain_pacing_gain = config.drain_pacing_gain.unwrap_or(DRAIN_PACING_GAIN);
        let pacing_margin_percent = config
            .pacing_margin_percent
            .unwrap_or(PACING_MARGIN_PERCENT);
        let default_cwnd_gain = config.default_cwnd_gain.unwrap_or(DEFAULT_CWND_GAIN);
        let probe_bw_up_cwnd_gain = config
            .probe_bw_up_cwnd_gain
            .unwrap_or(PROBE_BW_UP_CWND_GAIN);
        let probe_rtt_cwnd_gain = config.probe_rtt_cwnd_gain.unwrap_or(PROBE_RTT_CWND_GAIN);
        // the calculation for initial pacing rate described here <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-5>
        let nominal_bandwidth = initial_cwnd as f64 / 0.001;
        let pacing_rate = startup_pacing_gain * nominal_bandwidth;
        Self {
            smss,
            initial_cwnd,
            delivered: 0,
            inflight: 0,
            is_cwnd_limited: false,
            cwnd_limited_this_round: false,
            cycle_count: 0,
            cwnd: initial_cwnd,
            pacing_rate,
            send_quantum: 2 * smss, // we start high, but it will be adjusted in set_send_quantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#section-5.6.3>
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
            probe_rtt_duration: Duration::from_millis(PROBE_RTT_DURATION_MS),
            probe_rtt_interval: Duration::from_secs(PROBE_RTT_INTERVAL_SEC),
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
            loss_events_in_round: 0,
            loss_round_delivered: 0,
            loss_in_round: false,
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
        }
    }

    /// equivalent to BBRUpdateModelAndState <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.2.3>
    fn update_model_and_state(&mut self, p: BbrPacket, now: Instant) {
        self.update_latest_delivery_signals();
        self.update_congestion_signals(p);
        self.update_ack_aggregation(now);
        self.check_full_bw_reached();
        self.check_startup_done();
        self.check_drain_done(now);
        self.update_probe_bw_cycle_phase(now);
        self.update_min_rtt(now);
        self.check_probe_rtt(now);
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();
    }

    /// equivalent to BBRUpdateLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn update_latest_delivery_signals(&mut self) {
        self.loss_round_start = false;
        if let Some(rate_sample) = self.rs {
            self.bw_latest = [self.bw_latest, rate_sample.delivery_rate]
                .iter()
                .copied()
                .fold(f64::NAN, f64::max);
            self.inflight_latest = Ord::max(self.inflight_latest, rate_sample.delivered);

            if rate_sample.prior_delivered >= self.loss_round_delivered {
                self.loss_round_delivered = self.delivered;
                self.loss_round_start = true;
            }
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

    /// equivalent to BBRUpdateMaxBw <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.5>
    fn update_max_bw(&mut self, p: BbrPacket) {
        self.update_round(p);
        if let Some(rate_sample) = self.rs {
            if rate_sample.delivery_rate > 0.0
                && (rate_sample.delivery_rate >= self.max_bw || !rate_sample.is_app_limited)
            {
                self.max_bw_filter
                    .update_max(self.cycle_count, rate_sample.delivery_rate.round() as u64);

                self.max_bw = self.max_bw_filter.get_max() as f64;
            }
        }
    }

    /// equivalent to BBRUpdateRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1-9>
    fn update_round(&mut self, packet: BbrPacket) {
        if packet.delivered >= self.next_round_delivered {
            self.start_round();
            // Snapshot the just-ended round's cwnd-limited status for this round's decisions, then
            // reset the accumulator for the new round.
            self.is_cwnd_limited = self.cwnd_limited_this_round;
            self.cwnd_limited_this_round = false;
            self.round_count += 1;
            self.rounds_since_bw_probe += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
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
        self.bw_shortterm = [self.bw_latest, BETA * self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = Ord::max(
            self.inflight_latest,
            (BETA * self.inflight_shortterm as f64) as u64,
        );
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
        extra = Ord::min(extra, self.cwnd);
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
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= MAX_FULL_BW_COUNT;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    /// equivalent to BBRCheckStartupDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.1-6>
    fn check_startup_done(&mut self) {
        self.check_startup_high_loss();
        if self.state == BbrState::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    /// equivalent to BBRCheckStartupHighLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.3>
    fn check_startup_high_loss(&mut self) {
        if self.full_bw_reached {
            return;
        }

        if self.loss_round_start
            && self.loss_events_in_round >= STARTUP_FULL_LOSS_CNT
            && self.is_inflight_too_high()
        {
            let mut new_inflight_hi = self.bdp.max(self.inflight_latest);
            if let Some(rate_sample) = self.rs {
                if new_inflight_hi < rate_sample.delivered {
                    new_inflight_hi = rate_sample.delivered;
                }
            }
            self.inflight_longterm = new_inflight_hi;
            self.full_bw_reached = true;
            self.full_bw_now = true;
        }

        if self.loss_round_start {
            self.loss_events_in_round = 0;
        }
    }

    /// equivalent to BBREnterDrain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2>
    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        self.pacing_gain = self.drain_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
        self.drain_start_round = self.round_count;
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

    /// equivalent to BBREnterProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6>
    fn enter_probe_bw(&mut self, now: Instant) {
        self.cwnd_gain = self.default_cwnd_gain;
        self.start_probe_bw_down(now);
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

    /// equivalent to BBRAdaptLongTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn adapt_long_term_model(&mut self) {
        if self.ack_phase == AckPhase::ProbeStarting && self.round_start {
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        if self.ack_phase == AckPhase::ProbeStopping && self.round_start {
            if let BbrState::ProbeBw(_) = self.state {
                if let Some(rate_sample) = self.rs {
                    if !rate_sample.is_app_limited {
                        self.advance_max_bw_filter();
                    }
                }
            }
        }
        if !self.is_inflight_too_high() {
            if self.inflight_longterm == u64::MAX {
                return;
            }
            if let Some(rate_sample) = self.rs {
                if rate_sample.tx_in_flight > self.inflight_longterm {
                    self.inflight_longterm = rate_sample.tx_in_flight;
                }
            }
            if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                self.probe_inflight_long_term_upward();
            }
        }
    }

    /// equivalent to BBRAdvanceMaxBwFilter <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.6>
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count = self.cycle_count.saturating_add(1);
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

    /// equivalent to BBRHasElapsedInPhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn has_elapsed_in_phase(&mut self, interval: Duration, now: Instant) -> bool {
        if let Some(cycle_stamp) = self.cycle_stamp {
            now > cycle_stamp.checked_add(interval).unwrap_or(cycle_stamp)
        } else {
            true
        }
    }

    /// equivalent to BBRIsRenoCoexistenceProbeTime <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self.target_inflight();
        let rounds = Ord::min(reno_rounds, MAX_RENO_ROUNDS);
        self.rounds_since_bw_probe >= rounds
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

    /// equivalent to BBRInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn get_inflight(&mut self, gain: f64) -> u64 {
        let inflight_cap = self.bdp_multiple(self.max_bw, gain);
        self.quantization_budget(inflight_cap)
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
        }
        if self.round_start {
            self.raise_inflight_long_term_slope();
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
        if let Some(rate_sample) = self.rs {
            if rate_sample.rtt >= Duration::from_secs(0)
                && (rate_sample.rtt < self.probe_rtt_min_delay || self.probe_rtt_expired)
            {
                self.probe_rtt_min_delay = rate_sample.rtt;
                self.probe_rtt_min_stamp = Some(now);
            }
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
        if let Some(rate_sample) = self.rs {
            if rate_sample.delivered > 0 {
                self.idle_restart = false;
            }
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

    /// equivalent to BBREnterProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn enter_probe_rtt(&mut self) {
        self.state = BbrState::ProbeRtt;
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.probe_rtt_cwnd_gain;
    }

    /// equivalent to BBRSaveCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.4-13>
    fn save_cwnd(&mut self) {
        if !self.loss_in_round && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = Ord::max(self.prior_cwnd, self.cwnd);
        }
    }

    /// equivalent to BBRAdvanceLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn advance_latest_delivery_signals(&mut self) {
        if self.loss_round_start {
            if let Some(rate_sample) = self.rs {
                self.bw_latest = rate_sample.delivery_rate;
                self.inflight_latest = rate_sample.delivered;
            }
        }
    }

    /// equivalent to BBRBoundBWForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn bound_bw_for_model(&mut self) {
        // gives min of both f64
        self.bw = [self.max_bw, self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::min);
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

    /// equivalent to BBRResetFullBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-4>
    fn reset_full_bw(&mut self) {
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// equivalent to BBRRaiseInflightLongtermSlope <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn raise_inflight_long_term_slope(&mut self) {
        let growth_this_round = self
            .smss
            .checked_shl(self.bw_probe_up_rounds)
            .unwrap_or(u64::MAX);
        self.bw_probe_up_rounds =
            Ord::min(self.bw_probe_up_rounds + 1, MAX_LONG_TERM_PROBE_UP_ROUNDS);
        self.probe_up_cnt = Ord::max(self.cwnd / growth_this_round, 1);
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

    /// equivalent to BBRCheckProbeRTTDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn check_probe_rtt_done(&mut self, now: Instant) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if now > probe_rtt_done_stamp {
                self.probe_rtt_min_stamp = Some(now);
                self.restore_cwnd();
                self.exit_probe_rtt(now);
            }
        }
    }

    /// equivalent to BBRRestoreCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.4-13>
    fn restore_cwnd(&mut self) {
        self.cwnd = Ord::max(self.cwnd, self.prior_cwnd);
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

    /// equivalent to BBRStartProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.4-4>
    fn start_probe_bw_cruise(&mut self) {
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBREnterStartup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.1-3>
    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
        self.pacing_gain = self.startup_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRUpdateControlParameters <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.2.3>
    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    /// equivalent to BBRSetCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.6>
    fn set_cwnd(&mut self) {
        self.update_max_inflight();
        if self.full_bw_reached {
            if let Some(rate_sample) = self.rs {
                self.cwnd = Ord::min(self.cwnd + rate_sample.newly_acked, self.max_inflight);
            } else {
                self.cwnd = Ord::min(self.cwnd, self.max_inflight);
            }
        } else if self.cwnd < self.max_inflight || self.delivered < self.initial_cwnd {
            if let Some(rate_sample) = self.rs {
                self.cwnd += rate_sample.newly_acked;
            }
        }
        self.cwnd = Ord::max(self.cwnd, self.min_pipe_cwnd);
        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    /// equivalent to BBRUpdateMaxInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn update_max_inflight(&mut self) {
        let mut inflight_cap = self.bdp_multiple(self.max_bw, self.cwnd_gain);
        inflight_cap += self.extra_acked;
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    /// equivalent to BBRQuantizationBudget <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn quantization_budget(&mut self, inflight_cap: u64) -> u64 {
        self.update_offload_budget();
        let mut inflight_cap = Ord::max(inflight_cap, self.offload_budget);
        inflight_cap = Ord::max(inflight_cap, self.min_pipe_cwnd);
        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            inflight_cap += 2 * self.smss;
        }
        inflight_cap
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
        let delayed_ack_term = Ord::min(threshold_bytes, delay_bytes);

        self.offload_budget = base.saturating_add(delayed_ack_term);
    }

    /// equivalent to BBRBoundCwndForProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.5-1>
    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = Ord::min(self.cwnd, self.probe_rtt_cwnd());
        }
    }

    /// equivalent to BBRProbeRTTCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.5-1>
    fn probe_rtt_cwnd(&mut self) -> u64 {
        let mut probe_rtt_cwnd = self.bdp_multiple(self.bw, self.probe_rtt_cwnd_gain);
        probe_rtt_cwnd = Ord::max(probe_rtt_cwnd, self.min_pipe_cwnd);
        probe_rtt_cwnd
    }

    /// equivalent to BBRBDPMultiple <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn bdp_multiple(&mut self, bw: f64, gain: f64) -> u64 {
        if self.min_rtt == Duration::from_secs(u64::MAX) {
            return self.initial_cwnd;
        }
        self.bdp = (bw * self.min_rtt.as_secs_f64()).round() as u64;
        (gain * self.bdp as f64) as u64
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
        cap = Ord::min(cap, self.inflight_shortterm);
        cap = Ord::max(cap, self.min_pipe_cwnd);
        self.cwnd = Ord::min(self.cwnd, cap);
    }

    /// equivalent to BBRInflightWithHeadroom <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == u64::MAX {
            return u64::MAX;
        }
        let total_headroom = Ord::max(self.smss, (HEADROOM * self.inflight_longterm as f64) as u64);
        if let Some(inflight_with_headroom) = self.inflight_longterm.checked_sub(total_headroom) {
            Ord::max(inflight_with_headroom, self.min_pipe_cwnd)
        } else {
            self.min_pipe_cwnd
        }
    }

    /// equivalent to BBRSetPacingRate <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-7>
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// equivalent to BBRSetPacingRateWithGain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-7>
    fn set_pacing_rate_with_gain(&mut self, gain: f64) {
        let rate = gain * self.bw * (100.0 - self.pacing_margin_percent) / 100.0;
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// equivalent to BBRSetSendQuantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#section-5.6.3>
    fn set_send_quantum(&mut self) {
        // C.pacing_rate is in bytes/sec, so multiplying by 1ms is dividing by 1000.
        let mut quantum = (self.pacing_rate / 1000.0) as u64;
        quantum = Ord::min(quantum, HIGH_PACE_MAX_QUANTUM);
        quantum = Ord::max(quantum, 2 * self.smss);
        self.send_quantum = quantum;
    }

    /// equivalent to IsNewestPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.3-3>
    fn is_newest_packet(&self, send_time: Instant, end_seq: u64) -> bool {
        if let Some(first_send_time) = self.first_send_time {
            if send_time > first_send_time {
                return true;
            }
            if let Some(rate_sample) = self.rs {
                if end_seq > rate_sample.last_end_seq {
                    return true;
                }
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
                rate_sample.tx_in_flight = self.inflight_at_loss(p.size as u64);
                self.rs = Some(rate_sample);
                self.handle_inflight_too_high(now);
            }
        }
        self.packets.remove(packet_index);
    }

    /// equivalent to BBRNoteLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    fn note_loss(&mut self) {
        if !self.loss_in_round {
            self.loss_round_delivered = self.delivered;
        }
        self.save_state_upon_loss();
        self.loss_in_round = true;
        self.loss_events_in_round = self.loss_events_in_round.saturating_add(1);
    }

    /// equivalent to BBRSaveStateUponLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11.1>
    /// Save state in case a loss episode is later declared spurious
    fn save_state_upon_loss(&mut self) {
        self.undo_state = self.state;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
    }

    /// equivalent to IsInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    fn is_inflight_too_high(&self) -> bool {
        if let Some(rate_sample) = self.rs {
            return rate_sample.lost as f64 > rate_sample.tx_in_flight as f64 * LOSS_THRESH;
        }
        false
    }

    /// equivalent to BBRInflightAtLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    /// We check at what prefix of packet did losses exceed `loss_thresh`
    fn inflight_at_loss(&mut self, packet_size: u64) -> u64 {
        let Some(rate_sample) = self.rs else {
            return 0;
        };
        let inflight_prev = rate_sample.tx_in_flight.saturating_sub(packet_size) as f64;
        let lost_prev = rate_sample.lost.saturating_sub(packet_size) as f64;
        let lost_prefix = (LOSS_THRESH * inflight_prev - lost_prev) / (1.0 - LOSS_THRESH);
        (inflight_prev + lost_prefix) as u64
    }

    /// equivalent to BBRHandleInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    fn handle_inflight_too_high(&mut self, now: Instant) {
        self.bw_probe_samples = false;
        if let Some(rate_sample) = self.rs {
            if !rate_sample.is_app_limited {
                self.inflight_longterm = Ord::max(
                    rate_sample.tx_in_flight,
                    (self.target_inflight() as f64 * BETA) as u64,
                );
            }
        }

        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            self.start_probe_bw_down(now);
        }
    }

    /// equivalent to BBRTargetInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn target_inflight(&self) -> u64 {
        Ord::min(self.bdp, self.cwnd)
    }

    /// equivalent to BBRResetShortTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = f64::INFINITY;
        self.inflight_shortterm = u64::MAX;
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

    /// equivalent to BBRResetCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.bw_latest = 0.0;
        self.inflight_latest = 0;
    }

    /// equivalent to BBRPickProbeWait <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn pick_probe_wait(&mut self) {
        // 0 or 1
        self.rounds_since_bw_probe = self.probe_rng.random_bool(0.5) as u64;
        self.bw_probe_wait = Duration::from_millis(
            MIN_PROBE_WAIT_MS + self.probe_rng.random_range(0..=MAX_ADDED_PROBE_WAIT_MS),
        );
    }

    /// equivalent to BBRStartRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1-9>
    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
    }
}
impl Controller for Bbr3 {
    fn on_packet_sent(&mut self, now: Instant, bytes: u16, packet_number: u64) {
        self.handle_restart_from_idle(now);
        if self.inflight == 0 {
            self.first_send_time = Some(now);
            self.delivered_time = Some(now);
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
            packet_number,
            size: bytes,
            lost: self.lost,
            acknowledged: false,
            stale: false,
            round_count: self.round_count,
        });
    }

    fn on_cwnd_limited(&mut self) {
        self.cwnd_limited_this_round = true;
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        packet_number: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_acked += bytes;
            self.rs = Some(rate_sample);
            self.delivered += bytes;
            self.delivered_time = Some(now);
        }
        let p_index_result = self
            .packets
            .binary_search_by_key(&(packet_number), |p| p.packet_number);
        let is_newest_packet = self.is_newest_packet(sent, packet_number);
        if let Ok(p_index) = p_index_result {
            if let Some(p) = self.packets.get_mut(p_index) {
                p.acknowledged = true;
                if let Some(mut rate_sample) = self.rs {
                    rate_sample.rtt = now - p.send_time;
                    if is_newest_packet {
                        self.srtt = rtt.get();
                        rate_sample.prior_delivered = p.delivered;
                        rate_sample.prior_time = p.delivered_time;
                        rate_sample.is_app_limited = p.is_app_limited;
                        rate_sample.tx_in_flight = p.tx_in_flight;
                        rate_sample.lost = self.lost.saturating_sub(p.lost);
                        rate_sample.send_elapsed = p.send_time - p.first_send_time;
                        rate_sample.ack_elapsed =
                            self.delivered_time.unwrap_or(now) - p.delivered_time;
                        rate_sample.last_end_seq = packet_number;
                        self.first_send_time = Some(p.send_time);
                        rate_sample.last_packet = *p;
                        self.rs = Some(rate_sample);
                        self.update_model_and_state(rate_sample.last_packet, now);
                        self.update_control_parameters();
                        // Zero newly_acked after folding so each packet's bytes count once;
                        // one ACK covers many packets and the model steps run per packet.
                        if let Some(mut rate_sample) = self.rs {
                            rate_sample.newly_acked = 0;
                            self.rs = Some(rate_sample);
                        }
                    }
                } else {
                    let rate_sample = BbrRateSample {
                        rtt: rtt.get(),
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
                        lost: self.lost.saturating_sub(p.lost),
                        last_end_seq: packet_number,
                        last_packet: *p,
                    };
                    self.rs = Some(rate_sample);
                    self.first_send_time = Some(p.send_time);
                    self.srtt = rate_sample.rtt;
                    self.update_model_and_state(rate_sample.last_packet, now);
                    self.update_control_parameters();
                    // Drain newly_acked after folding, as in the branch above.
                    if let Some(mut rate_sample) = self.rs {
                        rate_sample.newly_acked = 0;
                        self.rs = Some(rate_sample);
                    }
                }
            }
        }
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
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
            self.packets.retain(|&p| !p.stale);
            for p in self.packets.iter_mut() {
                if p.acknowledged || self.round_count - p.round_count > ROUND_COUNT_WINDOW {
                    p.stale = true;
                }
            }
            if let Some(mut rate_sample) = self.rs {
                if rate_sample.prior_delivered == 0 {
                    return;
                }
                rate_sample.interval = Ord::max(rate_sample.send_elapsed, rate_sample.ack_elapsed);
                rate_sample.delivered = self.delivered.saturating_sub(rate_sample.prior_delivered);
                // ignore this condition on an initially high min rtt as per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.3-5>
                if rate_sample.interval < self.min_rtt
                    && self.min_rtt != Duration::from_secs(u64::MAX)
                {
                    return;
                }
                if rate_sample.interval != Duration::ZERO {
                    rate_sample.delivery_rate =
                        rate_sample.delivered as f64 / rate_sample.interval.as_secs_f64();
                }
                self.rs = Some(rate_sample);
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
        largest_lost: u64,
    ) {
        // only process ecn here, regular packet loss is detected per packet in on_packet_lost.
        if is_ecn {
            self.lost += lost_bytes;
            let p_index_result = self
                .packets
                .binary_search_by_key(&(largest_lost), |p| p.packet_number);
            if let Ok(p_index) = p_index_result {
                self.process_lost_packet(lost_bytes, p_index, now);
            }
            if is_persistent_congestion {
                self.cwnd = self.min_pipe_cwnd;
            }
        }
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, packet_number: u64, now: Instant) {
        let lost_bytes_64 = lost_bytes as u64;
        self.lost += lost_bytes_64;
        let p_index_result = self
            .packets
            .binary_search_by_key(&(packet_number), |p| p.packet_number);
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
        self.inflight_shortterm = Ord::max(self.inflight_shortterm, self.undo_inflight_shortterm);
        self.inflight_longterm = Ord::max(self.inflight_longterm, self.undo_inflight_longterm);
        if self.state != BbrState::ProbeRtt && self.state != self.undo_state {
            if self.undo_state == BbrState::Startup {
                self.enter_startup();
            } else if self.undo_state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                self.start_probe_bw_up();
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.smss = Ord::min(
            Ord::max(MIN_MAX_DATAGRAM_SIZE, new_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
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
        self.cwnd
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.pacing_rate.round() as u64),
            send_quantum: Some(self.send_quantum),
        }
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
}

impl Bbr3Config {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
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
    use std::cell::Cell;
    use std::ops::ControlFlow;

    /// PROBE_UP undo snapshot taken before a (possibly spurious) loss:
    /// (state, bw_shortterm, inflight_shortterm, inflight_longterm).
    type UndoSnapshot = (BbrState, f64, u64, u64);
    /// A loss episode: (pre-loss undo snapshot, post-loss state, post-loss inflight_longterm).
    type LossEpisode = (UndoSnapshot, BbrState, u64);

    /// A packet in flight in the link simulator: its packet number and the
    /// simulator-nanosecond timestamps at which it was sent and will be acked.
    struct SimPacket {
        pn: u64,
        send_ns: u64,
        ack_ns: u64,
    }

    /// Single-bottleneck FIFO link simulator driving the real BBR
    /// `on_packet_sent`/`on_ack`/`on_end_acks` path against a constant bandwidth
    /// `bw`, constant propagation `rtt_ns`, and an infinite buffer (no loss).
    /// Packets queue at the bottleneck and are served at `bw`. The sender always
    /// has data, paced at BBR's chosen rate, so it is cwnd-limited (never
    /// application-limited). Shared harness for the constant-link tests
    /// (A.1/A.3/A.5/A.8/A.9/A.10); tests needing loss, app-limiting, a mid-flight
    /// bandwidth change, idle periods, or ACK aggregation use their own loops.
    struct Sim {
        bbr: Bbr3,
        base: Instant,
        rtt_est: RttEstimator,
        flight: VecDeque<SimPacket>,
        now_ns: u64,
        next_send_ns: u64,
        // time at which the bottleneck finishes serving everything queued so far
        btl_free_ns: u64,
        inflight: u64,
        pn: u64,
        mss: u64,
        fwd_ns: u64,
        ret_ns: u64,
        // bottleneck serialization time for one MSS-sized packet
        btl_service_ns: u64,
    }

    impl Sim {
        fn new(config: Bbr3Config, mss: u64, bw: f64, rtt_ns: u64) -> Self {
            Self {
                bbr: Bbr3::new(Arc::new(config), mss as u16),
                base: Instant::now(),
                rtt_est: RttEstimator::new(Duration::from_nanos(rtt_ns)),
                flight: VecDeque::new(),
                now_ns: 0,
                next_send_ns: 0,
                btl_free_ns: 0,
                inflight: 0,
                pn: 0,
                mss,
                fwd_ns: rtt_ns / 2,
                ret_ns: rtt_ns / 2,
                btl_service_ns: (mss as f64 / bw * 1e9).round() as u64,
            }
        }

        /// Convert a simulator-nanosecond offset into an `Instant`.
        fn at(&self, off_ns: u64) -> Instant {
            self.base + Duration::from_nanos(off_ns)
        }

        /// Drive the send/ack loop for up to `max_iters` steps. On each step the
        /// sender sends if the window allows and a send is due no later than the
        /// next ack, otherwise it processes the next ack. `on_send` runs after each
        /// send, `on_ack` after each `on_end_acks`; either returning
        /// `ControlFlow::Break` stops the loop. Panics if the window fills with
        /// nothing in flight, or if `max_iters` elapses without a break.
        fn run(
            &mut self,
            max_iters: u64,
            mut on_send: impl FnMut(&mut Bbr3) -> ControlFlow<()>,
            mut on_ack: impl FnMut(&mut Bbr3, u64, u64, u64) -> ControlFlow<()>,
        ) {
            for _ in 0..max_iters {
                let can_send = self.inflight + self.mss <= self.bbr.window();
                // Report the cwnd-blocked signal as the connection layer does: always-backlogged,
                // so whenever the window (not pacing) is what stops the send, the flow is cwnd-limited.
                if !can_send {
                    self.bbr.on_cwnd_limited();
                }
                let next_ack = self.flight.front().map(|p| p.ack_ns);
                let do_send = can_send && next_ack.is_none_or(|ack| self.next_send_ns <= ack);

                if do_send {
                    self.now_ns = self.now_ns.max(self.next_send_ns);
                    let send_ns = self.now_ns;
                    // enqueue at the FIFO bottleneck, served at bw
                    let arrival = send_ns + self.fwd_ns;
                    let service_start = arrival.max(self.btl_free_ns);
                    let finish = service_start + self.btl_service_ns;
                    self.btl_free_ns = finish;
                    let ack_ns = finish + self.ret_ns;

                    self.bbr.on_packet_sent(
                        self.base + Duration::from_nanos(send_ns),
                        self.mss as u16,
                        self.pn,
                    );
                    self.inflight += self.mss;
                    self.flight.push_back(SimPacket {
                        pn: self.pn,
                        send_ns,
                        ack_ns,
                    });

                    // pace the next send at BBR's chosen pacing rate
                    let pacing = self.bbr.pacing_rate.max(1.0);
                    self.next_send_ns = send_ns + (self.mss as f64 / pacing * 1e9).round() as u64;
                    self.pn += 1;

                    if on_send(&mut self.bbr).is_break() {
                        return;
                    }
                } else if let Some(p) = self.flight.pop_front() {
                    self.now_ns = self.now_ns.max(p.ack_ns);
                    self.inflight -= self.mss;
                    let now_at = self.base + Duration::from_nanos(self.now_ns);
                    let send_at = self.base + Duration::from_nanos(p.send_ns);
                    self.rtt_est.update(
                        Duration::ZERO,
                        Duration::from_nanos(self.now_ns - p.send_ns),
                    );
                    self.bbr
                        .on_ack(now_at, send_at, self.mss, p.pn, false, &self.rtt_est);
                    self.bbr
                        .on_end_acks(now_at, self.inflight, false, Some(p.pn));

                    if on_ack(&mut self.bbr, self.now_ns, self.inflight, p.pn).is_break() {
                        return;
                    }
                } else {
                    panic!("simulation stalled: window full but nothing in flight");
                }
            }
            panic!("simulation exceeded {max_iters} iterations without reaching the target state");
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
        };
        let mut bbr3 = Bbr3::new(Arc::new(config), 2500);
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2652));
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2570));
    }

    /// A.1: Exiting STARTUP on a bandwidth plateau.
    /// equivalent to: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#name-exiting-startup-on-bandwidt>
    /// Drives a flow through the real `on_packet_sent`/`on_ack`/`on_end_acks`
    /// path against a single-bottleneck simulator: constant bandwidth `BW`,
    /// constant propagation `RTT`, infinite buffer (no loss). Packets queue and
    /// are served at `BW`, so once the pipe fills the delivery-rate samples
    /// plateau at `BW`. The sender always has data, so it is never app-limited.
    ///
    /// Asserts that once the delivery rate stops growing by >=25% for 3
    /// consecutive rounds (`full_bw_count` == `MAX_FULL_BW_COUNT`),
    /// `full_bw_now`/`full_bw_reached` are set, `max_bw` sits within 2% of the
    /// simulated bandwidth, and the flow transitions STARTUP -> DRAIN.
    #[test]
    fn startup_exits_to_drain_on_bandwidth_plateau() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// Simulated propagation RTT. Kept large (100ms) so the transient
        /// ProbeRTT BBR enters on the first ack (its `probe_rtt_min_stamp`
        /// starts unset, initializing `min_rtt`) spans fewer than
        /// `MAX_FULL_BW_COUNT` rounds and cannot falsely complete the plateau
        /// there; the flow bounces back to STARTUP and ramps cleanly.
        const RTT_NS: u64 = 100_000_000;

        // Drive the production default configuration.
        let mut sim = Sim::new(Bbr3Config::default(), MSS, BW, RTT_NS);
        assert_eq!(sim.bbr.state, BbrState::Startup);

        // captured on the STARTUP -> DRAIN edge (DRAIN is only ever entered from
        // STARTUP, via check_startup_done). BBR dips through a transient ProbeRTT
        // right after the first ack, so we run until DRAIN rather than breaking on
        // the first non-STARTUP state.
        let mut transition: Option<(u64, bool, bool, f64)> = None;
        sim.run(
            1_000_000,
            |_| ControlFlow::Continue(()),
            |bbr, _now_ns, _inflight, _pn| {
                if bbr.state == BbrState::Drain {
                    transition = Some((
                        bbr.full_bw_count,
                        bbr.full_bw_now,
                        bbr.full_bw_reached,
                        bbr.max_bw,
                    ));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
        );

        // The break condition guarantees we landed on the STARTUP -> DRAIN edge.
        let (full_bw_count, full_bw_now, full_bw_reached, max_bw) =
            transition.expect("BBR never left STARTUP");

        // Plateau detected: 3 consecutive rounds with <25% delivery-rate growth.
        assert_eq!(full_bw_count, MAX_FULL_BW_COUNT);
        assert!(full_bw_now, "full_bw_now should be set on plateau");
        assert!(full_bw_reached, "full_bw_reached should be set on plateau");
        // Bandwidth estimate within 2% of the simulated link bandwidth.
        let err = (max_bw - BW).abs() / BW;
        assert!(
            err < 0.02,
            "max_bw {max_bw} not within 2% of simulated {BW} (rel err {err})"
        );
    }

    /// A.2: Exiting STARTUP on loss when application-limited.
    /// equivalent to: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#name-exiting-startup-on-loss-whe>
    ///
    /// Drives a STARTUP flow whose delivery-rate samples are all app-limited (the
    /// app keeps only `APP_WINDOW` bytes outstanding, well below cwnd), so
    /// `check_full_bw_reached` bails every round (`rate_sample.is_app_limited`
    /// short-circuit) and the bandwidth-plateau path can never end STARTUP. Loss
    /// is then injected above `LOSS_THRESH` (2%), with at least
    /// `STARTUP_FULL_LOSS_CNT` discontiguous losses per round trip, so
    /// `check_startup_high_loss` observes the high loss rate and ends STARTUP:
    /// `full_bw_now`/`full_bw_reached` become true and the flow transitions
    /// STARTUP -> DRAIN, purely from loss.
    #[test]
    fn startup_exits_to_drain_on_loss_when_app_limited() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// application window: bytes the app keeps outstanding. Fixed and well
        /// below the STARTUP cwnd so the sender is application-limited (never
        /// cwnd-limited), which blocks the bandwidth-plateau exit and isolates
        /// the loss path. Sized so a single round trip carries at least
        /// `STARTUP_FULL_LOSS_CNT` losses at the `LOSS_PERIOD` rate below.
        const APP_WINDOW: u64 = 200 * MSS;
        /// drop 1 in every `LOSS_PERIOD` packets -> 4% loss, above `LOSS_THRESH`
        /// (2%), spread evenly so each round trip carries loss over its full
        /// sequence range.
        const LOSS_PERIOD: u64 = 25;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
            lost: bool,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Whether BBRCheckStartupHighLoss ever observed a too-high loss rate
        // (the A.2 signal). Sampled right after each ack is processed.
        let mut observed_high_loss = false;

        // Counts of STARTUP delivery-rate samples by app-limited flag. The
        // app-limited samples are the precondition A.2 relies on: they are what
        // check_full_bw_reached short-circuits on, blocking the bandwidth-plateau
        // exit so that loss is the only thing that can end STARTUP.
        let mut startup_app_limited_samples = 0u64;
        let mut startup_non_app_limited_samples = 0u64;

        // captured on the STARTUP -> DRAIN edge (DRAIN is only ever entered from
        // STARTUP, via check_startup_done). A transient ProbeRTT dip right after
        // the first ack bounces back to STARTUP, so we run until DRAIN.
        let mut transition: Option<(u64, bool, bool)> = None;

        for _ in 0..1_000_000 {
            // Application-limited: only send while the (small) app window has
            // room, independent of cwnd.
            let can_send = inflight + MSS <= APP_WINDOW.min(bbr.window());
            let next_ack = flight.front().map(|p| p.ack_ns);

            if can_send && next_ack.is_none_or(|ack| now_ns <= ack) {
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;
                let lost = pn % LOSS_PERIOD == LOSS_PERIOD - 1;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                    lost,
                });
                // Emulate the connection layer's C.app_limited (the index of the
                // last packet sent while the app had no more data). BBR's folded
                // `on_end_acks` can only ever raise `app_limited` to the largest
                // *acked* pn and clears it as soon as a larger pn is acked, so it
                // cannot keep samples app-limited on its own; set it to the last
                // sent pn, as a genuinely app-limited quinn connection would.
                bbr.app_limited = pn;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                if p.lost {
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, true, &rtt_est);
                    if bbr.state == BbrState::Startup {
                        match bbr.rs.map(|rs| rs.is_app_limited) {
                            Some(true) => {
                                startup_app_limited_samples =
                                    startup_app_limited_samples.saturating_add(1)
                            }
                            Some(false) => {
                                startup_non_app_limited_samples =
                                    startup_non_app_limited_samples.saturating_add(1)
                            }
                            None => {}
                        }
                    }
                }
                // Sample before on_end_acks clears the rate sample's loss fields.
                observed_high_loss |= bbr.is_inflight_too_high();
                bbr.on_end_acks(at(now_ns), inflight, true, Some(p.pn));
                if bbr.state == BbrState::Drain {
                    transition = Some((bbr.full_bw_count, bbr.full_bw_now, bbr.full_bw_reached));
                    break;
                }
            } else {
                // app window drained and nothing left to ack: advance to next send
                now_ns += btl_service_ns;
            }
        }

        // Landed on the STARTUP -> DRAIN edge.
        let (full_bw_count, full_bw_now, full_bw_reached) =
            transition.expect("BBR never left STARTUP on loss");

        // Loss, not the plateau path, drove the exit: the plateau path is
        // blocked by app-limited samples, so full_bw_count stayed below the
        // 3-round plateau threshold.
        assert!(
            full_bw_count < MAX_FULL_BW_COUNT,
            "expected loss-driven exit, but plateau counter reached {full_bw_count}"
        );
        assert!(
            observed_high_loss,
            "BBRCheckStartupHighLoss never observed a too-high loss rate"
        );
        // The app-limited precondition held: STARTUP delivery-rate samples were
        // app-limited, so app-limiting (not a race with loss) kept the plateau
        // path from completing. The only packets sent non-app-limited are
        // the two warmup packets (pn 0 and 1, before app_limited was first set
        // nonzero); the bound tolerates them in case they are acked in STARTUP (in
        // practice they land in the transient first-ack ProbeRTT and are not counted).
        assert!(
            startup_app_limited_samples > 0,
            "no app-limited STARTUP samples observed"
        );
        assert!(
            startup_non_app_limited_samples <= 2,
            "expected app-limited samples throughout STARTUP, saw \
             {startup_non_app_limited_samples} non-app-limited"
        );
        assert!(
            full_bw_reached,
            "full_bw_reached should be set on high loss"
        );
        assert!(full_bw_now, "full_bw_now should be set on high loss");
    }

    /// A.3: Exiting DRAIN based on inflight.
    /// equivalent to: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#name-exiting-drain-based-on-infl>
    ///
    /// Drives a flow STARTUP -> DRAIN on the same infinite-buffer simulator as
    /// A.1, then keeps running through DRAIN. Entering DRAIN sets `pacing_gain`
    /// to `DrainPacingGain` (0.5) while `cwnd_gain` stays at the default, so the
    /// window stays wide but pacing sends slower than the link delivers. The
    /// queue built during STARTUP drains and `C.inflight` falls.
    ///
    /// Asserts that on the STARTUP -> DRAIN edge `pacing_gain == DRAIN_PACING_GAIN`
    /// (0.5), and that DRAIN ends via the inflight branch of `check_drain_done`
    /// (`C.inflight <= BBRInflight(1.0)`, i.e. `get_inflight(1.0)`, the estimated
    /// BDP at unit gain) rather than the `drain_start_round + 3` round fallback,
    /// transitioning to PROBE_BW (substate DOWN).
    #[test]
    fn drain_exits_to_probe_bw_on_inflight() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;

        // Drive the production default configuration.
        let mut sim = Sim::new(Bbr3Config::default(), MSS, BW, RTT_NS);
        assert_eq!(sim.bbr.state, BbrState::Startup);

        // pacing_gain observed on the STARTUP -> DRAIN edge (0.5), and the round
        // in which DRAIN started, captured once when DRAIN is first entered.
        let mut drain_pacing_gain: Option<f64> = None;
        let mut drain_start_round: u64 = 0;
        // captured on the DRAIN -> PROBE_BW edge: (state, inflight at exit,
        // BBRInflight(1.0) == get_inflight(1.0), round_count).
        let mut probe_bw_transition: Option<(BbrState, u64, u64, u64)> = None;

        sim.run(
            1_000_000,
            |_| ControlFlow::Continue(()),
            |bbr, _now_ns, inflight, _pn| {
                // Capture the STARTUP -> DRAIN edge: entering DRAIN sets
                // pacing_gain to DrainPacingGain (0.5) and records the round.
                if bbr.state == BbrState::Drain && drain_pacing_gain.is_none() {
                    drain_pacing_gain = Some(bbr.pacing_gain);
                    drain_start_round = bbr.drain_start_round;
                }

                // Capture the DRAIN -> PROBE_BW edge. get_inflight(1.0) is
                // BBRInflight(1.0), the estimated BDP at unit gain that
                // check_drain_done compares C.inflight against.
                if matches!(bbr.state, BbrState::ProbeBw(_)) {
                    let bdp = bbr.get_inflight(1.0);
                    probe_bw_transition = Some((bbr.state, inflight, bdp, bbr.round_count));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
        );

        // Entered DRAIN with the drain pacing gain (0.5).
        let drain_pacing_gain = drain_pacing_gain.expect("BBR never entered DRAIN");
        assert_eq!(
            drain_pacing_gain, DRAIN_PACING_GAIN,
            "DRAIN pacing_gain should be DrainPacingGain (0.5)"
        );

        // Landed on the DRAIN -> PROBE_BW edge.
        let (state, inflight_at_exit, bdp, round_count) =
            probe_bw_transition.expect("BBR never left DRAIN");

        // DRAIN enters PROBE_BW at DOWN, but the same ack may advance DOWN ->
        // CRUISE (the inflight condition that ends DRAIN also opens the
        // time-to-cruise gate). Refill can't fire on entry, so DOWN and CRUISE are
        // the only legitimate entry substates.
        assert!(
            matches!(
                state,
                BbrState::ProbeBw(ProbeBwSubstate::Down | ProbeBwSubstate::Cruise)
            ),
            "DRAIN should transition to PROBE_BW (DOWN or same-ack CRUISE), got {state:?}"
        );

        // The inflight branch of check_drain_done drove the exit: C.inflight fell
        // to/below BBRInflight(1.0), and it happened within the 3-round window so
        // the `drain_start_round + 3` fallback did not fire.
        assert!(
            inflight_at_exit <= bdp,
            "expected inflight-driven DRAIN exit: inflight {inflight_at_exit} > BBRInflight(1.0) {bdp}"
        );
        assert!(
            round_count <= drain_start_round + 3,
            "expected inflight-driven exit, but the round fallback fired \
             (round_count {round_count} > drain_start_round {drain_start_round} + 3)"
        );
    }

    /// A.4: Exiting DRAIN based on time.
    /// equivalent to: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#name-exiting-drain-based-on-time>
    ///
    /// Same simulator as A.1/A.3, driven STARTUP -> DRAIN. On the DRAIN edge the
    /// link is cut, simulating a STARTUP bandwidth over-estimate: DRAIN keeps
    /// pacing off the stale (too-high) `max_bw`, so the queue never drains and
    /// `C.inflight` stays above `BBRInflight(1.0)` (`get_inflight(1.0)`) for
    /// several rounds. The inflight branch of `check_drain_done` never fires, so
    /// the time fallback exits DRAIN once `round_count > drain_start_round + 3`,
    /// even though `C.inflight` has not reached the target BDP.
    #[test]
    fn drain_exits_to_probe_bw_on_time() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// STARTUP bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// propagation round-trip time (100ms), matching A.1/A.3
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// Fraction of STARTUP bandwidth surviving into DRAIN. `max_bw` holds its STARTUP
        /// peak, so DRAIN paces at `DRAIN_PACING_GAIN * BW`; the surviving link must stay
        /// below that for the queue to persist (the draft's 10% cut leaves the link
        /// outrunning drain pacing). Derived from the constant (0.8x → 0.4 today) so it
        /// tracks it.
        const DRAIN_BW_FACTOR: f64 = 0.8 * DRAIN_PACING_GAIN;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // bottleneck serialization time per MSS; cut on the DRAIN edge
        let mut btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        let mut drain_start_round: Option<u64> = None;
        // per-round (round_count, inflight, bdp) while in DRAIN
        let mut drain_round_samples: Vec<(u64, u64, u64)> = Vec::new();
        let mut last_sampled_round: Option<u64> = None;
        // DRAIN -> PROBE_BW edge: (state, inflight, bdp, round)
        let mut probe_bw_transition: Option<(BbrState, u64, u64, u64)> = None;

        for _ in 0..1_000_000 {
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            let next_ack = flight.front().map(|p| p.ack_ns);

            // The sender always has data; send whenever the window allows and a
            // send is due no later than the next ack, otherwise process an ack.
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at the current rate
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));

                // STARTUP -> DRAIN edge: cut the link (over-estimate), record round
                if bbr.state == BbrState::Drain && drain_start_round.is_none() {
                    drain_start_round = Some(bbr.drain_start_round);
                    btl_service_ns = (MSS as f64 / (BW * DRAIN_BW_FACTOR) * 1e9).round() as u64;
                    // Re-drain the queued STARTUP backlog at the new (slower) link
                    // rate. A FIFO bottleneck serves already-queued packets at the
                    // rate in force when they are served, not the rate at enqueue,
                    // so the pre-cut fast ack times must be recomputed. Without this
                    // the backlog drains at the old STARTUP rate and inflight
                    // collapses to BBRInflight(1.0) within a single round, firing the
                    // inflight-branch exit and masking the time fallback under test.
                    let mut serve = now_ns;
                    for q in flight.iter_mut() {
                        let service_start = (q.send_ns + FWD_NS).max(serve);
                        let finish = service_start + btl_service_ns;
                        serve = finish;
                        q.ack_ns = finish + RET_NS;
                    }
                    btl_free_ns = serve;
                }

                // sample inflight vs BBRInflight(1.0) once per DRAIN round
                if bbr.state == BbrState::Drain && last_sampled_round != Some(bbr.round_count) {
                    let bdp = bbr.get_inflight(1.0);
                    drain_round_samples.push((bbr.round_count, inflight, bdp));
                    last_sampled_round = Some(bbr.round_count);
                }

                if matches!(bbr.state, BbrState::ProbeBw(_)) {
                    let bdp = bbr.get_inflight(1.0);
                    probe_bw_transition = Some((bbr.state, inflight, bdp, bbr.round_count));
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let drain_start_round = drain_start_round.expect("BBR never entered DRAIN");
        let (state, inflight_at_exit, bdp_at_exit, round_count) =
            probe_bw_transition.expect("BBR never left DRAIN");

        // DRAIN exits to PROBE_BW.
        assert!(
            matches!(
                state,
                BbrState::ProbeBw(ProbeBwSubstate::Down | ProbeBwSubstate::Cruise)
            ),
            "DRAIN should transition to PROBE_BW, got {state:?}"
        );

        // Time fallback drove the exit: after 3 full DRAIN rounds...
        assert!(
            round_count > drain_start_round + 3,
            "expected time-driven DRAIN exit at round_count > drain_start_round + 3, \
             got round_count {round_count}, drain_start_round {drain_start_round}"
        );

        // ...with C.inflight still above target (inflight branch never fired).
        assert!(
            inflight_at_exit > bdp_at_exit,
            "expected time-driven exit with inflight still above target: \
             inflight {inflight_at_exit} <= BBRInflight(1.0) {bdp_at_exit}"
        );

        // inflight stayed above target every round in DRAIN
        assert!(
            drain_round_samples.iter().all(|&(_, ifl, bdp)| ifl > bdp),
            "C.inflight dropped to/below BBRInflight(1.0) during DRAIN: {drain_round_samples:?}"
        );
        assert!(
            drain_round_samples.len() >= 3,
            "expected several round trips observed in DRAIN, got {}",
            drain_round_samples.len()
        );
    }

    /// A.5: Exiting PROBE_UP on a bandwidth plateau.
    /// equivalent to BBRIsTimeToGoDown:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-6>
    ///
    /// Same infinite-buffer simulator as A.1/A.3 (constant `BW`, constant `RTT`,
    /// no loss), driven STARTUP -> DRAIN -> PROBE_BW until PROBE_BW cycles into
    /// its PROBE_UP phase. In PROBE_UP `pacing_gain` is `ProbeBwUpPacingGain`
    /// (1.25), so the sender pushes above the link rate and a standing queue
    /// forms. `inflight_longterm`/`cwnd` grow to fully utilize that queue with no
    /// loss, but the measured delivery rate is pinned at `BW` and plateaus.
    ///
    /// Asserts that once the delivery rate grows by <25% for 3 consecutive rounds
    /// (`check_full_bw_reached` drives `full_bw_count` to `MAX_FULL_BW_COUNT` and
    /// sets `full_bw_now`), `BBRIsTimeToGoDown()` (`maybe_go_down`) fires and the
    /// flow transitions PROBE_UP -> PROBE_DOWN. On the deciding round-start ack
    /// `is_cwnd_limited` has just been cleared by `start_round`, so the "keep
    /// probing" branch of `maybe_go_down` is skipped and the plateau drives the
    /// exit.
    #[test]
    fn probe_bw_exits_probe_up_to_probe_down_on_bandwidth_plateau() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.3
        const RTT_NS: u64 = 100_000_000;

        // Drive the production default configuration.
        let mut sim = Sim::new(Bbr3Config::default(), MSS, BW, RTT_NS);
        assert_eq!(sim.bbr.state, BbrState::Startup);

        // Whether the flow has reached the PROBE_UP phase of PROBE_BW; the go-down
        // edge we care about is PROBE_UP -> PROBE_DOWN, distinct from the initial
        // DRAIN -> PROBE_BW(DOWN) entry.
        let mut reached_probe_up = false;
        // Captured on the PROBE_UP -> PROBE_DOWN edge: (state, full_bw_count,
        // full_bw_now). start_probe_bw_down leaves full_bw_count/full_bw_now
        // untouched, so they still read the plateau values right after the edge.
        let mut go_down_transition: Option<(BbrState, u64, bool)> = None;

        sim.run(
            1_000_000,
            |_| ControlFlow::Continue(()),
            |bbr, _now_ns, _inflight, _pn| {
                if bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    reached_probe_up = true;
                }

                // Capture the PROBE_UP -> PROBE_DOWN edge (only meaningful once
                // PROBE_UP has actually been entered).
                if reached_probe_up && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Down) {
                    go_down_transition = Some((bbr.state, bbr.full_bw_count, bbr.full_bw_now));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
        );

        // Landed on the PROBE_UP -> PROBE_DOWN edge.
        assert!(reached_probe_up, "BBR never reached the PROBE_UP phase");
        let (state, full_bw_count, full_bw_now) =
            go_down_transition.expect("BBR never left PROBE_UP");

        // Plateau drove the exit: 3 consecutive rounds with <25% delivery-rate
        // growth set full_bw_now, and BBRIsTimeToGoDown() moved to PROBE_DOWN.
        assert_eq!(
            full_bw_count, MAX_FULL_BW_COUNT,
            "full_bw_count should reach MAX_FULL_BW_COUNT on the plateau"
        );
        assert!(full_bw_now, "full_bw_now should be set on the plateau");
        assert_eq!(
            state,
            BbrState::ProbeBw(ProbeBwSubstate::Down),
            "PROBE_UP should transition to PROBE_DOWN on the plateau"
        );
    }

    /// A.6: Exiting PROBE_UP on loss when application-limited.
    /// equivalent to BBRHandleInflightTooHigh:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    ///
    /// NOTE: the loss-driven PROBE_UP exit runs through `handle_inflight_too_high`
    /// (BBRHandleInflightTooHigh), reached per-lost-packet from
    /// `process_lost_packet`, NOT through `maybe_go_down` (BBRIsTimeToGoDown).
    /// BBRIsTimeToGoDown only inspects the cwnd-limited/plateau signals
    /// (`full_bw_now`) and never the loss rate, so high loss cannot trigger it;
    /// the plateau path (A.5) is what BBRIsTimeToGoDown covers. This test drives
    /// the code path that ends PROBE_UP on excess loss.
    ///
    /// Same simulator as A.1/A.3/A.5, in two phases:
    ///  1. Not app-limited, no loss, full-cwnd (identical to A.5) until the flow
    ///     cycles STARTUP -> DRAIN -> PROBE_BW -> PROBE_UP.
    ///  2. Once PROBE_UP is entered, the app is throttled to a small fixed window
    ///     (`APP_WINDOW`, well below cwnd) so every fresh sample is app-limited,
    ///     and 1-in-`LOSS_PERIOD` packets are dropped -> a per-round loss rate
    ///     (4%) above `BBR.LossThresh` (2%).
    ///
    /// In PROBE_UP `bw_probe_samples` is true, so each lost packet is fed through
    /// `process_lost_packet`; `is_inflight_too_high()` sees the loss exceed
    /// `LOSS_THRESH * tx_in_flight` and calls `handle_inflight_too_high`. Because
    /// the deciding sample is app-limited, the `!is_app_limited` guard in
    /// `handle_inflight_too_high` skips the `inflight_longterm` reduction (an
    /// app-limited loss sample is not trusted to lower the long-term model), yet
    /// the `state == PROBE_UP` branch still runs `start_probe_bw_down`
    /// unconditionally.
    ///
    /// Asserts that, purely from loss, the flow transitions PROBE_UP ->
    /// PROBE_DOWN with the deciding sample flagged app-limited, that the plateau
    /// path did NOT drive it (`full_bw_now` stays false, blocked by the
    /// app-limited short-circuit in `check_full_bw_reached`), and that
    /// `inflight_longterm` is updated appropriately for an app-limited sample,
    /// i.e. left unchanged across the transition rather than lowered.
    #[test]
    fn probe_bw_exits_probe_up_to_probe_down_on_loss_when_app_limited() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.3/A.5
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// application window once PROBE_UP is reached: bytes the app keeps
        /// outstanding. Well below the PROBE_UP cwnd (~2*BDP, ~1000 packets here)
        /// so the sender is app-limited (never cwnd-limited), keeping every sample
        /// app-limited and isolating the loss path. Matches A.2's window.
        const APP_WINDOW: u64 = 200 * MSS;
        /// drop 1 in every `LOSS_PERIOD` packets -> 4% loss, above `LOSS_THRESH`
        /// (2%), spread evenly so each round trip carries loss over its full
        /// sequence range.
        const LOSS_PERIOD: u64 = 25;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
            lost: bool,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Phase 2 begins once PROBE_UP is reached: from then the app is limited
        // to APP_WINDOW and packets are dropped at the LOSS_PERIOD rate.
        let mut app_limited_phase = false;
        let mut reached_probe_up = false;
        // Captured on the loss-driven PROBE_UP -> PROBE_DOWN edge:
        // (inflight_longterm before/after the deciding loss, whether the deciding
        // sample was app-limited, full_bw_now at the edge).
        let mut go_down: Option<(u64, u64, bool, bool)> = None;

        for _ in 0..1_000_000 {
            let cwnd = bbr.window();
            let window_cap = if app_limited_phase {
                APP_WINDOW.min(cwnd)
            } else {
                cwnd
            };
            let can_send = inflight + MSS <= window_cap;
            let next_ack = flight.front().map(|p| p.ack_ns);

            // Send whenever the window allows and a paced send is due no later
            // than the next ack; otherwise process an ack. In the app-limited
            // phase the small window is the binding limit, not cwnd.
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;
                // Only drop packets once app-limited (phase 2); phase 1 is loss
                // free so the flow reaches PROBE_UP exactly as in A.5.
                let lost = app_limited_phase && pn % LOSS_PERIOD == LOSS_PERIOD - 1;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                    lost,
                });

                if app_limited_phase {
                    // Emulate the connection layer's C.app_limited (the index of
                    // the last packet sent while the app had no more data) so the
                    // next packet is stamped app-limited at send time. Same shape
                    // as A.2: on_end_acks cannot keep samples app-limited on its
                    // own, so drive it here.
                    bbr.app_limited = pn;
                }

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                if p.lost {
                    // Capture the loss-driven PROBE_UP -> PROBE_DOWN edge. The
                    // transition happens inside on_packet_lost (via
                    // handle_inflight_too_high), never on an ack, so any Up->Down
                    // move seen here is attributable to this loss.
                    let before_ilt = bbr.inflight_longterm;
                    let was_up = bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up);
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));
                    if was_up && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Down) {
                        let app_lim = bbr.rs.is_some_and(|rs| rs.is_app_limited);
                        go_down =
                            Some((before_ilt, bbr.inflight_longterm, app_lim, bbr.full_bw_now));
                        break;
                    }
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(
                        at(now_ns),
                        at(p.send_ns),
                        MSS,
                        p.pn,
                        app_limited_phase,
                        &rtt_est,
                    );
                    bbr.on_end_acks(at(now_ns), inflight, app_limited_phase, Some(p.pn));

                    // Flip to the application-limited, lossy phase the moment
                    // PROBE_BW is entered, so that by the time the cycle reaches
                    // PROBE_UP the pipe has already drained to APP_WINDOW and
                    // every in-flight sample is app-limited (the plateau path
                    // cannot fire on stale non-app-limited samples).
                    if !app_limited_phase && matches!(bbr.state, BbrState::ProbeBw(_)) {
                        app_limited_phase = true;
                    }
                    if bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                        reached_probe_up = true;
                    }
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // Landed on the loss-driven PROBE_UP -> PROBE_DOWN edge.
        assert!(reached_probe_up, "BBR never reached the PROBE_UP phase");
        let (before_ilt, after_ilt, app_lim, full_bw_now) =
            go_down.expect("BBR never left PROBE_UP on loss");

        // The deciding loss sample was application-limited.
        assert!(
            app_lim,
            "deciding loss sample should be application-limited"
        );
        // Loss, not the plateau path, drove the exit: check_full_bw_reached bails
        // on app-limited samples, so full_bw_now (BBRIsTimeToGoDown's plateau
        // signal) never got set.
        assert!(
            !full_bw_now,
            "expected loss-driven exit, but the plateau signal full_bw_now was set"
        );
        // Updated appropriately for an app-limited sample: handle_inflight_too_high
        // skips the reduction (the !is_app_limited guard), so inflight_longterm is
        // left unchanged across the transition rather than lowered toward
        // max(tx_in_flight, target_inflight * BETA). A non-app-limited loss would
        // instead set it here.
        assert_eq!(
            before_ilt, after_ilt,
            "inflight_longterm should be unchanged on an app-limited loss exit"
        );
    }

    /// A.7: Never exiting STARTUP when application-limited with no loss.
    ///
    /// The negative counterpart to A.1 (plateau exit) and A.2 (loss exit): with
    /// neither signal present, STARTUP must persist. STARTUP leaves for DRAIN only
    /// via `check_startup_done`, which requires `full_bw_reached`
    /// (`self.state == Startup && self.full_bw_reached` -> `enter_drain`), plus the
    /// high-loss escape in `check_startup_high_loss`. When every round is
    /// app-limited, `check_full_bw_reached` bails on the `is_app_limited` guard, so
    /// `full_bw_now`/`full_bw_reached` are never set; with zero loss the high-loss
    /// escape never fires either. Both STARTUP -> DRAIN triggers are closed.
    ///
    /// The one state change that still occurs is the scheduled min-RTT refresh:
    /// with a constant RTT the min-RTT filter expires every `probe_rtt_interval`
    /// (5s) and `check_probe_rtt` moves STARTUP -> PROBE_RTT. This is orthogonal to
    /// the app-limited/loss exits A.7 concerns, and because `full_bw_reached` is
    /// still false, `exit_probe_rtt` routes back to STARTUP (`enter_startup`)
    /// rather than on to PROBE_BW. So the flow oscillates STARTUP <-> PROBE_RTT and
    /// never advances past STARTUP, i.e. it stays in STARTUP indefinitely.
    ///
    /// Same infinite-buffer simulator as A.1/A.2, but the app is limited to a
    /// small fixed window (`APP_WINDOW`, well below cwnd) from the first packet so
    /// every sample is app-limited, and no packet is ever dropped.
    ///
    /// Runs long enough (`ROUNDS_TO_OBSERVE`, several `probe_rtt_interval`s) to
    /// cover multiple PROBE_RTT interludes, and asserts that: the flow only ever
    /// occupies STARTUP or PROBE_RTT (never DRAIN/PROBE_BW), at least one
    /// PROBE_RTT interlude was exercised and returned to STARTUP, every observed
    /// sample was application-limited, `full_bw_reached`/`full_bw_now` were never
    /// set, and `full_bw_count` never reached `MAX_FULL_BW_COUNT`.
    #[test]
    fn startup_never_exits_when_app_limited_without_loss() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.2
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// bytes the app keeps outstanding, from the first packet on. Well below
        /// cwnd (initial cwnd ~109*MSS, and the app-limited delivery rate keeps
        /// cwnd = cwnd_gain*bdp ~= 2.77*APP_WINDOW thereafter) so the sender is
        /// app-limited, never cwnd-limited. Comfortably above `min_pipe_cwnd`
        /// (4*MSS).
        const APP_WINDOW: u64 = 20 * MSS;
        /// rounds to observe before declaring "indefinitely". Each round is ~1 RTT
        /// (100ms), so this spans ~16s (several `probe_rtt_interval`s of 5s) and
        /// covers multiple STARTUP <-> PROBE_RTT oscillations.
        const ROUNDS_TO_OBSERVE: u64 = 160;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Signals gathered over the run; every assertion is checked after the loop.
        // The set of states ever visited (must stay within {Startup, ProbeRtt}).
        let mut saw_probe_rtt = false;
        // A PROBE_RTT interlude was seen and the flow subsequently returned to
        // STARTUP: proof exit_probe_rtt routed back to STARTUP, not on to
        // PROBE_BW.
        let mut returned_to_startup = false;
        // Set true the moment any forbidden (past-STARTUP) state is entered.
        let mut advanced_past_startup: Option<BbrState> = None;
        // Whether every ack we processed carried an application-limited sample.
        let mut all_samples_app_limited = true;
        let mut samples_seen: u64 = 0;
        // Highest full_bw_count / whether full_bw_now/full_bw_reached ever set.
        let mut max_full_bw_count: u64 = 0;
        let mut full_bw_now_ever = false;
        let mut full_bw_reached_ever = false;

        for _ in 0..1_000_000 {
            let cwnd = bbr.window();
            // The app never wants more than APP_WINDOW outstanding.
            let window_cap = APP_WINDOW.min(cwnd);
            let can_send = inflight + MSS <= window_cap;
            let next_ack = flight.front().map(|p| p.ack_ns);

            // Send whenever the small app window allows and a paced send is due no
            // later than the next ack; otherwise process an ack. The app window is
            // always the binding limit, not cwnd.
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW (infinite buffer, no
                // loss)
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                // Emulate the connection layer's C.app_limited (index of the last
                // packet sent while the app had no more data) so the next packet is
                // stamped app-limited at send time. Same shape as A.2/A.6.
                bbr.app_limited = pn;

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, true, &rtt_est);
                bbr.on_end_acks(at(now_ns), inflight, true, Some(p.pn));

                // Record the sample's app-limited flag, but only for STARTUP
                // rounds: PROBE_RTT deliberately clamps cwnd to min_pipe_cwnd
                // (below APP_WINDOW), so its samples are cwnd-limited by design and
                // are not part of the app-limited premise.
                if let Some(rs) = bbr.rs {
                    if bbr.state == BbrState::Startup {
                        samples_seen += 1;
                        all_samples_app_limited &= rs.is_app_limited;
                    }
                }
                max_full_bw_count = max_full_bw_count.max(bbr.full_bw_count);
                full_bw_now_ever |= bbr.full_bw_now;
                full_bw_reached_ever |= bbr.full_bw_reached;

                match bbr.state {
                    BbrState::Startup => {
                        // Returning to STARTUP after a PROBE_RTT interlude confirms
                        // exit_probe_rtt routed back here (full_bw_reached false).
                        if saw_probe_rtt {
                            returned_to_startup = true;
                        }
                    }
                    BbrState::ProbeRtt => {
                        saw_probe_rtt = true;
                    }
                    // Any of these means STARTUP was actually left for the next
                    // phase: the failure A.7 guards against.
                    other => {
                        advanced_past_startup.get_or_insert(other);
                    }
                }

                if advanced_past_startup.is_some() || bbr.round_count >= ROUNDS_TO_OBSERVE {
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // Never advanced past STARTUP: only STARTUP and the scheduled PROBE_RTT
        // min-RTT refresh were ever entered.
        assert!(
            advanced_past_startup.is_none(),
            "BBR left STARTUP for {:?} while application-limited with no loss",
            advanced_past_startup,
        );
        // The run was long enough to actually exercise the oscillation.
        assert!(
            bbr.round_count >= ROUNDS_TO_OBSERVE,
            "simulation ended early ({} rounds) before observing enough rounds",
            bbr.round_count,
        );
        // The min-RTT refresh fired and returned to STARTUP (not on to PROBE_BW),
        // proving STARTUP is genuinely re-entered rather than merely never left
        // because time stood still.
        assert!(saw_probe_rtt, "expected a scheduled PROBE_RTT interlude");
        assert!(
            returned_to_startup,
            "PROBE_RTT should route back to STARTUP while full_bw_reached is false"
        );
        assert_eq!(
            bbr.state,
            BbrState::Startup,
            "BBR should still be in STARTUP at the end of the run"
        );
        // The premise held: every sample really was application-limited.
        assert!(samples_seen > 0, "no samples were observed");
        assert!(
            all_samples_app_limited,
            "every sample should be application-limited"
        );
        // The plateau path never armed: check_full_bw_reached short-circuits on
        // app-limited samples, so full_bw_reached/full_bw_now stayed false and
        // full_bw_count never reached MAX_FULL_BW_COUNT.
        assert!(
            !full_bw_reached_ever,
            "full_bw_reached must never be set on application-limited samples"
        );
        assert!(
            !full_bw_now_ever,
            "full_bw_now must never be set on application-limited samples"
        );
        assert!(
            max_full_bw_count < MAX_FULL_BW_COUNT,
            "full_bw_count must never reach MAX_FULL_BW_COUNT on application-limited samples (was {max_full_bw_count})"
        );
    }

    /// A.8: Exiting PROBE_DOWN on inflight.
    /// equivalent to BBRIsTimeToCruise:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    ///
    /// Same infinite-buffer simulator as A.5 (constant `BW`, constant `RTT`, no
    /// loss, sender always has data), driven STARTUP -> DRAIN -> PROBE_BW until
    /// PROBE_BW has cycled through PROBE_UP and back into a PROBE_DOWN phase.
    /// PROBE_UP paces at `ProbeBwUpPacingGain` (1.25) and builds a standing queue,
    /// so on the PROBE_UP -> PROBE_DOWN edge `C.inflight` sits well above both
    /// cruise thresholds: a genuine queue to drain (distinct from the first
    /// DRAIN -> PROBE_DOWN entry, where DRAIN has already emptied the pipe).
    ///
    /// In PROBE_DOWN `pacing_gain` is `ProbeDownPacingGain` (0.90), so the sender
    /// paces below the link rate and the standing queue drains at ~0.1*`BW`. Each
    /// ack runs `update_probe_bw_cycle_phase`, whose PROBE_DOWN arm first checks
    /// `maybe_enter_probe_bw_refill` (still false: `bw_probe_wait` is 2-3s and
    /// `rounds_since_bw_probe` was reset at down entry, so neither the elapsed-time
    /// nor the Reno-coexistence trigger fires within the short drain) and then
    /// `maybe_update_budget_and_time_to_cruise` (`BBRIsTimeToCruise`). The latter
    /// returns true only once `C.inflight` has fallen to <= both
    /// `BBRInflightWithHeadroom()` and `BBRInflight(1.0)`, at which point
    /// `start_probe_bw_cruise` moves PROBE_DOWN -> PROBE_CRUISE.
    ///
    /// `update_probe_bw_cycle_phase` reads `self.inflight`, which the previous
    /// `on_end_acks` set from the simulator's `inflight` one tick earlier, so the
    /// deciding value lags the loop's `inflight` by a single MSS: the same lag
    /// A.3's `check_drain_done` relies on. Because the queue only shrinks, the
    /// post-transition `C.inflight` (slightly smaller still) is likewise <= both
    /// thresholds, so the thresholds recomputed right after the edge witness the
    /// same condition that fired it (`start_probe_bw_cruise` touches neither
    /// `max_bw`, `min_rtt`, `inflight_longterm`, nor `C.inflight`).
    ///
    /// Asserts that: the flow entered PROBE_DOWN via PROBE_UP with
    /// `pacing_gain == ProbeDownPacingGain` (0.90) and `C.inflight` above at least
    /// one cruise threshold (a real queue to drain); the flow then transitioned to
    /// PROBE_CRUISE with `pacing_gain` back at `DefaultPacingGain`; and at that
    /// edge `C.inflight` was <= both `BBRInflightWithHeadroom()` and
    /// `BBRInflight(1.0)`.
    #[test]
    fn probe_bw_exits_probe_down_to_probe_cruise_on_inflight() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.3/A.5
        const RTT_NS: u64 = 100_000_000;

        // Drive the production default configuration.
        let mut sim = Sim::new(Bbr3Config::default(), MSS, BW, RTT_NS);
        assert_eq!(sim.bbr.state, BbrState::Startup);

        // Whether the flow has reached the PROBE_UP phase; the PROBE_DOWN we care
        // about is the one PROBE_UP cycles back into (it carries the standing queue
        // PROBE_UP built), not the initial DRAIN -> PROBE_DOWN entry.
        let mut reached_probe_up = false;
        // Captured on the PROBE_UP -> PROBE_DOWN edge: (pacing_gain, C.inflight,
        // BBRInflightWithHeadroom(), BBRInflight(1.0)) at entry, before any drain.
        let mut down_entry: Option<(f64, u64, u64, u64)> = None;
        // Captured on the PROBE_DOWN -> PROBE_CRUISE edge: (pacing_gain,
        // C.inflight, BBRInflightWithHeadroom(), BBRInflight(1.0)).
        let mut cruise_edge: Option<(f64, u64, u64, u64)> = None;

        sim.run(
            1_000_000,
            |_| ControlFlow::Continue(()),
            |bbr, _now_ns, _inflight, _pn| {
                if bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    reached_probe_up = true;
                }

                // Capture the PROBE_UP -> PROBE_DOWN entry (only meaningful once
                // PROBE_UP has actually been entered, and only the first time).
                if reached_probe_up
                    && down_entry.is_none()
                    && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Down)
                {
                    down_entry = Some((
                        bbr.pacing_gain,
                        bbr.inflight,
                        bbr.inflight_with_headroom(),
                        bbr.get_inflight(1.0),
                    ));
                }

                // Capture the PROBE_DOWN -> PROBE_CRUISE edge and stop. Reachable
                // only after the down entry has been recorded.
                if down_entry.is_some() && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Cruise) {
                    cruise_edge = Some((
                        bbr.pacing_gain,
                        bbr.inflight,
                        bbr.inflight_with_headroom(),
                        bbr.get_inflight(1.0),
                    ));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
        );
        let bbr = &mut sim.bbr;

        // Entered PROBE_DOWN via PROBE_UP, pacing at ProbeDownPacingGain (0.90),
        // with a genuine queue still to drain.
        assert!(reached_probe_up, "BBR never reached the PROBE_UP phase");
        let (down_gain, down_inflight, down_headroom, down_inflight_1) =
            down_entry.expect("BBR never entered PROBE_DOWN after PROBE_UP");
        assert_eq!(
            down_gain, bbr.probe_bw_down_pacing_gain,
            "PROBE_DOWN pacing_gain should be ProbeDownPacingGain"
        );
        assert_eq!(
            down_gain, PROBE_BW_DOWN_PACING_GAIN,
            "ProbeDownPacingGain should be 0.90"
        );
        // Standing queue at entry: C.inflight exceeded the binding cruise threshold
        // BBRInflight(1.0), so cruise couldn't fire immediately. (Loss-free here, so
        // inflight_longterm stays u64::MAX and BBRInflightWithHeadroom() never binds; cf. A.9.)
        assert!(
            down_inflight > down_inflight_1,
            "expected a standing queue at PROBE_DOWN entry (inflight {down_inflight} vs \
             inflight(1.0) {down_inflight_1}; headroom {down_headroom} unbounded)"
        );

        // Drained into PROBE_CRUISE.
        let (cruise_gain, cruise_inflight, cruise_headroom, cruise_inflight_1) =
            cruise_edge.expect("PROBE_DOWN never transitioned to PROBE_CRUISE");
        assert_eq!(
            bbr.state,
            BbrState::ProbeBw(ProbeBwSubstate::Cruise),
            "flow should have transitioned to PROBE_CRUISE"
        );
        // Cruise resets pacing_gain to DefaultPacingGain.
        assert_eq!(
            cruise_gain, bbr.default_pacing_gain,
            "PROBE_CRUISE pacing_gain should be DefaultPacingGain"
        );
        // BBRIsTimeToCruise held: C.inflight fell to <= BBRInflight(1.0), the binding
        // threshold. The queue only shrinks, so the post-edge recompute still holds.
        // (Headroom is unbounded here, inflight_longterm == u64::MAX, so it never binds; cf. A.9.)
        assert!(
            cruise_inflight <= cruise_inflight_1,
            "at PROBE_CRUISE, inflight ({cruise_inflight}) should be <= BBRInflight(1.0) \
             ({cruise_inflight_1}); headroom {cruise_headroom} unbounded"
        );
    }

    /// A.9: Exiting PROBE_DOWN after max time, direct to PROBE_REFILL, bypassing
    /// PROBE_CRUISE.
    /// equivalent to BBRIsTimeToProbeBW:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    ///
    /// Drives the same single-bottleneck simulator as A.8 through
    /// STARTUP -> DRAIN -> PROBE_BW and on into the PROBE_DOWN that PROBE_UP cycles
    /// back into (carrying the standing queue PROBE_UP built), breaking on that
    /// PROBE_UP -> PROBE_DOWN edge while `C.inflight` is still well above the cruise
    /// threshold `BBRInflight(1.0)` (~BDP). That standing queue is exactly the state
    /// A.9 constructs by "decreasing available bandwidth 10% on entering PROBE_DOWN so
    /// C.inflight never drops below the cruise threshold". (In this loss-free single
    /// flow `inflight_longterm` stays at its `u64::MAX` init, so
    /// `BBRInflightWithHeadroom()` is unbounded and `BBRInflight(1.0)` is the only
    /// binding cruise threshold.)
    ///
    /// From that state it isolates the elapsed-time exit: it refreshes
    /// `probe_rtt_min_stamp` so the periodic min-RTT re-probe (PROBE_RTT, cf. A.10)
    /// cannot preempt, advances `now` just past `cycle_stamp + bw_probe_wait`, and
    /// drives `update_probe_bw_cycle_phase`. Because that function checks
    /// `BBRIsTimeToProbeBW` (the timer) *before* `BBRIsTimeToCruise`, and `C.inflight`
    /// is above the cruise threshold, the flow moves in a single cycle step DIRECTLY
    /// from PROBE_DOWN to PROBE_REFILL, bypassing PROBE_CRUISE. The Reno-coexistence
    /// disjunct is not the trigger: `rounds_since_bw_probe` was reset at down entry and
    /// stays below the `min(target_inflight(), MAX_RENO_ROUNDS)` threshold.
    ///
    /// Asserts that: the flow entered PROBE_DOWN via PROBE_UP with
    /// `pacing_gain == ProbeDownPacingGain` (0.90); at the exit `C.inflight` was above
    /// `BBRInflight(1.0)` so cruise was not an available exit; the single cycle step
    /// took PROBE_DOWN straight to PROBE_REFILL (no intervening PROBE_CRUISE); and
    /// PROBE_REFILL reset `pacing_gain` to `DefaultPacingGain`.
    #[test]
    fn probe_bw_exits_probe_down_to_probe_refill_on_max_time() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.3/A.5/A.8
        const RTT_NS: u64 = 100_000_000;

        // Drive the production default configuration with a fixed probe RNG seed so
        // bw_probe_wait is deterministic; its exact value does not matter here since
        // the deadline is computed from it below.
        let config = Bbr3Config {
            probe_rng_seed: Some([6; 16]),
            ..Bbr3Config::default()
        };
        let mut sim = Sim::new(config, MSS, BW, RTT_NS);
        assert_eq!(sim.bbr.state, BbrState::Startup);

        // Whether the flow has reached the PROBE_UP phase; the PROBE_DOWN we care
        // about is the one PROBE_UP cycles back into (it carries the standing queue),
        // not the initial DRAIN -> PROBE_DOWN entry.
        let mut reached_probe_up = false;
        // pacing_gain captured on the PROBE_UP -> PROBE_DOWN edge; also the break
        // signal (Some once we have landed in the PROBE_DOWN we care about).
        let mut down_gain: Option<f64> = None;
        // Deadline after which BBRIsTimeToProbeBW's elapsed-time trigger fires:
        // cycle_stamp + bw_probe_wait, in simulator nanoseconds.
        let mut probe_deadline_ns: u64 = 0;

        sim.run(
            1_000_000,
            |_| ControlFlow::Continue(()),
            |bbr, now_ns, _inflight, _pn| {
                if bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    reached_probe_up = true;
                }

                // Break on the PROBE_UP -> PROBE_DOWN edge (only once PROBE_UP has been
                // entered, so not the initial DRAIN -> PROBE_DOWN entry). At this point
                // the queue PROBE_UP built is still standing, so C.inflight is above the
                // cruise threshold. Capture the pacing gain and the bw_probe_wait
                // deadline stamped by start_probe_bw_down (cycle_stamp == at(now_ns)).
                if reached_probe_up && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Down) {
                    down_gain = Some(bbr.pacing_gain);
                    probe_deadline_ns = now_ns + bbr.bw_probe_wait.as_nanos() as u64;
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
        );

        // Entered PROBE_DOWN via PROBE_UP, pacing at ProbeDownPacingGain (0.90).
        assert!(reached_probe_up, "BBR never reached the PROBE_UP phase");
        let down_gain = down_gain.expect("BBR never entered PROBE_DOWN after PROBE_UP");
        // Instant for the elapsed-time fire, computed before borrowing bbr below.
        let fire_at = sim.at(probe_deadline_ns + 1);
        let bbr = &mut sim.bbr;
        assert_eq!(
            down_gain, bbr.probe_bw_down_pacing_gain,
            "PROBE_DOWN pacing_gain should be ProbeDownPacingGain"
        );
        assert_eq!(
            down_gain, PROBE_BW_DOWN_PACING_GAIN,
            "ProbeDownPacingGain should be 0.90"
        );

        // The standing PROBE_UP queue keeps C.inflight above the cruise threshold
        // BBRInflight(1.0), so BBRIsTimeToCruise is false and PROBE_CRUISE is not an
        // available exit: the state A.9 sets up by decreasing bandwidth 10% on
        // PROBE_DOWN entry so inflight never drops below the threshold.
        let cruise_threshold = bbr.get_inflight(1.0);
        assert!(
            bbr.inflight > cruise_threshold,
            "C.inflight ({}) should be above the cruise threshold BBRInflight(1.0) ({cruise_threshold})",
            bbr.inflight
        );
        assert_eq!(bbr.state, BbrState::ProbeBw(ProbeBwSubstate::Down));

        // Isolate the elapsed-time exit. Refresh probe_rtt_min_stamp so the periodic
        // min-RTT re-probe (PROBE_RTT, cf. A.10) cannot preempt, then advance now just
        // past cycle_stamp + bw_probe_wait (has_elapsed_in_phase is a strict `>`) and
        // drive one cycle-phase step.
        bbr.probe_rtt_min_stamp = Some(fire_at);
        bbr.update_probe_bw_cycle_phase(fire_at);

        // A single cycle step took PROBE_DOWN straight to PROBE_REFILL, bypassing
        // PROBE_CRUISE, because update_probe_bw_cycle_phase checks BBRIsTimeToProbeBW
        // (the timer) before BBRIsTimeToCruise. Refill resets pacing_gain to
        // DefaultPacingGain.
        assert_eq!(
            bbr.state,
            BbrState::ProbeBw(ProbeBwSubstate::Refill),
            "PROBE_DOWN should transition directly to PROBE_REFILL"
        );
        assert_eq!(
            bbr.pacing_gain, bbr.default_pacing_gain,
            "PROBE_REFILL pacing_gain should be DefaultPacingGain"
        );
    }

    /// A.10: Entering and exiting PROBE_RTT.
    /// equivalent to BBRCheckProbeRTT / BBRHandleProbeRTT / BBRExitProbeRTT:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3>
    ///
    /// Same infinite-buffer FIFO simulator as A.1/A.8 (constant link rate,
    /// constant propagation delay), driven STARTUP -> DRAIN -> PROBE_BW and then
    /// left to run for more than `BBR.ProbeRTTInterval` (5 s). This is the
    /// periodic min-RTT re-probe: once `BBR.probe_rtt_min_delay` has not been
    /// lowered for a full ProbeRTTInterval, `update_min_rtt` flips
    /// `BBR.probe_rtt_expired` true and `check_probe_rtt` enters PROBE_RTT.
    ///
    /// Why `probe_rtt_min_delay` stays put for the whole 5 s: with a constant link
    /// rate and propagation delay, the smallest achievable RTT is the fixed floor
    /// `FWD + service + RET`, hit whenever the bottleneck queue is empty (every
    /// PROBE_DOWN drains to it). `update_min_rtt` only refreshes
    /// `probe_rtt_min_stamp` on a *strictly* lower sample (`rtt < probe_rtt_min_delay`),
    /// so repeated floor-equal samples never move the stamp. The first ack stamps the
    /// floor (~t=100 ms via the `probe_rtt_expired`-on-None branch); nothing beats it
    /// afterward, so the stamp is frozen and expiry fires ~5 s later, comfortably
    /// after STARTUP/DRAIN have handed off to PROBE_BW with `full_bw_reached` true.
    ///
    /// On entry `check_probe_rtt` calls `enter_probe_rtt` (state -> ProbeRtt,
    /// `cwnd_gain` -> `ProbeRTTCwndGain` = 0.5), saves the cwnd, clears
    /// `probe_rtt_done_stamp`, and starts a round. `bound_cwnd_for_probe_rtt` then
    /// caps `C.cwnd` at `BBRProbeRTTCwnd` (~0.5·BDP), so the sender stalls until
    /// `C.inflight` drains below that cap. When it does, `handle_probe_rtt` stamps
    /// `probe_rtt_done_stamp = now + ProbeRTTDuration` (200 ms) and starts a fresh
    /// round; PROBE_RTT then holds until *both* one packet-timed round has elapsed
    /// (`probe_rtt_round_done`) *and* `now > probe_rtt_done_stamp`. `check_probe_rtt_done`
    /// then restores the cwnd and calls `exit_probe_rtt`, which (because
    /// `full_bw_reached` is true) runs `start_probe_bw_down` then
    /// `start_probe_bw_cruise`, landing back in PROBE_BW (Cruise) and lifting the
    /// cwnd cap so the sender resumes.
    ///
    /// Asserts that: the flow reached PROBE_BW with `full_bw_reached` true before any
    /// PROBE_RTT entry; PROBE_RTT was entered only after ProbeRTTInterval (5 s) had
    /// elapsed, with `cwnd_gain == ProbeRTTCwndGain` (0.5); the exit came at least
    /// ProbeRTTDuration (200 ms) *and* one round after `probe_rtt_done_stamp` was
    /// armed; and the flow transitioned back to PROBE_BW (Cruise) with
    /// `full_bw_reached` still true and resumed sending.
    #[test]
    fn probe_bw_enters_and_exits_probe_rtt() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.8
        const RTT_NS: u64 = 100_000_000;

        // Held constant (no queue-shaping hacks) so the min RTT floor is deterministic.
        let mut sim = Sim::new(Bbr3Config::default(), MSS, BW, RTT_NS);
        assert_eq!(sim.bbr.state, BbrState::Startup);

        // Whether the flow reached PROBE_BW with full_bw_reached before PROBE_RTT.
        let mut reached_probe_bw = false;
        // Captured on the first transition into PROBE_RTT: (now_ns, cwnd_gain, round).
        let mut probe_rtt_entry: Option<(u64, f64, u64)> = None;
        // Captured when probe_rtt_done_stamp is first armed inside PROBE_RTT (i.e.
        // once C.inflight has drained below the ProbeRTT cwnd cap): (now_ns, round).
        let mut done_armed: Option<(u64, u64)> = None;
        // Captured on the PROBE_RTT -> PROBE_BW exit edge:
        // (now_ns, state, round, full_bw_reached).
        let mut probe_rtt_exit: Option<(u64, BbrState, u64, bool)> = None;
        // Whether the exit has happened (shared with the send hook via a Cell so
        // both closures can read it without aliasing probe_rtt_exit).
        let exited = Cell::new(false);
        // Sends observed after the exit, proving the flow resumed transmitting.
        let mut sends_after_exit: u64 = 0;

        sim.run(
            2_000_000,
            |_bbr| {
                if exited.get() {
                    sends_after_exit += 1;
                }
                // Stop a few sends after the exit, enough to prove sending resumed.
                if sends_after_exit >= 3 {
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            },
            |bbr, now_ns, _inflight, _pn| {
                // Note the first time PROBE_BW is reached with the bandwidth model
                // considered full: the precondition for PROBE_RTT's full_bw exit.
                if !reached_probe_bw
                    && bbr.full_bw_reached
                    && matches!(bbr.state, BbrState::ProbeBw(_))
                {
                    reached_probe_bw = true;
                }

                // Entry edge into PROBE_RTT: the periodic min-RTT re-probe we care
                // about, i.e. the one after PROBE_BW. (A transient PROBE_RTT also
                // fires on the very first ack, because probe_rtt_min_stamp starts
                // unset so probe_rtt_expired is true at t=0; that one happens during
                // STARTUP, exits straight back to STARTUP via !full_bw_reached, and
                // is filtered out by the reached_probe_bw guard.)
                if reached_probe_bw && probe_rtt_entry.is_none() && bbr.state == BbrState::ProbeRtt
                {
                    probe_rtt_entry = Some((now_ns, bbr.cwnd_gain, bbr.round_count));
                }

                // The moment probe_rtt_done_stamp is armed: C.inflight has drained
                // below the ProbeRTT cwnd cap and the ProbeRTTDuration clock starts.
                if probe_rtt_entry.is_some()
                    && done_armed.is_none()
                    && bbr.state == BbrState::ProbeRtt
                    && bbr.probe_rtt_done_stamp.is_some()
                {
                    done_armed = Some((now_ns, bbr.round_count));
                }

                // Exit edge: PROBE_RTT -> PROBE_BW.
                if probe_rtt_entry.is_some()
                    && probe_rtt_exit.is_none()
                    && matches!(bbr.state, BbrState::ProbeBw(_))
                {
                    probe_rtt_exit =
                        Some((now_ns, bbr.state, bbr.round_count, bbr.full_bw_reached));
                    exited.set(true);
                }
                ControlFlow::Continue(())
            },
        );
        let bbr = &sim.bbr;

        // Reached PROBE_BW with a full bandwidth model before probing RTT.
        assert!(
            reached_probe_bw,
            "BBR never reached PROBE_BW with full_bw_reached before PROBE_RTT"
        );

        // Entered PROBE_RTT, and only after ProbeRTTInterval (5 s) elapsed with
        // probe_rtt_min_delay never lowered.
        let (entry_ns, entry_cwnd_gain, entry_round) =
            probe_rtt_entry.expect("BBR never entered PROBE_RTT");
        assert!(
            entry_ns >= PROBE_RTT_INTERVAL_SEC * 1_000_000_000,
            "PROBE_RTT entered before ProbeRTTInterval elapsed \
             (entry {entry_ns} ns vs interval {}s)",
            PROBE_RTT_INTERVAL_SEC
        );
        // cwnd_gain was set to ProbeRTTCwndGain (0.5) on entry.
        assert_eq!(
            entry_cwnd_gain, bbr.probe_rtt_cwnd_gain,
            "PROBE_RTT cwnd_gain should be ProbeRTTCwndGain"
        );
        assert_eq!(
            entry_cwnd_gain, PROBE_RTT_CWND_GAIN,
            "ProbeRTTCwndGain should be 0.5"
        );

        // The ProbeRTTDuration clock was armed once inflight drained below the cap.
        let (done_ns, done_round) = done_armed.expect("PROBE_RTT never armed probe_rtt_done_stamp");

        // Exited PROBE_RTT back to PROBE_BW (Cruise), full_bw_reached still true.
        let (exit_ns, exit_state, exit_round, exit_full_bw) =
            probe_rtt_exit.expect("BBR never exited PROBE_RTT");
        assert_eq!(
            exit_state,
            BbrState::ProbeBw(ProbeBwSubstate::Cruise),
            "PROBE_RTT should exit to PROBE_BW (Cruise) when full_bw_reached"
        );
        assert!(
            exit_full_bw,
            "full_bw_reached should remain true across the PROBE_RTT exit"
        );

        // Held for at least ProbeRTTDuration (200 ms) after the clock was armed
        // (check_probe_rtt_done uses a strict `now > probe_rtt_done_stamp`).
        assert!(
            exit_ns - done_ns >= PROBE_RTT_DURATION_MS * 1_000_000,
            "PROBE_RTT exited before ProbeRTTDuration elapsed \
             (held {} ns vs duration {} ms)",
            exit_ns - done_ns,
            PROBE_RTT_DURATION_MS
        );
        // ...and for at least one packet-timed round after arming.
        assert!(
            exit_round > done_round,
            "PROBE_RTT should hold at least one round after arming \
             (arm round {done_round} vs exit round {exit_round})"
        );
        // Sanity: entry preceded the exit.
        assert!(exit_round >= entry_round && exit_ns > entry_ns);

        // The flow resumed sending after exiting PROBE_RTT (cwnd cap lifted).
        assert!(
            sends_after_exit > 0,
            "flow did not resume sending after exiting PROBE_RTT"
        );
    }

    /// A.11: Skipping PROBE_RTT due to application-limited (restart-from-idle) sending.
    /// equivalent to BBRHandleRestartFromIdle / BBRCheckProbeRTT:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.4.1>
    ///
    /// Same infinite-buffer FIFO simulator as A.10 (constant link rate, constant
    /// propagation delay), driven STARTUP -> DRAIN -> PROBE_BW. Then the
    /// application stops offering data: every in-flight packet is acked with no new
    /// sends, so `C.inflight` drains to 0 and the connection goes idle. Virtual time is
    /// then advanced past `BBR.ProbeRTTInterval` (5 s) with nothing in flight, long
    /// enough that the periodic min-RTT re-probe is due (`probe_rtt_expired` becomes
    /// true on the next `update_min_rtt`), exactly the condition that drove the PROBE_RTT
    /// entry in A.10.
    ///
    /// The difference here is the idle gap. When the application resumes and sends the
    /// first packet, `on_packet_sent` calls `handle_restart_from_idle`: because
    /// `C.inflight` was 0 and the connection is application-limited (`C.app_limited != 0`),
    /// it sets `BBR.idle_restart = true`. On the resulting ack, `check_probe_rtt` sees
    /// `probe_rtt_expired` true but refuses to `enter_probe_rtt` because of the
    /// `!idle_restart` guard: an idle period is itself deemed a sufficient drain of the
    /// bottleneck queue, so a formal PROBE_RTT is unnecessary. `idle_restart` is then
    /// cleared once a delivering ack arrives, and the refreshed `probe_rtt_min_stamp`
    /// keeps expiry from re-firing on the following acks.
    ///
    /// Asserts that: the flow reached PROBE_BW with `full_bw_reached` and then drained to
    /// idle (`C.inflight == 0`) while still in PROBE_BW; more than ProbeRTTInterval (5 s)
    /// elapsed during the idle gap; the first send after idle set `BBR.idle_restart`; and
    /// although the min-RTT re-probe was due at that point (`probe_rtt_expired` true), the
    /// connection never entered PROBE_RTT over the subsequent rounds.
    #[test]
    fn probe_bw_skips_probe_rtt_on_restart_from_idle() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.10
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;

        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Phase 1: drive STARTUP -> DRAIN -> PROBE_BW, stopping as soon as the flow is in
        // PROBE_BW with the bandwidth model considered full. The application then stops.
        let mut reached_probe_bw = false;
        for _ in 0..2_000_000 {
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            let next_ack = flight.front().map(|p| p.ack_ns);
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));

                if bbr.full_bw_reached && matches!(bbr.state, BbrState::ProbeBw(_)) {
                    reached_probe_bw = true;
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }
        assert!(
            reached_probe_bw,
            "BBR never reached PROBE_BW with full_bw_reached"
        );

        // Phase 2: the application pauses. Ack every remaining in-flight packet without
        // sending anything new, so the connection goes fully idle (C.inflight == 0).
        while let Some(p) = flight.pop_front() {
            now_ns = now_ns.max(p.ack_ns);
            inflight -= MSS;
            rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
            bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
            bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
        }
        assert_eq!(
            inflight, 0,
            "harness should have drained all in-flight data"
        );
        assert_eq!(
            bbr.inflight, 0,
            "C.inflight should be 0 once the app goes idle"
        );
        assert!(
            matches!(bbr.state, BbrState::ProbeBw(_)),
            "flow should still be in PROBE_BW when it goes idle, got {:?}",
            bbr.state
        );
        let idle_start_ns = now_ns;

        // Phase 3: stay idle past BBR.ProbeRTTInterval (5 s), so the periodic min-RTT
        // re-probe becomes due. Nothing is in flight, so no BBR callbacks fire; time just
        // advances. With no data to send during the gap, the connection is app-limited.
        now_ns = idle_start_ns + PROBE_RTT_INTERVAL_SEC * 1_000_000_000 + 2 * RTT_NS;
        bbr.app_limited = pn;
        assert!(
            now_ns - idle_start_ns >= PROBE_RTT_INTERVAL_SEC * 1_000_000_000,
            "idle gap must exceed ProbeRTTInterval (5 s)"
        );

        // Phase 4: the application resumes and sends one packet. handle_restart_from_idle
        // runs on this transmit and must set BBR.idle_restart because C.inflight was 0 and
        // the connection is app-limited.
        let resume_pn = pn;
        {
            let send_ns = now_ns;
            let arrival = send_ns + FWD_NS;
            let service_start = arrival.max(btl_free_ns);
            let finish = service_start + btl_service_ns;
            btl_free_ns = finish;
            let ack_ns = finish + RET_NS;

            bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
            inflight += MSS;
            flight.push_back(InFlight {
                pn,
                send_ns,
                ack_ns,
            });
            next_send_ns = now_ns;
            pn += 1;
        }
        assert!(
            bbr.idle_restart,
            "handle_restart_from_idle should set BBR.idle_restart on the first send \
             after an idle, app-limited period"
        );

        // Phase 5: keep sending/acking. On the resume packet's ack the min-RTT re-probe is
        // due (probe_rtt_expired true), yet PROBE_RTT must be skipped because idle_restart
        // is set. Run enough rounds to prove it stays skipped.
        let mut probe_rtt_expired_at_resume: Option<bool> = None;
        let mut entered_probe_rtt = false;
        let mut acks_after_resume: u64 = 0;
        for _ in 0..2_000_000 {
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            let next_ack = flight.front().map(|p| p.ack_ns);
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));

                if p.pn == resume_pn {
                    // Snapshot right after the restarting packet's ack: the re-probe was
                    // due (probe_rtt_expired) so only idle_restart could suppress entry.
                    probe_rtt_expired_at_resume = Some(bbr.probe_rtt_expired);
                }
                acks_after_resume += 1;

                if bbr.state == BbrState::ProbeRtt {
                    entered_probe_rtt = true;
                    break;
                }
                if acks_after_resume >= 40 {
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // The min-RTT re-probe was due at resume (the same trigger that entered
        // PROBE_RTT in A.10), so idle_restart is the only thing that could suppress entry.
        assert_eq!(
            probe_rtt_expired_at_resume,
            Some(true),
            "probe_rtt_expired should be true at resume (5 s elapsed), making the \
             PROBE_RTT skip attributable to idle_restart"
        );
        // The connection skipped PROBE_RTT: idleness was a sufficient queue drain.
        assert!(
            !entered_probe_rtt,
            "connection must skip PROBE_RTT after restarting from idle (idle_restart set)"
        );
    }

    /// A.12: Achieving expected STARTUP bandwidth on a link with ACK aggregation.
    /// equivalent to BBRUpdateACKAggregation / BBRUpdateMaxInflight:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.9>
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2>
    ///
    /// Same constant-rate FIFO simulator as A.1, with one change: the path
    /// aggregates ACKs. Instead of each served packet being acked as soon as it clears
    /// the bottleneck (+propagation), completed packets are held and released in bursts on a
    /// fixed `AGG_NS` epoch grid, modelling the L2 batching / radio-DRX behaviour of a
    /// cellular link, where the receiver's ACKs for many packets arrive bunched at one
    /// instant. Every packet whose service finishes inside the same `AGG_NS` window shares a
    /// single delivery instant, so the sender sees one ACK "event" cover many packets. The
    /// bottleneck still drains at exactly `BW`, so the *average* delivery rate is unchanged;
    /// only its arrival timing is bursty.
    ///
    /// Each aggregation burst is fed to BBR exactly as the connection layer would (cf.
    /// `Connection::on_packet_acked` looping over the newly-acked packets, then a single
    /// `on_end_acks`): one `on_ack` per packet in the burst, all stamped with the same ack
    /// instant `now`, followed by one `on_end_acks` carrying the burst's largest packet
    /// number.
    ///
    /// This exercises two mechanisms the draft calls for on aggregating paths:
    ///  1. The delivery-rate sampler must not be fooled by the burst. A burst delivers
    ///     `K*MSS` over a near-zero ACK-arrival span, but the underlying packets were *sent*
    ///     over a much longer span; because `RS.interval = max(send_elapsed, ack_elapsed)`
    ///     uses the (longer) send span, the sampled rate is capped at the send rate and
    ///     `BBR.max_bw` tracks the true bottleneck `BW` rather than the instantaneous burst
    ///     rate. Asserted via `max_bw` staying within a few percent of `BW`.
    ///  2. `BBRUpdateACKAggregation` must estimate the excess data delivered by aggregation
    ///     (`BBR.extra_acked`) and `BBRUpdateMaxInflight` must add it to the cwnd budget, so
    ///     that inflight does not throttle throughput on the bursty path. With STARTUP's
    ///     `cwnd_gain` of 2, `max_inflight = 2*BDP + extra_acked`, so a positive
    ///     `extra_acked` drives `C.cwnd` above `2 * BDP`. Asserted directly.
    ///
    /// Despite the aggregation, STARTUP must still ramp (pacing_gain 2.773 doubles the send
    /// rate each round) and discover the full bottleneck bandwidth, exiting to DRAIN on the
    /// delivery-rate plateau with `full_bw_reached` and `max_bw` ~= `BW`, exactly as A.1.
    #[test]
    fn startup_reaches_full_bw_with_ack_aggregation() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// ACK-aggregation epoch. All packets whose bottleneck service finishes within the
        /// same `AGG_NS` window have their ACKs released together. 1ms is ~10 MSS-times at
        /// BW (bursty, cellular-like) yet well under the 100ms RTT, so bursts stay within a
        /// round trip.
        const AGG_NS: u64 = 1_000_000;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Signals gathered while still in STARTUP; asserted after the loop.
        // Largest ACK burst (packets acked at one instant) actually produced; proves the
        // path aggregated rather than degenerating to one-packet acks.
        let mut max_burst: usize = 0;
        // Highest BBR.extra_acked observed in STARTUP (aggregation estimate).
        let mut max_extra_acked: u64 = 0;
        // A STARTUP burst where extra_acked>0 pushed C.cwnd strictly above 2*BDP.
        let mut cwnd_exceeded_2bdp = false;
        // Peak max_bw seen in STARTUP; must stay ~BW, proving the burst didn't inflate the
        // delivery-rate estimate above the send rate.
        let mut peak_startup_max_bw: f64 = 0.0;
        // Captured on the STARTUP -> DRAIN edge, as in A.1.
        let mut transition: Option<(bool, f64)> = None;

        for _ in 0..2_000_000 {
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            let next_ack = flight.front().map(|p| p.ack_ns);
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                // ACK aggregation: hold the completed packet until the next AGG_NS epoch
                // boundary at/after `finish`, so packets finishing in the same window are
                // released to the sender together (identical ack_ns == one ACK event).
                let ack_ns = finish.div_ceil(AGG_NS) * AGG_NS + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(first) = flight.pop_front() {
                // Gather the whole aggregation burst: every in-flight packet sharing this
                // release instant is acknowledged by the same ACK event.
                let burst_ack_ns = first.ack_ns;
                let mut burst = vec![first];
                while flight.front().is_some_and(|p| p.ack_ns == burst_ack_ns) {
                    burst.push(flight.pop_front().unwrap());
                }
                now_ns = now_ns.max(burst_ack_ns);
                max_burst = max_burst.max(burst.len());

                // Feed the burst as the connection layer does: one on_ack per packet (same
                // ack instant), then a single on_end_acks with the largest pn in the burst.
                let largest_pn = burst.last().map(|p| p.pn).unwrap();
                for p in &burst {
                    inflight -= MSS;
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                }
                bbr.on_end_acks(at(now_ns), inflight, false, Some(largest_pn));

                if bbr.state == BbrState::Startup {
                    max_extra_acked = max_extra_acked.max(bbr.extra_acked);
                    peak_startup_max_bw = peak_startup_max_bw.max(bbr.max_bw);
                    // bbr.bdp is refreshed to max_bw*min_rtt on every set_cwnd; once the
                    // aggregation estimate is positive it should lift cwnd past 2*BDP.
                    if bbr.extra_acked > 0 && bbr.bdp > 0 && bbr.cwnd > 2 * bbr.bdp {
                        cwnd_exceeded_2bdp = true;
                    }
                }
                if bbr.state == BbrState::Drain {
                    transition = Some((bbr.full_bw_reached, bbr.max_bw));
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // The path genuinely aggregated: at least one ACK event covered many packets.
        assert!(
            max_burst > 1,
            "harness should have produced aggregated ACK bursts, max burst was {max_burst}"
        );
        // BBRUpdateACKAggregation estimated a positive excess from the bursts.
        assert!(
            max_extra_acked > 0,
            "extra_acked should be positive on an aggregating path"
        );
        // The extra_acked budget lifted the cwnd above 2*BDP (BBRUpdateMaxInflight adds
        // extra_acked on top of cwnd_gain*BDP, cwnd_gain being 2 in STARTUP).
        assert!(
            cwnd_exceeded_2bdp,
            "C.cwnd should exceed 2*BDP while extra_acked>0 in STARTUP (max_extra_acked {max_extra_acked})"
        );
        // The delivery-rate sampler was not fooled by the bursts: interval =
        // max(send_elapsed, ack_elapsed) caps the sample at the send rate, so max_bw never
        // ran far above the true bottleneck BW during STARTUP.
        let startup_bw_err = (peak_startup_max_bw - BW).abs() / BW;
        assert!(
            peak_startup_max_bw <= BW * 1.05,
            "max_bw {peak_startup_max_bw} inflated above send rate {BW} by bursts (rel {startup_bw_err})"
        );

        // STARTUP still ramped and discovered the full bottleneck bandwidth: it exited to
        // DRAIN on the plateau with full_bw_reached and max_bw ~= BW, as in A.1.
        let (full_bw_reached, max_bw) = transition.expect("BBR never left STARTUP");
        assert!(
            full_bw_reached,
            "full_bw_reached should be set on the bandwidth plateau"
        );
        let err = (max_bw - BW).abs() / BW;
        assert!(
            err < 0.05,
            "max_bw {max_bw} not within 5% of simulated {BW} (rel err {err})"
        );
    }

    /// A.13: Achieving expected cruise bandwidth on a link with ACK aggregation.
    /// equivalent to BBRUpdateACKAggregation / BBRUpdateMaxInflight:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.9>
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2>
    ///
    /// The aggregation-in-STARTUP counterpart is A.12; this covers the same excess-data
    /// mechanism in the steady-state PROBE_BW cruise phase, where the aggregation estimate
    /// is drawn from the windowed max filter rather than a single round.
    ///
    /// Two phases over the same constant-rate FIFO simulator as A.1:
    ///  1. Reach steady state with plain (unaggregated) delivery, one ACK per packet, as in
    ///     `probe_bw_exits_probe_down_to_probe_cruise_on_inflight`, driving
    ///     STARTUP -> DRAIN -> PROBE_BW and on into PROBE_CRUISE.
    ///  2. On entering PROBE_CRUISE, switch the path to aggregate ACKs: completed packets are
    ///     held and released in bursts on a fixed `AGG_NS` epoch grid (the L2 batching /
    ///     radio-DRX behaviour A.12 models), so many packets share one delivery instant and
    ///     the sender sees one ACK "event" cover a burst. The bottleneck still drains at
    ///     exactly `BW`, so only ACK arrival *timing* is bursty; the average rate is unchanged.
    ///
    /// Each burst is fed exactly as the connection layer would (cf. `Connection::on_packet_acked`
    /// looping over the newly-acked packets, then a single `on_end_acks`): one `on_ack` per
    /// packet, all stamped with the same ack instant, followed by one `on_end_acks` carrying
    /// the burst's largest packet number.
    ///
    /// Once `full_bw_reached` (true throughout PROBE_BW), `BBRUpdateACKAggregation` tracks the
    /// per-round excess in a windowed max filter over the last `BBR.ExtraAckedFilterLen`
    /// (`EXTRA_ACKED_FILTER_LEN`, 10) rounds and sets `BBR.extra_acked` to that max, unlike
    /// STARTUP, which just remembers one round (A.12). `BBRUpdateMaxInflight` then adds
    /// `extra_acked` on top of `cwnd_gain*BDP` (cruise `cwnd_gain` is `DefaultCwndGain` = 2),
    /// so `C.cwnd` is lifted above `2*BDP`.
    ///
    /// Asserts that, in PROBE_CRUISE on the aggregating path:
    ///  - the path genuinely aggregated (some ACK event covered many packets);
    ///  - `extra_acked` became positive and equalled `extra_acked_filter.get_max()` on every
    ///    ack, i.e. it is sourced from the windowed max filter, not the instantaneous round;
    ///  - the windowed max held: within `EXTRA_ACKED_FILTER_LEN` rounds of the peak, a
    ///    lower-excess round (an inter-ACK silence) never knocked `extra_acked` below that
    ///    peak (the filter retained it), so the cwnd budget did not collapse between bursts;
    ///  - `C.cwnd` exceeded `2*BDP` while `extra_acked>0` (the augmentation), and actual
    ///    inflight rose above `2*BDP` too: the sender kept the pipe full across the silences
    ///    rather than stalling at the un-augmented budget.
    #[test]
    fn probe_cruise_reaches_full_bw_with_ack_aggregation() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.1/A.12
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// ACK-aggregation epoch (enabled only once in PROBE_CRUISE). All packets whose
        /// bottleneck service finishes within the same `AGG_NS` window have their ACKs
        /// released together. 1ms is ~10 MSS-times at BW (bursty) yet well under the 100ms
        /// RTT, so bursts stay within a round trip. Matches A.12.
        const AGG_NS: u64 = 1_000_000;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Aggregation is off until the flow reaches PROBE_CRUISE; before that the path acks
        // one packet at a time (distinct ack_ns), exactly like the cruise-reaching harness in
        // probe_bw_exits_probe_down_to_probe_cruise_on_inflight.
        let mut agg_on = false;
        let mut cruise_start_round: Option<u64> = None;

        // Signals gathered while in PROBE_CRUISE; asserted after the loop.
        // Largest ACK burst (packets acked at one instant) actually produced.
        let mut max_burst: usize = 0;
        // Highest BBR.extra_acked observed in cruise, and the round it was first seen.
        let mut max_extra_acked: u64 = 0;
        let mut peak_round: Option<u64> = None;
        // extra_acked must be sourced from the windowed max filter on every cruise ack.
        let mut extra_acked_is_filter_max = true;
        // Largest amount by which C.cwnd sat above the un-augmented cruise budget (2*BDP),
        // i.e. the headroom BBRUpdateMaxInflight added from extra_acked.
        let mut max_cwnd_augmentation: u64 = 0;
        // The sender was never cwnd-blocked in cruise (cwnd stayed strictly above inflight on
        // every ack); a stall would show up as inflight catching the cwnd cap.
        let mut never_cwnd_blocked = true;
        // Peak inflight seen in cruise; should stay near a full BDP (pipe kept full).
        let mut max_inflight: u64 = 0;
        // Peak max_bw in cruise; must stay ~BW, proving the bursts didn't inflate the
        // delivery-rate estimate above the send rate (same sampler guard as A.12).
        let mut peak_cruise_max_bw: f64 = 0.0;
        // (round_count, extra_acked) at every cruise ack, for the windowed-retention check.
        let mut cruise_samples: Vec<(u64, u64)> = Vec::new();

        for _ in 0..3_000_000 {
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            let next_ack = flight.front().map(|p| p.ack_ns);
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                // Once aggregating, hold the completed packet until the next AGG_NS epoch
                // boundary at/after `finish` so packets finishing in the same window release
                // together (identical ack_ns == one ACK event); otherwise ack as soon as it
                // clears the bottleneck (+propagation), one ack per packet.
                let ack_ns = if agg_on {
                    finish.div_ceil(AGG_NS) * AGG_NS + RET_NS
                } else {
                    finish + RET_NS
                };

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(first) = flight.pop_front() {
                // Gather the whole aggregation burst: every in-flight packet sharing this
                // release instant is acknowledged by the same ACK event. Off the aggregating
                // path each ack_ns is unique, so bursts degenerate to a single packet.
                let burst_ack_ns = first.ack_ns;
                let mut burst = vec![first];
                while flight.front().is_some_and(|p| p.ack_ns == burst_ack_ns) {
                    burst.push(flight.pop_front().unwrap());
                }
                now_ns = now_ns.max(burst_ack_ns);

                // Feed the burst as the connection layer does: one on_ack per packet (same
                // ack instant), then a single on_end_acks with the largest pn in the burst.
                let largest_pn = burst.last().map(|p| p.pn).unwrap();
                for p in &burst {
                    inflight -= MSS;
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                }
                bbr.on_end_acks(at(now_ns), inflight, false, Some(largest_pn));

                let in_cruise = bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Cruise);

                // On the first cruise ack, turn the path aggregating for all subsequent sends.
                if in_cruise && cruise_start_round.is_none() {
                    agg_on = true;
                    cruise_start_round = Some(bbr.round_count);
                }

                if in_cruise && agg_on {
                    max_burst = max_burst.max(burst.len());

                    let ea = bbr.extra_acked;
                    // extra_acked is fed from the windowed max filter (full_bw_reached arm of
                    // BBRUpdateACKAggregation), not the raw per-round excess.
                    if ea != bbr.extra_acked_filter.get_max() {
                        extra_acked_is_filter_max = false;
                    }
                    if ea > max_extra_acked {
                        max_extra_acked = ea;
                        peak_round = Some(bbr.round_count);
                    }
                    cruise_samples.push((bbr.round_count, ea));

                    peak_cruise_max_bw = peak_cruise_max_bw.max(bbr.max_bw);
                    max_inflight = max_inflight.max(inflight);
                    if bbr.cwnd <= inflight {
                        never_cwnd_blocked = false;
                    }
                    // bbr.bdp is refreshed to max_bw*min_rtt inside update_max_inflight on
                    // every set_cwnd; 2*bdp is the un-augmented cruise budget (cwnd_gain 2), so
                    // any excess of cwnd over 2*bdp is exactly the extra_acked headroom
                    // BBRUpdateMaxInflight added.
                    if bbr.bdp > 0 {
                        max_cwnd_augmentation =
                            max_cwnd_augmentation.max(bbr.cwnd.saturating_sub(2 * bbr.bdp));
                    }

                    // Gathered a couple of filter windows' worth of cruise rounds.
                    if bbr.round_count - cruise_start_round.unwrap()
                        >= 2 * EXTRA_ACKED_FILTER_LEN as u64
                    {
                        break;
                    }
                } else if cruise_start_round.is_some() && !in_cruise {
                    // Left PROBE_CRUISE (on to PROBE_REFILL/UP); stop gathering.
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // The flow reached PROBE_CRUISE and we gathered acks there.
        let cruise_start_round = cruise_start_round.expect("flow never reached PROBE_CRUISE");
        assert!(
            !cruise_samples.is_empty(),
            "no acks gathered in PROBE_CRUISE"
        );
        // The cruise sojourn spanned at least one full filter window, so the windowed-max
        // behaviour was actually exercised.
        let last_round = cruise_samples.last().unwrap().0;
        assert!(
            last_round - cruise_start_round >= EXTRA_ACKED_FILTER_LEN as u64,
            "cruise spanned only {} rounds, need >= {EXTRA_ACKED_FILTER_LEN} to exercise the filter",
            last_round - cruise_start_round
        );

        // The path genuinely aggregated: at least one ACK event covered many packets.
        assert!(
            max_burst > 1,
            "harness should have produced aggregated ACK bursts, max burst was {max_burst}"
        );
        // BBRUpdateACKAggregation estimated a positive excess from the bursts.
        assert!(
            max_extra_acked > 0,
            "extra_acked should be positive on an aggregating path in cruise"
        );
        // extra_acked was sourced from the windowed max filter on every cruise ack.
        assert!(
            extra_acked_is_filter_max,
            "extra_acked should equal extra_acked_filter.get_max() throughout cruise"
        );

        // Windowed max held: within EXTRA_ACKED_FILTER_LEN rounds of the peak, no lower-excess
        // round (inter-ACK silence) drove extra_acked below the peak: the max filter retained
        // it over its window, keeping the cwnd budget from collapsing between bursts.
        let peak_round = peak_round.expect("no positive extra_acked observed in cruise");
        for &(round, ea) in &cruise_samples {
            if round > peak_round && round <= peak_round + EXTRA_ACKED_FILTER_LEN as u64 {
                assert!(
                    ea >= max_extra_acked,
                    "extra_acked {ea} at round {round} fell below the peak {max_extra_acked} \
                     (peak round {peak_round}) still inside the {EXTRA_ACKED_FILTER_LEN}-round filter window"
                );
            }
        }

        // C.cwnd carried the extra_acked headroom: BBRUpdateMaxInflight adds extra_acked on top
        // of cwnd_gain*BDP (=2*BDP in cruise). Both sides are peak maxima reduced independently
        // over the sojourn (not necessarily the same round), so this asserts peak augmentation
        // >= peak extra_acked, enough to catch dropping the `+ extra_acked` term.
        assert!(
            max_cwnd_augmentation >= max_extra_acked,
            "C.cwnd should sit >= max_extra_acked ({max_extra_acked}) above 2*BDP in cruise, \
             observed augmentation {max_cwnd_augmentation}"
        );
        // That augmentation is what prevents an inter-ACK stall: cwnd stayed strictly above
        // inflight on every cruise ack, so the sender was never cwnd-blocked despite the bursty,
        // silence-punctuated acks; without the extra_acked headroom a burst could push inflight
        // into the cwnd cap and stall the flow.
        assert!(
            never_cwnd_blocked,
            "cwnd should stay above inflight throughout cruise (no cwnd-induced stall)"
        );
        // Full utilization was maintained: inflight stayed near a full BDP (the pipe never
        // drained empty between bursts).
        assert!(
            max_inflight * 10 >= bbr.bdp * 9,
            "inflight ({max_inflight}) should stay near a full BDP ({}) in cruise",
            bbr.bdp
        );
        // The delivery-rate sampler was not fooled by the bursts: max_bw tracked the true
        // bottleneck BW rather than the instantaneous burst rate (interval =
        // max(send_elapsed, ack_elapsed) caps the sample at the send rate).
        let cruise_bw_err = (peak_cruise_max_bw - BW).abs() / BW;
        assert!(
            cruise_bw_err < 0.05,
            "max_bw {peak_cruise_max_bw} not within 5% of simulated {BW} (rel err {cruise_bw_err})"
        );
    }

    /// A.14: Correctly managing sub-packet BDPs.
    /// equivalent to BBRInflight / BBRQuantizationBudget (the BBR.MinPipeCwnd floor):
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2>
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.7-4>
    ///
    /// On a very slow bottleneck the model-derived congestion window collapses below the
    /// pipelining minimum. `BBR.MinPipeCwnd` (4 * SMSS) is the floor that keeps enough packets
    /// outstanding to tolerate an "ACK every other packet" delayed-ACK receiver without
    /// stalling. This test drives that regime and asserts the floor governs `C.cwnd` while the
    /// pacing rate still tracks the low link bandwidth.
    ///
    /// A single-bottleneck FIFO link at `BW` = 1 MB/s with a small propagation delay. Because
    /// the bottleneck serialization of one MSS (`MSS/BW` = 1.2ms) dominates the measured
    /// min-RTT, the model's BDP estimate (`bw*min_rtt`) sits near a single packet (the
    /// propagation BDP `bw*prop` is well under one packet). Either way the cruise inflight
    /// budget `cwnd_gain*BDP` (cwnd_gain = DefaultCwndGain = 2) falls below `MinPipeCwnd`
    /// (4 packets), so `MinPipeCwnd` is the binding floor on `C.cwnd`.
    ///
    /// Two phases over one bespoke loop (the shared `Sim` acks one packet per ack; this needs a
    /// delayed-ACK receiver, so it drives the send/ack path directly like A.12/A.13):
    ///  1. Reach steady-state PROBE_BW/PROBE_CRUISE with a plain receiver (one ACK per packet),
    ///     driving STARTUP -> DRAIN -> PROBE_BW -> PROBE_CRUISE. Capture BDP, `C.cwnd`, the
    ///     pacing rate and `MinPipeCwnd` at cruise entry.
    ///  2. Switch to an "ACK every other packet" receiver: completed packets are released in
    ///     pairs (the second packet's arrival triggers one ACK covering both), the delayed-ACK
    ///     policy `MinPipeCwnd` exists to serve. Because the 4-packet floor keeps ~4 packets
    ///     outstanding, a pair is always forming, so the bottleneck never idles waiting on a
    ///     held ACK, so the pipeline does not stall and throughput stays at `BW`. With only the
    ///     sub-packet model budget (~1 packet) the receiver would hold its lone packet's ACK
    ///     forever and the flow would deadlock; the floor is what prevents that.
    ///
    /// Asserts:
    ///  - at cruise entry the model budget was genuinely sub-floor (`cwnd_gain*BDP <
    ///    MinPipeCwnd`, BDP no more than ~2 packets) and `MinPipeCwnd == 4*MSS`;
    ///  - `C.cwnd` sat exactly at `MinPipeCwnd` (the floor, not the tiny model budget, governs);
    ///  - the pacing rate matched the low link bandwidth (within 5% of `BW`);
    ///  - under the delayed-ACK receiver the pipeline never stalled: pairs genuinely formed,
    ///    `C.cwnd` held at the 4-packet floor throughout, and achieved throughput stayed at
    ///    `BW` (within 10%).
    #[test]
    fn probe_bw_floors_sub_packet_bdp_at_min_pipe_cwnd() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// bottleneck bandwidth: 8 Mbit/s (1 MB/s) in bytes/sec. Two constraints pin this:
        ///  - cruise pacing (~0.99*BW) times 1ms (~990 B) must stay under the `2*SMSS`
        ///    `set_send_quantum` floor, so `send_quantum` sits at that floor and
        ///    `offload_budget` (send_quantum + delayed-ACK term) stays below `MinPipeCwnd`
        ///    (4*SMSS); otherwise the floor can't bind.
        ///  - it must still be fast enough to reach PROBE_CRUISE well within the 10s min-RTT
        ///    filter window, so the clean (drained) min-RTT sample from DRAIN survives to cruise
        ///    rather than aging out and re-latching to a queued value.
        const BW: f64 = 1_000_000.0;
        /// small propagation round-trip time (0.4ms): the propagation BDP `bw*prop` = 400 bytes is
        /// under one packet ("sub-packet BDP"). The measured clean min-RTT is `prop + MSS/BW`
        /// (one packet serializes through the bottleneck), so the model BDP lands near a single
        /// packet and the cruise budget `2*BDP` stays below the 4-packet `MinPipeCwnd`.
        const PROP_NS: u64 = 400_000;
        const FWD_NS: u64 = PROP_NS / 2;
        const RET_NS: u64 = PROP_NS / 2;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Seed the probe RNG so the PROBE_BW bw-probe wait (hence the cruise sojourn length) is
        // deterministic and the pair-count target below is not flaky.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(PROP_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Delayed-ACK receiver is off until PROBE_CRUISE; before that one ACK per packet, as in
        // probe_bw_exits_probe_down_to_probe_cruise_on_inflight.
        let mut delayed_on = false;
        // Packet number of the first packet of a pair still waiting for its partner (the
        // "every other packet" hold). When the partner is sent, both are stamped with the
        // partner's (later) arrival so they share one ACK instant.
        let mut pending_first: Option<u64> = None;

        // Captured at the first PROBE_CRUISE ack (plain receiver).
        let mut cruise_capture: Option<(u64, u64, u64, f64, f64)> = None;

        // Delayed-phase signals, asserted after the loop.
        // Largest ACK event size (packets acked at one instant) on the delayed path.
        let mut max_burst: usize = 0;
        // Number of ACK events that covered exactly a pair (the every-other-packet policy).
        let mut pair_events: usize = 0;
        // C.cwnd never dropped below the 4-packet floor on any delayed ack.
        let mut cwnd_floor_held = true;
        // Bytes delivered, and the first/last delivery instant, while in the delayed phase, for
        // the achieved-throughput (no-stall) check.
        let mut delayed_delivered: u64 = 0;
        let mut delayed_first_ns: Option<u64> = None;
        let mut delayed_last_ns: u64 = 0;

        for _ in 0..3_000_000 {
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            let next_ack = flight.front().map(|p| p.ack_ns);
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let arrival_ns = finish + RET_NS;

                // Delayed-ACK ("every other packet") pairing, assigned at send time so a pair
                // shares one ACK instant without stalling paced sends in between: the first of a
                // pair is provisionally stamped with its own arrival, then lifted to the second's
                // (later) arrival when the partner is sent; both then release together. Off the
                // delayed path each packet acks on its own arrival.
                let ack_ns = if delayed_on {
                    if let Some(first_pn) = pending_first.take() {
                        // second of the pair: lift the held first to this (later) arrival
                        for p in flight.iter_mut() {
                            if p.pn == first_pn {
                                p.ack_ns = arrival_ns;
                            }
                        }
                        arrival_ns
                    } else {
                        pending_first = Some(pn);
                        arrival_ns
                    }
                } else {
                    arrival_ns
                };

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(first) = flight.pop_front() {
                // Gather every packet sharing this release instant: a delayed-ACK pair carries
                // one ACK instant (equal ack_ns), so both release together; off the delayed path
                // each ack_ns is unique and the burst degenerates to a single packet.
                let burst_ack_ns = first.ack_ns;
                let mut burst = vec![first];
                while flight.front().is_some_and(|p| p.ack_ns == burst_ack_ns) {
                    burst.push(flight.pop_front().unwrap());
                }
                now_ns = now_ns.max(burst_ack_ns);

                let largest_pn = burst.iter().map(|p| p.pn).max().unwrap();
                for p in &burst {
                    inflight -= MSS;
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                }
                bbr.on_end_acks(at(now_ns), inflight, false, Some(largest_pn));

                let in_cruise = bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Cruise);

                // First cruise ack (plain receiver): capture the model state, then turn the
                // receiver delayed for the rest of the run.
                if in_cruise && cruise_capture.is_none() {
                    cruise_capture = Some((
                        bbr.bdp,
                        bbr.cwnd,
                        bbr.min_pipe_cwnd,
                        bbr.pacing_rate,
                        bbr.default_cwnd_gain,
                    ));
                    delayed_on = true;
                    continue;
                }

                if delayed_on {
                    // Leaving PROBE_CRUISE ends the measured window (a fresh bw-probe would lift
                    // cwnd above the floor); stop once we've gathered enough pairs.
                    if !in_cruise {
                        break;
                    }
                    max_burst = max_burst.max(burst.len());
                    if burst.len() == 2 {
                        pair_events += 1;
                    }
                    // The floor is a lower bound; delayed (paired) ACKs read as ACK aggregation,
                    // so extra_acked may lift cwnd above it (as in A.13), but never below.
                    if bbr.cwnd < bbr.min_pipe_cwnd {
                        cwnd_floor_held = false;
                    }
                    delayed_delivered += burst.len() as u64 * MSS;
                    delayed_first_ns.get_or_insert(now_ns);
                    delayed_last_ns = now_ns;

                    // Cap well above one cruise sojourn; in practice the loop exits earlier when
                    // the flow leaves PROBE_CRUISE (the `!in_cruise` break above).
                    if pair_events >= 40 {
                        break;
                    }
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let (bdp, cwnd, min_pipe_cwnd, pacing_rate, cwnd_gain) =
            cruise_capture.expect("flow never reached PROBE_CRUISE");

        // The model budget was genuinely sub-floor: a very low, near-single-packet BDP whose
        // cruise inflight target (cwnd_gain*BDP) sits below the 4-packet MinPipeCwnd.
        assert!(bdp > 0, "BDP should be defined once min-RTT is known");
        assert!(
            bdp <= 2 * MSS,
            "expected a sub-two-packet BDP on this slow link, got {bdp} ({} packets)",
            bdp as f64 / MSS as f64
        );
        assert!(
            (cwnd_gain * bdp as f64) < min_pipe_cwnd as f64,
            "model cruise budget cwnd_gain*BDP ({}) should be below MinPipeCwnd ({min_pipe_cwnd}) \
             for the floor to bind",
            cwnd_gain * bdp as f64
        );
        // MinPipeCwnd is 4 * SMSS.
        assert_eq!(min_pipe_cwnd, 4 * MSS, "MinPipeCwnd should be 4 packets");
        // The floor, not the tiny model budget, governs C.cwnd.
        assert_eq!(
            cwnd, min_pipe_cwnd,
            "C.cwnd should sit at the MinPipeCwnd floor on a sub-packet BDP"
        );
        // Pacing still tracks the low link bandwidth (cruise pacing_gain = 1, 1% margin).
        let pacing_err = (pacing_rate - BW).abs() / BW;
        assert!(
            pacing_err < 0.05,
            "pacing_rate {pacing_rate} should match low link BW {BW} (rel err {pacing_err})"
        );

        // The delayed-ACK receiver was genuinely exercised: ACK events covered pairs.
        assert!(
            max_burst == 2 && pair_events >= 10,
            "expected the every-other-packet receiver to produce ACK pairs \
             (max_burst {max_burst}, pair_events {pair_events})"
        );
        // C.cwnd never dropped below the 4-packet floor throughout the delayed phase.
        assert!(
            cwnd_floor_held,
            "C.cwnd should never drop below the MinPipeCwnd floor during the delayed-ACK phase"
        );
        // No stall: with 4 packets outstanding a pair is always forming, so the bottleneck never
        // idled waiting on a held ACK: achieved throughput stayed at the link rate. A stall
        // (as a sub-floor cwnd would cause) would collapse this far below BW.
        let first_ns = delayed_first_ns.expect("no delayed-phase acks gathered");
        let elapsed_s = (delayed_last_ns - first_ns) as f64 / 1e9;
        assert!(elapsed_s > 0.0, "delayed phase had no elapsed time");
        let throughput = delayed_delivered as f64 / elapsed_s;
        let throughput_err = (throughput - BW).abs() / BW;
        assert!(
            throughput_err < 0.10,
            "delayed-ACK throughput {throughput} should hold at link BW {BW} \
             (rel err {throughput_err}); a stalled pipeline would fall well below"
        );
    }

    /// A.15: Increasing bandwidth 10x and ensuring full bandwidth is reached.
    /// equivalent to BBRRaiseInflightLongtermSlope / BBRProbeInflightLongtermUpward:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    ///
    /// After PROBE_BW is reached at a low link rate, the bottleneck bandwidth jumps 10x. In
    /// PROBE_UP BBR grows `inflight_longterm` with an exponentially increasing per-round step so
    /// it rediscovers a much larger BDP in O(log(BDP)) round trips rather than linearly.
    ///
    /// The step doubling comes from `raise_inflight_long_term_slope`, called once per round-start
    /// while probing up: `growth_this_round = SMSS << bw_probe_up_rounds` and `bw_probe_up_rounds`
    /// increments each round, so the unit of growth doubles every round. `probe_up_cnt` (bytes to
    /// ack per +1 byte of `inflight_longterm`) is set to `cwnd / growth_this_round`, so over one
    /// round (~cwnd bytes acked) `inflight_longterm` climbs by ~`growth_this_round`, a per-round
    /// increment that doubles each round.
    ///
    /// The growth path only engages when the flow is genuinely cwnd-limited. That signal is
    /// spec-defined as connection-provided (`C.is_cwnd_limited`), so the harness reports it exactly
    /// as the connection layer does: calling `on_cwnd_limited` whenever a send is blocked by the
    /// window rather than by pacing.
    ///
    /// A bespoke single-bottleneck FIFO loop (bandwidth changes mid-flight, which the shared `Sim`
    /// can't express; cf. A.12/A.13/A.14, which also drive the path directly) with an always-
    /// backlogged, paced sender. In PROBE_UP the pacing gain (1.25) drives sends above the delivery
    /// rate, so the flow rides at cwnd (cwnd-limited) and the 25% surplus probes for more bandwidth.
    ///  1. `BW_LO` = 10 Mbit/s. Ramp cleanly to `BW_LO` in PROBE_BW, then a brief 1-in-`LOSS_PERIOD`
    ///     loss seeds a finite `inflight_longterm` (a PROBE_UP loss runs `handle_inflight_too_high`);
    ///     the loss is switched off the instant it fires. Only a finite `inflight_longterm` gives the
    ///     exponential slope a base to grow from.
    ///  2. Jump the bottleneck rate 10x (`BW_HI` = 100 Mbit/s). PROBE_BW cycles into PROBE_UP, where
    ///     `inflight_longterm` is grown back up. Record it at each PROBE_UP round-start; run until
    ///     `max_bw` reaches `BW_HI`.
    ///
    /// Asserts:
    ///  - at the bump the flow was in the low-rate regime (`max_bw` well below `BW_HI`);
    ///  - the additive step added to `inflight_longterm` doubles each round trip: `bw_probe_up_rounds`
    ///    (the `SMSS << bw_probe_up_rounds` slope) advances once per cwnd-limited round, and the
    ///    per-round `inflight_longterm` increment grows geometrically (a sustained ~2x run);
    ///  - the full 100 Mbit/s is rediscovered (`max_bw` >= 97% of `BW_HI`) within a small,
    ///    O(log(BDP)) number of PROBE_UP round trips.
    #[test]
    fn probe_up_rediscovers_full_bw_after_10x_increase() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        /// low link rate before the jump: 10 Mbit/s in bytes/sec
        const BW_LO: f64 = 1_250_000.0;
        /// high link rate after the jump: 100 Mbit/s in bytes/sec (10x)
        const BW_HI: f64 = 12_500_000.0;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// drop 1 in every `LOSS_PERIOD` packets during the low-rate PROBE_BW phase, until the
        /// first loss taken in PROBE_UP drives `handle_inflight_too_high`. That is what pulls
        /// `inflight_longterm` down from its `u64::MAX` init to a finite value; only once it is
        /// finite does the exponential-slope machinery (`raise_inflight_long_term_slope`) have a
        /// base to grow. The loss is switched off the instant it fires (see `loss_active`), so the
        /// post-jump probing sees a clean, loss-free 100 Mbit/s link.
        const LOSS_PERIOD: u64 = 25;

        // Seed the probe RNG so the PROBE_BW cycle timing (hence when PROBE_UP is entered) is
        // deterministic.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            // time this packet resolves: its ACK arrival, or (for a seeded drop) the instant its
            // loss is detected.
            event_ns: u64,
            lost: bool,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // bottleneck serialization time for one MSS-sized packet; lowered 10x at the bump.
        let mut btl_service_ns: u64 = (MSS as f64 / BW_LO * 1e9).round() as u64;
        // The 10x jump fires once PROBE_BW has been reached AND inflight_longterm is finite (the
        // seeding loss has set it). Only then does the exponential-slope machinery have a base.
        let mut bumped = false;
        // Low-rate seeding loss: off until the flow has ramped cleanly to BW_LO in PROBE_BW, then
        // on until inflight_longterm is first set finite (so it is seeded from a healthy operating
        // point ~BDP_LO rather than a loss-depressed one).
        let mut loss_active = false;
        // max_bw captured at the bump (the low-rate operating point) and the round it happened.
        let mut bump_max_bw = 0.0f64;
        let mut bump_round: u64 = 0;
        // Round the first post-bump PROBE_UP began, for the O(log) discovery bound.
        let mut first_up_round: Option<u64> = None;
        // (inflight_longterm, bw_probe_up_rounds) at each post-bump PROBE_UP round-start.
        let mut up_rounds: Vec<(u64, u32)> = Vec::new();
        // PROBE_UP rounds from first probe to rediscovering the full BW_HI.
        let mut discover_rounds: Option<u64> = None;

        for _ in 0..5_000_000 {
            let cwnd = bbr.window();
            // Always-backlogged, paced sender: it offers data continuously and is paced at BBR's
            // chosen rate (in PROBE_UP that is 1.25x the delivery rate, the probe that drives the
            // bandwidth search). Whenever the congestion window (not pacing) is what stops the
            // next send, report the cwnd-blocked signal exactly as the connection layer does.
            let can_send = inflight + MSS <= cwnd;
            if !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.event_ns);
            let do_send = can_send && next_ack.is_none_or(|ev| next_send_ns <= ev);

            if do_send {
                let send_ns = now_ns.max(next_send_ns);
                now_ns = send_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let event_ns = finish + RET_NS;

                // Low-rate loss to seed a finite inflight_longterm: drop 1-in-LOSS_PERIOD only
                // while in PROBE_BW and inflight_longterm is still unset. A drop taken in PROBE_UP
                // runs handle_inflight_too_high, which sets inflight_longterm and stops the loss.
                let lost = loss_active
                    && matches!(bbr.state, BbrState::ProbeBw(_))
                    && pn % LOSS_PERIOD == LOSS_PERIOD - 1;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    event_ns,
                    lost,
                });
                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.event_ns);
                inflight -= MSS;
                if p.lost {
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                    bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
                }

                // Turn the seeding loss on once cleanly ramped to BW_LO, off the instant
                // inflight_longterm is set finite.
                if !bumped && matches!(bbr.state, BbrState::ProbeBw(_)) && bbr.max_bw >= 0.9 * BW_LO
                {
                    loss_active = true;
                }
                if bbr.inflight_longterm != u64::MAX {
                    loss_active = false;
                }

                // Phase 1 -> 2: once settled in PROBE_BW at the low rate (max_bw near BW_LO) with a
                // finite inflight_longterm (a low-rate PROBE_UP overshoot has hit the buffer), jump
                // the link 10x. Only a finite inflight_longterm gives the exponential slope a base.
                if !bumped
                    && matches!(bbr.state, BbrState::ProbeBw(_))
                    && bbr.inflight_longterm != u64::MAX
                {
                    bumped = true;
                    bump_max_bw = bbr.max_bw;
                    bump_round = bbr.round_count;
                    up_rounds.push((bbr.inflight_longterm, bbr.bw_probe_up_rounds));
                    btl_service_ns = (MSS as f64 / BW_HI * 1e9).round() as u64;
                }

                // Record (inflight_longterm, bw_probe_up_rounds) once per PROBE_UP round-start after
                // the bump, and the round the first post-bump PROBE_UP began.
                if bumped && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) && bbr.round_start
                {
                    first_up_round.get_or_insert(bbr.round_count);
                    up_rounds.push((bbr.inflight_longterm, bbr.bw_probe_up_rounds));
                }

                // Full BW_HI rediscovered.
                if bumped && bbr.max_bw >= 0.97 * BW_HI {
                    discover_rounds = Some(bbr.round_count - first_up_round.unwrap_or(bump_round));
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // The flow was jumped 10x while genuinely in the low-rate regime (well below BW_HI).
        assert!(
            bumped,
            "flow never reached PROBE_BW with a finite inflight_longterm to bump"
        );
        assert!(
            bump_max_bw > 0.0 && bump_max_bw < 0.3 * BW_HI,
            "at the bump the flow should be in the low-rate regime, got max_bw {bump_max_bw}"
        );

        // The full 100 Mbit/s was discovered, and within a small, O(log(BDP)) number of PROBE_UP
        // round trips (BDP_HI is ~1041 packets, log2 ~= 10; the bound leaves generous headroom for
        // constant factors and the rounds where the paced sender briefly wasn't cwnd-limited).
        let discover_rounds = discover_rounds.expect("BBR never rediscovered the full 100 Mbit/s");
        assert!(
            discover_rounds <= 25,
            "expected O(log(BDP)) PROBE_UP rounds to rediscover BW_HI, took {discover_rounds}"
        );

        // The additive step added to inflight_longterm doubles each round trip: bw_probe_up_rounds
        // is raised once per cwnd-limited round (the `SMSS << bw_probe_up_rounds` slope), and the
        // per-round inflight_longterm increment grows geometrically as a result.
        let max_probe_up_rounds = up_rounds.iter().map(|&(_, r)| r).max().unwrap_or(0);
        assert!(
            max_probe_up_rounds >= 6,
            "the slope should be raised each cwnd-limited round; bw_probe_up_rounds only reached {max_probe_up_rounds}"
        );

        // Per-round inflight_longterm increments (over the rounds where growth actually occurred).
        let steps: Vec<u64> = up_rounds
            .windows(2)
            .map(|w| w[1].0.saturating_sub(w[0].0))
            .filter(|&d| d > 0)
            .collect();
        // Find the longest run of consecutive increments that each at least ~1.6x the previous:
        // the exponential doubling (a linear ramp would hold the step constant, ratio ~1).
        let mut best_run = 1usize;
        let mut run = 1usize;
        for w in steps.windows(2) {
            if w[1] as f64 >= 1.6 * w[0] as f64 {
                run += 1;
                best_run = best_run.max(run);
            } else {
                run = 1;
            }
        }
        assert!(
            best_run >= 4,
            "expected a sustained per-round doubling of the inflight_longterm step, \
             longest ~2x run was {best_run} over steps {steps:?}"
        );
    }

    /// A.16: Decreasing bandwidth 10x and ensuring max bandwidth adapts down.
    /// Exercises the short-term loss response (`loss_lower_bounds`) and the windowed `max_bw`
    /// filter expiry (`advance_max_bw_filter`, `BBR.MaxBwFilterLen`):
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.10>
    ///
    /// After PROBE_BW is reached at a high link rate, the bottleneck bandwidth drops 10x. The
    /// flow is still carrying ~BDP of the *old* (high) rate, so once the link slows the standing
    /// queue overflows the bottleneck buffer and packets are lost. Two things must happen:
    ///
    ///  1. The short-term model reacts within the current probe cycle. A loss round runs
    ///     `loss_lower_bounds`, decaying `BBR.bw_shortterm` by `BETA` (0.7) toward the freshly
    ///     measured `bw_latest`. Because `bw = min(max_bw, bw_shortterm)`, this throttles
    ///     pacing/cwnd immediately, long before the long-term `max_bw` moves. (Each PROBE_BW
    ///     refill resets `bw_shortterm` and re-seeds it from the still-stale-high `max_bw`, so per
    ///     cycle it only steps down ~one `BETA`; the full collapse to the new rate is the filter's
    ///     job, below.)
    ///  2. The long-term `max_bw` is a max filter over `RS.delivery_rate` keyed on `cycle_count`
    ///     with a window of `MAX_BW_FILTER_LEN` (2). The stale high sample only expires once
    ///     `cycle_count` has advanced past the window, i.e. after ~2 PROBE_BW cycles
    ///     (`advance_max_bw_filter` ticks once per cycle at `ProbeStopping`). Then `get_max()`
    ///     returns the recent ~low-rate samples and `max_bw` drops to the new 10 Mbit/s limit.
    ///
    /// Same bespoke single-bottleneck FIFO loop as A.15 (bandwidth changes mid-flight, which the
    /// shared `Sim` can't express), inverted: start at 100 Mbit/s, then cut to 10 Mbit/s. A finite
    /// bottleneck buffer (~1 BDP of the high rate) makes the 10x cut produce real tail-drop loss:
    /// the flow runs cleanly at 100 Mbit/s but overflows the moment the link slows.
    ///  1. `BW_HI` = 100 Mbit/s. Ramp cleanly into PROBE_BW with `max_bw` ~= `BW_HI`.
    ///  2. Cut the bottleneck rate 10x (`BW_LO` = 10 Mbit/s). The overflowing queue drives loss;
    ///     track the minimum `bw_shortterm` seen afterwards and the `cycle_count` at which `max_bw`
    ///     first collapses to the new rate.
    ///
    /// Asserts:
    ///  - at the cut the flow was in the high-rate regime (`max_bw` ~= `BW_HI`);
    ///  - `bw_shortterm` adapts down rapidly after the cut: its post-cut minimum falls at least one
    ///    `BETA` step below `BW_HI`, throttling the flow within the cycle;
    ///  - `max_bw` collapses to the new `BW_LO` (within ~15%) once the filter window expires, and
    ///    does so within a small number of PROBE_BW cycles (`MAX_BW_FILTER_LEN` + headroom).
    #[test]
    fn max_bw_adapts_down_after_10x_decrease() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        /// high link rate before the cut: 100 Mbit/s in bytes/sec
        const BW_HI: f64 = 12_500_000.0;
        /// low link rate after the cut: 10 Mbit/s in bytes/sec (1/10th)
        const BW_LO: f64 = 1_250_000.0;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// bottleneck buffer, in bytes. Sized at ~1 BDP of the high rate so the 100 Mbit/s flow
        /// runs loss-free (BBR holds ~1 BDP inflight with only a small standing queue), but the
        /// instant the rate is cut 10x the ~1 BDP still in flight drains at a tenth the rate: the
        /// queue overflows this buffer and packets are tail-dropped. That loss is the signal that
        /// drives `bw_shortterm` down and, once the max-bw filter window expires, `max_bw`.
        const BUFFER_BYTES: f64 = BW_HI * (RTT_NS as f64 / 1e9);

        // Seed the probe RNG so the PROBE_BW cycle timing is deterministic.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            // time this packet resolves: its ACK arrival, or (for a tail drop) the instant its
            // loss is detected.
            event_ns: u64,
            lost: bool,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // bottleneck serialization time for one MSS-sized packet; raised 10x at the cut.
        let mut btl_service_ns: u64 = (MSS as f64 / BW_HI * 1e9).round() as u64;
        // The 10x cut fires once PROBE_BW has been reached at the high rate (max_bw ~= BW_HI).
        let mut cut = false;
        // max_bw / cycle_count captured at the cut (the high-rate operating point).
        let mut cut_max_bw = 0.0f64;
        let mut cut_cycle: u64 = 0;
        // Minimum finite bw_shortterm seen after the cut: the short-term model's rapid descent.
        let mut min_shortterm_after = f64::INFINITY;
        // PROBE_BW cycles (cycle_count advances) elapsed when max_bw first collapses to ~BW_LO.
        let mut adapt_cycles: Option<u64> = None;

        for _ in 0..5_000_000 {
            let cwnd = bbr.window();
            // Always-backlogged, paced sender, as in A.15. Report the cwnd-blocked signal exactly
            // as the connection layer does whenever the window (not pacing) stops the next send.
            let can_send = inflight + MSS <= cwnd;
            if !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.event_ns);
            let do_send = can_send && next_ack.is_none_or(|ev| next_send_ns <= ev);

            if do_send {
                let send_ns = now_ns.max(next_send_ns);
                now_ns = send_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                // Bytes already queued behind the bottleneck when this packet arrives. A tail drop
                // occurs if the standing queue already exceeds the buffer.
                let queue_bytes = service_start.saturating_sub(arrival) as f64
                    / btl_service_ns as f64
                    * MSS as f64;
                let lost = queue_bytes > BUFFER_BYTES;

                let event_ns = if lost {
                    // Dropped: never served, so the bottleneck is not advanced. Its loss is detected
                    // roughly when the packets around it would have been served/acked.
                    service_start + RET_NS
                } else {
                    let finish = service_start + btl_service_ns;
                    btl_free_ns = finish;
                    finish + RET_NS
                };

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    event_ns,
                    lost,
                });
                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.event_ns);
                inflight -= MSS;
                if p.lost {
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                    bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
                }

                // Phase 1 -> 2: once settled in PROBE_BW at the high rate (max_bw ~= BW_HI), cut the
                // link 10x. The ~1 BDP still in flight now overflows the buffer -> loss.
                if !cut && matches!(bbr.state, BbrState::ProbeBw(_)) && bbr.max_bw >= 0.9 * BW_HI {
                    cut = true;
                    cut_max_bw = bbr.max_bw;
                    cut_cycle = bbr.cycle_count;
                    btl_service_ns = (MSS as f64 / BW_LO * 1e9).round() as u64;
                }

                // After the cut, watch the short-term model descend and the long-term filter expire.
                if cut {
                    if bbr.bw_shortterm.is_finite() {
                        min_shortterm_after = min_shortterm_after.min(bbr.bw_shortterm);
                    }
                    // max_bw collapses to the new rate once the stale high sample ages out of the
                    // MAX_BW_FILTER_LEN-wide window (keyed on cycle_count).
                    if adapt_cycles.is_none() && bbr.max_bw <= 1.15 * BW_LO {
                        adapt_cycles = Some(bbr.cycle_count - cut_cycle);
                        break;
                    }
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // The link was cut 10x while genuinely in the high-rate regime (max_bw ~= BW_HI).
        assert!(cut, "flow never reached PROBE_BW at the high rate to cut");
        assert!(
            cut_max_bw >= 0.9 * BW_HI,
            "at the cut the flow should be in the high-rate regime, got max_bw {cut_max_bw}"
        );

        // The short-term model reacted to the loss immediately: bw_shortterm was pulled below the
        // high operating point by at least one BETA (0.7) decay of loss_lower_bounds. This is the
        // *rapid* response: `bw = min(max_bw, bw_shortterm)` so this throttles sending within the
        // current cycle, long before max_bw moves. It only steps down ~one BETA per cycle because
        // each PROBE_BW refill resets bw_shortterm to INFINITY and re-seeds it from the (still
        // stale-high) max_bw; the deep collapse all the way to BW_LO is delivered by the max_bw
        // filter expiry below, not by bw_shortterm alone.
        assert!(
            min_shortterm_after <= 0.75 * BW_HI,
            "bw_shortterm should adapt down (>=1 BETA step) after the cut; min seen {min_shortterm_after}"
        );

        // max_bw collapsed to the new 10 Mbit/s limit (matching the path delivery rate) once the
        // filter window expired, and within a small number of PROBE_BW cycles (MAX_BW_FILTER_LEN
        // is 2; the bound leaves headroom for the cycle in which the cut was recorded).
        let adapt_cycles = adapt_cycles.expect("max_bw never collapsed to the new BW_LO");
        assert!(
            adapt_cycles <= (MAX_BW_FILTER_LEN as u64) + 2,
            "expected max_bw to adapt within ~MAX_BW_FILTER_LEN PROBE_BW cycles, took {adapt_cycles}"
        );
        // The break fired on max_bw <= 1.15*BW_LO, so only the lower bound informs here:
        // confirm the estimate collapsed to (not below) the new rate.
        assert!(
            bbr.max_bw >= 0.85 * BW_LO,
            "max_bw should track the new path delivery rate BW_LO, got {}",
            bbr.max_bw
        );
    }

    /// A.17: Handling token bucket policers.
    /// Exercises the short-term loss response (`init_lower_bounds` + `loss_lower_bounds`, driven from
    /// `adapt_lower_bounds_from_congestion`) settling the flow to a token-bucket policer's token rate:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    ///
    /// A token-bucket policer is not a queue. It holds a bucket of `BURST` bytes that refills at the
    /// token rate, admits a packet only if a token is available, and *drops* (never buffers) any
    /// packet that arrives with the bucket empty. This is the classic BBR failure mode: during the
    /// initial burst every packet passes at line rate, so BBR's `max_bw` filter latches onto a
    /// delivery rate well above the token rate; once the burst is spent the policer starts dropping,
    /// and (because the policer adds no delay, so RTT never grows and there is no queueing signal)
    /// only the short-term model's loss response can pull the flow back down to the token rate.
    ///
    ///  1. The short-term model reacts within the PROBE_BW cruise/down cycle. A loss round there runs
    ///     `init_lower_bounds` (seeding `bw_shortterm`/`inflight_shortterm` finite from the current
    ///     `max_bw`/`cwnd`) then `loss_lower_bounds`, decaying `bw_shortterm` by `BETA` toward the
    ///     measured `bw_latest` and `inflight_shortterm` by `BETA` toward `inflight_latest`. Because
    ///     `bw = min(max_bw, bw_shortterm)` and the window is capped at `inflight_shortterm`, this
    ///     throttles pacing and inflight even though the stale-high `max_bw` never moves.
    ///  2. Repeated across cycles the short-term bounds settle the flow so its send rate matches the
    ///     token rate: the bucket stays near empty but drops become rare rather than continuous.
    ///
    /// Bespoke single-bottleneck loop in the spirit of A.15/A.16, with the FIFO buffer replaced by a
    /// token bucket (refill at `TOKEN_RATE`, cap `BURST`, no queue). A packet passes iff a token is
    /// available on arrival, otherwise it is dropped with only propagation delay (no serialization,
    /// no queueing), so RTT is constant and loss is the only congestion signal. Run for a fixed
    /// simulated duration; the last `WINDOW_NS` is the stable-point measurement window.
    ///
    /// Asserts:
    ///  - the flow reaches PROBE_BW (past STARTUP) with a burst-inflated `max_bw` above the token rate;
    ///  - once the burst is exhausted and the policer drops, the short-term model engages:
    ///    `bw_shortterm` drops below the stale-high `max_bw` and `inflight_shortterm` becomes finite;
    ///  - the flow settles to a stable operating point conforming to the token rate: over the late
    ///    window the delivered goodput tracks `TOKEN_RATE` and the loss rate stays low (no excessive
    ///    continuous loss).
    #[test]
    fn probe_bw_settles_to_token_rate_under_policer() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        /// policer token (fill) rate: 10 Mbit/s in bytes/sec
        const TOKEN_RATE: f64 = 1_250_000.0;
        /// initial (and maximum) bucket depth in bytes. ~2 BDP of the token rate: big enough that
        /// STARTUP's ramp passes cleanly (the flow reaches PROBE_BW with a healthy, burst-inflated
        /// bw estimate), small enough that continued over-sending in PROBE_BW spends it and exposes
        /// the policer.
        const BURST: f64 = 2.0 * TOKEN_RATE * (RTT_NS as f64 / 1e9);
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// total simulated time and the trailing stable-point measurement window.
        const TOTAL_NS: u64 = 20_000_000_000;
        const WINDOW_NS: u64 = 5_000_000_000;

        // Seed the probe RNG so the PROBE_BW cycle timing is deterministic.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            // time this packet resolves: its ACK arrival, or (for a policed drop) the instant its
            // loss is detected.
            event_ns: u64,
            lost: bool,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Token bucket: starts full, refills at TOKEN_RATE up to BURST, drained MSS per admitted
        // packet. Advanced by packet arrival time (send_ns + FWD_NS), which is monotonic in send_ns.
        let mut tokens: f64 = BURST;
        let mut last_refill_ns: u64 = 0;

        let mut reached_probe_bw = false;
        // max_bw captured when PROBE_BW is first reached (the burst-inflated operating point).
        let mut max_bw_at_probe_bw = 0.0f64;
        // short-term model signals after the burst first drives loss in PROBE_BW.
        let mut min_shortterm_after = f64::INFINITY;
        let mut inflight_shortterm_engaged = false;

        // late-window goodput/loss accounting.
        let mut win_start_ns: Option<u64> = None;
        let mut win_last_ns: u64 = 0;
        let mut win_acked: u64 = 0;
        let mut win_lost: u64 = 0;

        for _ in 0..50_000_000 {
            if now_ns >= TOTAL_NS {
                break;
            }
            let cwnd = bbr.window();
            // Always-backlogged, paced sender, as in A.15/A.16. Report the cwnd-blocked signal
            // exactly as the connection layer does whenever the window (not pacing) stops the send.
            let can_send = inflight + MSS <= cwnd;
            if !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.event_ns);
            let do_send = can_send && next_ack.is_none_or(|ev| next_send_ns <= ev);

            if do_send {
                let send_ns = now_ns.max(next_send_ns);
                now_ns = send_ns;
                let arrival = send_ns + FWD_NS;

                // Refill the bucket up to its arrival time, cap at BURST, then admit-or-drop.
                tokens = (tokens + TOKEN_RATE * (arrival - last_refill_ns) as f64 / 1e9).min(BURST);
                last_refill_ns = arrival;
                let lost = tokens < MSS as f64;
                if !lost {
                    tokens -= MSS as f64;
                }
                // Policer adds no queueing/serialization delay: passed packets are acked, dropped
                // packets are detected, purely after propagation.
                let event_ns = arrival + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    event_ns,
                    lost,
                });
                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.event_ns);
                inflight -= MSS;
                if p.lost {
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                    bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
                }

                if !reached_probe_bw && matches!(bbr.state, BbrState::ProbeBw(_)) {
                    reached_probe_bw = true;
                    max_bw_at_probe_bw = bbr.max_bw;
                }
                // After PROBE_BW, watch the short-term model react to the policer's drops.
                if reached_probe_bw {
                    if bbr.bw_shortterm.is_finite() {
                        min_shortterm_after = min_shortterm_after.min(bbr.bw_shortterm);
                    }
                    if bbr.inflight_shortterm != u64::MAX {
                        inflight_shortterm_engaged = true;
                    }
                }

                // Late-window goodput/loss accounting.
                if now_ns >= TOTAL_NS - WINDOW_NS {
                    win_start_ns.get_or_insert(now_ns);
                    win_last_ns = now_ns;
                    if p.lost {
                        win_lost += MSS;
                    } else {
                        win_acked += MSS;
                    }
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let win_start = win_start_ns.expect("no packets resolved in the measurement window");
        let win_secs = (win_last_ns - win_start) as f64 / 1e9;
        let goodput = win_acked as f64 / win_secs.max(1e-9);
        let loss_rate = win_lost as f64 / (win_acked + win_lost).max(1) as f64;

        // The flow reached PROBE_BW past STARTUP, with a burst-inflated max_bw above the token rate.
        assert!(reached_probe_bw, "flow never reached PROBE_BW");
        assert!(
            max_bw_at_probe_bw > TOKEN_RATE,
            "the burst should inflate max_bw above the token rate on reaching PROBE_BW, got {max_bw_at_probe_bw}"
        );

        // The short-term model engaged on the policer's drops: bw_shortterm fell below the stale-high
        // max_bw (throttling via bw = min(max_bw, bw_shortterm)), and inflight_shortterm went finite
        // (capping the window).
        assert!(
            min_shortterm_after < max_bw_at_probe_bw,
            "bw_shortterm should drop below the stale-high max_bw {max_bw_at_probe_bw}, got {min_shortterm_after}"
        );
        assert!(
            inflight_shortterm_engaged,
            "inflight_shortterm should become finite when the policer drops packets"
        );

        // goodput tracks TOKEN_RATE, loss stays low. The lower bound is load-bearing (BBR
        // keeps the pipe full); the upper bound is the policer's own cap, so it corroborates
        // rather than tests BBR.
        assert!(
            (0.75 * TOKEN_RATE..=1.25 * TOKEN_RATE).contains(&goodput),
            "late-window goodput should track the token rate, got {goodput} ({:.2}x)",
            goodput / TOKEN_RATE
        );
        assert!(
            loss_rate <= 0.10,
            "policer loss should settle to a low rate, got {loss_rate}"
        );
    }

    /// A.18: Handling spurious Fast Recovery (the loss-undo path).
    /// Exercises `save_state_upon_loss` (BBRSaveStateUponLoss) and `on_spurious_congestion_event`
    /// (BBRHandleSpuriousLossDetection):
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11>
    ///
    /// Packet reordering (later packets delivered while earlier ones sit apparently missing) makes
    /// the transport's loss detector declare a Fast Recovery that never really happened: the "lost"
    /// packets were only reordered, and arrive (or are DSACK'd) shortly after. BBR guards against this
    /// by snapshotting the pre-loss model on every declared loss (`note_loss` -> `save_state_upon_loss`)
    /// and restoring it if the transport later reports the episode spurious (in QUIC, the original
    /// packet's delivery is confirmed by packet number / a DSACK-equivalent, so the retransmission was
    /// spurious). The connection layer signals this via `Controller::on_spurious_congestion_event`.
    ///
    /// The reordering is introduced while the flow is in PROBE_UP:
    ///  1. Reach PROBE_UP loss-free, so the short-term model is at its reset sentinels
    ///     (`bw_shortterm` = +inf, `inflight_shortterm` = u64::MAX) and `inflight_longterm` is still
    ///     u64::MAX (only a loss makes it finite). Snapshot those.
    ///  2. Declare the oldest still-in-flight packets lost, a reordering picture: later packets are
    ///     being delivered while these earlier ones look missing. Feed them one at a time until the
    ///     accumulated loss trips `is_inflight_too_high` (> `LOSS_THRESH` of tx_in_flight): that runs
    ///     `handle_inflight_too_high`, which clamps `inflight_longterm` to a finite value and moves
    ///     PROBE_UP -> PROBE_DOWN. Stop declaring losses the instant the state leaves PROBE_UP, so the
    ///     last `note_loss` (which runs before the transition inside the same call) saved
    ///     `undo_state` = PROBE_UP.
    ///  3. The transport detects the loss was spurious -> `on_spurious_congestion_event`.
    ///
    /// Asserts:
    ///  - `save_state_upon_loss` captured the pre-loss PROBE_UP model into the undo fields:
    ///    `undo_state` = PROBE_UP, `undo_bw_shortterm` = +inf, `undo_inflight_shortterm` = u64::MAX,
    ///    `undo_inflight_longterm` = u64::MAX.
    ///  - the spurious Fast Recovery actually moved the flow off PROBE_UP and clamped
    ///    `inflight_longterm` finite.
    ///  - `on_spurious_congestion_event` restored the saved model: `bw_shortterm`/`inflight_shortterm`
    ///    to `max(current, undo)` (their +inf/u64::MAX sentinels) and `inflight_longterm` back to
    ///    u64::MAX, and seamlessly returned the flow to its previous state, PROBE_UP.
    ///
    /// Note on the short-term fields: for a spurious episode that restores to PROBE_UP they are
    /// necessarily at their sentinels. `adapt_lower_bounds_from_congestion` skips PROBE_UP, so no
    /// loss taken in PROBE_UP moves them; and any loss taken *after* the PROBE_UP -> PROBE_DOWN
    /// transition would re-run `note_loss` and overwrite `undo_state` to PROBE_DOWN (losing the
    /// return-to-PROBE_UP). So the meaningful restored quantities here are `inflight_longterm` and the
    /// state; the short-term fields are verified saved and restored at their reset sentinels.
    #[test]
    fn probe_up_restores_state_on_spurious_loss_detection() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        /// bottleneck bandwidth: 10 Mbit/s in bytes/sec. Modest BDP keeps `LOSS_THRESH` (2% of
        /// tx_in_flight) small, so a short reordering burst trips `is_inflight_too_high`.
        const BW: f64 = 1_250_000.0;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;

        // Seed the probe RNG so the PROBE_BW cycle timing (hence when PROBE_UP is entered) is
        // deterministic.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Pre-loss PROBE_UP snapshot, taken the first time the flow is in PROBE_UP,
        // before any reordering is introduced.
        let mut pre: Option<UndoSnapshot> = None;
        // Set once the reordering-induced loss has moved the flow off PROBE_UP; carries the
        // undo snapshot + post-loss state/inflight_longterm for the assertions below.
        let mut episode: Option<LossEpisode> = None;

        for _ in 0..5_000_000 {
            if episode.is_some() {
                break;
            }
            let cwnd = bbr.window();
            // Always-backlogged, paced sender (as in A.15/A.16/A.17): report the cwnd-blocked signal
            // exactly as the connection layer does whenever the window (not pacing) stops the send.
            let can_send = inflight + MSS <= cwnd;
            if !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.ack_ns);
            // Once in PROBE_UP we stop sending and drain the reordering burst out of the queue, so a
            // send is only due while we have not yet snapshotted PROBE_UP.
            let do_send =
                pre.is_none() && can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                let send_ns = now_ns.max(next_send_ns);
                now_ns = send_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });
                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;

                // First time in PROBE_UP: snapshot the pre-loss model, then stop sending and begin
                // introducing reordering on the packets already in flight.
                if pre.is_none() && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    pre = Some((
                        bbr.state,
                        bbr.bw_shortterm,
                        bbr.inflight_shortterm,
                        bbr.inflight_longterm,
                    ));
                }
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;

                // Before PROBE_UP: normal delivery, ramping the flow up.
                // In PROBE_UP: introduce reordering by declaring the oldest still-in-flight packets
                // lost (later packets are being delivered while these look missing). Keep declaring
                // until the accumulated loss trips is_inflight_too_high and the flow leaves PROBE_UP;
                // these declarations are spurious: the packets were only reordered.
                let reordering =
                    pre.is_some() && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up);
                if reordering {
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));

                    // The moment handle_inflight_too_high moved us off PROBE_UP, record the episode:
                    // the undo snapshot save_state_upon_loss captured on this loss, plus the post-loss
                    // state and inflight_longterm. The last note_loss ran while still in PROBE_UP, so
                    // undo_state is PROBE_UP.
                    if bbr.state != BbrState::ProbeBw(ProbeBwSubstate::Up) {
                        episode = Some((
                            (
                                bbr.undo_state,
                                bbr.undo_bw_shortterm,
                                bbr.undo_inflight_shortterm,
                                bbr.undo_inflight_longterm,
                            ),
                            bbr.state,
                            bbr.inflight_longterm,
                        ));
                    }
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                    bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let (pre_state, pre_bw_st, pre_inflight_st, pre_inflight_lt) =
            pre.expect("flow never reached PROBE_UP");
        let ((undo_state, undo_bw_st, undo_inflight_st, undo_inflight_lt), post_state, post_lt) =
            episode.expect("reordering never triggered a Fast Recovery out of PROBE_UP");

        // The pre-loss PROBE_UP model was at its reset sentinels (loss-free ramp).
        assert_eq!(pre_state, BbrState::ProbeBw(ProbeBwSubstate::Up));
        assert_eq!(
            pre_bw_st,
            f64::INFINITY,
            "bw_shortterm should be at its reset sentinel entering PROBE_UP"
        );
        assert_eq!(
            pre_inflight_st,
            u64::MAX,
            "inflight_shortterm should be at its reset sentinel entering PROBE_UP"
        );
        assert_eq!(
            pre_inflight_lt,
            u64::MAX,
            "inflight_longterm should still be unset (u64::MAX) before any loss"
        );

        // save_state_upon_loss captured the pre-loss PROBE_UP model into the undo fields.
        assert_eq!(
            undo_state,
            BbrState::ProbeBw(ProbeBwSubstate::Up),
            "save_state_upon_loss should have saved BBR.state = PROBE_UP"
        );
        assert_eq!(
            undo_bw_st, pre_bw_st,
            "save_state_upon_loss should have saved BBR.bw_shortterm"
        );
        assert_eq!(
            undo_inflight_st, pre_inflight_st,
            "save_state_upon_loss should have saved BBR.inflight_shortterm to undo_inflight_shortterm"
        );
        assert_eq!(
            undo_inflight_lt, pre_inflight_lt,
            "save_state_upon_loss should have saved BBR.inflight_longterm to undo_inflight_longterm"
        );

        // The spurious Fast Recovery actually moved the flow off PROBE_UP (into PROBE_DOWN) and
        // clamped inflight_longterm to a finite value.
        assert_eq!(
            post_state,
            BbrState::ProbeBw(ProbeBwSubstate::Down),
            "the loss should drive PROBE_UP -> PROBE_DOWN via handle_inflight_too_high"
        );
        assert!(
            post_lt < u64::MAX,
            "handle_inflight_too_high should clamp inflight_longterm finite, got u64::MAX"
        );

        // The transport detects the loss was spurious (original packet delivered; the Fast Recovery
        // should never have happened) and reports it.
        bbr.on_spurious_congestion_event();

        // on_spurious_congestion_event restored the saved model and returned to PROBE_UP.
        assert_eq!(
            bbr.state,
            BbrState::ProbeBw(ProbeBwSubstate::Up),
            "on_spurious_congestion_event should seamlessly return the flow to PROBE_UP"
        );
        assert_eq!(
            bbr.inflight_longterm,
            u64::MAX,
            "inflight_longterm should be restored to max(current, undo) = u64::MAX"
        );
        assert_eq!(
            bbr.bw_shortterm,
            f64::INFINITY,
            "bw_shortterm should be restored to max(current, undo) = +inf"
        );
        assert_eq!(
            bbr.inflight_shortterm,
            u64::MAX,
            "inflight_shortterm should be restored to max(current, undo) = u64::MAX"
        );
    }

    /// A.19: Handling spurious RTO Recovery (the loss-undo path, RTO variant).
    /// Exercises `save_state_upon_loss` (BBRSaveStateUponLoss) and `on_spurious_congestion_event`
    /// (BBRHandleSpuriousLossDetection):
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11>
    ///
    /// Where A.18 covers a spurious *Fast* Recovery (later packets keep being delivered while a few
    /// earlier ones look missing), this covers a spurious *RTO* Recovery: acknowledgements stop
    /// arriving entirely, the transport's PTO/RTO timer fires, and the whole outstanding tail is
    /// declared lost in one burst. The tail was not really lost: the ACKs (or the packets) were only
    /// delayed by reordering on the path, so once the delayed acknowledgements arrive (in QUIC the
    /// original packet numbers confirm the delivery, a DSACK-equivalent), the episode is reported
    /// spurious and the model must be rolled back.
    ///
    /// Both recovery kinds reach BBR through the same loss path: the connection layer calls
    /// `on_packet_lost` per timed-out packet, which runs `process_lost_packet` -> `note_loss` ->
    /// `save_state_upon_loss`. (bbr3's `on_congestion_event` only acts on ECN, so a non-ECN RTO /
    /// persistent-congestion batch reaches BBR purely as these per-packet losses; see the trait note
    /// on `on_congestion_event`.) The RTO character here is the *shape* of the loss: a single tail
    /// burst with no interleaved deliveries, i.e. a timeout, not a SACK-driven Fast Recovery.
    ///
    /// The timeout is introduced while the flow is in PROBE_UP:
    ///  1. Reach PROBE_UP loss-free with a full window outstanding, so the short-term model is at its
    ///     reset sentinels (`bw_shortterm` = +inf, `inflight_shortterm` = u64::MAX) and
    ///     `inflight_longterm` is still u64::MAX (only a loss makes it finite). Snapshot those.
    ///  2. Simulate the RTO: stop delivering ACKs and time out the entire outstanding tail, declaring
    ///     the packets lost oldest-first in one burst. Feed them until the accumulated loss trips
    ///     `is_inflight_too_high` (> `LOSS_THRESH` of tx_in_flight): that runs
    ///     `handle_inflight_too_high`, which clamps `inflight_longterm` to a finite value and moves
    ///     PROBE_UP -> PROBE_DOWN. Stop the instant the state leaves PROBE_UP, so the last `note_loss`
    ///     (which runs before the transition inside the same call) saved `undo_state` = PROBE_UP.
    ///  3. The delayed acknowledgements arrive; the transport detects the RTO was spurious ->
    ///     `on_spurious_congestion_event`.
    ///
    /// Asserts:
    ///  - `save_state_upon_loss` captured the pre-loss PROBE_UP model into the undo fields:
    ///    `undo_state` = PROBE_UP, `undo_bw_shortterm` = +inf, `undo_inflight_shortterm` = u64::MAX,
    ///    `undo_inflight_longterm` = u64::MAX.
    ///  - the spurious RTO actually moved the flow off PROBE_UP and clamped `inflight_longterm` finite.
    ///  - `on_spurious_congestion_event` restored the saved model: `bw_shortterm`/`inflight_shortterm`
    ///    to `max(current, undo)` (their +inf/u64::MAX sentinels) and `inflight_longterm` back to
    ///    u64::MAX, and seamlessly returned the flow to its previous state, PROBE_UP.
    ///
    /// Note on the short-term fields: as in A.18, for a spurious episode that restores to PROBE_UP they
    /// are necessarily at their sentinels (`adapt_lower_bounds_from_congestion` skips PROBE_UP, and any
    /// loss taken *after* the PROBE_UP -> PROBE_DOWN transition would overwrite `undo_state`). So the
    /// meaningful restored quantities here are `inflight_longterm` and the state; the short-term fields
    /// are verified saved and restored at their reset sentinels.
    #[test]
    fn probe_up_restores_state_on_spurious_rto_detection() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated propagation round-trip time (100ms), matching A.1
        const RTT_NS: u64 = 100_000_000;
        /// bottleneck bandwidth: 10 Mbit/s in bytes/sec. Modest BDP keeps `LOSS_THRESH` (2% of
        /// tx_in_flight) small, so a short tail burst trips `is_inflight_too_high`.
        const BW: f64 = 1_250_000.0;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;

        // Seed the probe RNG so the PROBE_BW cycle timing (hence when PROBE_UP is entered) is
        // deterministic.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Pre-loss PROBE_UP snapshot, taken the first time the flow is in PROBE_UP,
        // before the RTO is introduced.
        let mut pre: Option<UndoSnapshot> = None;
        // Set once the RTO-induced loss burst has moved the flow off PROBE_UP; carries the
        // undo snapshot + post-loss state/inflight_longterm for the assertions below.
        let mut episode: Option<LossEpisode> = None;

        for _ in 0..5_000_000 {
            if episode.is_some() {
                break;
            }
            let cwnd = bbr.window();
            // Always-backlogged, paced sender (as in A.15/A.16/A.17/A.18): report the cwnd-blocked
            // signal exactly as the connection layer does whenever the window (not pacing) stops the
            // send.
            let can_send = inflight + MSS <= cwnd;
            if !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.ack_ns);
            // Once in PROBE_UP we stop sending: the RTO scenario is a *silence*, no more packets go
            // out and no ACKs come back while the outstanding tail times out. A send is only due while
            // we have not yet snapshotted PROBE_UP.
            let do_send =
                pre.is_none() && can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                let send_ns = now_ns.max(next_send_ns);
                now_ns = send_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });
                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;

                // First time in PROBE_UP: snapshot the pre-loss model, then stop sending so a full
                // window is left outstanding for the RTO to time out.
                if pre.is_none() && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    pre = Some((
                        bbr.state,
                        bbr.bw_shortterm,
                        bbr.inflight_shortterm,
                        bbr.inflight_longterm,
                    ));
                }
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;

                // Before PROBE_UP: normal delivery, ramping the flow up.
                // In PROBE_UP: the RTO has fired, no ACKs are arriving, so the whole outstanding tail
                // times out. Declare the packets lost oldest-first, in one burst with no interleaved
                // deliveries (a timeout, not a Fast Recovery). Keep declaring until the accumulated
                // loss trips is_inflight_too_high and the flow leaves PROBE_UP; these declarations are
                // spurious: the tail was only delayed by reordering, not lost.
                let rto_timeout =
                    pre.is_some() && bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up);
                if rto_timeout {
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));

                    // The moment handle_inflight_too_high moved us off PROBE_UP, record the episode:
                    // the undo snapshot save_state_upon_loss captured on this loss, plus the post-loss
                    // state and inflight_longterm. The last note_loss ran while still in PROBE_UP, so
                    // undo_state is PROBE_UP.
                    if bbr.state != BbrState::ProbeBw(ProbeBwSubstate::Up) {
                        episode = Some((
                            (
                                bbr.undo_state,
                                bbr.undo_bw_shortterm,
                                bbr.undo_inflight_shortterm,
                                bbr.undo_inflight_longterm,
                            ),
                            bbr.state,
                            bbr.inflight_longterm,
                        ));
                    }
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                    bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let (pre_state, pre_bw_st, pre_inflight_st, pre_inflight_lt) =
            pre.expect("flow never reached PROBE_UP");
        let ((undo_state, undo_bw_st, undo_inflight_st, undo_inflight_lt), post_state, post_lt) =
            episode.expect("RTO tail burst never triggered a recovery out of PROBE_UP");

        // The pre-loss PROBE_UP model was at its reset sentinels (loss-free ramp).
        assert_eq!(pre_state, BbrState::ProbeBw(ProbeBwSubstate::Up));
        assert_eq!(
            pre_bw_st,
            f64::INFINITY,
            "bw_shortterm should be at its reset sentinel entering PROBE_UP"
        );
        assert_eq!(
            pre_inflight_st,
            u64::MAX,
            "inflight_shortterm should be at its reset sentinel entering PROBE_UP"
        );
        assert_eq!(
            pre_inflight_lt,
            u64::MAX,
            "inflight_longterm should still be unset (u64::MAX) before any loss"
        );

        // save_state_upon_loss captured the pre-loss PROBE_UP model into the undo fields.
        assert_eq!(
            undo_state,
            BbrState::ProbeBw(ProbeBwSubstate::Up),
            "save_state_upon_loss should have saved BBR.state = PROBE_UP"
        );
        assert_eq!(
            undo_bw_st, pre_bw_st,
            "save_state_upon_loss should have saved BBR.bw_shortterm"
        );
        assert_eq!(
            undo_inflight_st, pre_inflight_st,
            "save_state_upon_loss should have saved BBR.inflight_shortterm to undo_inflight_shortterm"
        );
        assert_eq!(
            undo_inflight_lt, pre_inflight_lt,
            "save_state_upon_loss should have saved BBR.inflight_longterm to undo_inflight_longterm"
        );

        // The spurious RTO actually moved the flow off PROBE_UP (into PROBE_DOWN) and clamped
        // inflight_longterm to a finite value.
        assert_eq!(
            post_state,
            BbrState::ProbeBw(ProbeBwSubstate::Down),
            "the RTO loss should drive PROBE_UP -> PROBE_DOWN via handle_inflight_too_high"
        );
        assert!(
            post_lt < u64::MAX,
            "handle_inflight_too_high should clamp inflight_longterm finite, got u64::MAX"
        );

        // The delayed acknowledgements arrive: the transport detects the RTO was spurious (original
        // packets delivered; the RTO recovery should never have happened) and reports it.
        bbr.on_spurious_congestion_event();

        // on_spurious_congestion_event restored the saved model and returned to PROBE_UP.
        assert_eq!(
            bbr.state,
            BbrState::ProbeBw(ProbeBwSubstate::Up),
            "on_spurious_congestion_event should seamlessly return the flow to PROBE_UP"
        );
        assert_eq!(
            bbr.inflight_longterm,
            u64::MAX,
            "inflight_longterm should be restored to max(current, undo) = u64::MAX"
        );
        assert_eq!(
            bbr.bw_shortterm,
            f64::INFINITY,
            "bw_shortterm should be restored to max(current, undo) = +inf"
        );
        assert_eq!(
            bbr.inflight_shortterm,
            u64::MAX,
            "inflight_shortterm should be restored to max(current, undo) = u64::MAX"
        );
    }

    /// A.20: Entering and exiting PROBE_RTT during STARTUP.
    /// equivalent to BBRCheckProbeRTT / BBRHandleProbeRTT / BBRExitProbeRTT:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3>
    ///
    /// A.10 covers the PROBE_RTT interlude that fires *after* PROBE_BW, where
    /// `full_bw_reached` is true and `exit_probe_rtt` therefore routes on to
    /// PROBE_BW. This is the STARTUP-phase counterpart: the periodic min-RTT
    /// re-probe fires while the flow is *still in STARTUP* with `full_bw_reached`
    /// false, so `exit_probe_rtt` must route back to STARTUP (`enter_startup`) to
    /// keep searching for the max bandwidth, never forward to PROBE_BW. A.7 shows
    /// this same STARTUP <-> PROBE_RTT oscillation as a side effect of its "never
    /// exits STARTUP" premise; A.20 isolates and asserts the entry / duration /
    /// exit mechanics of one such interlude.
    ///
    /// Extended, slow STARTUP (same construction as A.7): the app is held to a
    /// small fixed window (`APP_WINDOW`, well below cwnd) from the first packet, so
    /// every sample is application-limited and `check_full_bw_reached` bails on its
    /// `is_app_limited` guard, `full_bw_reached` never arms and STARTUP persists.
    /// With a constant RTT the min-RTT floor never drops, so `update_min_rtt`
    /// freezes `probe_rtt_min_stamp` and flips `BBR.probe_rtt_expired` true one
    /// `BBR.ProbeRTTInterval` (5 s) after it was last stamped; `check_probe_rtt`
    /// then enters PROBE_RTT, all while `full_bw_reached` is still false.
    ///
    /// A transient PROBE_RTT also fires on the very first ack (`probe_rtt_min_stamp`
    /// starts unset, so `probe_rtt_expired` is true at t~0); its exit re-stamps
    /// `probe_rtt_min_stamp`, so the *next* expiry (the one this test targets)
    /// lands a full ProbeRTTInterval later, ~5 s into the still-running STARTUP.
    /// The t~0 transient is filtered out by requiring the entry at
    /// >= ProbeRTTInterval.
    ///
    /// On entry `check_probe_rtt` runs `enter_probe_rtt` (state -> ProbeRtt,
    /// `cwnd_gain` -> ProbeRTTCwndGain 0.5) and clears `probe_rtt_done_stamp`;
    /// `bound_cwnd_for_probe_rtt` caps cwnd at `BBRProbeRTTCwnd` (~0.5*BDP) so the
    /// sender stalls until `C.inflight` drains below the cap. When it does,
    /// `handle_probe_rtt` arms `probe_rtt_done_stamp = now + ProbeRTTDuration`
    /// (200 ms) and starts a fresh round; PROBE_RTT then holds until *both* one
    /// packet-timed round has elapsed (`probe_rtt_round_done`) *and*
    /// `now > probe_rtt_done_stamp`. `check_probe_rtt_done` then restores the cwnd
    /// and calls `exit_probe_rtt`, which (`full_bw_reached` being false) runs
    /// `enter_startup`, returning the flow to STARTUP.
    ///
    /// Asserts that: the flow only ever occupied STARTUP or PROBE_RTT (never
    /// advanced to DRAIN/PROBE_BW) and `full_bw_reached` was never set; the targeted
    /// PROBE_RTT was entered only after ProbeRTTInterval (5 s) had elapsed, with
    /// `cwnd_gain == ProbeRTTCwndGain` (0.5) and `full_bw_reached` still false;
    /// `probe_rtt_done_stamp` armed once inflight drained below the cap; the
    /// interlude held for at least ProbeRTTDuration (200 ms) *and* one round after
    /// arming; and the exit returned to STARTUP (not PROBE_BW) with
    /// `full_bw_reached` still false.
    #[test]
    fn startup_enters_and_exits_probe_rtt_back_to_startup() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.7/A.10
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// bytes the app keeps outstanding, from the first packet on. Fixed and
        /// well below cwnd so the sender is application-limited, never cwnd-limited,
        /// keeping `full_bw_reached` false and STARTUP alive (cf. A.7). Comfortably
        /// above `min_pipe_cwnd` (4*MSS).
        const APP_WINDOW: u64 = 20 * MSS;
        /// round cap (~1 RTT each, so ~12 s): more than one ProbeRTTInterval (5 s)
        /// plus a ProbeRTTDuration (200 ms), enough to capture the interval-expiry
        /// interlude and its exit if the loop does not break earlier.
        const ROUNDS_CAP: u64 = 120;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Drive the production default configuration.
        let mut bbr = Bbr3::new(Arc::new(Bbr3Config::default()), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Captured on the targeted PROBE_RTT entry edge (first entry at or after
        // ProbeRTTInterval, i.e. the genuine interval-expiry interlude, not the t~0
        // transient): (now_ns, cwnd_gain, full_bw_reached).
        let mut entry: Option<(u64, f64, bool)> = None;
        // Captured when probe_rtt_done_stamp is first armed inside that interlude
        // (C.inflight has drained below the ProbeRTT cwnd cap): (now_ns, round).
        let mut done_armed: Option<(u64, u64)> = None;
        // Captured on the PROBE_RTT -> STARTUP exit edge:
        // (now_ns, state, round, full_bw_reached).
        let mut exit: Option<(u64, BbrState, u64, bool)> = None;
        // Set the moment any forbidden (past-STARTUP) state is entered.
        let mut advanced_past_startup: Option<BbrState> = None;
        // Whether full_bw_reached was ever set (must stay false throughout).
        let mut full_bw_reached_ever = false;

        for _ in 0..1_000_000 {
            let cwnd = bbr.window();
            // The app never wants more than APP_WINDOW outstanding.
            let window_cap = APP_WINDOW.min(cwnd);
            let can_send = inflight + MSS <= window_cap;
            let next_ack = flight.front().map(|p| p.ack_ns);

            // Send whenever the small app window allows and a paced send is due no
            // later than the next ack; otherwise process an ack. The app window is
            // always the binding limit, not cwnd (cf. A.7).
            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                // Emulate the connection layer's C.app_limited so the next packet is
                // stamped app-limited at send time (same shape as A.7).
                bbr.app_limited = pn;

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, true, &rtt_est);
                bbr.on_end_acks(at(now_ns), inflight, true, Some(p.pn));

                full_bw_reached_ever |= bbr.full_bw_reached;

                match bbr.state {
                    BbrState::Startup => {
                        // Once the targeted interlude has been entered, the next time
                        // we are back in STARTUP is the PROBE_RTT -> STARTUP exit.
                        if entry.is_some() && exit.is_none() {
                            exit = Some((now_ns, bbr.state, bbr.round_count, bbr.full_bw_reached));
                        }
                    }
                    BbrState::ProbeRtt => {
                        // Target only the interval-expiry interlude (>= ProbeRTTInterval),
                        // skipping the t~0 unset-stamp transient.
                        if entry.is_none() && now_ns >= PROBE_RTT_INTERVAL_SEC * 1_000_000_000 {
                            entry = Some((now_ns, bbr.cwnd_gain, bbr.full_bw_reached));
                        }
                        // The moment probe_rtt_done_stamp is armed inside that interlude:
                        // C.inflight has drained below the ProbeRTT cwnd cap.
                        if entry.is_some()
                            && done_armed.is_none()
                            && bbr.probe_rtt_done_stamp.is_some()
                        {
                            done_armed = Some((now_ns, bbr.round_count));
                        }
                    }
                    // Any other state means STARTUP was actually left for the next
                    // phase: the failure this test guards against.
                    other => {
                        advanced_past_startup.get_or_insert(other);
                    }
                }

                if advanced_past_startup.is_some()
                    || exit.is_some()
                    || bbr.round_count >= ROUNDS_CAP
                {
                    break;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        // Never advanced past STARTUP: only STARTUP and the scheduled PROBE_RTT
        // min-RTT refresh were ever entered.
        assert!(
            advanced_past_startup.is_none(),
            "BBR left STARTUP for {:?} during the extended slow-STARTUP PROBE_RTT interlude",
            advanced_past_startup,
        );
        // The plateau path never armed: check_full_bw_reached short-circuits on
        // app-limited samples, so full_bw_reached stayed false: the precondition
        // for PROBE_RTT routing back to STARTUP rather than on to PROBE_BW.
        assert!(
            !full_bw_reached_ever,
            "full_bw_reached must never be set on application-limited samples"
        );

        // Entered PROBE_RTT only after ProbeRTTInterval (5 s), still in STARTUP. `entry`
        // is only set inside the `>= ProbeRTTInterval` guard above, so a successful
        // `expect` already pins the interval-expiry timing.
        let (entry_ns, entry_cwnd_gain, entry_full_bw) =
            entry.expect("BBR never entered the interval-expiry PROBE_RTT during STARTUP");
        assert!(
            !entry_full_bw,
            "full_bw_reached should be false on the STARTUP-phase PROBE_RTT entry"
        );
        // cwnd_gain was set to ProbeRTTCwndGain (0.5) on entry.
        assert_eq!(
            entry_cwnd_gain, bbr.probe_rtt_cwnd_gain,
            "PROBE_RTT cwnd_gain should be ProbeRTTCwndGain"
        );
        assert_eq!(
            entry_cwnd_gain, PROBE_RTT_CWND_GAIN,
            "ProbeRTTCwndGain should be 0.5"
        );

        // The ProbeRTTDuration clock was armed once inflight drained below the cap.
        let (done_ns, done_round) = done_armed.expect("PROBE_RTT never armed probe_rtt_done_stamp");

        // Exited PROBE_RTT back to STARTUP (not PROBE_BW), full_bw_reached still false.
        let (exit_ns, exit_state, exit_round, exit_full_bw) =
            exit.expect("BBR never exited PROBE_RTT back to STARTUP");
        assert_eq!(
            exit_state,
            BbrState::Startup,
            "PROBE_RTT should exit back to STARTUP when full_bw_reached is false"
        );
        assert!(
            !exit_full_bw,
            "full_bw_reached should remain false across the PROBE_RTT -> STARTUP exit"
        );

        // Held for at least ProbeRTTDuration (200 ms) after the clock was armed
        // (check_probe_rtt_done uses a strict `now > probe_rtt_done_stamp`)...
        assert!(
            exit_ns - done_ns >= PROBE_RTT_DURATION_MS * 1_000_000,
            "PROBE_RTT exited before ProbeRTTDuration elapsed \
             (held {} ns vs duration {} ms)",
            exit_ns - done_ns,
            PROBE_RTT_DURATION_MS
        );
        // ...and for at least one packet-timed round after arming.
        assert!(
            exit_round > done_round,
            "PROBE_RTT should hold at least one round after arming \
             (arm round {done_round} vs exit round {exit_round})"
        );
        // Sanity: entry preceded the exit.
        assert!(exit_ns > entry_ns);

        // Ends in STARTUP, still searching for max bandwidth.
        assert_eq!(
            bbr.state,
            BbrState::Startup,
            "BBR should be back in STARTUP after the PROBE_RTT interlude"
        );
    }

    /// A.21: Handling loss during PROBE_UP after `inflight_longterm` is set.
    /// equivalent to BBRHandleInflightTooHigh:
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    ///
    /// The counterpart to A.6 (loss in PROBE_UP while application-limited, where the
    /// `!is_app_limited` guard makes `handle_inflight_too_high` leave
    /// `inflight_longterm` untouched) and to A.18/A.19 (loss in PROBE_UP while
    /// `inflight_longterm` is still at its `u64::MAX` init, where the loss merely
    /// clamps it *from infinity* to a finite value for the first time). A.21 isolates
    /// the remaining case: a non-application-limited loss in PROBE_UP while
    /// `inflight_longterm` is **already established finite**, so the loss actively
    /// scales the standing long-term estimate *down* via the beta-scaled reduction
    /// rule `inflight_longterm = max(tx_in_flight, target_inflight * BETA)`.
    ///
    /// Loss cannot make `inflight_longterm` finite except through a loss: in PROBE_UP
    /// `adapt_long_term_model` short-circuits on `inflight_longterm == u64::MAX`, so
    /// nothing raises it until a first loss (`handle_inflight_too_high`) or the
    /// STARTUP high-loss escape seeds it. The scenario therefore runs two loss
    /// episodes over one non-app-limited, full-window flow (bottleneck bandwidth
    /// modest, as in A.18/A.19, so a short oldest-first loss burst trips
    /// `is_inflight_too_high`, `lost > LOSS_THRESH * tx_in_flight`):
    ///
    ///  1. Establish. Reach PROBE_UP loss-free, then declare the oldest in-flight
    ///     packets lost until the accumulated loss trips `is_inflight_too_high`.
    ///     `handle_inflight_too_high` clamps `inflight_longterm` from `u64::MAX` to a
    ///     finite value and moves PROBE_UP -> PROBE_DOWN. Loss injection then stops;
    ///     this is the "established `inflight_longterm`" precondition.
    ///  2. Ride loss-free back up. PROBE_DOWN -> (cruise) -> refill -> PROBE_UP again.
    ///     With `inflight_longterm` now finite, `adapt_long_term_model` /
    ///     `probe_inflight_long_term_upward` carry it forward (it only ever grows) as
    ///     the standing long-term operating point.
    ///  3. Deciding loss. In this second PROBE_UP, before any bandwidth plateau forms
    ///     (`start_probe_bw_up` resets `full_bw`, and a plateau needs
    ///     `MAX_FULL_BW_COUNT` rounds, so injecting immediately keeps `full_bw_now`
    ///     false, `BBRIsTimeToGoDown`/`maybe_go_down` never fires), declare the
    ///     oldest in-flight packets lost until `is_inflight_too_high` trips again.
    ///     Because the sample is non-app-limited, `handle_inflight_too_high` runs the
    ///     reduction and resets `inflight_longterm` to
    ///     `max(tx_in_flight, target_inflight * BETA)` (below the established value)
    ///     then aborts PROBE_UP straight into PROBE_DOWN.
    ///
    /// Asserts on the deciding loss that: `inflight_longterm` was established finite
    /// (and, only ever growing, was still >= that value entering the loss); the
    /// deciding sample was non-app-limited; `inflight_longterm` was reset exactly to
    /// the beta-scaled rule `max(tx_in_flight, target_inflight * BETA)` and strictly
    /// lower than before the loss (scaled down); the exit was loss-driven, not the
    /// plateau path (`full_bw_now` false); and PROBE_UP aborted immediately to
    /// PROBE_DOWN.
    #[test]
    fn probe_up_loss_scales_down_established_inflight_longterm() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated propagation round-trip time (100ms), matching A.18/A.19
        const RTT_NS: u64 = 100_000_000;
        /// bottleneck bandwidth: 10 Mbit/s in bytes/sec. Modest BDP keeps `LOSS_THRESH`
        /// (2% of tx_in_flight) small, so a short oldest-first loss burst trips
        /// `is_inflight_too_high`.
        const BW: f64 = 1_250_000.0;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;

        // Seed the probe RNG so the PROBE_BW cycle timing (hence when each PROBE_UP is
        // entered) is deterministic.
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            probe_rng_seed: Some(seed),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Episode 1: the value inflight_longterm was clamped to when the first PROBE_UP loss made it
        // finite (from u64::MAX). Marks the "established" precondition and switches episode 1 off.
        let mut established: Option<u64> = None;
        // Episode 2 (deciding loss): (inflight_longterm before/after the deciding loss, the deciding
        // sample's tx_in_flight, target_inflight = min(bdp, cwnd) at the loss, whether the sample was
        // app-limited, full_bw_now at the edge, and the post-loss state).
        let mut ep2: Option<(u64, u64, u64, u64, bool, bool, BbrState)> = None;

        for _ in 0..5_000_000 {
            if ep2.is_some() {
                break;
            }
            let cwnd = bbr.window();
            let can_send = inflight + MSS <= cwnd;
            if !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.ack_ns);

            let in_up = bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up);
            // Drop (declare oldest-first lost) whenever in PROBE_UP and the relevant episode is still
            // pending: episode 1 while inflight_longterm is unset, episode 2 (still pending, ep2 None)
            // on the next PROBE_UP. Between the two (any non-PROBE_UP state) delivery is loss-free,
            // so inflight_longterm carries forward untouched and the flow rides back up to PROBE_UP.
            let dropping = in_up && (established.is_none() || ep2.is_none());
            let do_send = !dropping && can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                let send_ns = now_ns.max(next_send_ns);
                now_ns = send_ns;
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                if dropping {
                    // The PROBE_UP -> PROBE_DOWN transition happens inside on_packet_lost (via
                    // handle_inflight_too_high), never on an ack, so any Up->Down move here is
                    // attributable to this loss. inflight_longterm is only touched by the tripping
                    // loss (non-tripping burst losses leave it unchanged), so `before` captured here
                    // is exactly the pre-reduction value.
                    let before = bbr.inflight_longterm;
                    let was_up = bbr.state == BbrState::ProbeBw(ProbeBwSubstate::Up);
                    bbr.on_packet_lost(MSS as u16, p.pn, at(now_ns));
                    if was_up && bbr.state != BbrState::ProbeBw(ProbeBwSubstate::Up) {
                        if established.is_none() {
                            // Episode 1: the first loss clamped inflight_longterm finite.
                            established = Some(bbr.inflight_longterm);
                        } else {
                            // Episode 2: the deciding loss scaled the established value down. Read the
                            // formula inputs (tx_in_flight was set to inflight_at_loss, target_inflight
                            // = min(bdp, cwnd)) live: set_cwnd does not run inside the loss path, so
                            // bdp/cwnd match what handle_inflight_too_high used.
                            let txif = bbr.rs.map(|rs| rs.tx_in_flight).unwrap();
                            let target = Ord::min(bbr.bdp, bbr.cwnd);
                            ep2 = Some((
                                before,
                                bbr.inflight_longterm,
                                txif,
                                target,
                                bbr.rs.is_some_and(|rs| rs.is_app_limited),
                                bbr.full_bw_now,
                                bbr.state,
                            ));
                        }
                    }
                } else {
                    rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));
                    bbr.on_ack(at(now_ns), at(p.send_ns), MSS, p.pn, false, &rtt_est);
                    bbr.on_end_acks(at(now_ns), inflight, false, Some(p.pn));
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let established =
            established.expect("episode 1 never established a finite inflight_longterm");
        let (before, after, txif, target, app_lim, full_bw_now, post_state) =
            ep2.expect("episode 2 deciding loss never fired out of PROBE_UP");

        // Precondition: inflight_longterm was established finite by episode 1, and (only ever growing
        // between the episodes, loss-free) was still >= that value entering the deciding loss.
        assert!(
            established < u64::MAX,
            "episode 1 should have clamped inflight_longterm finite"
        );
        assert!(
            before >= established && before < u64::MAX,
            "the standing inflight_longterm entering the deciding loss should be the established \
             finite value carried forward (before {before} vs established {established})"
        );

        // The deciding loss sample was non-application-limited, so handle_inflight_too_high runs the
        // reduction rather than skipping it (the A.6 path).
        assert!(
            !app_lim,
            "deciding loss sample should be non-application-limited so the reduction applies"
        );

        // handle_inflight_too_high reset inflight_longterm to the beta-scaled rule
        // max(tx_in_flight, target_inflight * BETA)...
        assert_eq!(
            after,
            Ord::max(txif, (target as f64 * BETA) as u64),
            "inflight_longterm should be reset to max(tx_in_flight, target_inflight * BETA)"
        );
        // ...scaling the established estimate strictly down.
        assert!(
            after < before,
            "inflight_longterm should be scaled down from its established value \
             (after {after} vs before {before})"
        );

        // Loss, not the plateau path, drove the exit: the deciding loss was injected before any
        // bandwidth plateau formed, so full_bw_now (BBRIsTimeToGoDown's signal) never got set.
        assert!(
            !full_bw_now,
            "expected a loss-driven exit, but the plateau signal full_bw_now was set"
        );
        // PROBE_UP aborted immediately into PROBE_DOWN.
        assert_eq!(
            post_state,
            BbrState::ProbeBw(ProbeBwSubstate::Down),
            "the loss should abort PROBE_UP straight to PROBE_DOWN via handle_inflight_too_high"
        );
    }

    /// A.22: Handling application-limited sending during PROBE_REFILL.
    /// equivalent to BBRUpdateMaxBw <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.5>
    ///
    /// The `!is_app_limited` half of the `update_max_bw` guard
    /// (`delivery_rate >= BBR.max_bw || !RS.is_app_limited`) in isolation: an
    /// application-limited delivery-rate sample whose rate is *below* the standing
    /// `max_bw` must NOT be folded into the max-bandwidth filter, so a pause in the
    /// application during a probe cannot pull the bandwidth estimate down toward the
    /// artificially low app-limited rate. (The complementary half, an app-limited
    /// sample that is `>= max_bw` still trusted to raise it, is not exercised
    /// here; only the "ignore low app-limited samples" behavior is.)
    ///
    /// Same single-bottleneck simulator as A.5/A.6, run in two phases:
    ///  1. Not application-limited, no loss, full-cwnd until the flow cycles
    ///     STARTUP -> DRAIN -> PROBE_BW, which establishes `max_bw` at ~`BW` (set
    ///     from the non-app-limited STARTUP delivery-rate samples).
    ///  2. The moment PROBE_BW is entered the app is throttled to a small fixed
    ///     window (`APP_WINDOW`, far below the ~1*BDP..2*BDP cwnd) and every sent
    ///     packet is stamped app-limited, exactly as A.6. The pipe drains to
    ///     `APP_WINDOW` during the PROBE_DOWN phase, so by the time the probe timer
    ///     fires the cycle into PROBE_REFILL every in-flight sample is app-limited
    ///     and its delivery rate (~`APP_WINDOW / RTT`) sits well below `max_bw`.
    ///
    /// Across that PROBE_REFILL round trip each ack carries an app-limited sample
    /// with `RS.delivery_rate < BBR.max_bw`, so `update_max_bw`'s guard is false and
    /// `max_bw` is left untouched, asserted both per-ack (the estimate does not move
    /// across any blocked sample) and across the whole round (its value on entering
    /// PROBE_UP equals its value on entering PROBE_REFILL). Note the max-bw filter's
    /// cycle counter only advances on non-app-limited round-start samples
    /// (`adapt_long_term_model`), so the established estimate cannot even age out
    /// while the app stays limited.
    ///
    /// PROBE_REFILL then advances to PROBE_UP on its round boundary
    /// (`update_probe_bw_cycle_phase`). At that edge the app un-pauses (full sending
    /// resumes); a purely app-limited PROBE_UP would never plateau nor be
    /// cwnd-limited (`maybe_go_down` could never fire), so resuming is what lets
    /// probing proceed. Asserts the estimate survived (`max_bw` still ~`BW`, never
    /// collapsed toward the app-limited rate) and the ProbeBW cycle keeps turning:
    /// the flow leaves that PROBE_UP and re-enters a fresh one. (On this constant-RTT,
    /// infinite-buffer link PROBE_UP is exited by the periodic min-RTT probe rather
    /// than a queue plateau, so the re-probe is the "still probing" signal.)
    #[test]
    fn probe_refill_ignores_app_limited_low_bw_samples() {
        /// packet size in bytes
        const MSS: u64 = 1200;
        /// simulated bottleneck bandwidth: 100 Mbit/s in bytes/sec
        const BW: f64 = 12_500_000.0;
        /// simulated propagation round-trip time (100ms), matching A.5/A.6
        const RTT_NS: u64 = 100_000_000;
        const FWD_NS: u64 = RTT_NS / 2;
        const RET_NS: u64 = RTT_NS / 2;
        /// application window used once PROBE_BW is reached: bytes the app keeps
        /// outstanding. Fixed and far below the PROBE_BW cwnd (~1000 packets here) so
        /// the sender is application-limited (never cwnd-limited) and the resulting
        /// delivery-rate samples (~`APP_WINDOW / RTT`) sit well below `max_bw`.
        /// Matches A.6's window.
        const APP_WINDOW: u64 = 200 * MSS;

        // bottleneck serialization time for one MSS-sized packet
        let btl_service_ns: u64 = (MSS as f64 / BW * 1e9).round() as u64;

        // Production default, but pin the probe RNG: once app-limiting lifts at the
        // PROBE_REFILL -> PROBE_UP edge the flow does genuine PROBE_BW cycling, whose
        // phase timing is RNG-driven, and default() seeds from entropy (cf. sibling
        // probing tests).
        let config = Bbr3Config {
            probe_rng_seed: Some([6; 16]),
            ..Bbr3Config::default()
        };
        let mut bbr = Bbr3::new(Arc::new(config), MSS as u16);
        assert_eq!(bbr.state, BbrState::Startup);

        let base = Instant::now();
        let at = |off_ns: u64| base + Duration::from_nanos(off_ns);
        let mut rtt_est = RttEstimator::new(Duration::from_nanos(RTT_NS));

        struct InFlight {
            pn: u64,
            send_ns: u64,
            ack_ns: u64,
        }
        let mut flight: VecDeque<InFlight> = VecDeque::new();

        let mut now_ns: u64 = 0;
        let mut next_send_ns: u64 = 0;
        // time at which the bottleneck finishes serving everything queued so far
        let mut btl_free_ns: u64 = 0;
        let mut inflight: u64 = 0;
        let mut pn: u64 = 0;

        // Phase 2 begins once PROBE_BW is entered: from then the app is limited to
        // APP_WINDOW and every sent packet is stamped app-limited. Flipped back off at
        // the PROBE_REFILL -> PROBE_UP edge so subsequent probing runs full-cwnd.
        let mut app_limited_phase = false;
        // One-shot latch: arm app-limiting exactly once, on first PROBE_BW entry.
        // Otherwise the check below re-fires next ack (still PROBE_BW) and undoes the
        // reset at the REFILL -> UP edge, trapping the flow app-limited forever.
        let mut app_limited_armed = false;

        // max_bw sampled right as PROBE_REFILL is entered and right as it advances to
        // PROBE_UP; equal iff the app-limited round left the estimate untouched.
        let mut max_bw_at_refill_entry: Option<f64> = None;
        let mut max_bw_at_up: Option<f64> = None;
        // app-limited PROBE_REFILL samples whose delivery_rate < max_bw (the guard's
        // target case), and the largest such rate seen (to show it really was below
        // max_bw). Each of these acks is asserted inline to not move max_bw.
        let mut blocked_samples: u64 = 0;
        let mut max_app_limited_dr: f64 = 0.0;
        // Whether the flow advanced PROBE_REFILL -> PROBE_UP, then (after full sending
        // resumed) reached the plateau-driven PROBE_UP -> PROBE_DOWN exit.
        let mut refill_to_up = false;
        // Set once the flow leaves that first post-refill PROBE_UP, then again when it
        // re-enters a fresh PROBE_UP, i.e. the ProbeBW cycle kept turning.
        let mut left_post_refill_up = false;
        let mut post_refill_reprobed = false;
        let mut max_bw_final: f64 = 0.0;

        for _ in 0..3_000_000 {
            if post_refill_reprobed {
                break;
            }
            let cwnd = bbr.window();
            let window_cap = if app_limited_phase {
                APP_WINDOW.min(cwnd)
            } else {
                cwnd
            };
            let can_send = inflight + MSS <= window_cap;
            // In the full-cwnd phases a blocked send is a genuine cwnd limit; in the
            // app-limited phase the small window is the binding limit, not cwnd, so it
            // must not be reported as cwnd-limited.
            if !app_limited_phase && !can_send {
                bbr.on_cwnd_limited();
            }
            let next_ack = flight.front().map(|p| p.ack_ns);

            let do_send = can_send && next_ack.is_none_or(|ack| next_send_ns <= ack);

            if do_send {
                now_ns = now_ns.max(next_send_ns);
                let send_ns = now_ns;
                // enqueue at the FIFO bottleneck, served at BW
                let arrival = send_ns + FWD_NS;
                let service_start = arrival.max(btl_free_ns);
                let finish = service_start + btl_service_ns;
                btl_free_ns = finish;
                let ack_ns = finish + RET_NS;

                bbr.on_packet_sent(at(send_ns), MSS as u16, pn);
                inflight += MSS;
                flight.push_back(InFlight {
                    pn,
                    send_ns,
                    ack_ns,
                });

                if app_limited_phase {
                    // Emulate the connection layer's C.app_limited (the index of the
                    // last packet sent while the app had no more data) so the next
                    // packet is stamped app-limited at send time. Same shape as A.2/A.6:
                    // on_end_acks cannot keep samples app-limited on its own.
                    bbr.app_limited = pn;
                }

                // pace the next send at BBR's chosen pacing rate
                let pacing = bbr.pacing_rate.max(1.0);
                next_send_ns = send_ns + (MSS as f64 / pacing * 1e9).round() as u64;
                pn += 1;
            } else if let Some(p) = flight.pop_front() {
                now_ns = now_ns.max(p.ack_ns);
                inflight -= MSS;
                rtt_est.update(Duration::ZERO, Duration::from_nanos(now_ns - p.send_ns));

                // update_max_bw runs inside on_ack, on the sample already pending from
                // the previous on_end_acks. Snapshot max_bw and state around on_ack, and
                // read that sample (bbr.rs) between on_ack and on_end_acks: that is
                // exactly what update_max_bw's guard consumed.
                let state_before = bbr.state;
                let max_bw_before = bbr.max_bw;
                bbr.on_ack(
                    at(now_ns),
                    at(p.send_ns),
                    MSS,
                    p.pn,
                    app_limited_phase,
                    &rtt_est,
                );
                let max_bw_after = bbr.max_bw;
                let state_after = bbr.state;
                let sample = bbr.rs;
                bbr.on_end_acks(at(now_ns), inflight, app_limited_phase, Some(p.pn));

                // Flip to the application-limited phase the moment PROBE_BW is entered,
                // so the pipe drains to APP_WINDOW during PROBE_DOWN and the first
                // PROBE_REFILL round is entirely app-limited. Same timing as A.6.
                if !app_limited_armed && matches!(bbr.state, BbrState::ProbeBw(_)) {
                    app_limited_armed = true;
                    app_limited_phase = true;
                }

                // Capture max_bw as the first PROBE_REFILL is entered.
                if state_after == BbrState::ProbeBw(ProbeBwSubstate::Refill)
                    && max_bw_at_refill_entry.is_none()
                {
                    max_bw_at_refill_entry = Some(bbr.max_bw);
                }

                // Acks processed while already in PROBE_REFILL carry this round's
                // samples. Every one is app-limited and low, so the guard must leave
                // max_bw untouched.
                if state_before == BbrState::ProbeBw(ProbeBwSubstate::Refill) {
                    if let Some(rs) = sample
                        .filter(|rs| rs.is_app_limited)
                        .filter(|rs| rs.delivery_rate > 0.0)
                        .filter(|rs| rs.delivery_rate < max_bw_before)
                    {
                        blocked_samples += 1;
                        max_app_limited_dr = max_app_limited_dr.max(rs.delivery_rate);
                        assert_eq!(
                            max_bw_after, max_bw_before,
                            "a low app-limited PROBE_REFILL sample \
                             (delivery_rate {} < max_bw {max_bw_before}) must not update max_bw",
                            rs.delivery_rate
                        );
                    }
                    // PROBE_REFILL -> PROBE_UP fires on this round's boundary ack. Snapshot
                    // max_bw and un-pause the app so subsequent probing runs full-cwnd.
                    if state_after == BbrState::ProbeBw(ProbeBwSubstate::Up) && !refill_to_up {
                        refill_to_up = true;
                        max_bw_at_up = Some(bbr.max_bw);
                        app_limited_phase = false;
                    }
                }

                // Subsequent probing: with full sending resumed, the ProbeBW cycle must
                // keep turning. Once the flow leaves the first post-refill PROBE_UP and
                // then re-enters a fresh PROBE_UP, it is probing normally again. (This
                // constant-RTT, infinite-buffer link exits PROBE_UP via the periodic
                // min-RTT probe rather than a queue plateau, so the re-probe (not a
                // PROBE_UP -> PROBE_DOWN edge) is the signal to check.)
                if refill_to_up && state_after != BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    left_post_refill_up = true;
                }
                if left_post_refill_up && state_after == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                    post_refill_reprobed = true;
                    max_bw_final = bbr.max_bw;
                }
            } else {
                panic!("simulation stalled: window full but nothing in flight");
            }
        }

        let max_bw_at_refill_entry =
            max_bw_at_refill_entry.expect("flow never entered PROBE_REFILL");
        let max_bw_at_up = max_bw_at_up.expect("PROBE_REFILL never advanced to PROBE_UP");

        // Precondition: PROBE_REFILL was reached with max_bw established at ~BW by the
        // non-app-limited STARTUP samples.
        let entry_err = (max_bw_at_refill_entry - BW).abs() / BW;
        assert!(
            entry_err < 0.05,
            "max_bw entering PROBE_REFILL ({max_bw_at_refill_entry}) should be within 5% of the \
             simulated {BW} (rel err {entry_err})"
        );

        // The app-limited round produced the guard's target case: samples flagged
        // app-limited with delivery_rate strictly below max_bw.
        assert!(
            blocked_samples > 0,
            "expected app-limited PROBE_REFILL samples with delivery_rate < max_bw"
        );
        assert!(
            max_app_limited_dr < max_bw_at_refill_entry,
            "the app-limited PROBE_REFILL rate ({max_app_limited_dr}) should sit below max_bw \
             ({max_bw_at_refill_entry})"
        );

        // Across the whole PROBE_REFILL round the artificially low app-limited samples
        // left max_bw exactly unchanged (the guard rejected every one; the max-bw
        // filter's cycle counter also never advanced on app-limited samples, so the
        // estimate could not age out either).
        assert_eq!(
            max_bw_at_up, max_bw_at_refill_entry,
            "max_bw must be unchanged across the app-limited PROBE_REFILL round \
             (entry {max_bw_at_refill_entry}, PROBE_UP {max_bw_at_up})"
        );

        // Subsequent probing was handled correctly: PROBE_REFILL advanced to PROBE_UP
        // and, once full sending resumed, the ProbeBW cycle kept turning: the flow
        // left that PROBE_UP and re-entered a fresh one, with the bandwidth estimate
        // intact (~BW, never collapsed to the app-limited rate).
        assert!(
            refill_to_up,
            "PROBE_REFILL should advance to PROBE_UP after its round trip"
        );
        assert!(
            post_refill_reprobed,
            "flow should keep probing: re-enter PROBE_UP after the PROBE_REFILL round"
        );
        // "Estimate intact" bar: genuine PROBE_BW cycling leaves max_bw a few % below the
        // bottleneck (samples taken while pacing_gain < 1), so this guards against collapse
        // to the app-limited rate (~0.19*BW), not tight tracking. 10% keeps ~4.7x margin;
        // exact preservation across the app-limited round is asserted strictly above.
        let final_err = (max_bw_final - BW).abs() / BW;
        assert!(
            final_err < 0.10,
            "max_bw after subsequent probing ({max_bw_final}) should still be within 10% of the \
             simulated {BW} (rel err {final_err})"
        );
    }
}
