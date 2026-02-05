mod max_filter;

use crate::RttEstimator;
use crate::congestion::bbr3::max_filter::MaxFilter;
use crate::congestion::{Controller, ControllerFactory, ControllerMetrics};
use crate::{Duration, Instant};
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg32;
use std::any::Any;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::sync::Arc;

/// equivalent to BBR.MaxBwFilterLen <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.10>
const MAX_BW_FILTER_LEN: usize = 2;

/// equivalent to BBR.ExtraAckedFilterLen <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.11>
const EXTRA_ACKED_FILTER_LEN: usize = 10;

/// safety mechanism to flag packets as stale within our tracking VecDeque. rounds refer to <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.1>.
/// The value of 10 rounds is picked because normally after max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity) <https://datatracker.ietf.org/doc/html/rfc9002#section-6.1.2>
/// the packet should have been declared lost already, this is just to guarantee that the VecDeque doesn't grow indefinitely.
const ROUND_COUNT_WINDOW: u64 = 10;

/// the minimum for the maximum datagram size <https://datatracker.ietf.org/doc/html/rfc9000#section-14>
const MIN_MAX_DATAGRAM_SIZE: u16 = 1200;

/// the maximum for the maximum datagram size <https://datatracker.ietf.org/doc/html/rfc9000#section-18.2>
const MAX_DATAGRAM_SIZE: u64 = 65527;

/// 1.2Mbps in bytes/sec used to determine send_quantum
/// this is the pacing rate used where we don't authorize a burst bigger than a full packet
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const PACING_RATE_1_2MBPS: f64 = 1200.0 * 1000.0;

/// 24Mbps in bytes/sec
/// this is the pacing rate used where we don't authorize a burst bigger than two full packets
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const PACING_RATE_24MBPS: f64 = 24000.0 * 1000.0;

/// 64 Kb in bytes
/// this is the maximum size we want for a quantum in `set_send_quantum`
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const HIGH_PACE_MAX_QUANTUM: u64 = 64 * 1000;

/// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
/// the sending rate to double each round (4 * ln(2) ~= 2.77)
/// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
const STARTUP_PACING_GAIN: f64 = 2.773;

/// default pacing gain is 1, when cruising, probing for RTT or refilling <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
const DEFAULT_PACING_GAIN: f64 = 1.0;

/// pacing gain when probing bandwidth down <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
const PROBE_BW_DOWN_PACING_GAIN: f64 = 0.9;

/// pacing gain when probing bandwidth up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
const PROBE_BW_UP_PACING_GAIN: f64 = 1.25;

/// equivalent to BBR.DrainPacingGain: A constant specifying the pacing gain value used in Drain mode,
/// to attempt to drain the estimated queue at the bottleneck link in one round-trip or less.
/// As noted in BBRDrainPacingGain, any value at or below 1 / BBRStartupCwndGain = 1 / 2 = 0.5 will theoretically achieve this.
/// BBR uses the value 0.35, which has been shown to offer good performance when compared with other alternatives.
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.4>
/// <https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_drain_gain.pdf>
const DRAIN_PACING_GAIN: f64 = 1.0 / STARTUP_PACING_GAIN;

/// equivalent to BBR.PacingMarginPercent: The static discount factor of 1% used to scale BBR.bw to produce C.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 1.0;

/// equivalent to BBR.DefaultCwndGain: A constant specifying the minimum gain value that allows the sending rate to double each round (2) BBRStartupCwndGain.
/// Used by default in most phases for BBR.cwnd_gain.
const DEFAULT_CWND_GAIN: f64 = 2.0;

/// cwnd gain used when probing up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
const PROBE_BW_UP_CWND_GAIN: f64 = 2.25;

/// cwnd gain used when probing RTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
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
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.2-6>
const FULL_BW_GROWTH: f64 = 1.25;

/// maximum number of rounds needed before we consider that the pipe is full <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.2-6>
const MAX_FULL_BW_COUNT: u64 = 3;

/// when setting `bw_probe_up_rounds` when raising our inflight long term slope we don't go above this
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
const MAX_LONG_TERM_PROBE_UP_ROUNDS: u32 = 30;

/// max number of rounds used when deciding to coexist with Reno / CUBIC <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.1>
const MAX_RENO_ROUNDS: u64 = 63;

/// minimum amount of time to wait before probing again <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.3-5>
const MIN_PROBE_WAIT_MS: u64 = 2000;

/// when waiting before probing again we add up to one second of added wait time
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.3-5>
const MAX_ADDED_PROBE_WAIT_MS: u64 = 1000;

/// Substates when probing bandwidth
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProbeBwSubstate {
    /// Deceleration: sends slower than delivery rate to reduce queue
    /// equivalent to ProbeBW_DOWN <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.1>
    Down,

    /// Cruising: sends at delivery rate to maintain high utilization
    /// equivalent to ProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.2>
    Cruise,

    /// Refill: sends at BBR.bw for one RTT to fill pipe before probing up
    /// equivalent to ProbeBW_REFILL <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.3>
    Refill,

    /// Acceleration: sends faster than delivery rate to probe for more bandwidth
    /// equivalent to ProbeBW_UP <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.4>
    Up,
}

/// State Machine description from BBR3
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BbrState {
    /// Initial state: rapidly probes for bandwidth using high pacing_gain
    /// equivalent to Startup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1>
    Startup,

    /// Drains queue created during Startup by using low pacing_gain (< 1.0)
    /// equivalent to Drain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.2>
    Drain,

    /// Steady-state phase that cycles through bandwidth probing tactics
    /// equivalent to ProbeBW states <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3>
    ProbeBw(ProbeBwSubstate),

    /// Temporarily reduces inflight to measure true min_rtt
    /// equivalent to ProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4>
    ProbeRtt,
}

/// Ack phases used during ProbeBW states
/// equivalent to BBR.ack_phase states <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6>
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
/// equivalent to P <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-4.1.2.1.2>
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
    /// equivalent to P.lost: C.lost when the packet was sent
    lost: u64,
    /// used to flag acknowledgement within our VecDeque, a packet can be flagged lost after having been flagged acknowledged
    /// hence the necessity of this flag being set before we remove it from packets.
    acknowledged: bool,
    /// once a packet has been acknowledged on a given round it is marked for removal on the next round.
    stale: bool,
    /// used to mark packets stale if they're far from the current round <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.1>
    round_count: u64,
}

/// Description of a per-ack rate sample state that will allow us to determine a short term evolution of the connection
/// equivalent to RS <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.2>
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
/// Based on <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html>
/// equivalent to a combination of BBR and C states
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.4>
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.1>
#[derive(Debug, Clone)]
pub struct Bbr3 {
    /// equivalent to C.SMSS The Sender Maximum Send Size in bytes. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.1>
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
    /// equivalent to BBR.cycle_count: The virtual time used by the BBR.max_bw filter window. Note that BBR.cycle_count only needs to be tracked with a single bit,
    /// since the BBR.max_bw_filter only needs to track samples from two time slots: the previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: bool,
    /// equivalent to C.cwnd: The transport sender's congestion window. When transmitting data, the sending connection ensures that C.inflight does not exceed C.cwnd.
    cwnd: u64,
    /// equivalent to C.pacing_rate: The current pacing rate for a BBR flow, which controls inter-packet spacing.
    pacing_rate: f64,
    /// equivalent to C.send_quantum: The maximum size of a data aggregate scheduled and transmitted together as a unit, e.g., to amortize per-packet transmission overheads.
    send_quantum: u64,
    /// equivalent to BBR.pacing_gain: The dynamic gain factor used to scale BBR.bw to produce C.pacing_rate.
    pacing_gain: f64,
    /// default pacing gain is 1, when cruising, probing for RTT or refilling <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    default_pacing_gain: f64,
    /// pacing gain when probing bandwidth down <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    probe_bw_down_pacing_gain: f64,
    /// pacing gain when probing bandwidth up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    probe_bw_up_pacing_gain: f64,
    /// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
    /// the sending rate to double each round (4 * ln(2) ~= 2.77)
    /// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    startup_pacing_gain: f64,
    /// equivalent to BBR.DrainPacingGain: A constant specifying the pacing gain value used in Drain mode,
    /// to attempt to drain the estimated queue at the bottleneck link in one round-trip or less.
    /// As noted in BBRDrainPacingGain, any value at or below 1 / BBRStartupCwndGain = 1 / 2 = 0.5 will theoretically achieve this.
    /// BBR uses the value 0.35, which has been shown to offer good performance when compared with other alternatives.
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    drain_pacing_gain: f64,
    /// equivalent to BBR.PacingMarginPercent: The static discount factor of 1% used to scale BBR.bw to produce C.pacing_rate.
    pacing_margin_percent: f64,
    /// equivalent to BBR.cwnd_gain: The dynamic gain factor used to scale the estimated BDP to produce a congestion window (C.cwnd).
    cwnd_gain: f64,
    /// equivalent to BBR.DefaultCwndGain: A constant specifying the minimum gain value that allows the sending rate to double each round (2) BBRStartupCwndGain.
    /// Used by default in most phases for BBR.cwnd_gain.
    default_cwnd_gain: f64,
    /// used to generate random numbers when deciding how long to wait before probing again
    probe_rng: Pcg32,
    /// cwnd gain used when probing up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    probe_bw_up_cwnd_gain: f64,
    /// cwnd gain used when probing RTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.1>
    probe_rtt_cwnd_gain: f64,
    /// equivalent to BBR.state: The current state of a BBR flow in the BBR state machine. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-3.3>
    state: BbrState,
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
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-4.1>,
    /// measured during the current or previous bandwidth probing cycle (or during Startup, if the flow is still in that state). (Part of the long-term model.)
    max_bw: f64,
    /// equivalent to BBR.bw_shortterm: The short-term maximum sending bandwidth that the algorithm estimates is safe for matching the current network path delivery rate,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_bw. (Part of the short-term model.)
    bw_shortterm: f64,
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
    /// equivalent to BBR.inflight_shortterm: Analogous to BBR.bw_shortterm,
    /// the short-term maximum inflight that the algorithm estimates is safe for matching the current network path delivery process,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_inflight or inflight_longterm. (Part of the short-term model.)
    inflight_shortterm: u64,
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
    /// equivalent to C.delivered_time: The wall clock time when C.delivered was last updated. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-4.1.1.2.1>
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
    /// equivalent to RS: Per-ACK Rate Sample State <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.2>
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
    /// equivalent to BBR.bw_probe_samples: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.2>
    bw_probe_samples: bool,
    /// equivalent to BBR.loss_round_delivered: C.delivered during the first loss of the round
    loss_round_delivered: u64,
    /// equivalent to BBR.loss_in_round: flag set to true when loss occurs during the round
    loss_in_round: bool,
    /// equivalent to BBR.probe_rtt_done_stamp: timestamp when probe RTT state is finished
    probe_rtt_done_stamp: Option<Instant>,
    /// equivalent to BBR.probe_rtt_round_done: set once per round when BBR.probe_rtt_done_stamp to check if we need to switch state
    probe_rtt_round_done: bool,
    /// equivalent to BBR.prior_cwnd: cwnd from last round
    prior_cwnd: u64,
    /// equivalent to BBR.loss_round_start: flag set to true at the very beginning of a round where loss occurred
    loss_round_start: bool,
}

impl Bbr3 {
    fn new(config: Arc<Bbr3Config>, current_mtu: u16) -> Self {
        let probe_rng: Pcg32;
        if let Some(probe_seed) = config.probe_rng_seed {
            probe_rng = Pcg32::seed_from_u64(probe_seed);
        } else {
            probe_rng = Pcg32::from_os_rng();
        }
        let smss = min(
            max(MIN_MAX_DATAGRAM_SIZE, current_mtu) as u64,
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
        // the calculation for initial pacing rate described here <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.2-5>
        let nominal_bandwidth = initial_cwnd as f64 / 0.001;
        let pacing_rate = startup_pacing_gain * nominal_bandwidth;
        Self {
            smss,
            initial_cwnd,
            delivered: 0,
            inflight: 0,
            is_cwnd_limited: false,
            cycle_count: false,
            cwnd: initial_cwnd,
            pacing_rate,
            send_quantum: 2 * smss, // we start high, but it will be adjusted in set_send_quantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.3>
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
            round_count: 0,
            round_start: true,
            next_round_delivered: 0,
            idle_restart: false,
            min_pipe_cwnd: 4 * smss, // 4 * C.SMSS as defined in <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-2.7-4>
            max_bw: 0.0,
            bw_shortterm: 0.0,
            bw: 0.0,
            min_rtt: Duration::from_secs(u64::MAX),
            bdp: 0,
            extra_acked: 0,
            offload_budget: 0,
            max_inflight: 0,
            inflight_longterm: 0,
            inflight_shortterm: 0,
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
            loss_round_delivered: 0,
            loss_in_round: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            prior_cwnd: 0,
            loss_round_start: false,
        }
    }

    /// equivalent to BBREnterStartup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.1-3>
    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
        self.pacing_gain = self.startup_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRResetFullBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.2-4>
    fn reset_full_bw(&mut self) {
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// equivalent to BBRNoteLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.2-11>
    fn note_loss(&mut self) {
        if !self.loss_in_round {
            self.loss_round_delivered = self.delivered;
        }
        self.loss_in_round = true;
    }

    /// equivalent to BBRInflightAtLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.2-11>
    /// We check at what prefix of packet did losses exceed `loss_thresh`
    fn inflight_at_loss(&mut self, lost_bytes: u64) -> u64 {
        if let Some(rate_sample) = self.rs {
            let inflight_prev = rate_sample.tx_in_flight.saturating_sub(lost_bytes);
            let lost_prev = rate_sample.lost.saturating_sub(lost_bytes);
            let compared_loss = inflight_prev.saturating_sub(lost_prev);
            let lost_prefix = (LOSS_THRESH * compared_loss as f64) / (1.0 - LOSS_THRESH);
            let inflight_at_loss = inflight_prev + lost_prefix as u64;
            return inflight_at_loss;
        }
        0
    }

    /// equivalent to BBRSaveCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.4-13>
    fn save_cwnd(&mut self) {
        if !self.loss_in_round && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = max(self.prior_cwnd, self.cwnd);
        }
    }

    /// equivalent to BBRRestoreCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.4-13>
    fn restore_cwnd(&mut self) {
        self.cwnd = max(self.cwnd, self.prior_cwnd);
    }

    /// equivalent to BBRProbeRTTCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.5-1>
    fn probe_rtt_cwnd(&mut self) -> u64 {
        let mut probe_rtt_cwnd = self.bdp_multiple(self.probe_rtt_cwnd_gain);
        probe_rtt_cwnd = max(probe_rtt_cwnd, self.min_pipe_cwnd);
        probe_rtt_cwnd
    }

    /// equivalent to BBRBoundCwndForProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.5-1>
    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = min(self.cwnd, self.probe_rtt_cwnd());
        }
    }

    /// equivalent to BBRTargetInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.3-6>
    fn target_inflight(&self) -> u64 {
        min(self.bdp, self.cwnd)
    }

    /// equivalent to BBRHandleInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.2-1>
    fn handle_inflight_too_high(&mut self, now: Instant) {
        self.bw_probe_samples = false;
        if let Some(rate_sample) = self.rs {
            if !rate_sample.is_app_limited {
                self.inflight_longterm = max(
                    rate_sample.tx_in_flight,
                    (self.target_inflight() as f64 * BETA) as u64,
                );
            }
        }

        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            self.start_probe_bw_down(now);
        }
    }

    /// equivalent to IsInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.2-1>
    fn is_inflight_too_high(&self) -> bool {
        if let Some(rate_sample) = self.rs {
            return rate_sample.lost as f64 > rate_sample.tx_in_flight as f64 * LOSS_THRESH;
        }
        false
    }

    /// equivalent to BBRCheckStartupHighLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.3>
    fn check_startup_high_loss(&mut self) {
        if self.full_bw_reached {
            return;
        }

        if self.is_inflight_too_high() {
            let mut new_inflight_hi = self.bdp.max(self.inflight_latest);
            if let Some(rate_sample) = self.rs {
                if new_inflight_hi < rate_sample.delivered {
                    new_inflight_hi = rate_sample.delivered;
                }
            }
            self.inflight_longterm = new_inflight_hi;
            self.full_bw_reached = true;
        }
    }

    /// equivalent to BBREnterProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6>
    fn enter_probe_bw(&mut self, now: Instant) {
        self.cwnd_gain = self.default_cwnd_gain;
        self.start_probe_bw_down(now);
    }

    /// equivalent to BBRPickProbeWait <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.3-6>
    fn pick_probe_wait(&mut self) {
        // 0 or 1
        self.rounds_since_bw_probe = self.probe_rng.random_bool(0.5) as u64;
        self.bw_probe_wait = Duration::from_millis(
            MIN_PROBE_WAIT_MS + self.probe_rng.random_range(0..=MAX_ADDED_PROBE_WAIT_MS),
        );
    }

    /// equivalent to BBRHasElapsedInPhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
    fn has_elapsed_in_phase(&mut self, interval: Duration, now: Instant) -> bool {
        if let Some(cycle_stamp) = self.cycle_stamp {
            now > cycle_stamp.checked_add(interval).unwrap_or(cycle_stamp)
        } else {
            true
        }
    }

    /// equivalent to BBRExitProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.4>
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// equivalent to BBRCheckProbeRTTDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.3-4>
    fn check_probe_rtt_done(&mut self, now: Instant) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if now > probe_rtt_done_stamp {
                self.probe_rtt_min_stamp = Some(now);
                self.restore_cwnd();
                self.exit_probe_rtt(now);
            }
        }
    }

    /// equivalent to BBRIsTimeToProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.3-6>
    fn maybe_enter_probe_bw_refill(&mut self, now: Instant) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    /// equivalent to BBRIsTimeToGoDown <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-6>
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

    /// equivalent to BBRIsRenoCoexistenceProbeTime <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.5.3-6>
    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self.target_inflight();
        let rounds = min(reno_rounds, MAX_RENO_ROUNDS);
        self.rounds_since_bw_probe >= rounds
    }

    /// equivalent to BBRBDPMultiple <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.2-2>
    fn bdp_multiple(&mut self, gain: f64) -> u64 {
        if self.min_rtt == Duration::from_secs(u64::MAX) {
            return self.initial_cwnd;
        }
        self.bdp = (self.bw * self.min_rtt.as_secs_f64()).round() as u64;
        (gain * self.bdp as f64) as u64
    }

    /// equivalent to BBRUpdateOffloadBudget <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.8>
    fn update_offload_budget(&mut self) {
        self.offload_budget = self.send_quantum;
    }

    /// equivalent to BBRQuantizationBudget <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.2-2>
    fn quantization_budget(&mut self, inflight_cap: u64) -> u64 {
        self.update_offload_budget();
        let mut inflight_cap = max(inflight_cap, self.offload_budget);
        inflight_cap = max(inflight_cap, self.min_pipe_cwnd);
        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            inflight_cap += 2 * self.smss;
        }
        inflight_cap
    }

    /// equivalent to BBRInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.2-2>
    fn get_inflight(&mut self, gain: f64) -> u64 {
        let inflight_cap = self.bdp_multiple(gain);
        self.quantization_budget(inflight_cap)
    }

    /// equivalent to BBRUpdateMaxInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.2-2>
    fn update_max_inflight(&mut self) {
        let mut inflight_cap = self.bdp_multiple(self.cwnd_gain);
        inflight_cap += self.extra_acked;
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    /// equivalent to BBRResetCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.bw_latest = 0.0;
        self.inflight_latest = 0;
    }

    /// equivalent to BBRStartRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.1-9>
    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
    }

    /// equivalent to BBRUpdateRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.1-9>
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

    /// equivalent to BBRStartProbeBW_DOWN <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-4>
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

    /// equivalent to BBRInflightWithHeadroom <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == u64::MAX {
            return u64::MAX;
        }
        let total_headroom = max(self.smss, (HEADROOM * self.inflight_longterm as f64) as u64);
        if let Some(inflight_with_headroom) = self.inflight_longterm.checked_sub(total_headroom) {
            max(inflight_with_headroom, self.min_pipe_cwnd)
        } else {
            self.min_pipe_cwnd
        }
    }

    /// equivalent to BBRSetPacingRateWithGain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.2-7>
    fn set_pacing_rate_with_gain(&mut self, gain: f64) {
        let rate = gain * self.bw * (100.0 - self.pacing_margin_percent) / 100.0;
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// equivalent to BBRRaiseInflightLongtermSlope <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
    fn raise_inflight_long_term_slope(&mut self) {
        let growth_this_round = self
            .smss
            .checked_shl(self.bw_probe_up_rounds)
            .unwrap_or(u64::MAX);
        self.bw_probe_up_rounds = min(self.bw_probe_up_rounds + 1, MAX_LONG_TERM_PROBE_UP_ROUNDS);
        self.probe_up_cnt = max(self.cwnd / growth_this_round, 1);
    }

    /// equivalent to BBRProbeInflightLongtermUpward <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
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

    /// equivalent to BBRAdvanceMaxBwFilter <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.6>
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count = !self.cycle_count;
    }

    /// equivalent to BBRAdaptLongTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
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
                } else {
                    self.advance_max_bw_filter();
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

    /// equivalent to BBRIsTimeToCruise <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-8>
    fn maybe_update_budget_and_time_to_cruise(&mut self) -> bool {
        if self.inflight > self.inflight_with_headroom() {
            return false;
        }
        if self.inflight <= self.get_inflight(1.0) {
            return true;
        }
        false
    }

    /// equivalent to BBRStartProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.4-4>
    fn start_probe_bw_cruise(&mut self) {
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRResetShortTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = f64::INFINITY;
        self.inflight_shortterm = u64::MAX;
    }

    /// equivalent to BBRInitLowerBounds <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == f64::INFINITY {
            self.bw_shortterm = self.max_bw;
        }
        if self.inflight_shortterm == u64::MAX {
            self.inflight_shortterm = self.cwnd;
        }
    }

    /// equivalent to BBRLossLowerBounds <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn loss_lower_bounds(&mut self) {
        // gives max of both f64
        self.bw_shortterm = [self.bw_latest, BETA * self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = max(
            self.inflight_latest,
            (BETA * self.inflight_shortterm as f64) as u64,
        );
    }

    /// equivalent to BBRBoundBWForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn bound_bw_for_model(&mut self) {
        // gives min of both f64
        self.bw = [self.max_bw, self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::min);
    }

    /// equivalent to BBRStartProbeBW_REFILL <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-4>
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

    /// equivalent to BBRStartProbeBW_UP <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-4>
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

    /// equivalent to BBREnterProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.3-4>
    fn enter_probe_rtt(&mut self) {
        self.state = BbrState::ProbeRtt;
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.probe_rtt_cwnd_gain;
    }

    /// equivalent to BBRHandleRestartFromIdle <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.4.1>
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

    /// equivalent to BBRUpdateProbeBWCyclePhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.3.6-6>
    fn update_probe_bw_cycle_phase(&mut self, now: Instant) {
        if !self.full_bw_reached {
            return;
        }
        self.adapt_long_term_model();
        match self.state {
            BbrState::ProbeBw(ProbeBwSubstate::Down) => {
                if self.maybe_enter_probe_bw_refill(now) {
                    return;
                }
                if self.maybe_update_budget_and_time_to_cruise() {
                    self.start_probe_bw_cruise();
                }
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise) => {
                if self.maybe_enter_probe_bw_refill(now) {}
            }
            BbrState::ProbeBw(ProbeBwSubstate::Refill) => {
                if self.round_start {
                    self.bw_probe_samples = true;
                    self.start_probe_bw_up();
                }
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) => {
                if self.maybe_go_down() {
                    self.start_probe_bw_down(now);
                }
            }
            _ => {}
        }
    }

    /// equivalent to BBRUpdateLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
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

    /// equivalent to BBRAdaptLowerBoundsFromCongestion <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn adapt_lower_bounds_from_congestion(&mut self) {
        match self.state {
            BbrState::ProbeBw(_) => {}
            _ => {
                if self.loss_in_round {
                    self.init_lower_bounds();
                    self.loss_lower_bounds();
                }
            }
        }
    }

    /// equivalent to BBRUpdateMaxBw <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.5>
    fn update_max_bw(&mut self, p: BbrPacket) {
        self.update_round(p);
        if let Some(rate_sample) = self.rs {
            if rate_sample.delivery_rate > 0.0
                && (rate_sample.delivery_rate >= self.max_bw || !rate_sample.is_app_limited)
            {
                self.max_bw_filter.update_max(
                    self.cycle_count as u64,
                    rate_sample.delivery_rate.round() as u64,
                );

                self.max_bw = self.max_bw_filter.get_max() as f64;
            }
        }
    }

    /// equivalent to BBRUpdateCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn update_congestion_signals(&mut self, p: BbrPacket) {
        self.update_max_bw(p);
        if !self.loss_round_start {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        self.loss_in_round = false;
    }

    /// equivalent to BBRUpdateACKAggregation <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.9>
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

    /// equivalent to BBRCheckFullBWReached <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.2-6>
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

    /// equivalent to BBREnterDrain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.2>
    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        self.pacing_gain = self.drain_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRCheckStartupDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.1.1-6>
    fn check_startup_done(&mut self) {
        self.check_startup_high_loss();
        if self.state == BbrState::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    /// equivalent to BBRCheckDrainDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.2-3>
    fn check_drain_done(&mut self, now: Instant) {
        if self.state == BbrState::Drain && self.inflight <= self.get_inflight(1.0) {
            self.enter_probe_bw(now);
        }
    }

    /// equivalent to BBRUpdateMinRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.3>
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

    /// equivalent to BBRHandleProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.3-4>
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

    /// equivalent to BBRCheckProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.3.4.3-4>
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
        if self.delivered > 0 {
            self.idle_restart = false;
        }
    }

    /// equivalent to BBRAdvanceLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.3-8>
    fn advance_latest_delivery_signals(&mut self) {
        if self.loss_round_start {
            if let Some(rate_sample) = self.rs {
                self.bw_latest = rate_sample.delivery_rate;
                self.inflight_latest = rate_sample.delivered;
            }
        }
    }

    /// equivalent to BBRUpdateModelAndState <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.2.3>
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

    /// equivalent to BBRSetPacingRate <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.2-7>
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// equivalent to BBRSetSendQuantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.3>
    /// this version is based on a version of bbr2 from quiche
    fn set_send_quantum(&mut self) {
        self.send_quantum = match self.pacing_rate {
            rate if rate < PACING_RATE_1_2MBPS => MAX_DATAGRAM_SIZE,
            rate if rate < PACING_RATE_24MBPS => 2 * MAX_DATAGRAM_SIZE,
            _ => min((self.pacing_rate / 1000.0) as u64, HIGH_PACE_MAX_QUANTUM),
        };
    }

    /// equivalent to BBRBoundCwndForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.7>
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

    /// equivalent to BBRSetCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.6.4.6>
    fn set_cwnd(&mut self) {
        self.update_max_inflight();
        if self.full_bw_reached {
            if let Some(rate_sample) = self.rs {
                self.cwnd = min(self.cwnd + rate_sample.newly_acked, self.max_inflight);
            } else {
                self.cwnd = min(self.cwnd, self.max_inflight);
            }
        } else if self.cwnd < self.max_inflight || self.delivered < self.initial_cwnd {
            if let Some(rate_sample) = self.rs {
                self.cwnd += rate_sample.newly_acked;
            }
        }
        self.cwnd = max(self.cwnd, self.min_pipe_cwnd);
        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    /// equivalent to BBRUpdateControlParameters <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.2.3>
    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    /// equivalent to IsNewestPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-4.1.2.3-3>
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

    /// equivalent to BBRHandleLostPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.10.2-11>
    fn process_lost_packet(&mut self, lost_bytes: u64, packet_index: usize, now: Instant) {
        let p = self.packets[packet_index];
        self.note_loss();
        if !self.bw_probe_samples {
            return;
        }
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_lost += lost_bytes;
            rate_sample.tx_in_flight = p.tx_in_flight;
            rate_sample.lost = self.lost.saturating_sub(p.lost);
            rate_sample.is_app_limited = p.is_app_limited;
            if self.is_inflight_too_high() {
                rate_sample.tx_in_flight = self.inflight_at_loss(lost_bytes);
                self.handle_inflight_too_high(now);
            }
            self.rs = Some(rate_sample);
        }
        self.packets.remove(packet_index);
    }
}
impl Controller for Bbr3 {
    fn on_packet_sent(&mut self, now: Instant, bytes: u16, packet_number: u64) {
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
            lost: self.lost,
            acknowledged: false,
            stale: false,
            round_count: self.round_count,
        });
        self.handle_restart_from_idle(now);
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
                        rate_sample.send_elapsed = p.send_time - p.first_send_time;
                        rate_sample.ack_elapsed =
                            self.delivered_time.unwrap_or(now) - p.delivered_time;
                        rate_sample.last_end_seq = packet_number;
                        self.first_send_time = Some(p.send_time);
                        rate_sample.last_packet = *p;
                        self.rs = Some(rate_sample);
                        self.update_model_and_state(rate_sample.last_packet, now);
                        self.update_control_parameters();
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
                        lost: 0,
                        last_end_seq: packet_number,
                        last_packet: *p,
                    };
                    self.rs = Some(rate_sample);
                    self.first_send_time = Some(p.send_time);
                    self.srtt = rate_sample.rtt;
                    self.update_model_and_state(rate_sample.last_packet, now);
                    self.update_control_parameters();
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
            if app_limited && self.delivered > self.app_limited {
                self.app_limited = largest_packet_num;
            } else {
                self.app_limited = 0;
            }
            if let Some(mut rate_sample) = self.rs {
                if rate_sample.prior_delivered == 0 {
                    return;
                }
                rate_sample.interval = max(rate_sample.send_elapsed, rate_sample.ack_elapsed);
                rate_sample.delivered = self.delivered.saturating_sub(rate_sample.prior_delivered);
                // ignore this condition on an initially high min rtt as per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-4.1.2.3-5>
                if rate_sample.interval < self.min_rtt
                    && self.min_rtt != Duration::from_secs(u64::MAX)
                {
                    return;
                }
                if rate_sample.interval != Duration::ZERO {
                    rate_sample.delivery_rate =
                        rate_sample.delivered as f64 / rate_sample.interval.as_secs_f64();
                }
                if rate_sample.delivered >= self.cwnd {
                    self.is_cwnd_limited = true;
                }
                self.rs = Some(rate_sample);
                self.packets.retain(|&p| !p.stale);
                for p in self.packets.iter_mut() {
                    if p.acknowledged || self.round_count - p.round_count > ROUND_COUNT_WINDOW {
                        p.stale = true;
                    }
                }
                rate_sample.newly_acked = 0;
                rate_sample.lost = 0;
                rate_sample.newly_lost = 0;
                self.rs = Some(rate_sample);
            }
        } else if self.app_limited > 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
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

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.smss = min(
            max(MIN_MAX_DATAGRAM_SIZE, new_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
        self.set_cwnd();
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
    probe_rng_seed: Option<u64>,
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

    #[test]
    fn test_probe_rng() {
        let seed: u64 = 123456789;
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
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2949));
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2590));
    }
}
