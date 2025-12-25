mod min_max;

use crate::RttEstimator;
use crate::congestion::bbr3::min_max::MinMax;
use crate::congestion::{Controller, ControllerFactory, ControllerMetrics};
use crate::{Duration, Instant};
use rand::Rng;
use std::any::Any;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::sync::Arc;

const MAX_BW_FILTER_LEN: usize = 2;
const EXTRA_ACKED_FILTER_LEN: usize = 10;
const ROUND_COUNT_WINDOW: u64 = 10;

const MAX_DATAGRAM_SIZE: u64 = 65527;

/// 1.2Mbps in bytes/sec
const PACING_RATE_1_2MBPS: f64 = 1200.0 * 1000.0;

/// 24Mbps in bytes/sec
const PACING_RATE_24MBPS: f64 = 24000.0 * 1000.0;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ProbeBwSubstate {
    /// Deceleration: sends slower than delivery rate to reduce queue
    Down,

    /// Cruising: sends at delivery rate to maintain high utilization
    Cruise,

    /// Refill: sends at BBR.bw for one RTT to fill pipe before probing up
    Refill,

    /// Acceleration: sends faster than delivery rate to probe for more bandwidth
    Up,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum BbrState {
    /// Initial state: rapidly probes for bandwidth using high pacing_gain
    Startup,

    /// Drains queue created during Startup by using low pacing_gain (< 1.0)
    Drain,

    /// Steady-state phase that cycles through bandwidth probing tactics
    ProbeBw(ProbeBwSubstate),

    /// Temporarily reduces inflight to measure true min_rtt
    ProbeRtt,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum AckPhase {
    ProbeStarting,
    ProbeStopping,
    Refilling,
    ProbeFeedback,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct BbrPacket {
    pub delivered: u64,
    pub delivered_time: Instant,
    pub first_send_time: Instant,
    pub send_time: Instant,
    pub is_app_limited: bool,
    pub tx_in_flight: u64,
    pub packet_number: u64,
    pub lost: u64,
    pub acknowledged: bool,
    pub stale: bool,
    pub round_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct BbrRateSample {
    pub delivery_rate: f64,
    pub is_app_limited: bool,
    pub interval: Duration,
    pub delivered: u64,
    pub prior_delivered: u64,
    pub prior_time: Instant,
    pub send_elapsed: Duration,
    pub ack_elapsed: Duration,
    pub rtt: Duration,
    pub tx_in_flight: u64,
    pub newly_acked: u64,
    pub newly_lost: u64,
    pub lost: u64,
    pub last_end_seq: u64,
    pub last_packet: BbrPacket,
}

/// Experimental! Use at your own risk.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.txt>
#[derive(Debug, Clone)]
pub struct Bbr3 {
    smss: u64,
    initial_cwnd: u64,
    delivered: u64,
    inflight: u64,
    is_cwnd_limited: bool,
    cycle_count: u64,
    cwnd: u64,
    pacing_rate: f64,
    send_quantum: u64,
    pacing_gain: f64,
    default_pacing_gain: f64,
    probe_bw_down_pacing_gain: f64,
    probe_bw_up_pacing_gain: f64,
    startup_pacing_gain: f64,
    drain_pacing_gain: f64,
    pacing_margin_percent: f64,
    cwnd_gain: f64,
    default_cwnd_gain: f64,
    probe_up_cwnd_gain: f64,
    probe_rtt_cwnd_gain: f64,
    state: BbrState,
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    idle_restart: bool,
    loss_thresh: f64,
    beta: f64,
    headroom: f64,
    min_pipe_cwnd: u64,
    max_bw: f64,
    bw_shortterm: f64,
    bw: f64,
    min_rtt: Duration,
    bdp: u64,
    extra_acked: u64,
    offload_budget: u64,
    max_inflight: u64,
    inflight_longterm: u64,
    inflight_shortterm: u64,
    bw_latest: f64,
    inflight_latest: u64,
    max_bw_filter: MinMax,
    extra_acked_interval_start: Option<Instant>,
    extra_acked_delivered: u64,
    extra_acked_filter: MinMax,
    full_bw_reached: bool,
    full_bw_now: bool,
    full_bw: f64,
    full_bw_count: u64,
    min_rtt_stamp: Option<Instant>,
    min_rtt_filter_len: u64,
    probe_rtt_duration: Duration,
    probe_rtt_interval: Duration,
    probe_rtt_min_delay: Duration,
    probe_rtt_min_stamp: Option<Instant>,
    probe_rtt_expired: bool,
    delivered_time: Instant,
    first_send_time: Instant,
    app_limited: u64,
    pending_transmissions: u64,
    lost: u64,
    srtt: Duration,
    packets: VecDeque<BbrPacket>,
    rs: Option<BbrRateSample>,
    rounds_since_bw_probe: u64,
    bw_probe_wait: Duration,
    bw_probe_up_rounds: u32,
    bw_probe_up_acks: u64,
    probe_up_cnt: u64,
    cycle_stamp: Option<Instant>,
    ack_phase: AckPhase,
    bw_probe_samples: bool,
    loss_round_delivered: u64,
    loss_in_round: bool,
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
    prior_cwnd: u64,
    loss_round_start: bool,
}

impl Bbr3 {
    pub(super) fn new(config: Arc<Bbr3Config>, current_mtu: u16) -> Self {
        // rfc9000 making sure maximum datagram size is between acceptable values
        // default values come from: https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.txt
        let mut smss = max(1200, current_mtu) as u64;
        smss = min(smss, MAX_DATAGRAM_SIZE);
        let initial_cwnd = config.initial_window;
        let nominal_bandwidth = initial_cwnd as f64 / 0.001;
        Self {
            smss,
            initial_cwnd,
            delivered: 0,
            inflight: 0,
            is_cwnd_limited: false,
            cycle_count: 0,
            cwnd: initial_cwnd,
            pacing_rate: 2.773 * nominal_bandwidth,
            send_quantum: 2 * smss,
            pacing_gain: 2.773,
            startup_pacing_gain: 2.773,
            default_pacing_gain: 1.0,
            probe_bw_down_pacing_gain: 0.9,
            probe_bw_up_pacing_gain: 1.25,
            drain_pacing_gain: 0.5,
            pacing_margin_percent: 1.0,
            cwnd_gain: 2.0,
            default_cwnd_gain: 2.0,
            probe_up_cwnd_gain: 2.25,
            state: BbrState::Startup,
            round_count: 0,
            round_start: true,
            next_round_delivered: 0,
            idle_restart: false,
            loss_thresh: 0.02,
            beta: 0.7,
            headroom: 0.15,
            min_pipe_cwnd: 4 * MAX_DATAGRAM_SIZE,
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
            max_bw_filter: MinMax::new(MAX_BW_FILTER_LEN as u64),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            extra_acked_filter: MinMax::new(EXTRA_ACKED_FILTER_LEN as u64),
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0.0,
            full_bw_count: 0,
            min_rtt_stamp: None,
            min_rtt_filter_len: 10,
            probe_rtt_cwnd_gain: 0.5,
            probe_rtt_duration: Duration::from_millis(200),
            probe_rtt_interval: Duration::from_secs(5),
            probe_rtt_min_delay: Duration::ZERO,
            probe_rtt_min_stamp: None,
            probe_rtt_expired: false,
            delivered_time: Instant::now(),
            first_send_time: Instant::now(),
            app_limited: 0,
            pending_transmissions: 0,
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

    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
        self.pacing_gain = self.startup_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    fn reset_full_bw(&mut self) {
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    fn note_loss(&mut self) {
        if !self.loss_in_round {
            self.loss_round_delivered = self.delivered;
        }
        self.loss_in_round = true;
    }

    fn inflight_at_loss(&mut self, lost_bytes: u64) -> u64 {
        let inflight_prev;
        if let Some(rate_sample) = self.rs {
            inflight_prev = rate_sample.tx_in_flight.saturating_sub(lost_bytes);
            let lost_prev = rate_sample.lost.saturating_sub(lost_bytes);
            let compared_loss = inflight_prev.saturating_sub(lost_prev);
            let lost_prefix = (self.loss_thresh * compared_loss as f64) / (1.0 - self.loss_thresh);
            let inflight_at_loss = inflight_prev.saturating_sub(lost_prefix as u64);
            return inflight_at_loss;
        }
        0
    }

    fn save_cwnd(&mut self) {
        if !self.loss_in_round && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = max(self.prior_cwnd, self.cwnd);
        }
    }

    fn restore_cwnd(&mut self) {
        self.cwnd = max(self.cwnd, self.prior_cwnd);
    }

    fn probe_rtt_cwnd(&mut self) -> u64 {
        let mut probe_rtt_cwnd = self.bdp_multiple(self.probe_rtt_cwnd_gain);
        probe_rtt_cwnd = max(probe_rtt_cwnd, self.min_pipe_cwnd);
        probe_rtt_cwnd
    }

    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = min(self.cwnd, self.probe_rtt_cwnd());
        }
    }

    fn target_inflight(&self) -> u64 {
        min(self.bdp, self.cwnd)
    }

    fn handle_inflight_too_high(&mut self) {
        self.bw_probe_samples = false;
        if let Some(rate_sample) = self.rs {
            if !rate_sample.is_app_limited {
                self.inflight_longterm = max(
                    rate_sample.tx_in_flight,
                    (self.target_inflight() as f64 * self.beta) as u64,
                );
            }
        }

        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            self.start_probe_bw_down();
        }
    }

    fn is_inflight_too_high(&self) -> bool {
        if let Some(rate_sample) = self.rs {
            return rate_sample.lost as f64 > (rate_sample.tx_in_flight) as f64 * self.loss_thresh;
        }
        false
    }

    fn check_startup_high_loss(&mut self) {
        if self.full_bw_reached {
            return;
        }

        if self.is_inflight_too_high() {
            let mut new_inflight_hi = self.bdp;
            if let Some(rate_sample) = self.rs {
                if new_inflight_hi < rate_sample.prior_delivered {
                    new_inflight_hi = rate_sample.prior_delivered;
                }
            }

            self.inflight_latest = new_inflight_hi;
            self.full_bw_reached = true;
        }
    }

    fn enter_probe_bw(&mut self) {
        self.cwnd_gain = self.default_cwnd_gain;
        self.start_probe_bw_down();
    }

    fn pick_probe_wait(&mut self) {
        let mut rng = rand::rng();
        // 0 or 1
        self.rounds_since_bw_probe = rng.random_bool(0.5) as u64;
        self.bw_probe_wait = Duration::from_millis(2000 + rng.random_range(0..=1000));
    }

    fn has_elapsed_in_phase(&mut self, interval: Duration) -> bool {
        if let Some(cycle_stamp) = self.cycle_stamp {
            Instant::now() > cycle_stamp.checked_add(interval).unwrap_or(cycle_stamp)
        } else {
            true
        }
    }

    fn exit_probe_rtt(&mut self) {
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down();
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    fn check_probe_rtt_done(&mut self) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if Instant::now() > probe_rtt_done_stamp {
                self.probe_rtt_min_stamp = Some(Instant::now());
                self.restore_cwnd();
                self.exit_probe_rtt();
            }
        }
    }

    // BBRIsTimeToProbeBW in IETF spec
    fn maybe_enter_probe_bw_refill(&mut self) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait) || self.is_reno_coexistence_probe_time() {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    // BBRIsTimeToGoDown in IETF spec
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

    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self.target_inflight();
        let rounds = min(reno_rounds, 63);
        self.rounds_since_bw_probe >= rounds
    }

    fn bdp_multiple(&mut self, gain: f64) -> u64 {
        if self.min_rtt == Duration::from_secs(u64::MAX) {
            return self.initial_cwnd;
        }
        self.bdp = (self.bw * self.min_rtt.as_secs_f64()).round() as u64;
        (gain * self.bdp as f64) as u64
    }

    fn update_offload_budget(&mut self) {
        self.offload_budget = self.send_quantum;
    }

    fn quantization_budget(&mut self, inflight_cap: u64) -> u64 {
        self.update_offload_budget();
        let mut inflight_cap = max(inflight_cap, self.offload_budget);
        inflight_cap = max(inflight_cap, self.min_pipe_cwnd);
        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            inflight_cap += 2 * self.smss;
        }
        inflight_cap
    }

    fn get_inflight(&mut self, gain: f64) -> u64 {
        let inflight_cap = self.bdp_multiple(gain);
        self.quantization_budget(inflight_cap)
    }

    fn update_max_inflight(&mut self) {
        let mut inflight_cap = self.bdp_multiple(self.cwnd_gain);
        inflight_cap += self.extra_acked;
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.bw_latest = 0.0;
        self.inflight_latest = 0;
    }

    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
    }

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

    fn start_probe_bw_down(&mut self) {
        self.reset_congestion_signals();
        self.probe_up_cnt = u64::MAX;
        self.pick_probe_wait();
        self.cycle_stamp = Some(Instant::now());
        self.ack_phase = AckPhase::ProbeStopping;
        self.start_round();
        self.pacing_gain = self.probe_bw_down_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Down);
    }

    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == u64::MAX {
            return u64::MAX;
        }
        let total_headroom = max(
            self.smss,
            (self.headroom * self.inflight_longterm as f64) as u64,
        );
        if let Some(inflight_with_headroom) = self.inflight_longterm.checked_sub(total_headroom) {
            max(inflight_with_headroom, self.min_pipe_cwnd)
        } else {
            self.min_pipe_cwnd
        }
    }

    fn set_pacing_rate_with_gain(&mut self, gain: f64) {
        let rate = gain * self.bw * (100.0 - self.pacing_margin_percent) / 100.0;
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    fn raise_inflight_long_term_slope(&mut self) {
        let growth_this_round = self
            .smss
            .checked_shl(self.bw_probe_up_rounds)
            .unwrap_or(u64::MAX);
        self.bw_probe_up_rounds = min(self.bw_probe_up_rounds + 1, 30);
        self.probe_up_cnt = max(self.cwnd / growth_this_round, 1);
    }

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

    fn advance_max_bw_filter(&mut self) {
        self.cycle_count += 1;
    }

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

    // BBRIsTimeToCruise in IETF spec
    fn maybe_update_budget_and_time_to_cruise(&mut self) -> bool {
        if self.inflight > self.inflight_with_headroom() {
            return false;
        }
        if self.inflight <= self.get_inflight(1.0) {
            return true;
        }
        false
    }

    fn start_probe_bw_cruise(&mut self) {
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = f64::INFINITY;
        self.inflight_shortterm = u64::MAX;
    }

    fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == f64::INFINITY {
            self.bw_shortterm = self.max_bw;
        }
        if self.inflight_shortterm == u64::MAX {
            self.inflight_shortterm = self.cwnd;
        }
    }

    fn loss_lower_bounds(&mut self) {
        // gives max of both f64
        self.bw_shortterm = [self.bw_latest, self.beta * self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = max(
            self.inflight_latest,
            (self.beta * self.inflight_shortterm as f64) as u64,
        );
    }

    fn bound_bw_for_model(&mut self) {
        // gives min of both f64
        self.bw = [self.max_bw, self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::min);
    }

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

    fn start_probe_bw_up(&mut self) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.start_round();
        self.reset_full_bw();
        if let Some(rate_sample) = self.rs {
            self.full_bw = rate_sample.delivery_rate;
        }
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        self.pacing_gain = self.probe_bw_up_pacing_gain;
        self.cwnd_gain = self.probe_up_cwnd_gain;
        self.raise_inflight_long_term_slope();
    }

    fn enter_probe_rtt(&mut self) {
        self.state = BbrState::ProbeRtt;
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.probe_rtt_cwnd_gain;
    }

    fn handle_restart_from_idle(&mut self, now: Instant) {
        if self.inflight == 0 && self.app_limited != 0 {
            self.idle_restart = true;
            self.extra_acked_interval_start = Some(now);
            match self.state {
                BbrState::ProbeBw(_) => {
                    self.set_pacing_rate_with_gain(1.0);
                }
                BbrState::ProbeRtt => {
                    self.check_probe_rtt_done();
                }
                _ => {}
            }
        }
    }

    fn update_probe_bw_cycle_phase(&mut self) {
        if !self.full_bw_reached {
            return;
        }
        self.adapt_long_term_model();
        match self.state {
            BbrState::ProbeBw(ProbeBwSubstate::Down) => {
                if self.maybe_enter_probe_bw_refill() {
                    return;
                }
                if self.maybe_update_budget_and_time_to_cruise() {
                    self.start_probe_bw_cruise();
                }
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise) => if self.maybe_enter_probe_bw_refill() {},
            BbrState::ProbeBw(ProbeBwSubstate::Refill) => {
                if self.round_start {
                    self.bw_probe_samples = true;
                    self.start_probe_bw_up();
                }
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) => {
                if self.maybe_go_down() {
                    self.start_probe_bw_down();
                }
            }
            _ => {}
        }
    }

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

    fn update_max_bw(&mut self, p: BbrPacket) {
        self.update_round(p);
        if let Some(rate_sample) = self.rs {
            if rate_sample.delivery_rate > 0.0
                && (rate_sample.delivery_rate >= self.max_bw || !rate_sample.is_app_limited)
            {
                self.max_bw_filter
                    .update_max(self.cycle_count, rate_sample.delivery_rate.round() as u64);
                self.max_bw = self.max_bw_filter.get() as f64;
            }
        }
    }

    fn update_congestion_signals(&mut self, p: BbrPacket) {
        self.update_max_bw(p);
        if !self.loss_round_start {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        self.loss_in_round = false;
    }

    fn update_ack_aggregation(&mut self) {
        let interval;
        if let Some(extra_acked_interval_start) = self.extra_acked_interval_start {
            interval = Instant::now() - extra_acked_interval_start;
        } else {
            interval = Duration::from_secs(0);
        }
        let mut expected_delivered = (self.bw * interval.as_secs_f64()) as u64;
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(Instant::now());
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
            self.extra_acked = self.extra_acked_filter.get();
        } else {
            self.extra_acked = extra; // In startup, just remember 1 round
        }
    }

    fn check_full_bw_reached(&mut self) {
        if self.full_bw_now || !self.round_start {
            return;
        }
        if let Some(rate_sample) = self.rs {
            if rate_sample.is_app_limited {
                return;
            }
            if rate_sample.delivery_rate >= self.full_bw * 1.25 {
                self.reset_full_bw();
                self.full_bw = rate_sample.delivery_rate;
                return;
            }
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= 3;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        self.pacing_gain = self.drain_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    fn check_startup_done(&mut self) {
        self.check_startup_high_loss();
        if self.state == BbrState::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    fn check_drain_done(&mut self) {
        if self.state == BbrState::Drain && self.inflight <= self.get_inflight(1.0) {
            self.enter_probe_bw();
        }
    }

    fn update_min_rtt(&mut self) {
        if let Some(probe_rtt_min_stamp) = self.probe_rtt_min_stamp {
            self.probe_rtt_expired = Instant::now()
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
                self.probe_rtt_min_stamp = Some(Instant::now());
            }
        }

        let min_rtt_expired;
        if let Some(min_rtt_stamp) = self.min_rtt_stamp {
            min_rtt_expired = Instant::now()
                > min_rtt_stamp
                    .checked_add(Duration::from_secs(self.min_rtt_filter_len))
                    .unwrap_or(min_rtt_stamp);
        } else {
            min_rtt_expired = true;
        }
        if self.probe_rtt_min_delay < self.min_rtt || min_rtt_expired {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    fn handle_probe_rtt(&mut self) {
        if self.probe_rtt_done_stamp.is_none() && self.inflight <= self.probe_rtt_cwnd() {
            self.probe_rtt_done_stamp = Some(
                Instant::now()
                    .checked_add(self.probe_rtt_duration)
                    .unwrap_or(Instant::now()),
            );
            self.probe_rtt_round_done = false;
            self.start_round();
        } else if self.probe_rtt_done_stamp.is_some() {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }
            if self.probe_rtt_round_done {
                self.check_probe_rtt_done();
            }
        }
    }

    fn check_probe_rtt(&mut self) {
        match self.state {
            BbrState::ProbeRtt => {
                self.handle_probe_rtt();
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

    fn advance_latest_delivery_signals(&mut self) {
        if self.loss_round_start {
            if let Some(rate_sample) = self.rs {
                self.bw_latest = rate_sample.delivery_rate;
            }
            self.inflight_latest = self.delivered;
        }
    }

    fn update_model_and_state(&mut self, p: BbrPacket) {
        self.update_latest_delivery_signals();
        self.update_congestion_signals(p);
        self.update_ack_aggregation();
        self.check_full_bw_reached();
        self.check_startup_done();
        self.check_drain_done();
        self.update_probe_bw_cycle_phase();
        self.update_min_rtt();
        self.check_probe_rtt();
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();
    }

    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    fn set_send_quantum(&mut self) {
        self.send_quantum = match self.pacing_rate {
            rate if rate < PACING_RATE_1_2MBPS => MAX_DATAGRAM_SIZE,
            rate if rate < PACING_RATE_24MBPS => 2 * MAX_DATAGRAM_SIZE,
            _ => min((self.pacing_rate / 1000.0) as u64, 64 * 1024),
        };
    }

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

    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    fn is_newest_packet(&self, send_time: Instant, end_seq: u64) -> bool {
        if send_time > self.first_send_time {
            return true;
        }
        if let Some(rate_sample) = self.rs {
            if end_seq > rate_sample.last_end_seq {
                return true;
            }
        }
        false
    }

    fn process_lost_packet(&mut self, lost_bytes: u64, packet_index: usize) {
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
                self.handle_inflight_too_high();
            }
            self.rs = Some(rate_sample);
        }
        self.packets.remove(packet_index);
    }
}
impl Controller for Bbr3 {
    fn on_packet_sent(&mut self, now: Instant, bytes: u16, packet_number: u64) {
        if self.inflight == 0 {
            self.first_send_time = now;
            self.delivered_time = now;
        }
        if bytes > 0 {
            let added_bytes = bytes as u64;
            self.pending_transmissions += added_bytes;
            self.first_send_time = now;
            self.inflight += added_bytes;
        }
        self.packets.push_back(BbrPacket {
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_send_time: now,
            send_time: Instant::now(),
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

    fn on_packet_acked(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u16,
        packet_number: u64,
        rtt: &RttEstimator,
    ) {
        let bytes64 = bytes as u64;
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_acked += bytes64;
            rate_sample.rtt = rtt.get();
            self.rs = Some(rate_sample);
            self.delivered += bytes64;
            self.delivered_time = now;
        }
        let p_index_result = self
            .packets
            .binary_search_by_key(&(packet_number), |p| p.packet_number);
        let is_newest_packet = self.is_newest_packet(sent, packet_number);
        if let Ok(p_index) = p_index_result {
            if let Some(p) = self.packets.get_mut(p_index) {
                p.acknowledged = true;
                if let Some(mut rate_sample) = self.rs {
                    if is_newest_packet {
                        self.srtt = rate_sample.rtt;
                        rate_sample.prior_delivered = p.delivered;
                        rate_sample.prior_time = p.delivered_time;
                        rate_sample.is_app_limited = p.is_app_limited;
                        rate_sample.tx_in_flight = p.tx_in_flight;
                        rate_sample.send_elapsed = p.send_time - p.first_send_time;
                        rate_sample.ack_elapsed = self.delivered_time - p.delivered_time;
                        rate_sample.last_end_seq = packet_number;
                        self.first_send_time = p.send_time;
                        rate_sample.last_packet = *p;
                        self.rs = Some(rate_sample);
                        self.update_model_and_state(rate_sample.last_packet);
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
                        ack_elapsed: self.delivered_time - p.delivered_time,
                        newly_acked: bytes64,
                        newly_lost: 0,
                        lost: 0,
                        last_end_seq: packet_number,
                        last_packet: *p,
                    };
                    self.rs = Some(rate_sample);
                    self.first_send_time = p.send_time;
                    self.srtt = rate_sample.rtt;
                    self.update_model_and_state(rate_sample.last_packet);
                    self.update_control_parameters();
                }
            }
        }
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        in_flight_ack_eliciting: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inflight = in_flight_ack_eliciting;
        if let Some(largest_packet_num) = largest_packet_num_acked {
            if app_limited {
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
                // ignore this condition on an initially high min rtt as per https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.txt
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
                    if p.acknowledged || p.round_count > ROUND_COUNT_WINDOW {
                        p.stale = true;
                    }
                }
                rate_sample.newly_acked = 0;
                self.rs = Some(rate_sample);
            }
        } else if self.app_limited > 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
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
                self.process_lost_packet(lost_bytes, p_index);
            }
        }
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, packet_number: u64) {
        let lost_bytes_64 = lost_bytes as u64;
        self.lost += lost_bytes_64;
        let p_index_result = self
            .packets
            .binary_search_by_key(&(packet_number), |p| p.packet_number);
        if let Ok(p_index) = p_index_result {
            self.process_lost_packet(lost_bytes_64, p_index);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let mut smss = max(1200, new_mtu) as u64;
        smss = min(smss, 65527);
        self.smss = smss;
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

/// Configuration for the [`Bbr3`] congestion controller
#[derive(Debug, Clone)]
pub struct Bbr3Config {
    initial_window: u64,
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
        }
    }
}

impl ControllerFactory for Bbr3Config {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr3::new(self, current_mtu))
    }
}
