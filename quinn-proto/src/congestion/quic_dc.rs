use std::any::Any;
use std::cmp;
use std::sync::Arc;

use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

/// QUIC-DC State Variables
#[derive(Debug, Default, Clone)]
pub(super) struct State {
    /// Minimum RTT observed (propagation delay)
    min_rtt: Option<Duration>,
    /// Current congestion window
    window: u64,
    /// Slow start threshold
    ssthresh: u64,
    /// Recovery start time
    recovery_start_time: Option<Instant>,
    /// Bandwidth estimate (bytes per second)
    bwe: f64,
    /// Last BWE update time
    last_bwe_update: Option<Instant>,
    /// Congestion window increment stored during congestion avoidance
    cwnd_inc: u64,
}

impl State {
    fn update_min_rtt(&mut self, rtt: Duration) {
        if let Some(min) = self.min_rtt {
            if rtt < min {
                self.min_rtt = Some(rtt);
            }
        } else {
            self.min_rtt = Some(rtt);
        }
    }
}

/// QUIC Delay Control congestion controller
#[derive(Debug, Clone)]
pub struct QuicDc {
    config: Arc<QuicDcConfig>,
    current_mtu: u64,
    state: State,
    /// Copy of the controller state to restore when a spurious congestion event is detected.
    pre_congestion_state: Option<State>,
}

impl QuicDc {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<QuicDcConfig>, _now: Instant, current_mtu: u16) -> Self {
        Self {
            state: State {
                window: config.initial_window,
                ssthresh: u64::MAX,
                ..Default::default()
            },
            current_mtu: current_mtu as u64,
            pre_congestion_state: None,
            config,
        }
    }

    fn minimum_window(&self) -> u64 {
        2 * self.current_mtu
    }
}

impl Controller for QuicDc {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if app_limited
            || self
                .state
                .recovery_start_time
                .map(|recovery_start_time| sent <= recovery_start_time)
                .unwrap_or(false)
        {
            return;
        }

        self.state.update_min_rtt(rtt.get());

        // Update BWE
        if let Some(last) = self.state.last_bwe_update {
            let interval = now.saturating_duration_since(last);
            if interval > Duration::ZERO {
                let sample = bytes as f64 / interval.as_secs_f64();
                self.state.bwe = 0.2 * self.state.bwe + 0.8 * sample;
            }
        }
        self.state.last_bwe_update = Some(now);

        if let Some(min_rtt) = self.state.min_rtt {
            let owqd = rtt.get().saturating_sub(min_rtt);
            let owqd_th = min_rtt * 8 / 10; // 80% of min_rtt

            if owqd > owqd_th {
                // Congestion event due to high queuing delay
                self.on_congestion_event(now, sent, false, false, 0);
                return;
            }

            if self.state.window < self.state.ssthresh {
                // Slow start
                self.state.window += bytes;
            } else {
                // Congestion avoidance - additive increase
                self.state.cwnd_inc += bytes;
                if self.state.cwnd_inc >= self.current_mtu {
                    self.state.window += self.current_mtu;
                    self.state.cwnd_inc = 0;
                }
            }
        } else {
            // No min_rtt yet, slow start
            self.state.window += bytes;
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        _lost_bytes: u64,
    ) {
        if self
            .state
            .recovery_start_time
            .map(|recovery_start_time| sent <= recovery_start_time)
            .unwrap_or(false)
        {
            return;
        }

        // Save state in case this event ends up being spurious
        if !is_ecn {
            self.pre_congestion_state = Some(self.state.clone());
        }

        self.state.recovery_start_time = Some(now);

        // QUIC-DC / Westwood+ style: set CWND = BWE * min_rtt
        if let Some(min_rtt) = self.state.min_rtt {
            let new_cwnd = (self.state.bwe * min_rtt.as_secs_f64()) as u64;
            self.state.ssthresh = cmp::max(new_cwnd, self.minimum_window());
        } else {
            self.state.ssthresh = cmp::max(self.state.window / 2, self.minimum_window());
        }
        self.state.window = self.state.ssthresh;
        self.state.cwnd_inc = 0;

        if is_persistent_congestion {
            self.state.recovery_start_time = None;
            self.state.ssthresh = cmp::max(self.state.window / 2, self.minimum_window());
            self.state.window = self.minimum_window();
            self.state.cwnd_inc = 0;
        }
    }

    fn on_spurious_congestion_event(&mut self) {
        if let Some(prior_state) = self.pre_congestion_state.take() {
            if self.state.window < prior_state.window {
                self.state = prior_state;
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.state.window = self.state.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.state.window
    }

    fn metrics(&self) -> super::ControllerMetrics {
        super::ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: Some(self.state.ssthresh),
            pacing_rate: None,
            min_rtt: self.state.min_rtt,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `QuicDc` congestion controller
#[derive(Debug, Clone)]
pub struct QuicDcConfig {
    initial_window: u64,
}

impl QuicDcConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for QuicDcConfig {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE),
        }
    }
}

impl ControllerFactory for QuicDcConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(QuicDc::new(self, now, current_mtu))
    }
}