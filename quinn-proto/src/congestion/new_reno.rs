use std::sync::Arc;
use std::time::Instant;

use super::{Controller, ControllerFactory};

/// A simple, standard congestion controller
#[derive(Debug, Clone)]
pub struct NewReno {
    config: Arc<NewRenoConfig>,
    /// Maximum number of bytes in flight that may be sent.
    window: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is
    /// slow start and the window grows by the number of bytes acknowledged.
    ssthresh: u64,
    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: Instant,
}

impl NewReno {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<NewRenoConfig>, now: Instant) -> Self {
        Self {
            window: config.initial_window,
            ssthresh: u64::max_value(),
            recovery_start_time: now,
            config,
        }
    }
}

impl Controller for NewReno {
    fn on_ack(&mut self, _now: Instant, sent: Instant, bytes: u64, congestion_blocked: bool) {
        if !congestion_blocked || sent <= self.recovery_start_time {
            return;
        }
        if self.window < self.ssthresh {
            // Slow start
            self.window += bytes;
        } else {
            // Congestion avoidance
            self.window += self.config.max_datagram_size * bytes / self.window;
        }
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool) {
        if sent <= self.recovery_start_time {
            return;
        }

        self.recovery_start_time = now;
        self.window = (self.window as f32 * self.config.loss_reduction_factor) as u64;
        self.window = self.window.max(self.config.minimum_window);
        self.ssthresh = self.window;

        if is_persistent_congestion {
            self.window = self.config.minimum_window;
        }
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
}

/// Configuration for the `NewReno` congestion controller
#[derive(Debug, Clone)]
pub struct NewRenoConfig {
    max_datagram_size: u64,
    initial_window: u64,
    minimum_window: u64,
    loss_reduction_factor: f32,
}

impl NewRenoConfig {
    /// The sender’s maximum UDP payload size. Does not include UDP or IP overhead.
    ///
    /// Used for calculating initial and minimum congestion windows.
    pub fn max_datagram_size(&mut self, value: u64) -> &mut Self {
        self.max_datagram_size = value;
        self
    }

    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    /// Default minimum congestion window.
    ///
    /// Recommended value: `2 * max_datagram_size`.
    pub fn minimum_window(&mut self, value: u64) -> &mut Self {
        self.minimum_window = value;
        self
    }

    /// Reduction in congestion window when a new loss event is detected.
    pub fn loss_reduction_factor(&mut self, value: f32) -> &mut Self {
        self.loss_reduction_factor = value;
        self
    }
}

impl Default for NewRenoConfig {
    fn default() -> Self {
        const MAX_DATAGRAM_SIZE: u64 = 1232;
        Self {
            max_datagram_size: MAX_DATAGRAM_SIZE,
            initial_window: 14720.max(2 * MAX_DATAGRAM_SIZE).min(10 * MAX_DATAGRAM_SIZE),
            minimum_window: 2 * MAX_DATAGRAM_SIZE,
            loss_reduction_factor: 0.5,
        }
    }
}

impl ControllerFactory for Arc<NewRenoConfig> {
    fn build(&self, now: Instant) -> Box<dyn Controller> {
        Box::new(NewReno::new(self.clone(), now))
    }
}
