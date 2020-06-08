use std::{cmp, net::SocketAddr, time::Duration};

use crate::{congestion, TIMER_GRANULARITY};

/// Description of a particular network path
pub struct PathData {
    pub remote: SocketAddr,
    pub rtt: RttEstimator,
    /// Whether we're enabling ECN on outgoing packets
    pub sending_ecn: bool,
    /// Congestion controller state
    pub congestion: Box<dyn congestion::Controller>,
    pub challenge: Option<u64>,
    pub challenge_pending: bool,
}

impl PathData {
    pub fn new(
        remote: SocketAddr,
        initial_rtt: Duration,
        congestion: Box<dyn congestion::Controller>,
    ) -> Self {
        PathData {
            remote,
            rtt: RttEstimator::new(initial_rtt),
            sending_ecn: true,
            congestion,
            challenge: None,
            challenge_pending: false,
        }
    }

    pub fn from_previous(remote: SocketAddr, prev: &PathData) -> Self {
        PathData {
            remote,
            rtt: prev.rtt,
            congestion: prev.congestion.clone_box(),
            sending_ecn: true,
            challenge: None,
            challenge_pending: false,
        }
    }
}

#[derive(Copy, Clone)]
pub struct RttEstimator {
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet
    latest: Duration,
    /// The smoothed RTT of the connection, computed as described in RFC6298
    smoothed: Option<Duration>,
    /// The RTT variance, computed as described in RFC6298
    var: Duration,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min: Duration,
}

impl RttEstimator {
    fn new(initial_rtt: Duration) -> Self {
        Self {
            latest: initial_rtt,
            smoothed: None,
            var: initial_rtt / 2,
            min: initial_rtt,
        }
    }

    pub fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest = rtt;
        // min_rtt ignores ack delay.
        self.min = cmp::min(self.min, self.latest);
        // Based on RFC6298.
        if let Some(smoothed) = self.smoothed {
            let adjusted_rtt = if self.min + ack_delay < self.latest {
                self.latest - ack_delay
            } else {
                self.latest
            };
            let var_sample = if smoothed > adjusted_rtt {
                smoothed - adjusted_rtt
            } else {
                adjusted_rtt - smoothed
            };
            self.var = (3 * self.var + var_sample) / 4;
            self.smoothed = Some((7 * smoothed + adjusted_rtt) / 8);
        } else {
            self.smoothed = Some(self.latest);
            self.var = self.latest / 2;
            self.min = self.latest;
        }
    }

    fn get(&self) -> Duration {
        self.smoothed.unwrap_or(self.latest)
    }

    /// Conservative estimate of RTT
    ///
    /// Takes the maximum of smoothed and latest RTT, as recommended
    /// in 6.1.2 of the recovery spec (draft 29).
    pub fn conservative(&self) -> Duration {
        self.get().max(self.latest)
    }

    pub fn pto_base(&self) -> Duration {
        self.get() + cmp::max(4 * self.var, TIMER_GRANULARITY)
    }
}
