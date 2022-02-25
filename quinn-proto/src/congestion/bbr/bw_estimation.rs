use std::fmt::{Debug, Display, Formatter};
use std::time::{Duration, Instant};

use super::min_max::MinMax;

#[derive(Clone, Debug)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Instant,
    prev_sent_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
}

impl BandwidthEstimation {
    pub fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.prev_total_sent = self.total_sent;
        self.total_sent += bytes;
        self.prev_sent_time = Some(self.sent_time);
        self.sent_time = now;
    }

    pub fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        self.prev_total_acked = self.total_acked;
        self.total_acked += bytes;
        self.prev_acked_time = self.acked_time;
        self.acked_time = Some(now);

        let prev_sent_time = match self.prev_sent_time {
            Some(prev_sent_time) => prev_sent_time,
            None => return,
        };

        let send_rate = if self.sent_time > prev_sent_time {
            BandwidthEstimation::bw_from_delta(
                self.total_sent - self.prev_total_sent,
                self.sent_time - prev_sent_time,
            )
            .unwrap_or(0)
        } else {
            u64::MAX // will take the min of send and ack, so this is just a skip
        };

        let ack_rate = match self.prev_acked_time {
            Some(prev_acked_time) => BandwidthEstimation::bw_from_delta(
                self.total_acked - self.prev_total_acked,
                now - prev_acked_time,
            )
            .unwrap_or(0),
            None => 0,
        };

        let bandwidth = send_rate.min(ack_rate);
        if !app_limited && self.max_filter.get() < bandwidth {
            self.max_filter.update_max(round, bandwidth);
        }
    }

    pub fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
    }

    pub fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let b_ns = bytes * 1_000_000_000;
        let bytes_per_second = b_ns / (window_duration_ns as u64);
        Some(bytes_per_second)
    }
}

impl Default for BandwidthEstimation {
    fn default() -> Self {
        BandwidthEstimation {
            total_acked: 0,
            prev_total_acked: 0,
            acked_time: None,
            prev_acked_time: None,
            total_sent: 0,
            prev_total_sent: 0,
            // The `sent_time` value set here is ignored; it is used in `on_ack()`, but will
            // have been reset by `on_sent()` before that method is called.
            sent_time: Instant::now(),
            prev_sent_time: None,
            max_filter: MinMax::default(),
            acked_at_last_window: 0,
        }
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}
