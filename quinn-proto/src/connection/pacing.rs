//! Pacing of packet transmissions.

use crate::config::{PacingConfig, PacingRateMode};
use crate::{Duration, Instant};

use tracing::warn;

/// A token-bucket pacer for smoothing packet transmissions over time
///
/// Tokens accumulate at [`pacing_rate`](Self::pacing_rate) bytes/second, up to
/// [`capacity`](Self::capacity). When enough tokens are available, a packet can be
/// sent immediately; otherwise, transmission is delayed until the bucket refills.
///
/// The burst cycle is: send up to `capacity` bytes, wait for the bucket to refill
/// (`capacity / pacing_rate` seconds), repeat.
pub(super) struct Pacer {
    config: PacingConfig,
    /// Token refill rate in bytes/second, or `None` if pacing is disabled
    pacing_rate: Option<u64>,
    /// Maximum burst size in bytes. Tokens cannot accumulate beyond this value.
    capacity: u64,
    /// Last congestion window (used PacingRateMode::RttDependent)
    last_window: u64,
    last_mtu: u16,
    /// Available send budget in bytes. Decremented on transmit, refilled over
    /// time at `pacing_rate`, capped at `capacity`.
    tokens: u64,
    /// Timestamp of the last token refill
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(
        config: PacingConfig,
        smoothed_rtt: Duration,
        window: u64,
        mtu: u16,
        now: Instant,
    ) -> Self {
        let (pacing_rate, capacity) = compute_pacing_params(&config, smoothed_rtt, window, mtu);
        Self {
            config,
            pacing_rate,
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Get a clone of the pacing configuration
    pub(super) fn config(&self) -> PacingConfig {
        self.config.clone()
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// `bytes_to_send` should reflect the actual transmission size (typically multiple
    /// MTU-sized segments when using GSO).
    ///
    /// NOTE: If `bytes_to_send` exceeds the burst capacity, a full token bucket is treated
    /// as sufficient to avoid deadlock.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if smoothed_rtt.as_nanos() == 0
            && matches!(self.config.rate_mode, PacingRateMode::RttDependent)
        {
            return None;
        }

        if window != self.last_window || mtu != self.last_mtu {
            let (pacing_rate, capacity) =
                compute_pacing_params(&self.config, smoothed_rtt, window, mtu);
            self.pacing_rate = pacing_rate;
            self.capacity = capacity;
            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // Pacing disabled
        let pacing_rate = self.pacing_rate?;

        // A full token bucket is always sufficient to send. This prevents deadlock when
        // bytes_to_send exceeds capacity (e.g., from GSO batches or misconfiguration).
        let send_threshold = bytes_to_send.min(self.capacity);

        // if we can already send a packet, there is no need for delay
        if self.tokens >= send_threshold {
            return None;
        }

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp earlier than a previous recorded time, ignoring");
            Default::default()
        });

        // Calculate new tokens based on elapsed time and pacing rate
        let new_tokens = (pacing_rate as f64 * time_elapsed.as_secs_f64()).round() as u64;
        self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);

        // In the unlikely event that we're getting polled faster than tokens are generated, ensure
        // that time can accumulate until we make progress.
        if new_tokens > 0 {
            self.prev = now;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= send_threshold {
            return None;
        }

        // Calculate delay based on the larger of capacity and bytes_to_send.
        // If bytes_to_send exceeds capacity, this intentionally oversleeps (the bucket can't
        // grow past capacity), but the deadlock-avoidance threshold above still allows a single
        // oversized batch once a full bucket is available.
        let tokens_needed = bytes_to_send.max(self.capacity) - self.tokens;
        let delay_secs = tokens_needed as f64 / pacing_rate as f64;
        let delay = Duration::from_secs_f64(delay_secs);

        Some(now + delay)
    }
}

/// Calculates pacing rate and capacity
///
/// Returns `(pacing_rate, capacity)`. `pacing_rate` is `None` if pacing should be disabled.
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space may be not high enough. Say, for RttDependent, if we miss
/// the interval by more than 25%, we will lose that part of the congestion window
/// since no additional tokens for the extra-elapsed time can be stored.
fn compute_pacing_params(
    config: &PacingConfig,
    smoothed_rtt: Duration,
    window: u64,
    mtu: u16,
) -> (Option<u64>, u64) {
    let mtu_u64 = u64::from(mtu);
    let rtt_nanos = smoothed_rtt.as_nanos();

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RttRate {
        Available(u64),
        Unavailable,
        TooHigh,
    }

    // For RttDependent, the rate is `cwnd × 1.25 / RTT` as recommended in
    // <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>,
    // such that `window` bytes of traffic are spread over 4/5 of the RTT.
    //
    // Returns Unavailable if RTT is zero or rate rounds to zero, and TooHigh if
    // the rate exceeds reasonable bounds (~4GB/s).
    // Unavailable disables pacing only for RttDependent; other modes may still pace.
    let rtt_rate = || -> RttRate {
        if rtt_nanos == 0 {
            return RttRate::Unavailable;
        }
        let rate = (window as f64 * 1.25) / smoothed_rtt.as_secs_f64();
        let rate = rate.round() as u64;
        if rate == 0 {
            return RttRate::Unavailable;
        }
        if rate > u64::from(u32::MAX) {
            return RttRate::TooHigh;
        }
        RttRate::Available(rate)
    };

    let rtt_capacity = |burst_interval: Duration| -> u64 {
        (window as u128 * burst_interval.as_nanos() / rtt_nanos.max(1)) as u64
    };

    let fixed_capacity = |rate: u64| -> u64 {
        let cap = (rate as u128 * config.target_burst_interval.as_nanos() / 1_000_000_000) as u64;
        cap.max(mtu_u64)
    };

    let rtt_dependent_capacity = || -> u64 {
        let target = rtt_capacity(config.target_burst_interval);
        let max_cap = rtt_capacity(config.max_burst_interval).max(mtu_u64);
        target
            .clamp(
                config.min_burst_size * mtu_u64,
                config.max_burst_size * mtu_u64,
            )
            .min(max_cap)
    };

    match config.rate_mode {
        PacingRateMode::RttDependent => match rtt_rate() {
            RttRate::Available(rate) => (Some(rate), rtt_dependent_capacity()),
            RttRate::Unavailable | RttRate::TooHigh => (None, rtt_dependent_capacity()),
        },
        PacingRateMode::Fixed(bytes_per_second) => {
            let pacing_rate = (bytes_per_second != 0).then_some(bytes_per_second);
            (pacing_rate, fixed_capacity(bytes_per_second))
        }
        PacingRateMode::RttDependentWithFloor(min_bytes_per_second) => {
            let floor_rate = (min_bytes_per_second != 0).then_some(min_bytes_per_second);
            match rtt_rate() {
                RttRate::Available(rate) => match floor_rate {
                    Some(floor) if rate < floor => (Some(floor), fixed_capacity(floor)),
                    _ => (Some(rate), rtt_dependent_capacity()),
                },
                RttRate::Unavailable => match floor_rate {
                    Some(floor) => (Some(floor), fixed_capacity(floor)),
                    None => (None, rtt_dependent_capacity()),
                },
                RttRate::TooHigh => (None, rtt_dependent_capacity()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants matching PacingConfig::default()
    const TARGET_BURST_INTERVAL: Duration = Duration::from_millis(2);
    const MIN_BURST_SIZE: u64 = 10;
    const MAX_BURST_SIZE: u64 = 256;

    fn default_config() -> PacingConfig {
        PacingConfig::default()
    }

    #[test]
    fn does_not_panic_on_bad_instant() {
        let config = default_config();
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(config.clone(), rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(config.clone(), rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(config, rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let config = default_config();
        let window = 2_000_000u64;
        let mtu = 1500u16;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        // RttDependent: capacity = window * burst_interval / rtt (original Quinn formula)
        let pacer = Pacer::new(config.clone(), rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        // Zero RTT disables pacing but preserves capacity for token accounting
        let pacer = Pacer::new(config.clone(), Duration::ZERO, window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert!(pacer.pacing_rate.is_none());

        // Very small window: capacity clamped to mtu by max_capacity limit
        let pacer = Pacer::new(config, rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let config = default_config();
        let window = 2_000_000u64;
        let mtu = 1500u16;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(config, rtt, window, mtu, now);
        let initial_capacity = pacer.capacity;
        let initial_tokens = pacer.tokens;

        // Double window -> capacity doubles
        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(pacer.capacity, initial_capacity * 2);
        assert_eq!(pacer.tokens, initial_tokens);

        // Half window -> capacity halves, tokens clamped
        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(pacer.capacity, initial_capacity / 2);
        assert_eq!(pacer.tokens, initial_capacity / 2);

        // Large MTU: capacity clamped to MIN_BURST_SIZE * mtu
        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * 20_000);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000u16;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(default_config(), rtt, window, mtu, now);
        let capacity = pacer.capacity;
        let pacing_rate = pacer.pacing_rate.unwrap();

        // Drain all tokens by sending packets
        while pacer.tokens >= mtu as u64 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, now),
                None,
                "When capacity is available packets should be sent immediately"
            );
            pacer.on_transmit(mtu);
        }

        // After draining, we wait for a full burst (capacity)
        // delay = capacity / pacing_rate
        let burst_delay_nanos = capacity as u128 * 1_000_000_000 / pacing_rate as u128;
        let burst_delay = Duration::from_nanos(burst_delay_nanos as u64);

        let actual_delay = pacer
            .delay(rtt, mtu as u64, mtu, window, now)
            .expect("Send must be delayed")
            .duration_since(now);

        let diff = actual_delay.abs_diff(burst_delay);
        assert!(
            diff < Duration::from_micros(10),
            "expected ≈ {burst_delay:?}, got {actual_delay:?} (diff {diff:?})"
        );

        // After waiting half the burst delay, tokens refill
        let half_delay = burst_delay / 2;
        assert_eq!(
            pacer.delay(rtt, mtu as u64, mtu, window, now + half_delay),
            None,
            "After waiting half_delay, should have enough tokens"
        );

        // Drain all tokens again
        while pacer.tokens >= mtu as u64 {
            pacer.on_transmit(mtu);
        }

        // After waiting longer than burst_delay, tokens cap at capacity
        assert_eq!(
            pacer.delay(rtt, mtu as u64, mtu, window, now + Duration::from_secs(1)),
            None
        );
        assert_eq!(pacer.tokens, capacity, "Tokens should cap at capacity");
    }

    #[test]
    fn oversized_send_oversleeps() {
        let window = 2_000_000u64;
        let mtu = 1000u16;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(default_config(), rtt, window, mtu, now);
        let capacity = pacer.capacity;
        let pacing_rate = pacer.pacing_rate.unwrap();

        // Drain tokens by sending packets
        while pacer.tokens >= mtu as u64 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, now),
                None,
                "When capacity is available packets should be sent immediately"
            );
            pacer.on_transmit(mtu);
        }
        pacer.tokens = 0;
        pacer.prev = now;

        let bytes_to_send = capacity + mtu as u64;

        let expected_delay_nanos = bytes_to_send as u128 * 1_000_000_000 / pacing_rate as u128;
        let expected_delay = Duration::from_nanos(expected_delay_nanos as u64);

        let actual_delay = pacer
            .delay(rtt, bytes_to_send, mtu, window, now)
            .expect("Send must be delayed")
            .duration_since(now);

        let diff = actual_delay.abs_diff(expected_delay);
        assert!(
            diff < Duration::from_micros(10),
            "expected ≈ {expected_delay:?}, got {actual_delay:?} (diff {diff:?})"
        );

        let burst_delay_nanos = capacity as u128 * 1_000_000_000 / pacing_rate as u128;
        let burst_delay = Duration::from_nanos(burst_delay_nanos as u64);
        assert!(
            actual_delay > burst_delay,
            "Oversleep expected when bytes_to_send > capacity"
        );

        // Even with bytes_to_send > capacity, a full bucket is sufficient.
        assert_eq!(
            pacer.delay(rtt, bytes_to_send, mtu, window, now + burst_delay),
            None,
            "With a full bucket we can send even if bytes_to_send > capacity"
        );
    }

    #[test]
    fn fixed_rate_mode() {
        let fixed_rate = 10_000_000u64; // 10 MB/s
        let config = PacingConfig {
            rate_mode: PacingRateMode::Fixed(fixed_rate),
            ..Default::default()
        };

        let window = 2_000_000u64;
        let mtu = 1500u16;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        // RTT is unknown: fixed rate still applies
        let pacer = Pacer::new(config.clone(), Duration::ZERO, window, mtu, now);
        assert_eq!(pacer.pacing_rate, Some(fixed_rate));
        assert_eq!(
            pacer.capacity,
            (fixed_rate as u128 * TARGET_BURST_INTERVAL.as_nanos() / 1_000_000_000) as u64
        );

        // capacity = fixed_rate * burst_interval
        let mut pacer = Pacer::new(config.clone(), rtt, window, mtu, now);
        let capacity = pacer.capacity;
        assert_eq!(
            capacity,
            (fixed_rate as u128 * TARGET_BURST_INTERVAL.as_nanos() / 1_000_000_000) as u64
        );

        // Drain all tokens
        while pacer.tokens >= mtu as u64 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, now),
                None,
                "When capacity is available packets should be sent immediately"
            );
            pacer.on_transmit(mtu);
        }

        // After draining, delay = tokens_needed / fixed_rate
        let tokens_needed = capacity - pacer.tokens;
        let burst_delay_nanos = tokens_needed as u128 * 1_000_000_000 / fixed_rate as u128;
        let burst_delay = Duration::from_nanos(burst_delay_nanos as u64);

        let actual_delay = pacer
            .delay(rtt, mtu as u64, mtu, window, now)
            .expect("Send must be delayed")
            .duration_since(now);

        let diff = actual_delay.abs_diff(burst_delay);
        assert!(
            diff < Duration::from_micros(10),
            "expected ≈ {burst_delay:?}, got {actual_delay:?} (diff {diff:?})"
        );

        // After waiting the burst delay, tokens refill to capacity
        assert_eq!(
            pacer.delay(rtt, mtu as u64, mtu, window, now + burst_delay),
            None,
            "After waiting burst_delay, should have enough tokens"
        );
        assert_eq!(pacer.tokens, capacity, "Tokens should refill to capacity");

        // Changing RTT or window should not affect capacity
        let mut pacer = Pacer::new(config, rtt, window, mtu, now);

        pacer.delay(rtt * 2, mtu as u64, mtu, window, now);
        assert_eq!(pacer.capacity, capacity);

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(pacer.capacity, capacity);
    }

    #[test]
    fn rtt_dependent_with_floor() {
        let min_rate = 20_000_000u64; // 20 MB/s floor
        let config = PacingConfig {
            rate_mode: PacingRateMode::RttDependentWithFloor(min_rate),
            ..Default::default()
        };

        let window = 2_000_000u64;
        let mtu = 1500u16;
        let now = Instant::now();

        // High RTT: rtt_rate = 2MB * 1.25 / 200ms = 12.5 MB/s < floor
        // capacity uses floor: min_rate * burst_interval
        let high_rtt = Duration::from_millis(200);
        let pacer = Pacer::new(config.clone(), high_rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (min_rate as u128 * TARGET_BURST_INTERVAL.as_nanos() / 1_000_000_000) as u64
        );

        // Low RTT: rtt_rate = 2MB * 1.25 / 20ms = 125 MB/s > floor
        // capacity uses rtt-based: window * burst_interval / rtt
        let low_rtt = Duration::from_millis(20);
        let pacer = Pacer::new(config.clone(), low_rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / low_rtt.as_nanos()) as u64
        );

        // Zero RTT: falls back to floor (not disabled)
        let pacer = Pacer::new(config, Duration::ZERO, window, mtu, now);
        assert_eq!(pacer.pacing_rate, Some(min_rate));
        assert_eq!(
            pacer.capacity,
            (min_rate as u128 * TARGET_BURST_INTERVAL.as_nanos() / 1_000_000_000) as u64
        );
    }

    #[test]
    fn zero_rate_disables_pacing() {
        let window = 2_000_000u64;
        let mtu = 1500u16;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let config = PacingConfig {
            rate_mode: PacingRateMode::Fixed(0),
            ..Default::default()
        };
        let pacer = Pacer::new(config, rtt, window, mtu, now);
        assert!(pacer.pacing_rate.is_none());

        let config = PacingConfig {
            rate_mode: PacingRateMode::RttDependentWithFloor(0),
            ..Default::default()
        };
        let pacer = Pacer::new(config, Duration::ZERO, window, mtu, now);
        assert!(pacer.pacing_rate.is_none());

        let config = PacingConfig {
            rate_mode: PacingRateMode::RttDependentWithFloor(0),
            ..Default::default()
        };
        let pacer = Pacer::new(config, rtt, window, mtu, now);
        assert!(pacer.pacing_rate.is_some());
    }

    #[test]
    fn too_high_rtt_rate_disables_pacing() {
        let window = 10_000_000u64;
        let mtu = 1500u16;
        let rtt = Duration::from_micros(1);
        let now = Instant::now();

        let pacer = Pacer::new(default_config(), rtt, window, mtu, now);
        assert!(pacer.pacing_rate.is_none());

        let config = PacingConfig {
            rate_mode: PacingRateMode::RttDependentWithFloor(20_000_000),
            ..Default::default()
        };
        let pacer = Pacer::new(config, rtt, window, mtu, now);
        assert!(pacer.pacing_rate.is_none());
    }
}
