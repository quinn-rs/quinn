//! Pacing of packet transmissions.

use crate::config::{PacingConfig, PacingRateMode};
use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// Once the bucket is empty, further transmission is blocked until tokens refill.
pub(super) struct Pacer {
    config: PacingConfig,
    /// Pacing rate in bytes/second, or None if pacing is disabled
    pacing_rate: Option<u64>,
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
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

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
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
        if self.tokens >= bytes_to_send {
            return None;
        }

        // Calculate delay: time to accumulate a full burst
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
/// accuracy in user-space is not high enough. Say, for RttDependent, if we miss
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

    // The rate is `cwnd × 1.25 / RTT` as recommended in
    // <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>,
    // such that `window` bytes of traffic are spread over 4/5 of the RTT.
    //
    // Returns None if RTT is zero or rate exceeds reasonable bounds (~4GB/s)
    let rtt_rate = || -> Option<u64> {
        if rtt_nanos == 0 {
            return None;
        }
        let rate = (window as f64 * 1.25) / smoothed_rtt.as_secs_f64();
        let rate = rate.round() as u64;
        if rate > u64::from(u32::MAX) {
            return None;
        }
        Some(rate)
    };

    // Original Quinn formula: window * burst_interval / rtt
    let rtt_capacity = |burst_interval: Duration| -> u64 {
        if rtt_nanos == 0 {
            return 0;
        }
        (window as u128 * burst_interval.as_nanos() / rtt_nanos) as u64
    };

    // Capacity from a fixed rate
    let rate_capacity = |rate: u64, burst_interval: Duration| -> u64 {
        (rate as u128 * burst_interval.as_nanos() / 1_000_000_000) as u64
    };

    let (pacing_rate, capacity) = match config.rate_mode {
        PacingRateMode::RttDependent => {
            let rate = match rtt_rate() {
                Some(rate) => rate,
                None => return (None, 0),
            };
            // Use original formula for capacity (without 1.25 multiplier)
            let target = rtt_capacity(config.target_burst_interval);
            let capacity = target.clamp(
                config.min_burst_size * mtu_u64,
                config.max_burst_size * mtu_u64,
            );
            (rate, capacity)
        }
        PacingRateMode::Fixed(bytes_per_second) => {
            let target = rate_capacity(bytes_per_second, config.target_burst_interval);
            let max_cap = rate_capacity(bytes_per_second, config.max_burst_interval).max(mtu_u64);
            let capacity = target
                .clamp(
                    config.min_burst_size * mtu_u64,
                    config.max_burst_size * mtu_u64,
                )
                .min(max_cap);
            (bytes_per_second, capacity)
        }
        PacingRateMode::RttDependentWithFloor(min_bytes_per_second) => {
            let rate = rtt_rate().unwrap_or(0).max(min_bytes_per_second);
            // Use floor-based capacity when RTT-based would be smaller
            let rtt_target = rtt_capacity(config.target_burst_interval);
            let floor_target = rate_capacity(min_bytes_per_second, config.target_burst_interval);
            let target = rtt_target.max(floor_target);
            let capacity = target.clamp(
                config.min_burst_size * mtu_u64,
                config.max_burst_size * mtu_u64,
            );
            (rate, capacity)
        }
    };

    (Some(pacing_rate), capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants matching PacingConfig::default()
    const TARGET_BURST_INTERVAL: Duration = Duration::from_millis(2);
    const MIN_BURST_SIZE: u64 = 10;

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

        // Zero RTT disables pacing (capacity=0, pacing_rate=None)
        let pacer = Pacer::new(config.clone(), Duration::ZERO, window, mtu, now);
        assert_eq!(pacer.capacity, 0);
        assert!(pacer.pacing_rate.is_none());

        // Very small window: capacity clamped to MIN_BURST_SIZE * mtu
        let pacer = Pacer::new(config, rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
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

        // capacity = fixed_rate * burst_interval
        let pacer = Pacer::new(config.clone(), rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (fixed_rate as u128 * TARGET_BURST_INTERVAL.as_nanos() / 1_000_000_000) as u64
        );

        // Changing RTT or window should not affect capacity
        let mut pacer = Pacer::new(config, rtt, window, mtu, now);
        let initial_capacity = pacer.capacity;

        pacer.delay(rtt * 2, mtu as u64, mtu, window, now);
        assert_eq!(pacer.capacity, initial_capacity);

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(pacer.capacity, initial_capacity);
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
        assert_eq!(
            pacer.capacity,
            (min_rate as u128 * TARGET_BURST_INTERVAL.as_nanos() / 1_000_000_000) as u64
        );
    }
}
