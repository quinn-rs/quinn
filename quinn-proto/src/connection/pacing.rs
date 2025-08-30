//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
    burst_mode: bool,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        // burst mode is the default for quick handshake
        let capacity = optimal_capacity(smoothed_rtt, window, mtu, true);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
            burst_mode: true,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// In slow mode, it fills the bucket progressively by yielding at a maximum of 10 ms.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
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
            self.burst_mode = is_burst_mode(smoothed_rtt, window, mtu);
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu, self.burst_mode);

            // clamp the tokens in burst mode
            if self.burst_mode {
                self.tokens = self.capacity.min(self.tokens);
            }
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;

        self.tokens = self.tokens.saturating_add(new_tokens as _);

        self.tokens = self.tokens.min(if self.burst_mode {
            // in burst mode, tokens must not be higher than the burst capacity
            self.capacity
        } else {
            // in slow mode, send a single packet per interval only
            mtu as u64
        });

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = if self.burst_mode {
            smoothed_rtt
                .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
                .unwrap_or(Duration::MAX)
                / window
        } else {
            // it is preferable to yield at a maximum of MAX_INTERVAL_MS repetitively instead
            // of waiting only once. Moreover, the extended delay of
            // MAX_INTERVAL_MS + BURST_INTERVAL_NANOS is authorized to avoid delay inferior to
            // BURST_INTERVAL_NANOS at the next round
            let mut delay = smoothed_rtt
                .checked_mul((bytes_to_send - self.tokens) as _)
                .unwrap_or(Duration::MAX)
                / window;
            let interval = Duration::from_millis(MAX_INTERVAL_MS);
            let extended_interval = interval + Duration::from_nanos(BURST_INTERVAL_NANOS as _);
            if delay > extended_interval {
                delay = interval;
            }
            delay
        };

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16, burst_mode: bool) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let mut capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    if burst_mode {
        // Small bursts are less efficient (no GSO), could increase latency and don't effectively
        // use the channel's buffer capacity. Large bursts might block the connection on sending.
        capacity = capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64);
    }
    capacity
}

/// Determine if pacer must stay in burst mode (original behavior) or switch to slow mode
///
/// On very slow network link, we must avoid sending packets by burst. This could lead to issues
/// such as packet drop. Instead, we would prefer to space each packet by the appropriate amount
/// of time.
///
/// We determine if the pacer must switch to slow mode depending on the packet spacing computed
/// as follows:
///
/// `packet_spacing = RTT * MTU / cwnd`
///
/// Slow mode is detected if packet_spacing is higher than `SLOW_MODE_PACKET_SPACING_THRESHOLD_MS`
fn is_burst_mode(smoothed_rtt: Duration, window: u64, mtu: u16) -> bool {
    smoothed_rtt.as_millis() as u64 * mtu as u64 / window < SLOW_MODE_PACKET_SPACING_THRESHOLD_MS
}

/// The burst interval
///
/// The capacity will be refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1 ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1 ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

/// Packet spacing threshold in ms computed from the congestion window and the RTT.
/// Above this threshold, we consider the network as slow and adapt the pacer accordingly
const SLOW_MODE_PACKET_SPACING_THRESHOLD_MS: u64 = 10;

/// Maximum amount of time the pacer can wait while in slow mode
const MAX_INTERVAL_MS: u64 = 10;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::{Mul, Sub};

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }
    #[test]
    fn slow_mode_two_long_delays() {
        let mut window = 50_000u64;
        let mtu = 1400;
        let rtt = Duration::from_millis(800);
        let mut old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        // by default capa 10
        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // change cwnd for mode refresh
        window = 60_000;

        // the next sent should be in 18,6 ms. 1st delay 10 ms and 2nd 8,6 ms
        let total_delay = rtt.mul(mtu as u32) / window as u32;

        let mut pace_duration = Duration::from_millis(MAX_INTERVAL_MS * 4 / 5);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration,
            "should be MAX_INTERVAL_MS"
        );

        old_instant += pace_duration;

        pace_duration = total_delay.sub(Duration::from_millis(MAX_INTERVAL_MS)) * 4 / 5;

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration,
            "should return the remaining period"
        );
    }

    #[test]
    fn slow_mode_extended_interval_delay() {
        let mut window = 50_000u64;
        let mtu = 1400;
        let rtt = Duration::from_millis(910);
        let mut old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        // by default capa 10
        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        window = 60_000;

        // the next sent should be in 21,23 ms. 1st delay 10 ms and 2nd 11,23 ms (without scaling)
        let total_delay = rtt.mul(mtu as u32) / window as u32;

        let mut pace_duration = Duration::from_millis(MAX_INTERVAL_MS * 4 / 5);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration,
            "should be MAX_INTERVAL_MS"
        );

        old_instant += pace_duration;

        pace_duration = total_delay.sub(Duration::from_millis(MAX_INTERVAL_MS)) * 4 / 5;

        // as_millis to avoid unprecise duration
        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant)
                .as_millis(),
            pace_duration.as_millis(),
            "should return the remaining period"
        );
    }

    #[test]
    fn slow_mode_resume_sending_after_long_period() {
        let mut window = 50_000u64;
        let mtu = 1400;
        let rtt = Duration::from_millis(600);
        let mut old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        // by default capa 10
        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        window = 60_000;

        // the next sent should be in 14 ms. 1st delay 10 ms and 2nd 4 ms (without scaling)
        let pace_duration = Duration::from_millis(MAX_INTERVAL_MS * 4 / 5);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration,
            "should be MAX_INTERVAL_MS"
        );

        // wait a long period
        old_instant += Duration::from_millis(500);

        assert!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .is_none(),
            "should be ready to send"
        );

        assert_eq!(
            pacer.tokens, mtu as u64,
            "should not have more than MTU tokens"
        );
    }
}
