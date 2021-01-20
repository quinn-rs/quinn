//! Pacing of packet transmissions.

use std::time::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer. The bucket starts full and has an adjustable capacity. Once the
/// bucket is empty, further transmission is blocked. The bucket refills at a rate slightly faster
/// than one congestion window per RTT.
pub struct Pacer {
    capacity: u64,
    tokens: u64,
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub fn new(capacity: u64, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending a packet.
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub fn delay(
        &mut self,
        smoothed_rtt: Duration,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        // if we can already send a packet, there is no need for delay
        if self.tokens >= mtu.into() {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u32::max_value().into() {
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
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        // if we can already send a packet, there is no need for delay
        if self.tokens > mtu.into() {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul(((mtu as u64).max(self.capacity) - self.tokens) as _)
            .unwrap_or_else(|| Duration::new(u64::max_value(), 999_999_999))
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        assert!(Pacer::new(1500, new_instant)
            .delay(Duration::from_micros(0), 0, 1, old_instant)
            .is_none());
        assert!(Pacer::new(1500, new_instant)
            .delay(Duration::from_micros(0), 1600, 1, old_instant)
            .is_none());
        assert!(Pacer::new(1500, new_instant)
            .delay(Duration::from_micros(0), 1500, 3000, old_instant)
            .is_none());
    }

    #[test]
    fn computes_pause_correctly() {
        let old_instant = Instant::now();
        let mut pacer = Pacer::new(1500, old_instant + Duration::from_micros(15));
        assert_eq!(
            pacer.delay(Duration::from_micros(0), 1600, 1, old_instant),
            None,
            "Zero RTT means that we should send immediately"
        );
        let computed_delay = pacer.delay(Duration::from_micros(5), 1600, 1, old_instant);
        assert_eq!(
            computed_delay,
            Some(pacer.prev + Duration::from_micros(400)),
            "Difference between expected and computed delays is {}ns",
            (computed_delay.unwrap() - pacer.prev).as_nanos()
        );
    }
}
