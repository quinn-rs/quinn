//! Adaptive reordering tolerance for loss detection
//!
//! RFC 9002 declares a packet lost once `packet_threshold` later packets have been acknowledged,
//! or once it is older than `time_threshold × rtt`. Both are static, so a path that reorders more
//! deeply than they allow has packets declared lost — and the congestion window cut — although
//! nothing was lost.
//!
//! A loss is proven spurious when the "lost" packet is acknowledged after all. That ACK tells us
//! how far the packet was displaced: how many later packets had been acknowledged when it was
//! declared lost, and how old it was when its ACK arrived. [`ReorderAdapter`] widens both
//! thresholds to cover what was observed. It narrows them again only once the path has gone
//! quiet: [`DECAY_AFTER_CONGESTION_EVENTS`] congestion events with no spurious loss proven for
//! the whole lost-packet [`horizon`], after which the learned values are halved, at most once per
//! horizon. Proofs arrive after the congestion events they disprove, so counting events alone
//! would discard what was learned on exactly the paths that reorder most.
//!
//! Prior art: TCP RACK (RFC 8985 §6.2) widens its reordering window when a DSACK shows a
//! retransmission was spurious and resets it after 16 loss recoveries; Linux TCP raises its
//! duplicate-ACK threshold (`tp->reordering`) to the observed reordering degree, up to
//! `tcp_max_reordering` (300).

use std::cmp;

use crate::{Duration, Instant};

/// Upper bound on the adapted packet threshold, matching Linux's default `tcp_max_reordering`
pub(super) const MAX_PACKET_THRESHOLD: u64 = 300;

/// Congestion events without a spurious loss before the adaptation decays
///
/// RACK resets its window multiplier after 16 loss recoveries.
pub(super) const DECAY_AFTER_CONGESTION_EVENTS: u32 = 16;

/// A learned loss delay below this is dropped rather than halved further
const MIN_LEARNED_LOSS_DELAY: Duration = Duration::from_millis(1);

/// How long a declared loss can still be proven spurious: the lost-packet horizon
///
/// Lost packets are forgotten after 2 PTO. On a path whose RTT is far below its reordering (a
/// sub-millisecond link reordering by tens of milliseconds) the ACK that proves a loss spurious
/// arrives long after that, so with 2 PTO alone the record is gone before its proof (nothing is
/// learned) and every congestion event looks quiet (what was learned decays at once). The horizon
/// is therefore also at least twice the loss delay in force.
pub(super) fn horizon(two_pto: Duration, loss_delay_in_force: Duration) -> Duration {
    cmp::max(two_pto, 2 * loss_delay_in_force)
}

/// Per-path reordering tolerance learned from spurious losses
#[derive(Debug, Default, Clone)]
pub(super) struct ReorderAdapter {
    /// Packet threshold learned from spurious losses; 0 when nothing has been learned
    packet_threshold: u64,
    /// Time-threshold loss delay learned from spurious losses; zero when nothing has been learned
    loss_delay: Duration,
    /// Congestion events since the last spurious loss was proven, or since the last decay
    events_since_spurious: u32,
    /// When the last spurious loss was proven
    last_proof: Option<Instant>,
    /// When the learned values were last halved
    last_decay: Option<Instant>,
}

impl ReorderAdapter {
    /// The packet threshold to use, given the configured one
    pub(super) fn packet_threshold(&self, configured: u64) -> u64 {
        cmp::max(configured, self.packet_threshold)
    }

    /// The time-threshold loss delay to use, given the one computed from the RTT
    pub(super) fn loss_delay(&self, computed: Duration) -> Duration {
        cmp::max(computed, self.loss_delay)
    }

    /// A packet declared lost has been acknowledged after all, at `now`
    ///
    /// `displacement` is how many packet numbers above it had been acknowledged when it was
    /// declared lost; `age` is how long after it was sent its ACK arrived. The learned loss delay
    /// is capped at `max_loss_delay`, the horizon past which lost packets are forgotten.
    pub(super) fn on_spurious_loss(
        &mut self,
        now: Instant,
        displacement: u64,
        age: Duration,
        max_loss_delay: Duration,
    ) {
        self.events_since_spurious = 0;
        self.last_proof = Some(now);
        // Tolerate the observed displacement: the packet was lost at `displacement`, so the
        // threshold must exceed it. The eighth of margin covers the next reordering being a
        // little deeper, e.g. by a packet number skipped in between.
        let packets = displacement
            .saturating_add(displacement / 8)
            .saturating_add(1)
            .min(MAX_PACKET_THRESHOLD);
        self.packet_threshold = cmp::max(self.packet_threshold, packets);
        // Leave an eighth of margin, as RFC 9002's default time threshold does over the RTT.
        let delay = cmp::min(age + age / 8, max_loss_delay);
        self.loss_delay = cmp::max(self.loss_delay, delay);
    }

    /// A congestion event was raised at `now`
    ///
    /// `quiet` is the lost-packet horizon: a loss not proven spurious within it never will be.
    /// Once [`DECAY_AFTER_CONGESTION_EVENTS`] events pass AND no proof has arrived for `quiet`,
    /// the path is taken to reorder less than it did and the learned values are halved; a few
    /// such periods in a row bring the configured thresholds back. While proofs keep arriving,
    /// however late, nothing decays.
    ///
    /// At most one halving per horizon: the quiet window counts from the last proof or the last
    /// halving, whichever is later. A halving shrinks the loss delay in force and with it the
    /// horizon, so without that a burst of congestion events would halve again and again, each
    /// against a shorter window, and wipe what was learned in one go.
    pub(super) fn on_congestion_event(&mut self, now: Instant, quiet: Duration) {
        if self.packet_threshold == 0 && self.loss_delay.is_zero() {
            return;
        }
        self.events_since_spurious = self.events_since_spurious.saturating_add(1);
        let quiet_long_enough = cmp::max(self.last_proof, self.last_decay)
            .is_none_or(|t| now.saturating_duration_since(t) >= quiet);
        if self.events_since_spurious < DECAY_AFTER_CONGESTION_EVENTS || !quiet_long_enough {
            return;
        }
        self.events_since_spurious = 0;
        self.last_decay = Some(now);
        self.packet_threshold /= 2;
        self.loss_delay /= 2;
        if self.loss_delay < MIN_LEARNED_LOSS_DELAY {
            self.loss_delay = Duration::ZERO;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);
    /// The lost-packet horizon the tests decay against
    const QUIET: Duration = Duration::from_millis(10);

    #[test]
    fn unadapted_uses_the_configured_values() {
        let r = ReorderAdapter::default();
        assert_eq!(r.packet_threshold(3), 3);
        assert_eq!(r.loss_delay(MS), MS);
    }

    #[test]
    fn spurious_loss_widens_both_thresholds() {
        let mut r = ReorderAdapter::default();
        r.on_spurious_loss(Instant::now(), 40, 16 * MS, 100 * MS);
        assert_eq!(r.packet_threshold(3), 46);
        assert_eq!(r.loss_delay(MS), 18 * MS);
        // Never narrower than configured
        assert_eq!(r.packet_threshold(64), 64);
        assert_eq!(r.loss_delay(50 * MS), 50 * MS);
    }

    /// The next reordering may be a packet deeper, e.g. when the sender skips a packet number
    #[test]
    fn a_slightly_deeper_reordering_is_still_covered() {
        let mut r = ReorderAdapter::default();
        r.on_spurious_loss(Instant::now(), 9, 2 * MS, 100 * MS);
        assert!(r.packet_threshold(3) > 10);
    }

    #[test]
    fn adaptation_only_grows_until_it_decays() {
        let mut r = ReorderAdapter::default();
        let now = Instant::now();
        r.on_spurious_loss(now, 40, 16 * MS, 100 * MS);
        r.on_spurious_loss(now, 5, 2 * MS, 100 * MS);
        assert_eq!(r.packet_threshold(3), 46);
        assert_eq!(r.loss_delay(MS), 18 * MS);
    }

    #[test]
    fn caps_apply() {
        let mut r = ReorderAdapter::default();
        r.on_spurious_loss(Instant::now(), u64::MAX, 10 * MS, 4 * MS);
        assert_eq!(r.packet_threshold(3), MAX_PACKET_THRESHOLD);
        assert_eq!(r.loss_delay(MS), 4 * MS);
    }

    /// The flaw this replaces: under heavy reordering many congestion events land before the
    /// late ACKs that disprove them. Events alone, within the horizon of the last proof, must not
    /// discard what was learned.
    #[test]
    fn no_decay_while_proofs_are_recent() {
        let mut r = ReorderAdapter::default();
        let t0 = Instant::now();
        r.on_spurious_loss(t0, 40, 16 * MS, 100 * MS);
        for _ in 0..10 * DECAY_AFTER_CONGESTION_EVENTS {
            r.on_congestion_event(t0 + QUIET / 2, QUIET);
        }
        assert_eq!(r.packet_threshold(3), 46);
        assert_eq!(r.loss_delay(MS), 18 * MS);
    }

    #[test]
    fn halves_after_quiet_congestion_events() {
        let mut r = ReorderAdapter::default();
        let t0 = Instant::now();
        r.on_spurious_loss(t0, 40, 16 * MS, 100 * MS);
        let later = t0 + QUIET;
        for _ in 1..DECAY_AFTER_CONGESTION_EVENTS {
            r.on_congestion_event(later, QUIET);
        }
        assert_eq!(r.packet_threshold(3), 46, "decayed one event early");
        r.on_congestion_event(later, QUIET);
        assert_eq!(r.packet_threshold(3), 23, "halved");
        assert_eq!(r.loss_delay(MS), 9 * MS, "halved");
    }

    #[test]
    fn repeated_quiet_periods_return_to_configured() {
        let mut r = ReorderAdapter::default();
        let t0 = Instant::now();
        r.on_spurious_loss(t0, 40, 16 * MS, 100 * MS);
        for period in 1..=8 {
            for _ in 0..DECAY_AFTER_CONGESTION_EVENTS {
                r.on_congestion_event(t0 + period * QUIET, QUIET);
            }
        }
        assert_eq!(r.packet_threshold(3), 3);
        assert_eq!(r.loss_delay(MS), MS);
    }

    #[test]
    fn a_new_spurious_loss_restarts_the_count() {
        let mut r = ReorderAdapter::default();
        let t0 = Instant::now();
        r.on_spurious_loss(t0, 40, 16 * MS, 100 * MS);
        let later = t0 + QUIET;
        for _ in 1..DECAY_AFTER_CONGESTION_EVENTS {
            r.on_congestion_event(later, QUIET);
        }
        r.on_spurious_loss(later, 10, 4 * MS, 100 * MS);
        r.on_congestion_event(later + QUIET, QUIET);
        assert_eq!(r.packet_threshold(3), 46);
    }

    /// The cascade the guard prevents: each halving shrinks the horizon the next one waits for,
    /// so a burst of events within one horizon must halve once, not repeatedly
    #[test]
    fn at_most_one_halving_per_horizon() {
        let mut r = ReorderAdapter::default();
        let t0 = Instant::now();
        r.on_spurious_loss(t0, 40, 16 * MS, 100 * MS);
        for _ in 0..10 * DECAY_AFTER_CONGESTION_EVENTS {
            r.on_congestion_event(t0 + QUIET, QUIET);
        }
        assert_eq!(
            (r.packet_threshold(3), r.loss_delay(MS)),
            (23, 9 * MS),
            "halved once"
        );
        for _ in 0..10 * DECAY_AFTER_CONGESTION_EVENTS {
            r.on_congestion_event(t0 + QUIET + QUIET / 2, QUIET);
        }
        assert_eq!(
            (r.packet_threshold(3), r.loss_delay(MS)),
            (23, 9 * MS),
            "halved again within one horizon"
        );
        for _ in 0..DECAY_AFTER_CONGESTION_EVENTS {
            r.on_congestion_event(t0 + 2 * QUIET, QUIET);
        }
        assert_eq!(
            r.packet_threshold(3),
            11,
            "the next horizon may halve again"
        );
    }

    /// On a sub-millisecond path 2 PTO is a couple of milliseconds while a 20 ms reordering
    /// proves its loss 20 ms later
    #[test]
    fn horizon_covers_the_loss_delay_in_force() {
        assert_eq!(horizon(2 * MS, 20 * MS), 40 * MS);
        assert_eq!(horizon(50 * MS, 20 * MS), 50 * MS);
    }
}
