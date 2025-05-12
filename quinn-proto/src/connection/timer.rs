use std::collections::{BinaryHeap, binary_heap::PeekMut};

use rustc_hash::FxHashMap;

use crate::Instant;

use super::PathId;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum Timer {
    /// When to send an ack-eliciting probe packet or declare unacked packets lost
    LossDetection(PathId),
    /// When to close the connection after no activity
    Idle,
    /// When the close timer expires, the connection has been gracefully terminated.
    Close,
    /// When keys are discarded because they should not be needed anymore
    KeyDiscard,
    /// When to give up on validating a new path to the peer
    PathValidation(PathId),
    /// When to send a `PING` frame to keep the connection alive
    KeepAlive(PathId),
    /// When pacing will allow us to send a packet
    Pacing(PathId),
    /// When to invalidate old CID and proactively push new one via NEW_CONNECTION_ID frame
    PushNewCid(PathId),
    /// When to send an immediate ACK if there are unacked ack-eliciting packets of the peer
    MaxAckDelay,
}

/// Keeps track of the nearest timeout for each `Timer`
///
/// The [`TimerTable`] is advanced with [`TimerTable::expire_timers`].
#[derive(Debug, Clone, Default)]
pub(crate) struct TimerTable {
    most_recent_timeout: FxHashMap<Timer, Instant>,
    timeout_queue: BinaryHeap<TimerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TimerEntry {
    pub(super) time: Instant,
    pub(super) timer: Timer,
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // `timeout_queue` is a max heap so we need to reverse the order to efficiently pop the
        // next timeout
        self.time
            .cmp(&other.time)
            .then_with(|| self.timer.cmp(&other.timer))
            .reverse()
    }
}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TimerTable {
    /// Sets the timer unconditionally
    pub(super) fn set(&mut self, timer: Timer, time: Instant) {
        self.most_recent_timeout.insert(timer, time);
        self.timeout_queue.push(TimerEntry { time, timer });
    }

    pub(super) fn get(&self, timer: Timer) -> Option<Instant> {
        self.most_recent_timeout.get(&timer).copied()
    }

    pub(super) fn stop(&mut self, timer: Timer) {
        self.most_recent_timeout.remove(&timer);
    }

    /// Get the next queued timeout
    ///
    /// Obsolete timers will be purged.
    pub(super) fn peek(&mut self) -> Option<TimerEntry> {
        while let Some(timer_entry) = self.timeout_queue.peek_mut() {
            if self.most_recent_timeout.get(&timer_entry.timer) != Some(&timer_entry.time) {
                // obsolete timeout
                PeekMut::pop(timer_entry);
                continue;
            }
            return Some(timer_entry.clone());
        }

        None
    }

    /// Remove the next timer up until `now`, including it
    pub(super) fn expire_before(&mut self, now: Instant) -> Option<Timer> {
        let TimerEntry { time, timer } = self.peek()?;
        if time <= now {
            self.most_recent_timeout.remove(&timer);
            self.timeout_queue.pop();
            return Some(timer);
        }

        None
    }

    pub(super) fn reset(&mut self) {
        self.most_recent_timeout.clear();
        self.timeout_queue.clear();
    }

    #[cfg(test)]
    pub(super) fn values(&self) -> Vec<TimerEntry> {
        let mut values = self.timeout_queue.clone().into_sorted_vec();
        values.retain(|entry| self.most_recent_timeout.get(&entry.timer) == Some(&entry.time));
        return values;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn timer_table() {
        let mut timers = TimerTable::default();
        let sec = Duration::from_secs(1);
        let now = Instant::now() + Duration::from_secs(10);
        timers.set(Timer::Idle, now - 3 * sec);
        timers.set(Timer::Close, now - 2 * sec);
        timers.set(Timer::Idle, now);

        assert_eq!(
            timers.peek(),
            Some(TimerEntry {
                timer: Timer::Close,
                time: now - 2 * sec
            })
        );
        assert_eq!(timers.expire_before(now), Some(Timer::Close));
        assert_eq!(timers.expire_before(now), Some(Timer::Idle));
        assert_eq!(timers.expire_before(now), None);
    }
}
