use identity_hash::{IdentityHashable, IntMap};

use crate::{
    Instant,
    connection::qlog::{QlogSink, QlogSinkWithTime},
};

use super::PathId;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum Timer {
    /// Per connection timers.
    Conn(ConnTimer),
    /// Per path timers.
    PerPath(PathId, PathTimer),
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ConnTimer {
    /// When to close the connection after no activity
    Idle = 0,
    /// When the close timer expires, the connection has been gracefully terminated.
    Close = 1,
    /// When keys are discarded because they should not be needed anymore
    KeyDiscard = 2,
    /// When to send a `PING` frame to keep the connection alive
    KeepAlive = 3,
    /// When to invalidate old CID and proactively push new one via NEW_CONNECTION_ID frame
    PushNewCid = 4,
}

impl ConnTimer {
    const VALUES: [Self; 5] = [
        Self::Idle,
        Self::Close,
        Self::KeyDiscard,
        Self::KeepAlive,
        Self::PushNewCid,
    ];
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum PathTimer {
    /// When to send an ack-eliciting probe packet or declare unacked packets lost
    LossDetection = 0,
    /// When to abandon a path after no activity
    PathIdle = 1,
    /// When to give up on validating a new path from RFC9000 migration
    PathValidation = 2,
    /// When to resend a path challenge deemed lost
    PathChallengeLost = 3,
    /// When to give up on validating a new (multi)path
    PathOpen = 4,
    /// When to send a `PING` frame to keep the path alive
    PathKeepAlive = 5,
    /// When pacing will allow us to send a packet
    Pacing = 6,
    /// When to send an immediate ACK if there are unacked ack-eliciting packets of the peer
    MaxAckDelay = 7,
    /// When to clean up state for an abandoned path
    PathAbandoned = 8,
    /// When the peer fails to confirm abandoning the path
    PathNotAbandoned = 9,
}

impl PathTimer {
    const VALUES: [Self; 10] = [
        Self::LossDetection,
        Self::PathIdle,
        Self::PathValidation,
        Self::PathChallengeLost,
        Self::PathOpen,
        Self::PathKeepAlive,
        Self::Pacing,
        Self::MaxAckDelay,
        Self::PathAbandoned,
        Self::PathNotAbandoned,
    ];
}

/// Keeps track of the nearest timeout for each `Timer`
///
/// The [`TimerTable`] is advanced with [`TimerTable::expire_before`].
#[derive(Debug, Clone, Default)]
pub(crate) struct TimerTable {
    generic: [Option<Instant>; ConnTimer::VALUES.len()],
    path_timers: SmallMap<PathId, PathTimerTable, STACK_TIMERS>,
}

/// For how many paths we keep the timers on the stack, before spilling onto the heap.
const STACK_TIMERS: usize = 4;

/// Works like a `HashMap` but stores up to `SIZE` items on the stack.
#[derive(Debug, Clone)]
struct SmallMap<K, V, const SIZE: usize> {
    stack: [Option<(K, V)>; SIZE],
    heap: Option<IntMap<K, V>>,
}

impl<K, V, const SIZE: usize> Default for SmallMap<K, V, SIZE> {
    fn default() -> Self {
        Self {
            stack: [const { None }; SIZE],
            heap: None,
        }
    }
}

impl<K, V, const SIZE: usize> SmallMap<K, V, SIZE>
where
    K: std::cmp::Eq + std::hash::Hash + IdentityHashable,
{
    fn insert(&mut self, key: K, value: V) -> Option<V> {
        // check stack for space
        for el in self.stack.iter_mut() {
            match el {
                Some((k, v)) => {
                    if *k == key {
                        let old_value = std::mem::replace(v, value);
                        return Some(old_value);
                    }
                }
                None => {
                    // make sure to remove a potentially old value from the heap
                    let old_heap = self.heap.as_mut().and_then(|h| h.remove(&key));
                    *el = Some((key, value));

                    return old_heap;
                }
            }
        }

        // No space on the stack, use the heap
        let heap = self.heap.get_or_insert_default();
        heap.insert(key, value)
    }

    #[cfg(test)]
    fn remove(&mut self, key: &K) -> Option<V> {
        for el in self.stack.iter_mut() {
            if let Some((k, _)) = el {
                if key == k {
                    return el.take().map(|(_, v)| v);
                }
            }
        }

        self.heap.as_mut().and_then(|h| h.remove(key))
    }

    #[cfg(test)]
    fn get(&self, key: &K) -> Option<&V> {
        for (k, v) in self.stack.iter().filter_map(|v| v.as_ref()) {
            if k == key {
                return Some(v);
            }
        }

        self.heap.as_ref().and_then(|h| h.get(key))
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        for (k, v) in self.stack.iter_mut().filter_map(|v| v.as_mut()) {
            if k == key {
                return Some(v);
            }
        }

        self.heap.as_mut().and_then(|h| h.get_mut(key))
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let a = self
            .stack
            .iter()
            .filter_map(|v| v.as_ref().map(|(k, v)| (k, v)));
        let b = self.heap.iter().flat_map(|h| h.iter());
        a.chain(b)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        let a = self.stack.iter().filter_map(|v| v.as_ref().map(|(_, v)| v));
        let b = self.heap.iter().flat_map(|h| h.values());
        a.chain(b)
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        let a = self
            .stack
            .iter_mut()
            .filter_map(|v| v.as_mut().map(|(k, v)| (&*k, v)));
        let b = self.heap.iter_mut().flat_map(|h| h.iter_mut());
        a.chain(b)
    }

    fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let mut to_remove = [false; SIZE];
        for (i, el) in self.stack.iter_mut().enumerate() {
            if let Some((key, value)) = el {
                to_remove[i] = !f(key, value);
            }
        }
        for (i, to_remove) in to_remove.into_iter().enumerate() {
            if to_remove {
                self.stack[i] = None;
            }
        }

        if let Some(ref mut heap) = self.heap {
            heap.retain(f);
        }
    }

    fn clear(&mut self) {
        for el in self.stack.iter_mut() {
            *el = None;
        }
        self.heap = None;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PathTimerTable {
    timers: [Option<Instant>; PathTimer::VALUES.len()],
}

impl PathTimerTable {
    fn set(&mut self, timer: PathTimer, time: Instant) {
        self.timers[timer as usize] = Some(time);
    }

    fn stop(&mut self, timer: PathTimer) {
        self.timers[timer as usize] = None;
    }

    /// Remove the next timer up until `now`, including it
    fn expire_before(&mut self, now: Instant) -> Option<(PathTimer, Instant)> {
        for timer in PathTimer::VALUES {
            if self.timers[timer as usize].is_some()
                && self.timers[timer as usize].expect("checked") <= now
            {
                return self.timers[timer as usize].take().map(|time| (timer, time));
            }
        }

        None
    }
}

impl TimerTable {
    /// Sets the timer unconditionally
    pub(super) fn set(&mut self, timer: Timer, time: Instant, qlog: QlogSinkWithTime<'_>) {
        match timer {
            Timer::Conn(timer) => {
                self.generic[timer as usize] = Some(time);
            }
            Timer::PerPath(path_id, timer) => match self.path_timers.get_mut(&path_id) {
                None => {
                    let mut table = PathTimerTable::default();
                    table.set(timer, time);
                    self.path_timers.insert(path_id, table);
                }
                Some(table) => {
                    table.set(timer, time);
                }
            },
        }
        qlog.emit_timer_set(timer, time);
    }

    pub(super) fn stop(&mut self, timer: Timer, qlog: QlogSinkWithTime<'_>) {
        match timer {
            Timer::Conn(timer) => {
                self.generic[timer as usize] = None;
            }
            Timer::PerPath(path_id, timer) => {
                if let Some(e) = self.path_timers.get_mut(&path_id) {
                    e.stop(timer);
                }
            }
        }
        qlog.emit_timer_stop(timer);
    }

    /// Stops all per-path timers
    pub(super) fn stop_per_path(&mut self, path_id: PathId, qlog: QlogSinkWithTime<'_>) {
        for timer in PathTimer::VALUES {
            if let Some(e) = self.path_timers.get_mut(&path_id) {
                e.stop(timer);
                qlog.emit_timer_stop(Timer::PerPath(path_id, timer));
            }
        }
    }

    /// Get the next queued timeout
    pub(super) fn peek(&mut self) -> Option<Instant> {
        // TODO: this is currently linear in the number of paths

        let min_generic = self.generic.iter().filter_map(|&x| x).min();
        let min_path = self
            .path_timers
            .values()
            .flat_map(|p| p.timers.iter().filter_map(|&x| x))
            .min();

        match (min_generic, min_path) {
            (None, None) => None,
            (Some(val), None) => Some(val),
            (Some(a), Some(b)) => Some(a.min(b)),
            (None, Some(val)) => Some(val),
        }
    }

    /// Remove the next timer up until `now`, including it
    pub(super) fn expire_before(
        &mut self,
        now: Instant,
        qlog: &QlogSink,
    ) -> Option<(Timer, Instant)> {
        let (timer, instant) = self.expire_before_inner(now)?;
        qlog.with_time(now).emit_timer_expire(timer);
        Some((timer, instant))
    }

    fn expire_before_inner(&mut self, now: Instant) -> Option<(Timer, Instant)> {
        // TODO: this is currently linear in the number of paths

        for timer in ConnTimer::VALUES {
            if self.generic[timer as usize].is_some()
                && self.generic[timer as usize].expect("checked") <= now
            {
                return self.generic[timer as usize]
                    .take()
                    .map(|time| (Timer::Conn(timer), time));
            }
        }

        let mut res = None;
        for (path_id, timers) in self.path_timers.iter_mut() {
            if let Some((timer, time)) = timers.expire_before(now) {
                res = Some((Timer::PerPath(*path_id, timer), time));
                break;
            }
        }

        // clear out old timers
        self.path_timers
            .retain(|_path_id, timers| timers.timers.iter().any(|t| t.is_some()));
        res
    }

    pub(super) fn reset(&mut self) {
        for timer in ConnTimer::VALUES {
            self.generic[timer as usize] = None;
        }
        self.path_timers.clear();
    }

    #[cfg(test)]
    pub(super) fn values(&self) -> Vec<(Timer, Instant)> {
        let mut values = Vec::new();

        for timer in ConnTimer::VALUES {
            if let Some(time) = self.generic[timer as usize] {
                values.push((Timer::Conn(timer), time));
            }
        }

        for timer in PathTimer::VALUES {
            for (path_id, timers) in self.path_timers.iter() {
                if let Some(time) = timers.timers[timer as usize] {
                    values.push((Timer::PerPath(*path_id, timer), time));
                }
            }
        }

        values
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::connection::qlog::QlogSink;

    use super::*;

    #[test]
    fn timer_table() {
        let mut timers = TimerTable::default();
        let sec = Duration::from_secs(1);
        let now = Instant::now() + Duration::from_secs(10);
        timers.set(
            Timer::Conn(ConnTimer::Idle),
            now - 3 * sec,
            QlogSink::default().with_time(now),
        );
        timers.set(
            Timer::Conn(ConnTimer::Close),
            now - 2 * sec,
            QlogSink::default().with_time(now),
        );

        assert_eq!(timers.peek(), Some(now - 3 * sec));
        assert_eq!(
            timers.expire_before(now, &QlogSink::default()),
            Some((Timer::Conn(ConnTimer::Idle), now - 3 * sec))
        );
        assert_eq!(
            timers.expire_before(now, &QlogSink::default()),
            Some((Timer::Conn(ConnTimer::Close), now - 2 * sec))
        );
        assert_eq!(timers.expire_before(now, &QlogSink::default()), None);
    }

    #[test]
    fn test_small_map() {
        let mut map = SmallMap::<usize, usize, 2>::default();

        // inserts only on the stack
        assert_eq!(map.insert(1, 1), None);
        assert!(map.heap.is_none());
        assert_eq!(map.insert(2, 2), None);
        assert!(map.heap.is_none());

        // replace on the stack
        assert_eq!(map.insert(1, 2), Some(1));

        assert_eq!(map.remove(&1), Some(2));
        assert_eq!(map.insert(3, 3), None);
        assert!(map.heap.is_none());

        // spill
        assert_eq!(map.insert(4, 4), None);
        assert!(map.heap.is_some());

        assert_eq!(
            map.iter()
                .map(|(&a, &b)| (a, b))
                .collect::<Vec<(usize, usize)>>(),
            vec![(3, 3), (2, 2), (4, 4)]
        );
        assert_eq!(
            map.iter()
                .map(|(a, b)| (*a, *b))
                .collect::<Vec<(usize, usize)>>(),
            map.iter_mut()
                .map(|(a, b)| (*a, *b))
                .collect::<Vec<(usize, usize)>>(),
        );

        assert_eq!(map.heap.as_ref().unwrap().len(), 1);

        for i in 0..10 {
            map.insert(10 + i, 10 + i);
        }
        assert_eq!(map.heap.as_ref().unwrap().len(), 11);
        map.retain(|k, _v| *k < 10);

        assert_eq!(map.heap.as_ref().unwrap().len(), 1);

        assert_eq!(
            map.iter()
                .map(|(&a, &b)| (a, b))
                .collect::<Vec<(usize, usize)>>(),
            vec![(3, 3), (2, 2), (4, 4)]
        );

        assert_eq!(
            map.iter()
                .map(|(a, b)| (*a, *b))
                .collect::<Vec<(usize, usize)>>(),
            map.iter_mut()
                .map(|(a, b)| (*a, *b))
                .collect::<Vec<(usize, usize)>>(),
        );

        map.clear();
        assert_eq!(map.iter().collect::<Vec<_>>(), Vec::new());
        assert!(map.heap.is_none());
    }
}
