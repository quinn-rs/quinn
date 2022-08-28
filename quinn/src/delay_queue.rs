use std::{fmt, ops::RangeInclusive};

use slab::Slab;

/// Stores values to be yielded at specific times in the future
///
/// Time is expressed as a bare u64 representing an absolute point in time. The caller may use any
/// consistent unit, e.g. milliseconds, and any consistent definition of time zero. Larger units
/// limit resolution but make `poll`ing over the same real-time interval proportionately faster,
/// whereas smaller units improve resolution, limit total range, and reduce `poll` performance.
#[derive(Debug)]
pub struct DelayQueue<T> {
    /// Definitions of each active timer
    ///
    /// Timers are defined here, and referenced indirectly by index from `levels` and in the public
    /// API. This allows for safe construction of intrusive linked lists between timers, and helps
    /// reduce the amount of data that needs to be routinely shuffled around in `levels` as time
    /// passes.
    timers: Slab<TimerState<T>>,

    /// A hierarchical timer wheel
    ///
    /// This data structure breaks down points in time into digits. The base of those digits can be
    /// chosen arbitrarily; this implementation uses base `2^LOG_2_SLOTS`. A power of two makes it
    /// easy to manipulate individual digits using bit shifts and masking because each digit
    /// corresponds directly to `LOG_2_SLOTS` bits in the binary representation. For familiarity, we
    /// will illustrate a timer wheel built instead on base 10, but the behavior is identical.
    ///
    /// Consider this timer wheel where timers are set at times 32, 42, and 46, and `next_tick` is
    /// between 30 and 32 inclusive. Note that the number of slots in each level is equal to the
    /// base of the digits used, in this case 10.
    ///
    /// ```text
    ///           +--+--+--+--+--
    /// Level 0   |30|31|32|33| ...
    ///           +--+--+--+--+--
    ///            \      |       /
    ///             \     V      /
    ///              \  +--+    /
    ///               \ |32|   /
    ///                \+--+  /
    ///                 \    /
    ///         +--+--+--+--+--+--+--+--+--+--+
    /// Level 1 |00|10|20|30|40|50|60|70|80|90|
    ///         +--+--+--+--+--+--+--+--+--+--+
    ///                       |
    ///                       V
    ///                     +--+
    ///                     |46|
    ///                     +--+
    ///                      ^|
    ///                      |V
    ///                     +--+
    ///                     |42|
    ///                     +--+
    /// ```
    ///
    /// Timers are organized into buckets (or slots) at a resolution that decreases exponentially
    /// with distance from `next_tick`, the present. Higher-numbered levels cover larger intervals,
    /// until the highest-numbered level covers the complete representable of timers, from 0 to
    /// `u64::MAX`. Every lower level covers the slot in the next highest level which `next_tick`
    /// lies within. Level 0 represents the maximum resolution, where each slot covers exactly one
    /// unit of time.
    ///
    /// The slot that a timer should be stored in is easily computed based on `next_tick` and the
    /// desired expiry time. For a base 10 structure, find the most significant digit in the base 10
    /// representations of `next_tick` and the desired expiry time that differs between the two. The
    /// position of that digit is the level, and the value of that digit is the position in the
    /// level. For example, if `next_tick` is 7342, and a timer is scheduled for time 7361, the
    /// timer would be stored at level 1, slot 6. Note that no subtraction is performed: the start
    /// of each level is always the greatest integer multiple of the level's span which is less than
    /// or equal to `next_tick`.
    ///
    /// Calls to `poll` move `next_tick` towards the passed-in time. When `next_tick` reaches a
    /// timer in level 0, it stops there and the timer is removed and returned from `poll`. Reaching
    /// the end of level 0 redefines level 0 to represent the next slot in level 1, at which point
    /// all timers stored in that slot are unpacked into appropriate slots of level 0, and traversal
    /// of level 0 begins again from the start. When level 1 is exhausted, the next slot in level 2
    /// is unpacked into levels 1 and 0, and so on for higher levels. Slots preceding `next_tick`
    /// are therefore empty at any level, and for levels above 0, the slot containing `next_tick` is
    /// also empty, having necessarily been unpacked into lower levels.
    ///
    /// Assuming the number of timers scheduled within a period of time is on average proportional
    /// to the size of that period, advancing the queue by a constant amount of time has amortized
    /// constant time complexity, because the frequency with which slots at a particular level are
    /// unpacked is inversely proportional to the expected number of timers stored in that
    /// slot.
    ///
    /// Inserting, removing, and updating timers are constant-time operations thanks to the above
    /// and the use of unordered doubly linked lists to represent the contents of a slot. We can
    /// also compute a lower bound for the next timeout in constant time by scanning for the
    /// earliest nonempty slot.
    levels: [Level; LEVELS],

    /// Earliest point at which a timer may be pending
    ///
    /// Each `LOG_2_SLOTS` bits of this are a cursor into the associated level, in order of
    /// ascending significance.
    next_tick: u64,
}

impl<T> DelayQueue<T> {
    /// Create an empty queue starting at time `0`
    pub fn new() -> Self {
        Self {
            timers: Slab::new(),
            levels: [Level::new(); LEVELS],
            next_tick: 0,
        }
    }

    /// Returns a timer that has expired by `now`, if any
    ///
    /// `now` must be at least the largest previously passed value
    pub fn poll(&mut self, now: u64) -> Option<T> {
        debug_assert!(now >= self.next_tick, "time advances monotonically");
        loop {
            // Advance towards the next timeout
            self.advance_towards(now);
            // Check for timeouts in the immediate future
            if let Some(value) = self.scan_bottom(now) {
                return Some(value);
            }
            // If we can't advance any further, bail out
            if self.next_tick >= now {
                return None;
            }
        }
    }

    /// Find a timer expired by `now` in level 0
    fn scan_bottom(&mut self, now: u64) -> Option<T> {
        if let Some((slot, timer)) = self.levels[0].slots[range_in_level(0, self.next_tick..=now)]
            .iter_mut()
            .find_map(|x| x.take().map(|timer| (x, timer)))
        {
            let state = self.timers.remove(timer.0);
            debug_assert_eq!(state.prev, None, "head of list has no predecessor");
            debug_assert!(state.expiry <= now);
            if let Some(next) = state.next {
                debug_assert_eq!(
                    self.timers[next.0].prev,
                    Some(timer),
                    "successor links to head"
                );
                self.timers[next.0].prev = None;
            }
            *slot = state.next;
            self.next_tick = state.expiry;
            self.maybe_shrink();
            return Some(state.value);
        }
        None
    }

    /// Advance to the start of the first nonempty slot or `now`, whichever is sooner
    fn advance_towards(&mut self, now: u64) {
        for level in 0..LEVELS {
            for slot in range_in_level(level, self.next_tick..=now) {
                debug_assert!(
                    now >= slot_start(self.next_tick, level, slot),
                    "slot overlaps with the past"
                );
                if self.levels[level].slots[slot].is_some() {
                    self.advance_to(level, slot);
                    return;
                }
            }
        }
        self.next_tick = now;
    }

    /// Advance to a specific slot, which must be the first nonempty slot
    fn advance_to(&mut self, level: usize, slot: usize) {
        debug_assert!(
            self.levels[..level]
                .iter()
                .all(|level| level.slots.iter().all(|x| x.is_none())),
            "lower levels are empty"
        );
        debug_assert!(
            self.levels[level].slots[..slot].iter().all(Option::is_none),
            "lower slots in this level are empty"
        );

        // Advance into the slot
        self.next_tick = slot_start(self.next_tick, level, slot);

        if level == 0 {
            // No lower levels exist to unpack timers into
            return;
        }

        // Unpack all timers in this slot into lower levels
        while let Some(timer) = self.levels[level].slots[slot].take() {
            let next = self.timers[timer.0].next;
            self.levels[level].slots[slot] = next;
            if let Some(next) = next {
                self.timers[next.0].prev = None;
            }
            self.list_unlink(timer);
            self.schedule(timer);
        }
    }

    /// Link `timer` from the slot associated with its expiry
    fn schedule(&mut self, timer: Timer) {
        debug_assert_eq!(
            self.timers[timer.0].next, None,
            "timer isn't already scheduled"
        );
        debug_assert_eq!(
            self.timers[timer.0].prev, None,
            "timer isn't already scheduled"
        );
        let (level, slot) = timer_index(self.next_tick, self.timers[timer.0].expiry);
        // Insert `timer` at the head of the list in the target slot
        let head = self.levels[level].slots[slot];
        self.timers[timer.0].next = head;
        if let Some(head) = head {
            self.timers[head.0].prev = Some(timer);
        }
        self.levels[level].slots[slot] = Some(timer);
    }

    /// Lower bound on when the next timer will expire, if any
    pub fn next_timeout(&self) -> Option<u64> {
        for level in 0..LEVELS {
            let start = ((self.next_tick >> (level * LOG_2_SLOTS)) & (SLOTS - 1) as u64) as usize;
            for slot in start..SLOTS {
                if self.levels[level].slots[slot].is_some() {
                    return Some(slot_start(self.next_tick, level, slot));
                }
            }
        }
        None
    }

    /// Register a timer that will yield `value` at `timeout`
    pub fn insert(&mut self, timeout: u64, value: T) -> Timer {
        let timer = Timer(self.timers.insert(TimerState {
            expiry: timeout.max(self.next_tick),
            prev: None,
            next: None,
            value,
        }));
        self.schedule(timer);
        timer
    }

    /// Adjust `timer` to expire at `timeout`
    pub fn reset(&mut self, timer: Timer, timeout: u64) {
        self.unlink(timer);
        self.timers[timer.0].expiry = timeout.max(self.next_tick);
        self.schedule(timer);
    }

    /// Cancel `timer`
    #[cfg(test)]
    pub fn remove(&mut self, timer: Timer) -> T {
        self.unlink(timer);
        let state = self.timers.remove(timer.0);
        self.maybe_shrink();
        state.value
    }

    /// Release timer state memory if it's mostly unused
    fn maybe_shrink(&mut self) {
        if self.timers.capacity() / 16 > self.timers.len() {
            self.timers.shrink_to_fit();
        }
    }

    /// Remove all references to `timer`
    fn unlink(&mut self, timer: Timer) {
        let (level, slot) = timer_index(self.next_tick, self.timers[timer.0].expiry);
        // If necessary, remove a reference to `timer` from its slot by replacing it with its
        // successor
        let slot_head = self.levels[level].slots[slot].unwrap();
        if slot_head == timer {
            self.levels[level].slots[slot] = self.timers[slot_head.0].next;
            debug_assert_eq!(
                self.timers[timer.0].prev, None,
                "head of list has no predecessor"
            );
        }
        // Remove references to `timer` from other timers
        self.list_unlink(timer);
    }

    /// Remove `timer` from its list
    fn list_unlink(&mut self, timer: Timer) {
        let prev = self.timers[timer.0].prev.take();
        let next = self.timers[timer.0].next.take();
        if let Some(prev) = prev {
            // Remove reference from predecessor
            self.timers[prev.0].next = next;
        }
        if let Some(next) = next {
            // Remove reference from successor
            self.timers[next.0].prev = prev;
        }
    }
}

fn range_in_level(level: usize, raw: RangeInclusive<u64>) -> RangeInclusive<usize> {
    let shift = level * LOG_2_SLOTS;
    const MASK: u64 = SLOTS as u64 - 1;
    let start = ((*raw.start() >> shift) & MASK) as usize;
    let level_end = (*raw.start() >> shift) | MASK;
    let end = ((*raw.end() >> shift).min(level_end) & MASK) as usize;
    start..=end
}

/// Compute the first tick that lies within a slot
fn slot_start(base: u64, level: usize, slot: usize) -> u64 {
    let shift = (level * LOG_2_SLOTS) as u64;
    // Shifting twice avoids an overflow when level = 10.
    (base & ((!0 << shift) << LOG_2_SLOTS as u64)) | ((slot as u64) << shift)
}

/// Compute the level and slot for a certain expiry
fn timer_index(base: u64, expiry: u64) -> (usize, usize) {
    // The level is the position of the first bit set in `expiry` but not in `base`, divided by the
    // number of bits spanned by each level.
    let differing_bits = base ^ expiry;
    let level = (63 - (differing_bits | 1).leading_zeros()) as usize / LOG_2_SLOTS;
    debug_assert!(level < LEVELS, "every possible expiry is in range");

    // The slot in that level is the difference between the expiry time and the time at which the
    // level's span begins, after both times are shifted down to the level's granularity. Each
    // level's spans starts at `base`, rounded down to a multiple of the size of its span.
    let slot_base = (base >> (level * LOG_2_SLOTS)) & (!0 << LOG_2_SLOTS);
    let slot = (expiry >> (level * LOG_2_SLOTS)) - slot_base;
    debug_assert!(slot < SLOTS as u64);

    (level, slot as usize)
}

impl<T> Default for DelayQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct TimerState<T> {
    /// Lowest argument to `poll` for which this timer may be returned
    expiry: u64,
    /// Value returned to the caller on expiry
    value: T,
    /// Predecessor within a slot's list
    prev: Option<Timer>,
    /// Successor within a slot's list
    next: Option<Timer>,
}

/// A set of contiguous timer lists, ordered by expiry
///
/// Level `n` spans `2^(LOG_2_SLOTS * (n+1))` ticks, and each of its slots corresponds to a span of
/// `2^(LOG_2_SLOTS * n)`.
#[derive(Copy, Clone)]
struct Level {
    slots: [Option<Timer>; SLOTS],
}

impl Level {
    fn new() -> Self {
        Self {
            slots: [None; SLOTS],
        }
    }
}

impl fmt::Debug for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        let numbered_nonempty_slots = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, x)| x.map(|t| (i, t)));
        for (i, Timer(t)) in numbered_nonempty_slots {
            m.entry(&i, &t);
        }
        m.finish()
    }
}

const LOG_2_SLOTS: usize = 6;
const LEVELS: usize = 1 + 64 / LOG_2_SLOTS;
const SLOTS: usize = 1 << LOG_2_SLOTS;

// Index in `DelayQueue::timers`. Future work: add a niche here.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Timer(usize);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use proptest::prelude::*;

    #[test]
    fn max_timeout() {
        let mut queue = DelayQueue::new();
        queue.insert(u64::MAX, ());
        assert!(queue.poll(u64::MAX - 1).is_none());
        assert!(queue.poll(u64::MAX).is_some());
    }

    #[test]
    fn level_ranges() {
        assert_eq!(range_in_level(0, 0..=1), 0..=1);
        assert_eq!(range_in_level(0, 0..=SLOTS as u64), 0..=SLOTS - 1);
        assert_eq!(range_in_level(1, 0..=SLOTS as u64), 0..=1);
        assert_eq!(range_in_level(1, 0..=(SLOTS as u64).pow(2)), 0..=SLOTS - 1);
        assert_eq!(range_in_level(2, 0..=(SLOTS as u64).pow(2)), 0..=1);
    }

    #[test]
    fn slot_starts() {
        for i in 0..SLOTS {
            assert_eq!(slot_start(0, 0, i), i as u64);
            assert_eq!(slot_start(SLOTS as u64, 0, i), SLOTS as u64 + i as u64);
            assert_eq!(slot_start(SLOTS as u64 + 1, 0, i), SLOTS as u64 + i as u64);
            for j in 1..LEVELS {
                assert_eq!(
                    slot_start(0, j, i),
                    (SLOTS as u64).pow(j as u32).wrapping_mul(i as u64)
                );
            }
        }
    }

    #[test]
    fn indexes() {
        assert_eq!(timer_index(0, 0), (0, 0));
        assert_eq!(timer_index(0, SLOTS as u64 - 1), (0, SLOTS - 1));
        assert_eq!(
            timer_index(SLOTS as u64 - 1, SLOTS as u64 - 1),
            (0, SLOTS - 1)
        );
        assert_eq!(timer_index(0, SLOTS as u64), (1, 1));
        for i in 0..LEVELS {
            assert_eq!(timer_index(0, (SLOTS as u64).pow(i as u32)), (i, 1));
            if i < LEVELS - 1 {
                assert_eq!(
                    timer_index(0, (SLOTS as u64).pow(i as u32 + 1) - 1),
                    (i, SLOTS - 1)
                );
                assert_eq!(
                    timer_index(SLOTS as u64 - 1, (SLOTS as u64).pow(i as u32 + 1) - 1),
                    (i, SLOTS - 1)
                );
            }
        }
    }

    #[test]
    fn next_timeout() {
        let mut queue = DelayQueue::new();
        assert_eq!(queue.next_timeout(), None);
        let k = queue.insert(0, ());
        assert_eq!(queue.next_timeout(), Some(0));
        queue.remove(k);
        assert_eq!(queue.next_timeout(), None);
        queue.insert(1234, ());
        assert!(queue.next_timeout().unwrap() > 12);
        queue.insert(12, ());
        assert_eq!(queue.next_timeout(), Some(12));
    }

    #[test]
    fn poll_boundary() {
        let mut queue = DelayQueue::new();
        queue.insert(SLOTS as u64 - 1, 'a');
        queue.insert(SLOTS as u64, 'b');
        assert_eq!(queue.poll(SLOTS as u64 - 2), None);
        assert_eq!(queue.poll(SLOTS as u64 - 1), Some('a'));
        assert_eq!(queue.poll(SLOTS as u64 - 1), None);
        assert_eq!(queue.poll(SLOTS as u64), Some('b'));
    }

    #[test]
    /// Validate that `reset` properly updates intrusive list links
    fn reset_list_middle() {
        let mut queue = DelayQueue::new();
        let slot = SLOTS as u64 / 2;
        let a = queue.insert(slot, ());
        let b = queue.insert(slot, ());
        let c = queue.insert(slot, ());

        queue.reset(b, slot + 1);

        assert_eq!(queue.levels[0].slots[slot as usize + 1], Some(b));
        assert_eq!(queue.timers[b.0].prev, None);
        assert_eq!(queue.timers[b.0].next, None);

        assert_eq!(queue.levels[0].slots[slot as usize], Some(c));
        assert_eq!(queue.timers[c.0].prev, None);
        assert_eq!(queue.timers[c.0].next, Some(a));
        assert_eq!(queue.timers[a.0].prev, Some(c));
        assert_eq!(queue.timers[a.0].next, None);
    }

    proptest! {
        #[test]
        fn poll(ts in times()) {
            let mut queue = DelayQueue::new();
            let mut time_values = HashMap::<u64, Vec<usize>>::new();
            for (i, t) in ts.into_iter().enumerate() {
                queue.insert(t, i);
                time_values.entry(t).or_default().push(i);
            }
            let mut time_values = time_values.into_iter().collect::<Vec<(u64, Vec<usize>)>>();
            time_values.sort_unstable_by_key(|&(t, _)| t);
            for &(t, ref is) in &time_values {
                assert!(queue.next_timeout().unwrap() <= t);
                if t > 0 {
                    assert_eq!(queue.poll(t-1), None);
                }
                let mut values = Vec::new();
                while let Some(i) = queue.poll(t) {
                    values.push(i);
                }
                assert_eq!(values.len(), is.len());
                for i in is {
                    assert!(values.contains(i));
                }
            }
        }

        #[test]
        fn reset(ts_a in times(), ts_b in times()) {
            let mut queue = DelayQueue::new();
            let timers = ts_a.map(|t| queue.insert(t, ()));
            for (timer, t) in timers.into_iter().zip(ts_b) {
                queue.reset(timer, t);
            }
            let mut n = 0;
            while let Some(()) = queue.poll(u64::MAX) {
                n += 1;
            }
            assert_eq!(n, timers.len());
        }

        #[test]
        fn index_start_consistency(a in time(), b in time()) {
            let base = a.min(b);
            let t = a.max(b);
            let (level, slot) = timer_index(base, t);
            let start = slot_start(base, level, slot);
            assert!(start <= t);
            if let Some(end) = start.checked_add((SLOTS as u64).pow(level as u32)) {
                assert!(end > t);
            } else {
                // Slot contains u64::MAX
                assert!(start >= slot_start(0, LEVELS - 1, 15));
                if level == LEVELS - 1 {
                    assert_eq!(slot, 15);
                } else {
                    assert_eq!(slot, SLOTS - 1);
                }
            }
        }
    }

    /// Generates a time whose level/slot is more or less uniformly distributed
    fn time() -> impl Strategy<Value = u64> {
        ((0..LEVELS as u32), (0..SLOTS as u64)).prop_perturb(|(level, mut slot), mut rng| {
            if level == LEVELS as u32 - 1 {
                slot %= 16;
            }
            let slot_size = (SLOTS as u64).pow(level);
            let slot_start = slot * slot_size;
            let slot_end = (slot + 1).saturating_mul(slot_size);
            rng.gen_range(slot_start..slot_end)
        })
    }

    #[rustfmt::skip]
    fn times() -> impl Strategy<Value = [u64; 16]> {
        [time(), time(), time(), time(), time(), time(), time(), time(),
         time(), time(), time(), time(), time(), time(), time(), time()]
    }
}
