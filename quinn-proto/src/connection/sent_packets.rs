use std::{
    iter,
    ops::{Bound, RangeBounds},
    slice,
};

use super::spaces::SentPacket;

/// A sparse map from packet number to [`SentPacket`].
///
/// Entries are grouped into chunks of consecutive packet numbers, possibly separated by holes
/// to mitigate the cost of removed packets.
///
/// Insertions are monotonically increasing since packets are sent in order. Removals typically
/// occur at the front, but they can also be in the middle (i.e. the non-ack-eliciting packets tail).
/// This storage is robust to such holes (they cost at most 63 slots) unlike a basic `VecDeque`
/// slot-based implementation, while being more efficient than a simple `BTreeMap` for the access
/// patterns we're interested in.
#[derive(Default)]
#[allow(unreachable_pub, reason = "only pub for benches")]
pub struct SentPackets {
    chunks: Vec<Chunk>,
    last_inserted_packet_number: u64,
    /// Count of present entries with `size != 0`, for O(1) `has_in_flight`.
    in_flight: usize,
}

impl SentPackets {
    /// Insert `value` at `pn`, which must exceed every previously inserted packet number.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn insert(&mut self, pn: u64, packet: SentPacket) {
        debug_assert!(
            pn == 0 || pn > self.last_inserted_packet_number,
            "insertions must be monotonically increasing"
        );

        let in_flight = packet.size != 0;

        if let Some(last_chunk) = self.chunks.last_mut()
            && let Some(slot) = last_chunk.slot(pn)
        {
            last_chunk.slots[slot] = Some(packet);
            last_chunk.mask.occupy(slot);
        } else {
            self.chunks.push(Chunk::new(pn, packet));
        }

        self.last_inserted_packet_number = pn;

        if in_flight {
            self.in_flight += 1;
        }
    }

    /// Remove and return the packet `pn`, if any.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        // Removals are typically oldest-first, avoid the binary search in the common case.
        let chunk_idx = self.chunk_index_head(pn);
        let chunk = &mut self.chunks.get_mut(chunk_idx)?;

        let slot = chunk.slot(pn)?;
        let packet = chunk.slots[slot].take()?;
        chunk.mask.vacate(slot);

        if self.chunks[chunk_idx].mask.is_empty() {
            self.chunks.remove(chunk_idx);
        }

        if packet.size != 0 {
            self.in_flight -= 1;
        }

        Some(packet)
    }

    /// Return the entry for `pn`.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn get(&self, pn: u64) -> Option<&SentPacket> {
        let chunk = self.chunks.get(self.chunk_index_extremes(pn))?;
        chunk.slots[chunk.slot(pn)?].as_ref()
    }

    /// Return a mutable reference to the entry for `pn`.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn get_mut(&mut self, pn: u64) -> Option<&mut SentPacket> {
        let chunk_idx = self.chunk_index_extremes(pn);
        let chunk = self.chunks.get_mut(chunk_idx)?;
        chunk.slots[chunk.slot(pn)?].as_mut()
    }

    /// Whether any present entry has `size != 0`.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn has_in_flight(&self) -> bool {
        self.in_flight != 0
    }

    /// Iterate over present entries in `range`.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn range(
        &self,
        range: impl RangeBounds<u64>,
    ) -> impl Iterator<Item = (u64, &SentPacket)> + '_ {
        let lo = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.saturating_add(1),
            Bound::Unbounded => 0,
        };

        let hi = match range.end_bound() {
            Bound::Included(&n) => n.saturating_add(1),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => u64::MAX,
        };

        let first_chunk = match self.chunks.first() {
            Some(c) if lo < c.offset.saturating_add(CHUNK_SIZE as u64) => 0,
            _ => self.chunk_index(lo),
        };

        RangeIter {
            chunks: self.chunks.iter().skip(first_chunk),
            current: None,
            rest: Occupancy::default(),
            lo,
            hi,
        }
    }

    /// Consume the map, yielding present entries in increasing packet-number order.
    #[allow(unreachable_pub, reason = "only pub for benches")]
    pub fn into_values(self) -> impl Iterator<Item = SentPacket> {
        self.chunks.into_iter().flat_map(|mut chunk| {
            iter::from_fn(move || {
                let slot = chunk.mask.vacate_lowest()?;
                // A hole in `mask` would silently drop the remaining entries.
                debug_assert!(chunk.slots[slot].is_some());
                chunk.slots[slot].take()
            })
        })
    }

    /// Index of the chunk that may contain `pn`, favoring the outermost chunks (last then first).
    fn chunk_index_extremes(&self, pn: u64) -> usize {
        if let Some(chunk) = self.chunks.last()
            && chunk.slot(pn).is_some()
        {
            return self.chunks.len() - 1;
        }

        self.chunk_index_head(pn)
    }

    /// Index of the chunk that may contain `pn`, favoring the first chunk.
    fn chunk_index_head(&self, pn: u64) -> usize {
        if let Some(chunk) = self.chunks.first()
            && chunk.slot(pn).is_some()
        {
            return 0;
        }

        self.chunk_index(pn)
    }

    /// Index of the chunk that may contain `pn`.
    ///
    /// It's the chunk with the largest offset lesser than or equal to `pn`.
    fn chunk_index(&self, pn: u64) -> usize {
        let idx = self.chunks.partition_point(|chunk| chunk.offset <= pn);
        // `idx` is the first chunk that does not respect the condition, we want the one before.
        idx.saturating_sub(1)
    }
}

/// A window of consecutive packet numbers, which may contain holes.
struct Chunk {
    /// Packet number of the first slot.
    offset: u64,
    /// Slot `i` holds the entry for packet number `offset + i`.
    slots: Box<[Option<SentPacket>; CHUNK_SIZE]>,
    /// Occupancy of `slots`.
    mask: Occupancy,
}

impl Chunk {
    fn new(pn: u64, value: SentPacket) -> Self {
        let mut slots = [const { None }; CHUNK_SIZE];
        slots[0] = Some(value);

        let mut mask = Occupancy::default();
        mask.occupy(0);

        Self {
            offset: pn,
            slots: Box::new(slots),
            mask,
        }
    }

    /// Index of the slot for `pn`, if this chunk covers it.
    fn slot(&self, pn: u64) -> Option<usize> {
        let diff = pn.checked_sub(self.offset)?;
        let slot = usize::try_from(diff).ok()?;
        (slot < CHUNK_SIZE).then_some(slot)
    }
}

/// Maximum number of slots per chunk.
///
/// Chosen using benchmarks for [`SentPackets`] as well as end-to-end throughput benchmarks.
const CHUNK_SIZE: usize = 64;

/// Occupancy of a [`Chunk`]'s slots: bit `i` is set if slot `i` holds an entry.
#[derive(Clone, Copy, Default)]
struct Occupancy(u64);

impl Occupancy {
    const MAX: Self = Self(u64::MAX);
}

const _: () = {
    assert!(size_of::<Occupancy>() * 8 >= CHUNK_SIZE);
};

impl Occupancy {
    /// Mark `slot` as holding an entry.
    fn occupy(&mut self, slot: usize) {
        self.0 |= 1 << slot;
    }

    /// Mark `slot` as free.
    fn vacate(&mut self, slot: usize) {
        self.0 &= !(1 << slot);
    }

    /// Whether `slot` holds an entry.
    #[cfg(test)]
    fn is_occupied(&self, slot: usize) -> bool {
        self.0 & (1 << slot) != 0
    }

    /// Whether any slot holds an entry.
    fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// The lowest occupied slot, marking it free.
    fn vacate_lowest(&mut self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

        let slot = self.0.trailing_zeros() as usize;
        self.vacate(slot);
        Some(slot)
    }

    /// A copy of this occupancy with the slots below `slot` vacated.
    fn cleared_below(self, slot: usize) -> Self {
        Self(self.0 & (Self::MAX.0 << slot))
    }
}

/// Iterator over the entries of [`SentPackets::range`].
struct RangeIter<'a> {
    chunks: iter::Skip<slice::Iter<'a, Chunk>>,
    /// The chunk currently being scanned, if any.
    current: Option<&'a Chunk>,
    /// Occupancy of `current`, truncated before `lo`.
    rest: Occupancy,
    /// First packet number to yield.
    lo: u64,
    /// First packet number to skip (exclusive).
    hi: u64,
}

impl<'a> Iterator for RangeIter<'a> {
    type Item = (u64, &'a SentPacket);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            self.current = Some(self.advance()?);
        }

        let chunk = self.current?;
        let slot = self.rest.vacate_lowest()?;

        let pn = chunk.offset + slot as u64;

        if pn >= self.hi {
            return None;
        }

        // A hole here would terminate the iterator early and hide the remaining entries.
        debug_assert!(chunk.slots[slot].is_some());
        chunk.slots[slot].as_ref().map(|packet| (pn, packet))
    }
}

impl<'a> RangeIter<'a> {
    /// Move to the next chunk holding a present entry at or above `lo`,
    /// setting `rest` to its occupancy from the first such slot.
    fn advance(&mut self) -> Option<&'a Chunk> {
        for chunk in self.chunks.by_ref() {
            if chunk.offset >= self.hi {
                return None;
            }

            // First slot that could hold a packet number greater than or equal to `lo`.
            let Some(start) = chunk.slot(Ord::max(self.lo, chunk.offset)) else {
                continue;
            };

            let rest = chunk.mask.cleared_below(start);
            if !rest.is_empty() {
                self.rest = rest;
                return Some(chunk);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Instant;

    #[test]
    fn storage_is_bounded_by_live_packets() {
        let mut packets = SentPackets::default();

        packets.insert(0, packet(1200));

        for pn in 1..4096 {
            packets.insert(pn, packet(0));
            packets.remove(pn);
        }

        assert_eq!(packets.range(..).count(), 1);
        assert_eq!(packets.chunks.len(), 1);
        assert!(packets.has_in_flight());
        assert_eq!(packets.get(0).unwrap().size, 1200);
    }

    #[test]
    fn storage_is_bounded_with_holes() {
        const MAX_TAIL: u64 = 32;
        let mut packets = SentPackets::default();
        for pn in 0..8 {
            packets.insert(pn, packet(1200));
        }

        let largest_ack_eliciting_sent = 7;
        let mut tail = 0;
        for i in 0..10_000 {
            packets.insert(8 + i, packet(0));
            tail += 1;

            if tail > MAX_TAIL {
                let oldest = packets
                    .range((
                        Bound::Excluded(largest_ack_eliciting_sent),
                        Bound::Unbounded,
                    ))
                    .next()
                    .expect("tail packets are retained")
                    .0;
                packets.remove(oldest);
                tail -= 1;
            }
        }

        let live = packets.range(..).count();
        assert_eq!(live, 8 + MAX_TAIL as usize);

        // The packet numbers span more than 10_000 packets, but storage only tracks the live
        // entries: the tail window spans at most `MAX_TAIL / CHUNK_SIZE + 1` aligned chunks,
        // plus the head chunk.
        let chunks = packets.chunks.len();
        assert!(chunks <= MAX_TAIL as usize / CHUNK_SIZE + 3);
    }

    /// A chunk that becomes empty in the middle of the deque is dropped.
    #[test]
    fn empty_middle_chunk_is_dropped() {
        let mut packets = SentPackets::default();
        for pn in 0..(3 * CHUNK_SIZE) {
            packets.insert(pn as u64, packet(pn as u16));
        }
        assert_eq!(packets.chunks.len(), 3);

        for pn in CHUNK_SIZE..(2 * CHUNK_SIZE) {
            packets.remove(pn as u64);
        }

        assert_eq!(packets.chunks.len(), 2);
        assert_eq!(packets.chunks[0].offset, 0);
        assert_eq!(packets.chunks[1].offset, 2 * CHUNK_SIZE as u64);
        assert!(packets.get(CHUNK_SIZE as u64).is_none());

        let stored_packets = packets.range(..).map(|(pn, _)| pn);
        let expected_packets =
            (0..CHUNK_SIZE as u64).chain(2 * CHUNK_SIZE as u64..3 * CHUNK_SIZE as u64);
        assert!(stored_packets.eq(expected_packets));
    }

    #[test]
    fn gaps_between_and_within_chunks() {
        let mut packets = SentPackets::default();
        packets.insert(0, packet(1));
        packets.insert(1, packet(1));
        packets.insert(10, packet(1)); // intra-chunk gap
        packets.insert(10 * CHUNK_SIZE as u64, packet(1)); // inter-chunk gap

        assert_eq!(packets.chunks.len(), 2);
        // Chunk 0 holds pn 0, 1 and 10 (slots 2..10 are empty holes).
        let occupied: usize = packets.chunks[0]
            .slots
            .iter()
            .filter(|s| s.is_some())
            .count();
        assert_eq!(occupied, 3);

        assert!(packets.get(5).is_none());
        assert!(packets.get(9 * CHUNK_SIZE as u64).is_none());

        assert!(packets.get(10).is_some());
        assert!(packets.get(10 * CHUNK_SIZE as u64).is_some());

        let stored_packets = packets.range(..).map(|(pn, _)| pn);
        assert!(stored_packets.eq([0, 1, 10, 10 * CHUNK_SIZE as u64]));
    }

    #[test]
    fn ordering_with_holes_across_chunks() {
        let mut packets = SentPackets::default();

        const TOTAL: u64 = 500;
        for pn in 0..TOTAL {
            packets.insert(pn, packet(pn as u16));
        }
        for pn in (0..TOTAL).step_by(3) {
            packets.remove(pn);
        }

        let expected: Vec<u64> = (0..TOTAL).filter(|pn| pn % 3 != 0).collect();
        assert_eq!(
            packets.range(..).map(|(pn, _)| pn).collect::<Vec<_>>(),
            expected
        );
        let sizes: Vec<u16> = packets.range(..).map(|(_, p)| p.size).collect();
        assert_eq!(
            sizes,
            expected.iter().map(|pn| *pn as u16).collect::<Vec<_>>()
        );
        let taken: Vec<u16> = packets.into_values().map(|p| p.size).collect();
        assert_eq!(
            taken,
            expected.iter().map(|pn| *pn as u16).collect::<Vec<_>>()
        );
    }

    #[test]
    fn insert_get_and_order() {
        let mut m = SentPackets::default();
        for pn in 3..=6 {
            m.insert(pn, packet(pn as u16 * 10));
        }

        assert_eq!(m.get(3).map(|p| p.size), Some(30));
        assert_eq!(m.get(6).map(|p| p.size), Some(60));

        assert!(m.get(2).is_none());
        assert!(m.get(7).is_none());

        assert_eq!(m.get(5).map(|p| p.size), Some(50));

        assert_eq!(
            m.range(..).map(|(_, p)| p.size).collect::<Vec<_>>(),
            vec![30, 40, 50, 60]
        );
    }

    #[test]
    fn skipped_numbers_leave_gaps() {
        let mut m = SentPackets::default();
        m.insert(0, packet(0));
        m.insert(1, packet(1));
        m.insert(4, packet(4)); // 2 and 3 skipped

        assert!(m.get(2).is_none());
        assert!(m.get(3).is_none());
        assert_eq!(m.get(4).map(|p| p.size), Some(4));
        assert_eq!(range_of(&m, ..), vec![(0, 0), (1, 1), (4, 4)]);
    }

    #[test]
    fn remove_middle_leaves_hole_front_unchanged() {
        let mut m = SentPackets::default();
        for pn in 0..5 {
            m.insert(pn, packet(pn as u16));
        }

        assert_eq!(m.remove(2).map(|p| p.size), Some(2));
        assert!(m.remove(2).is_none());
        assert!(m.get(2).is_none());
        // Front intact: offset unchanged, iteration skips the hole.
        assert_eq!(range_of(&m, ..), vec![(0, 0), (1, 1), (3, 3), (4, 4)]);
    }

    #[test]
    fn remove_front_reclaims_leading_holes() {
        let mut m = SentPackets::default();
        for pn in 0..5 {
            m.insert(pn, packet(pn as u16));
        }

        // Removing the front also reclaims the already-vacated 1 and 2.
        assert_eq!(m.remove(1).map(|p| p.size), Some(1));
        assert_eq!(m.remove(2).map(|p| p.size), Some(2));
        assert_eq!(m.remove(0).map(|p| p.size), Some(0));
        assert_eq!(range_of(&m, ..), vec![(3, 3), (4, 4)]);

        // A later insert still lands at the right packet number.
        m.insert(9, packet(9));
        assert_eq!(m.get(9).map(|p| p.size), Some(9));
        assert_eq!(range_of(&m, ..), vec![(3, 3), (4, 4), (9, 9)]);
    }

    #[test]
    fn head_and_tail_lookups_and_removals() {
        let mut m = SentPackets::default();
        for pn in 0..(4 * CHUNK_SIZE as u64) {
            m.insert(pn, packet(pn as u16));
        }
        assert_eq!(m.chunks.len(), 4);

        // Oldest, newest and middle entries resolve through different paths.
        assert_eq!(m.get(0).map(|p| p.size), Some(0));
        assert_eq!(m.get(4 * CHUNK_SIZE as u64 - 1).map(|p| p.size), Some(255));
        assert_eq!(m.get(CHUNK_SIZE as u64 + 1).map(|p| p.size), Some(65));

        // Drain the first chunk.
        for pn in 0..CHUNK_SIZE as u64 {
            assert_eq!(m.remove(pn).map(|p| p.size), Some(pn as u16));
        }
        assert_eq!(m.chunks.len(), 3);
        assert!(m.get(CHUNK_SIZE as u64 - 1).is_none());
        assert_eq!(
            m.range(0..).next().map(|(pn, _)| pn),
            Some(CHUNK_SIZE as u64)
        );

        // Mutable access on the new first chunk.
        m.get_mut(CHUNK_SIZE as u64).unwrap().size += 100;
        assert_eq!(m.get(CHUNK_SIZE as u64).map(|p| p.size), Some(164));

        // Removal in the first chunk.
        assert_eq!(m.remove(70).map(|p| p.size), Some(70));
        assert!(m.remove(70).is_none());
        assert_eq!(m.chunks.len(), 3);

        // Middle removal.
        assert_eq!(
            m.remove(3 * CHUNK_SIZE as u64 - 1).map(|p| p.size),
            Some(191)
        );
    }

    #[test]
    fn range_bounds() {
        let mut m = SentPackets::default();
        for pn in 10..20 {
            m.insert(pn, packet(pn as u16));
        }
        assert_eq!(range_of(&m, 12..15), vec![(12, 12), (13, 13), (14, 14)]);
        assert_eq!(range_of(&m, 12..=14), vec![(12, 12), (13, 13), (14, 14)]);
        assert_eq!(
            range_of(&m, (Bound::Excluded(17), Bound::Unbounded)),
            vec![(18, 18), (19, 19)]
        );

        // Out-of-window ranges are empty, not a panic.
        assert_eq!(range_of(&m, 0..5), vec![]);
        assert_eq!(range_of(&m, 100..200), vec![]);
    }

    #[test]
    fn get_mut_and_into_values() {
        let mut m = SentPackets::default();
        for pn in 0..4 {
            m.insert(pn, packet(pn as u16));
        }
        m.remove(1);

        let pns: Vec<u64> = m.range(..).map(|(pn, _)| pn).collect();
        for pn in pns {
            m.get_mut(pn).unwrap().size += 100;
        }

        assert_eq!(m.get(0).map(|p| p.size), Some(100));
        assert_eq!(m.get(2).map(|p| p.size), Some(102));
        assert_eq!(
            m.into_values().map(|p| p.size).collect::<Vec<_>>(),
            vec![100, 102, 103]
        );
    }

    #[test]
    fn take_resets() {
        let mut m = SentPackets::default();
        for pn in 5..8 {
            m.insert(pn, packet(pn as u16));
        }

        let taken = std::mem::take(&mut m);
        assert_eq!(
            taken.into_values().map(|p| p.size).collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(range_of(&m, ..), vec![]);

        // Reusable after take.
        m.insert(100, packet(100));
        assert_eq!(m.get(100).map(|p| p.size), Some(100));
    }

    #[test]
    fn tracks_in_flight() {
        let mut m = SentPackets::default();
        assert!(!m.has_in_flight());

        m.insert(0, packet(0)); // size 0: not in flight
        assert!(!m.has_in_flight());

        m.insert(1, packet(1200));
        m.insert(2, packet(1200));
        assert!(m.has_in_flight());

        m.remove(1);
        assert!(m.has_in_flight()); // 2 still in flight

        m.remove(2);
        assert!(!m.has_in_flight()); // only size-0 remains

        m.remove(0);
        assert!(!m.has_in_flight());
    }

    #[test]
    fn occupancy_stays_in_sync_with_slots() {
        let mut m = SentPackets::default();

        for pn in 0..40 {
            m.insert(pn, packet(pn as u16));
        }

        for pn in (0..40).step_by(2) {
            m.remove(pn);
        }

        for pn in 40..44 {
            m.insert(pn, packet(pn as u16));
        }

        for chunk in &m.chunks {
            for slot in 0..CHUNK_SIZE {
                let expected = chunk.slots[slot].is_some() as u16;
                let actual = chunk.mask.is_occupied(slot) as u16;
                assert_eq!(actual, expected);
            }
        }
    }

    /// A `SentPacket` identified by its `size`.
    fn packet(size: u16) -> SentPacket {
        SentPacket {
            path_generation: 0,
            time_sent: Instant::now(),
            size,
            ack_eliciting: false,
            largest_acked: None,
            retransmits: Default::default(),
            stream_frames: Default::default(),
        }
    }

    /// `(pn, size)` pairs from `range`.
    fn range_of<R: RangeBounds<u64>>(m: &SentPackets, r: R) -> Vec<(u64, u16)> {
        m.range(r).map(|(pn, v)| (pn, v.size)).collect()
    }
}
