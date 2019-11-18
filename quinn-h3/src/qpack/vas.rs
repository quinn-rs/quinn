/**
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2.1
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2.2
 */

/*
 *  # Virtually infinite address space mapper.
 *
 *  It can be described as a infinitively growable list, with a visibility
 *  window that can only move in the direction of insertion.
 *
 *  Origin          Visible window
 *  /\         /===========^===========\
 *  ++++-------+ - + - + - + - + - + - +
 *  ||||       |   |   |   |   |   |   |  ==> Grow direction
 *  ++++-------+ - + - + - + - + - + - +
 *  \================v==================/
 *           Full Virtual Space
 *
 *
 *  QPACK indexing is 1-based for absolute index, and 0-based for relative's.
 *  Container (ex: list) indexing is 0-based.
 *
 *
 *  # Basics
 *
 *  inserted: number of insertion
 *  dropped : number of drop
 *  delta   : count of available elements
 *
 *  abs: absolute index
 *  rel: relative index
 *  pos: real index in memory container
 *  pst: post-base relative index (only with base index)
 *
 *    first      oldest              lastest
 *    element    insertion           insertion
 *    (not       available           available
 *    available) |                   |
 *    |          |                   |
 *    v          v                   v
 *  + - +------+ - + - + - + - + - + - +  inserted: 21
 *  | a |      | p | q | r | s | t | u |  dropped: 15
 *  + - +------+ - + - + - + - + - + - +  delta: 21 - 15: 6
 *    ^          ^                   ^
 *    |          |                   |
 * abs:-      abs:16              abs:21
 * rel:-      rel:5               rel:0
 * pos:-      pos:0               pos:6
 *
 *
 * # Base index
 * A base index can arbitrary shift the relative index.
 * The base index itself is a absolute index.
 *
 *                       base index: 17
 *                       |
 *                       v
 *  + - +------+ - + - + - + - + - + - +  inserted: 21
 *  | a |      | p | q | r | s | t | u |  dropped: 15
 *  + - +------+ - + - + - + - + - + - +  delta: 21 - 15: 6
 *    ^          ^       ^           ^
 *    |          |       |           |
 * abs:-      abs:16  abs:18      abs:21
 * rel:-      rel:2   rel:0       rel:-
 * pst:-      pst:-   pst:-       pst:2
 * pos:-      pos:0   pos:2       pos:6
 */

pub type RelativeIndex = usize;
pub type AbsoluteIndex = usize;

#[derive(Debug, PartialEq)]
pub enum Error {
    BadRelativeIndex(usize),
    BadPostbaseIndex(usize),
    BadIndex(usize),
}

#[derive(Debug, Default)]
pub struct VirtualAddressSpace {
    inserted: usize,
    dropped: usize,
    delta: usize,
}

impl VirtualAddressSpace {
    pub fn add(&mut self) -> AbsoluteIndex {
        self.inserted += 1;
        self.delta += 1;
        self.inserted
    }

    pub fn drop(&mut self) {
        self.dropped += 1;
        self.delta -= 1;
    }

    pub fn relative(&self, index: RelativeIndex) -> Result<usize, Error> {
        if self.inserted < index || self.delta == 0 || self.inserted - index <= self.dropped {
            Err(Error::BadRelativeIndex(index))
        } else {
            Ok(self.inserted - self.dropped - index - 1)
        }
    }

    pub fn evicted(&self, index: AbsoluteIndex) -> bool {
        index != 0 && index <= self.dropped
    }

    pub fn relative_base(&self, base: usize, index: RelativeIndex) -> Result<usize, Error> {
        if self.delta == 0 || index > base || base - index <= self.dropped {
            Err(Error::BadRelativeIndex(index))
        } else {
            Ok(base - self.dropped - index - 1)
        }
    }

    pub fn post_base(&self, base: usize, index: RelativeIndex) -> Result<usize, Error> {
        if self.delta == 0 || base + index >= self.inserted || base + index < self.dropped {
            Err(Error::BadPostbaseIndex(index))
        } else {
            Ok(base + index - self.dropped)
        }
    }

    pub fn index(&self, index: usize) -> Result<usize, Error> {
        if index >= self.delta {
            Err(Error::BadIndex(index))
        } else {
            Ok(index + self.dropped + 1)
        }
    }

    pub fn largest_ref(&self) -> usize {
        (self.inserted - self.dropped)
    }

    pub fn total_inserted(&self) -> usize {
        self.inserted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_relative_index_when_empty() {
        let vas = VirtualAddressSpace::default();
        let res = vas.relative_base(0, 0);
        assert_eq!(res, Err(Error::BadRelativeIndex(0)));
    }

    #[test]
    fn test_relative_underflow_protected() {
        let mut vas = VirtualAddressSpace::default();
        vas.add();
        assert_eq!(vas.relative(2), Err(Error::BadRelativeIndex(2)));
    }

    proptest! {
        #[test]
        fn test_first_insertion_without_drop(
            ref count in 1..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            vas.add();
            (1..*count).for_each(|_| { vas.add(); });

            assert_eq!(vas.relative_base(*count, count - 1), Ok(0), "{:?}", vas);
        }

        #[test]
        fn test_first_insertion_with_drop(
            ref count in 2..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            vas.add();
            (1..*count).for_each(|_| { vas.add(); });
            (0..*count - 1).for_each(|_| vas.drop());

            assert_eq!(vas.relative_base(*count, count - 1), Err(Error::BadRelativeIndex(count - 1)), "{:?}", vas);
        }

        #[test]
        fn test_last_insertion_without_drop(
            ref count in 1..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            (1..*count).for_each(|_| { vas.add(); });
            vas.add();

            assert_eq!(vas.relative_base(*count, 0), Ok(count -1),
                       "{:?}", vas);
        }

        #[test]
        fn test_last_insertion_with_drop(
            ref count in 2..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            (0..*count - 1).for_each(|_| { vas.add(); });
            vas.add();
            (0..*count - 1).for_each(|_| { vas.drop(); });

            assert_eq!(vas.relative_base(*count, 0), Ok(0),
                       "{:?}", vas);
        }
    }

    #[test]
    fn test_post_base_index() {
        /*
         * Base index: D
         * Target value: B
         *
         * VAS: ]GFEDCBA]
         * abs:  1234567
         * rel:  3210---
         * pst:  ----012
         * pos:  0123456
         */
        let mut vas = VirtualAddressSpace::default();
        (0..7).for_each(|_| {
            vas.add();
        });

        assert_eq!(vas.post_base(4, 1), Ok(5));
    }

    #[test]
    fn largest_ref() {
        let mut vas = VirtualAddressSpace::default();
        (0..7).for_each(|_| {
            vas.add();
        });
        assert_eq!(vas.largest_ref(), 7);
    }

    #[test]
    fn relative() {
        let mut vas = VirtualAddressSpace::default();

        (0..7).for_each(|_| {
            vas.add();
        });

        assert_eq!(vas.relative(0), Ok(6));
        assert_eq!(vas.relative(1), Ok(5));
        assert_eq!(vas.relative(6), Ok(0));
        assert_eq!(vas.relative(7), Err(Error::BadRelativeIndex(7)));
    }

    #[test]
    fn absolute_from_real_index() {
        let mut vas = VirtualAddressSpace::default();
        assert_eq!(vas.index(0), Err(Error::BadIndex(0)));
        vas.add();
        assert_eq!(vas.index(0), Ok(1));
        vas.add();
        vas.drop();
        assert_eq!(vas.index(0), Ok(2));
        vas.drop();
        assert_eq!(vas.index(0), Err(Error::BadIndex(0)));
        vas.add();
        vas.add();
        assert_eq!(vas.index(0), Ok(3));
        assert_eq!(vas.index(1), Ok(4));
        assert_eq!(vas.index(2), Err(Error::BadIndex(2)));
    }

    #[test]
    fn evicted() {
        let mut vas = VirtualAddressSpace::default();
        assert_eq!(vas.evicted(0), false);
        assert_eq!(vas.evicted(1), false);
        vas.add();
        vas.add();
        assert_eq!(vas.evicted(1), false);
        vas.drop();
        assert_eq!(vas.evicted(0), false);
        assert_eq!(vas.evicted(1), true);
        assert_eq!(vas.evicted(2), false);
        vas.drop();
        assert_eq!(vas.evicted(2), true);
    }
}
