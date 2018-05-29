// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

/**
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
 * 3.2.  Indexing
 */

/*
 *  # Virtualy infinit address space mapper.
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


pub type RelativeIndex = u32;
pub type AbsoluteIndex = u32;


#[derive(Debug)]
pub struct VirtualAddressSpace {
    inserted: u32,
    dropped: u32,
    delta: u32,
    base: u32
}


impl VirtualAddressSpace {

    pub fn new() -> VirtualAddressSpace {
        VirtualAddressSpace {
            inserted: 0,
            dropped: 0,
            delta: 0,
            base: 0
        }
    }

    pub fn set_base_index(&mut self, base: AbsoluteIndex) {
        self.base = base;
    }

    pub fn add(&mut self) -> AbsoluteIndex {
        self.inserted += 1;
        self.delta += 1;
        self.inserted
    }

    pub fn drop(&mut self) {
        self.dropped += 1;
        self.delta -= 1;
    }

    pub fn relative(&self, index: RelativeIndex) -> Option<usize> {
        if self.delta == 0 
            || index > self.base
            || self.base - index < self.dropped { None }
        else { Some((self.base - index - 1) as usize) }
    }
    
    pub fn post_base(&self, index: RelativeIndex) -> Option<usize> {
        if self.delta == 0 
            || self.base + index + 1 >= self.inserted { None }
        else { Some((self.base - self.dropped + index) as usize) }
    }

    pub fn absolute(&self, index: AbsoluteIndex) -> Option<usize> {
        if index == 0
            || index < self.dropped
            || index > self.inserted { None }
        else { Some((index - self.dropped - 1) as usize) }
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_no_relative_index_when_empty() {
        let vas = VirtualAddressSpace::new();
        let res = vas.relative(0);
        assert_eq!(res, None);
    }

    #[test]
    fn test_no_absolute_index_when_empty() {
        let vas = VirtualAddressSpace::new();
        let res = vas.absolute(1);
        assert_eq!(res, None);
    }
    
    proptest! {
        #[test]
        fn test_first_insertion_without_drop(
            ref count in 1..2200u32
        ) {
            let mut vas = VirtualAddressSpace::new();
            let abs_index = vas.add();
            (1..*count).for_each(|_| { vas.add(); });
            
            vas.set_base_index(*count);
            assert_eq!(vas.relative(count - 1), Some(0));
            assert_eq!(vas.absolute(abs_index), Some(0));
        }

        #[test]
        fn test_first_insertion_with_drop(
            ref count in 2..2200u32
        ) {
            let mut vas = VirtualAddressSpace::new();
            let abs_index = vas.add();
            (1..*count).for_each(|_| { vas.add(); });
            (0..*count - 1).for_each(|_| vas.drop());
            
            vas.set_base_index(*count);
            assert_eq!(vas.relative(count - 1), None);
            assert_eq!(vas.absolute(abs_index), None);
        }
        
        #[test]
        fn test_last_insertion_without_drop(
            ref count in 1..2200u32
        ) {
            let mut vas = VirtualAddressSpace::new();
            (1..*count).for_each(|_| { vas.add(); });
            let abs_index = vas.add();
            
            vas.set_base_index(*count);
            assert_eq!(vas.relative(0), Some((count - 1) as usize));
            assert_eq!(vas.absolute(abs_index), Some((count - 1) as usize));
        }
        
        #[test]
        fn test_last_insertion_with_drop(
            ref count in 2..2200u32
        ) {
            let mut vas = VirtualAddressSpace::new();
            (0..*count - 1).for_each(|_| { vas.add(); });
            let abs_index = vas.add();
            (0..*count - 1).for_each(|_| { vas.drop(); });
            
            vas.set_base_index(*count);
            assert_eq!(vas.relative(0), Some((count - 1) as usize));
            assert_eq!(vas.absolute(abs_index), Some(0));
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
        let mut vas = VirtualAddressSpace::new();
        (0..7).for_each(|_| { vas.add(); });
        
        vas.set_base_index(4);
        assert_eq!(vas.post_base(1), Some(5));
    }

}
