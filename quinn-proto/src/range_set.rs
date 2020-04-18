use std::{
    cmp,
    cmp::Ordering,
    collections::{
        btree_map, BTreeMap,
        Bound::{Excluded, Included},
    },
    ops::Range,
};

/// A set of u64 values optimized for long runs and random insert/delete/contains
#[derive(Debug, Default, Clone)]
pub struct RangeSet(BTreeMap<u64, u64>);

impl RangeSet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn contains(&self, x: u64) -> bool {
        self.pred(x).map_or(false, |(_, end)| end > x)
    }

    pub fn insert_one(&mut self, x: u64) -> bool {
        if let Some((start, end)) = self.pred(x) {
            match end.cmp(&x) {
                // Wholly contained
                Ordering::Greater => {
                    return false;
                }
                Ordering::Equal => {
                    // Extend existing
                    self.0.remove(&start);
                    let mut new_end = x + 1;
                    if let Some((next_start, next_end)) = self.succ(x) {
                        if next_start == new_end {
                            self.0.remove(&next_start);
                            new_end = next_end;
                        }
                    }
                    self.0.insert(start, new_end);
                    return true;
                }
                _ => {}
            }
        }
        let mut new_end = x + 1;
        if let Some((next_start, next_end)) = self.succ(x) {
            if next_start == new_end {
                self.0.remove(&next_start);
                new_end = next_end;
            }
        }
        self.0.insert(x, new_end);
        true
    }

    pub fn insert(&mut self, mut x: Range<u64>) -> bool {
        if let Some((start, end)) = self.pred(x.start) {
            if end >= x.end {
                // Wholly contained
                return false;
            } else if end >= x.start {
                // Overlaps with pred
                self.0.remove(&start);
                while let Some((next_start, next_end)) = self.succ(x.start) {
                    if next_start > x.end {
                        break;
                    }
                    // ..and succ
                    self.0.remove(&next_start);
                    x.end = cmp::max(next_end, x.end);
                }
                self.0.insert(start, x.end);
                return true;
            }
        }
        while let Some((next_start, next_end)) = self.succ(x.start) {
            if next_start > x.end {
                break;
            }
            // Overlaps with succ
            self.0.remove(&next_start);
            x.end = cmp::max(next_end, x.end);
        }
        self.0.insert(x.start, x.end);
        true
    }

    fn pred(&self, x: u64) -> Option<(u64, u64)> {
        self.0
            .range((Included(0), Included(x)))
            .rev()
            .next()
            .map(|(&x, &y)| (x, y))
    }

    fn succ(&self, x: u64) -> Option<(u64, u64)> {
        self.0
            .range((Excluded(x), Included(u64::max_value())))
            .next()
            .map(|(&x, &y)| (x, y))
    }

    pub fn remove(&mut self, x: Range<u64>) -> bool {
        let before = match self.pred(x.start) {
            Some((start, end)) if end > x.start => {
                self.0.remove(&start);
                if start < x.start {
                    self.0.insert(start, x.start);
                }
                if end > x.end {
                    self.0.insert(x.end, end);
                }
                // Short-circuit if we cannot possibly overlap with another range
                if end >= x.end {
                    return true;
                }
                true
            }
            Some(_) | None => false,
        };
        let mut after = false;
        while let Some((start, end)) = self.succ(x.start) {
            if start >= x.end {
                break;
            }
            after = true;
            self.0.remove(&start);
            if end > x.end {
                self.0.insert(x.end, end);
                break;
            }
        }
        before || after
    }

    pub fn add(&mut self, other: &RangeSet) {
        for (&start, &end) in &other.0 {
            self.insert(start..end);
        }
    }

    pub fn subtract(&mut self, other: &RangeSet) {
        for (&start, &end) in &other.0 {
            self.remove(start..end);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn min(&self) -> Option<u64> {
        self.iter().next().map(|x| x.start)
    }
    pub fn max(&self) -> Option<u64> {
        self.iter().rev().next().map(|x| x.end - 1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.0.iter())
    }
    pub fn elts(&self) -> EltIter<'_> {
        EltIter {
            inner: self.0.iter(),
            next: 0,
            end: 0,
        }
    }

    pub fn peek_min(&self) -> Option<Range<u64>> {
        let (&start, &end) = self.0.iter().next()?;
        Some(start..end)
    }

    pub fn pop_min(&mut self) -> Option<Range<u64>> {
        let result = self.peek_min()?;
        self.0.remove(&result.start);
        Some(result)
    }
}

pub struct Iter<'a>(btree_map::Iter<'a, u64, u64>);

impl<'a> Iterator for Iter<'a> {
    type Item = Range<u64>;
    fn next(&mut self) -> Option<Range<u64>> {
        let (&start, &end) = self.0.next()?;
        Some(start..end)
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Range<u64>> {
        let (&start, &end) = self.0.next_back()?;
        Some(start..end)
    }
}

impl<'a> IntoIterator for &'a RangeSet {
    type Item = Range<u64>;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

pub struct EltIter<'a> {
    inner: btree_map::Iter<'a, u64, u64>,
    next: u64,
    end: u64,
}

impl<'a> Iterator for EltIter<'a> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.next == self.end {
            let (&start, &end) = self.inner.next()?;
            self.next = start;
            self.end = end;
        }
        let x = self.next;
        self.next += 1;
        Some(x)
    }
}

impl<'a> DoubleEndedIterator for EltIter<'a> {
    fn next_back(&mut self) -> Option<u64> {
        if self.next == self.end {
            let (&start, &end) = self.inner.next_back()?;
            self.next = start;
            self.end = end;
        }
        self.end -= 1;
        Some(self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_and_split() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..2));
        assert!(set.insert(2..4));
        assert!(!set.insert(1..3));
        assert_eq!(set.len(), 1);
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 1, 2, 3]);
        assert!(!set.contains(4));
        assert!(set.remove(2..3));
        assert_eq!(set.len(), 2);
        assert!(!set.contains(2));
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 1, 3]);
    }

    #[test]
    fn double_merge_exact() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..2));
        assert!(set.insert(4..6));
        assert_eq!(set.len(), 2);
        assert!(set.insert(2..4));
        assert_eq!(set.len(), 1);
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn single_merge_low() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..2));
        assert!(set.insert(4..6));
        assert_eq!(set.len(), 2);
        assert!(set.insert(2..3));
        assert_eq!(set.len(), 2);
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 1, 2, 4, 5]);
    }

    #[test]
    fn single_merge_high() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..2));
        assert!(set.insert(4..6));
        assert_eq!(set.len(), 2);
        assert!(set.insert(3..4));
        assert_eq!(set.len(), 2);
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 1, 3, 4, 5]);
    }

    #[test]
    fn double_merge_wide() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..2));
        assert!(set.insert(4..6));
        assert_eq!(set.len(), 2);
        assert!(set.insert(1..5));
        assert_eq!(set.len(), 1);
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn double_remove() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..2));
        assert!(set.insert(4..6));
        assert!(set.remove(1..5));
        assert_eq!(set.len(), 2);
        assert_eq!(&set.elts().collect::<Vec<_>>()[..], [0, 5]);
    }

    #[test]
    fn insert_multiple() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..1));
        assert!(set.insert(2..3));
        assert!(set.insert(4..5));
        assert!(set.insert(0..5));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn remove_multiple() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..1));
        assert!(set.insert(2..3));
        assert!(set.insert(4..5));
        assert!(set.remove(0..5));
        assert!(set.is_empty());
    }
}
