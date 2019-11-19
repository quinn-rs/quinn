use std::ops::{Index, IndexMut};
use std::slice;

/// Kinds of timeouts needed to run the protocol logic
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Timer(pub(crate) TimerKind);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum TimerKind {
    /// When to send an ack-eliciting probe packet or declare unacked packets lost
    LossDetection = 0,
    /// When to close the connection after no activity
    Idle = 1,
    /// When the close timer expires, the connection has been gracefully terminated.
    Close = 2,
    /// When keys are discarded because they should not be needed anymore
    KeyDiscard = 3,
    /// When to give up on validating a new path to the peer
    PathValidation = 4,
    /// When to send a `PING` frame to keep the connection alive
    KeepAlive = 5,
}

impl TimerKind {
    const VALUES: [Self; 6] = [
        TimerKind::LossDetection,
        TimerKind::Idle,
        TimerKind::Close,
        TimerKind::KeyDiscard,
        TimerKind::PathValidation,
        TimerKind::KeepAlive,
    ];
}

/// A table of data associated with each distinct kind of `Timer`
#[derive(Debug, Copy, Clone, Default)]
pub struct TimerTable<T> {
    data: [T; 6],
}

impl<T> TimerTable<T> {
    /// Create a table initialized with the value returned by `f` for each timer
    pub fn new(mut f: impl FnMut() -> T) -> Self {
        Self {
            data: [f(), f(), f(), f(), f(), f()],
        }
    }

    /// Iterate over the contained values
    pub fn iter(&self) -> TimerTableIter<T> {
        TimerTableIter {
            kind: TimerKind::VALUES.iter(),
            table: self,
        }
    }

    /// Mutably iterate over the contained values
    pub fn iter_mut(&mut self) -> TimerTableIterMut<T> {
        TimerTableIterMut {
            kind: TimerKind::VALUES.iter(),
            table: self.data.iter_mut(),
        }
    }
}

/// Iterator over a `TimerTable`
pub struct TimerTableIter<'a, T> {
    kind: slice::Iter<'static, TimerKind>,
    table: &'a TimerTable<T>,
}

impl<'a, T> Iterator for TimerTableIter<'a, T> {
    type Item = (Timer, &'a T);
    fn next(&mut self) -> Option<(Timer, &'a T)> {
        let timer = Timer(*self.kind.next()?);
        Some((timer, &self.table[timer]))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.kind.size_hint()
    }
}

impl<'a, T> ExactSizeIterator for TimerTableIter<'a, T> {
    fn len(&self) -> usize {
        self.kind.len()
    }
}

/// Mutable iterator over a `TimerTable`
pub struct TimerTableIterMut<'a, T> {
    kind: slice::Iter<'static, TimerKind>,
    table: slice::IterMut<'a, T>,
}

impl<'a, T> Iterator for TimerTableIterMut<'a, T> {
    type Item = (Timer, &'a mut T);
    fn next(&mut self) -> Option<(Timer, &'a mut T)> {
        Some((Timer(*self.kind.next()?), self.table.next().unwrap()))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.kind.size_hint()
    }
}

impl<'a, T> ExactSizeIterator for TimerTableIterMut<'a, T> {
    fn len(&self) -> usize {
        self.kind.len()
    }
}

impl<'a, T> IntoIterator for &'a TimerTable<T> {
    type Item = (Timer, &'a T);
    type IntoIter = TimerTableIter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut TimerTable<T> {
    type Item = (Timer, &'a mut T);
    type IntoIter = TimerTableIterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T> Index<Timer> for TimerTable<T> {
    type Output = T;
    fn index(&self, index: Timer) -> &T {
        &self.data[index.0 as usize]
    }
}

impl<T> IndexMut<Timer> for TimerTable<T> {
    fn index_mut(&mut self, index: Timer) -> &mut T {
        &mut self.data[index.0 as usize]
    }
}
