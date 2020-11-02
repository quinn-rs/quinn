use std::ops::Range;

use crate::{shared::IssuedCid, ConnectionId, ResetToken};

/// DataType stored in CidQueue buffer
type CidData = (ConnectionId, Option<ResetToken>);

/// Sliding window of active Connection IDs
///
/// May contain gaps due to packet loss or reordering
#[derive(Debug)]
pub struct CidQueue {
    /// Ring buffer indexed by `self.cursor`
    buffer: [Option<CidData>; Self::LEN],
    /// Index at which circular buffer addressing is based
    cursor: usize,
    /// Sequence number of `self.buffer[cursor]`
    ///
    /// The sequence number of the active CID; must be the smallest among CIDs in `buffer`.
    offset: u64,
}

impl CidQueue {
    pub fn new(cid: ConnectionId) -> Self {
        let mut buffer = [None; Self::LEN];
        buffer[0] = Some((cid, None));
        Self {
            buffer,
            cursor: 0,
            offset: 0,
        }
    }

    pub fn insert(&mut self, cid: IssuedCid) -> Result<(), InsertError> {
        if cid.sequence == self.offset && self.buffer[self.cursor].is_some() {
            // This is a duplicate of the active CID.
            return Ok(());
        }
        let index = match cid.sequence.checked_sub(self.offset) {
            None => return Err(InsertError::Retired),
            Some(x) => x,
        };
        if index >= Self::LEN as u64 {
            return Err(InsertError::ExceedsLimit);
        }
        let index = (self.cursor + index as usize) % Self::LEN;
        self.buffer[index] = Some((cid.id, Some(cid.reset_token)));
        Ok(())
    }

    /// Returns the possibly-empty range of newly retired CIDs
    // clippy will stop warning in 1.46+, https://github.com/rust-lang/rust-clippy/pull/5692
    #[allow(clippy::reversed_empty_ranges)]
    pub fn retire_prior_to(&mut self, sequence: u64) -> Range<u64> {
        let n = match sequence.checked_sub(self.offset) {
            None => return 0..0,
            Some(n) => n as usize,
        };
        for i in 0..n {
            self.buffer[(self.cursor + i) % Self::LEN] = None;
        }
        let orig_offset = self.offset;
        self.offset = sequence;
        self.cursor = (self.cursor + n) % Self::LEN;
        orig_offset..sequence
    }

    /// Switch to next active CID if possible, return
    /// 1) the corresponding ResetToken and 2) a possibly-empty range preceding it to retire
    pub fn next(&mut self) -> Option<(ResetToken, Range<u64>)> {
        let (i, cid_data) = self.iter().next()?;
        self.buffer[self.cursor] = None;

        let orig_offset = self.offset;
        self.offset += i as u64;
        self.cursor = (self.cursor + i) % Self::LEN;
        let sequence = orig_offset + i as u64;
        Some((cid_data.1.unwrap(), orig_offset..sequence))
    }

    /// Iterate inactive CIDs in CidQueue that are not `None`
    fn iter(&self) -> impl Iterator<Item = (usize, CidData)> + '_ {
        (1..Self::LEN).filter_map(move |step| {
            let index = (self.cursor + step) % Self::LEN;
            match self.buffer[index] {
                Some(cid_data) => Some((step, cid_data)),
                None => None,
            }
        })
    }

    pub fn update_cid(&mut self, cid: ConnectionId) {
        debug_assert_eq!(self.offset, 0);
        self.buffer[self.cursor] = Some((cid, None));
    }

    /// Return active remote CID itself
    pub fn active(&self) -> ConnectionId {
        self.buffer[self.cursor].unwrap().0
    }

    /// Check whether self.offset points to a valid CID in CidQueue
    pub fn is_active_retired(&mut self) -> bool {
        self.buffer[self.cursor].is_none()
    }

    /// Return the sequence number of active remote CID
    pub fn active_seq(&self) -> u64 {
        self.offset
    }

    pub const LEN: usize = 5;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InsertError {
    /// CID was already retired
    Retired,
    /// Sequence number violates the leading edge of the window
    ExceedsLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(sequence: u64) -> IssuedCid {
        IssuedCid {
            sequence,
            id: ConnectionId::new(&[0xAB; 8]),
            reset_token: ResetToken::from([0xCD; crate::RESET_TOKEN_SIZE]),
        }
    }

    fn initial_cid() -> ConnectionId {
        ConnectionId::new(&[0xFF; 8])
    }

    #[test]
    fn next_dense() {
        let mut q = CidQueue::new(initial_cid());
        assert!(q.next().is_none());
        assert!(q.next().is_none());

        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }
        for i in 1..CidQueue::LEN as u64 {
            let (_, retire) = q.next().unwrap();
            assert_eq!(q.active_seq(), i);
            assert_eq!(retire.end - retire.start, 1);
        }
        assert!(q.next().is_none());
    }
    #[test]
    fn next_sparse() {
        let mut q = CidQueue::new(initial_cid());
        let seqs = (1..CidQueue::LEN as u64).filter(|x| x % 2 == 0);
        for i in seqs.clone() {
            q.insert(cid(i)).unwrap();
        }
        for i in seqs {
            let (_, retire) = q.next().unwrap();
            dbg!(&retire);
            assert_eq!(q.active_seq(), i);
            assert_eq!(retire, (q.active_seq().saturating_sub(2))..q.active_seq());
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn wrap() {
        let mut q = CidQueue::new(initial_cid());

        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }
        for _ in 1..(CidQueue::LEN as u64 - 1) {
            q.next().unwrap();
        }
        for i in CidQueue::LEN as u64..(CidQueue::LEN as u64 + 3) {
            q.insert(cid(i)).unwrap();
        }
        for i in (CidQueue::LEN as u64 - 1)..(CidQueue::LEN as u64 + 3) {
            q.next().unwrap();
            assert_eq!(q.active_seq(), i);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn retire() {
        let mut q = CidQueue::new(initial_cid());

        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }

        assert_eq!(q.retire_prior_to(2), 0..2);
        let r = q.retire_prior_to(2);
        assert_eq!(r.end - r.start, 0);

        for i in 2..(CidQueue::LEN as u64 - 1) {
            let _ = q.next().unwrap();
            assert_eq!(q.active_seq(), i + 1);
            let retire = q.retire_prior_to(i + 1);
            assert_eq!(retire.end - retire.start, 0);
            assert!(!q.is_active_retired());
        }

        assert!(q.next().is_none());
        assert!(!q.is_active_retired());
    }

    #[test]
    fn insert_limit() {
        let mut q = CidQueue::new(initial_cid());
        assert_eq!(q.insert(cid(CidQueue::LEN as u64 - 1)), Ok(()));
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64)),
            Err(InsertError::ExceedsLimit)
        );
    }

    #[test]
    fn insert_duplicate() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(0)).unwrap();
        q.insert(cid(0)).unwrap();
    }

    #[test]
    fn insert_retired() {
        let mut q = CidQueue::new(initial_cid());
        assert_eq!(q.insert(cid(0)), Ok(()), "reinserting active CID succeeds");
        assert!(q.next().is_none(), "active CID isn't requeued");
        q.insert(cid(1)).unwrap();
        q.next().unwrap();
        assert_eq!(
            q.insert(cid(0)),
            Err(InsertError::Retired),
            "previous active CID is already retired"
        );
    }

    #[test]
    fn retire_then_insert_next() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }
        q.next().unwrap();
        q.insert(cid(CidQueue::LEN as u64)).unwrap();
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64 + 1)),
            Err(InsertError::ExceedsLimit)
        );
    }

    #[test]
    fn always_valid() {
        let mut q = CidQueue::new(initial_cid());
        assert!(q.next().is_none());
        assert_eq!(q.active(), initial_cid());
        assert_eq!(q.active_seq(), 0);
    }
}
