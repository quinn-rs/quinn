use std::ops::Range;

use crate::{shared::IssuedCid, ConnectionId, ResetToken};

/// Sliding window of active Connection IDs
///
/// May contain gaps due to packet loss or reordering
#[derive(Debug)]
pub struct CidQueue {
    /// Ring buffer indexed by `self.cursor`
    buffer: [Option<(ConnectionId, ResetToken)>; Self::LEN],
    /// Index at which circular buffer addressing is based
    cursor: usize,
    /// Sequence number of `self.buffer[cursor]`
    ///
    /// The CID sequenced immediately prior to this is the active CID, which this data structure is
    /// not responsible for retiring.
    offset: u64,
}

impl CidQueue {
    pub const LEN: usize = 4;

    pub fn new(offset: u64) -> Self {
        Self {
            buffer: [None; Self::LEN],
            cursor: 0,
            offset,
        }
    }

    pub fn insert(&mut self, cid: IssuedCid) -> Result<(), InsertError> {
        if cid.sequence + 1 == self.offset {
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
        self.buffer[index] = Some((cid.id, cid.reset_token));
        Ok(())
    }

    /// Returns the possibly-empty range of newly retired CIDs
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

    /// Returns a new CID if any were available and a possibly-empty range preceding it to retire
    pub fn next(&mut self) -> Option<(IssuedCid, Range<u64>)> {
        for i in 0..Self::LEN {
            let index = (self.cursor + i) % Self::LEN;
            let (id, reset_token) = match self.buffer[index].take() {
                None => continue,
                Some(x) => x,
            };
            let orig_offset = self.offset;
            self.offset += i as u64 + 1;
            self.cursor = (self.cursor + i + 1) % Self::LEN;
            let sequence = orig_offset + i as u64;
            let cid = IssuedCid {
                sequence,
                id,
                reset_token,
            };
            return Some((cid, orig_offset..sequence));
        }
        None
    }
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

    #[test]
    fn next_dense() {
        let mut q = CidQueue::new(0);
        assert!(q.next().is_none());
        assert!(q.next().is_none());

        for i in 0..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }
        for i in 0..CidQueue::LEN as u64 {
            let (cid, retire) = q.next().unwrap();
            assert_eq!(cid.sequence, i);
            assert_eq!(retire.end - retire.start, 0);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn next_sparse() {
        let mut q = CidQueue::new(0);
        let seqs = (0..CidQueue::LEN as u64).filter(|x| x % 2 == 0);
        for i in seqs.clone() {
            q.insert(cid(i)).unwrap();
        }
        for i in seqs {
            let (cid, retire) = q.next().unwrap();
            dbg!(&retire);
            assert_eq!(cid.sequence, i);
            assert_eq!(retire, (cid.sequence.saturating_sub(1))..cid.sequence);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn wrap() {
        let mut q = CidQueue::new(0);

        for i in 0..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }
        for _ in 0..3 {
            q.next().unwrap();
        }
        for i in CidQueue::LEN as u64..(CidQueue::LEN as u64 + 3) {
            q.insert(cid(i)).unwrap();
        }
        for i in 3..(CidQueue::LEN as u64 + 3) {
            assert_eq!(q.next().unwrap().0.sequence, i);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn retire() {
        let mut q = CidQueue::new(0);

        for i in 0..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }

        assert_eq!(q.retire_prior_to(4), 0..4);
        let r = q.retire_prior_to(4);
        assert_eq!(r.end - r.start, 0);

        for i in 4..CidQueue::LEN as u64 {
            let (cid, retire) = q.next().unwrap();
            assert_eq!(cid.sequence, i);
            assert_eq!(retire.end - retire.start, 0);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn insert_limit() {
        let mut q = CidQueue::new(0);
        assert_eq!(q.insert(cid(CidQueue::LEN as u64 - 1)), Ok(()));
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64)),
            Err(InsertError::ExceedsLimit)
        );
    }

    #[test]
    fn insert_duplicate() {
        let mut q = CidQueue::new(0);
        q.insert(cid(0)).unwrap();
        q.insert(cid(0)).unwrap();
    }

    #[test]
    fn insert_retired() {
        let mut q = CidQueue::new(0);
        q.insert(cid(0)).unwrap();
        q.next().unwrap();
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
        let mut q = CidQueue::new(0);
        for i in 0..CidQueue::LEN as u64 {
            q.insert(cid(i)).unwrap();
        }
        q.next().unwrap();
        q.insert(cid(CidQueue::LEN as u64)).unwrap();
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64 + 1)),
            Err(InsertError::ExceedsLimit)
        );
    }
}
