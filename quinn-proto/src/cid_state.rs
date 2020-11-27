//! Maintain the state of local connection IDs
use std::{
    collections::{HashSet, VecDeque},
    time::{Duration, Instant},
};
use tracing::trace;

/// Data structure that records when issued cids should be retired
#[derive(Copy, Clone, Eq, PartialEq)]
struct CidTimeStamp {
    /// Highest cid sequence number created in a batch
    sequence: u64,
    /// Timestamp when cid needs to be retired
    timestamp: Instant,
}

/// Local connection IDs management
///
/// `CidState` maintains attributes of local connection IDs
pub struct CidState {
    /// Timestamp when issued cids should be retired
    retire_timestamp: VecDeque<CidTimeStamp>,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    pub(crate) issued: u64,
    /// Sequence numbers of local connection IDs not yet retired by the peer
    pub(crate) active_seq: HashSet<u64>,
    /// Sequence number the peer has already retired all CIDs below at our request via `retire_prior_to`
    prev_retire_seq: u64,
    /// Sequence number to set in retire_prior_to field in NEW_CONNECTION_ID frame
    pub(crate) retire_seq: u64,
    /// cid length used to decode short packet
    pub(crate) cid_len: usize,
    //// cid lifetime
    cid_lifetime: Option<Duration>,
}

impl CidState {
    pub(crate) fn new(cid_len: usize, cid_lifetime: Option<Duration>) -> Self {
        let mut this = CidState {
            retire_timestamp: VecDeque::new(),
            issued: 1, // One CID is already supplied during handshaking
            active_seq: HashSet::new(),
            prev_retire_seq: 0,
            retire_seq: 0,
            cid_len,
            cid_lifetime,
        };
        // Add sequence number of CID used in handshaking into tracking set
        this.active_seq.insert(0);
        this
    }

    /// Find the next timestamp when previously issued CID should be retired
    pub(crate) fn next_timeout(&mut self) -> Option<Instant> {
        self.retire_timestamp.front().map(|nc| {
            trace!("CID {} will expire at {:?}", nc.sequence, nc.timestamp);
            nc.timestamp
        })
    }

    /// Track the lifetime of issued cids in `retire_timestamp`
    pub(crate) fn track_lifetime(&mut self, new_cid_seq: u64, now: Instant) {
        let lifetime = match self.cid_lifetime {
            Some(lifetime) => lifetime,
            None => return,
        };
        let expire_timestamp = now.checked_add(lifetime);
        if let Some(expire_at) = expire_timestamp {
            let last_record = self.retire_timestamp.back_mut();
            if let Some(last) = last_record {
                // Compare the timestamp with the last inserted record
                // Combine into a single batch if timestamp of current cid is same as the last record
                if expire_at == last.timestamp {
                    debug_assert!(new_cid_seq > last.sequence);
                    last.sequence = new_cid_seq;
                    return;
                }
            }
            self.retire_timestamp.push_back(CidTimeStamp {
                sequence: new_cid_seq,
                timestamp: expire_at,
            });
        }
    }

    /// Update local CID state when previously issued CID is retired
    /// Return a flag that indicates whether a new CID needs to be pushed that notifies remote peer to respond `RETIRE_CONNECTION_ID`
    pub(crate) fn on_cid_retirement_timeout(&mut self) -> bool {
        // Whether the peer hasn't retired all the CIDs we asked it to yet
        let unretired_ids_found =
            (self.prev_retire_seq..self.retire_seq).any(|seq| self.active_seq.contains(&seq));
        // According to RFC:
        // Endpoints SHOULD NOT issue updates of the Retire Prior To field
        // before receiving RETIRE_CONNECTION_ID frames that retire all
        // connection IDs indicated by the previous Retire Prior To value.
        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-5.1.2
        //
        // All Cids are retired, `prev_retire_cid_seq` can be assigned to `retire_cid_seq`
        if !unretired_ids_found {
            self.prev_retire_seq = self.retire_seq;
        }

        let next_retire_sequence = self
            .retire_timestamp
            .pop_front()
            .map(|seq| seq.sequence + 1);
        let current_retire_prior_to = self.retire_seq;

        // Advance `retire_cid_seq` if next cid that needs to be retired exists
        if let Some(next_retire_prior_to) = next_retire_sequence {
            if !unretired_ids_found && next_retire_prior_to > current_retire_prior_to {
                self.retire_seq = next_retire_prior_to;
            }
        }

        // Check if retirement of all CIDs that reach their lifetime is still needed
        // If yes (return true), a new CID must be pushed with updated `retire_prior_to` field to remote peer.
        // If no (return false), it means remote peer has proactively retired those CIDs (for other reasons) before CID lifetime is reached.
        (current_retire_prior_to..self.retire_seq).any(|seq| self.active_seq.contains(&seq))
    }
}
