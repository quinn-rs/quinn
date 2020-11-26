//! Maintain the state of local connection IDs
use std::{
    collections::{HashSet, VecDeque},
    time::{Duration, Instant},
};
use tracing::trace;

/// Data structure that records when issued cids should be retired
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct CidTimeStamp {
    /// Highest cid sequence number created in a batch
    pub(crate) sequence: u64,
    /// Timestamp when cid needs to be retired
    pub(crate) timestamp: Instant,
}

/// Local connection IDs management
///
/// `CidState` maintains attributes of local connection IDs
pub struct CidState {
    /// Timestamp when issued cids should be retired
    pub(crate) retire_timestamp: VecDeque<CidTimeStamp>,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    pub(crate) issued: u64,
    /// Sequence numbers of local connection IDs not yet retired by the peer
    pub(crate) active_seq: HashSet<u64>,
    /// Sequence number the peer has already retired all CIDs below at our request via `retire_prior_to`
    pub(crate) prev_retire_seq: u64,
    /// Sequence number to set in retire_prior_to field in NEW_CONNECTION_ID frame
    pub(crate) retire_seq: u64,
    /// cid length used to decode short packet
    pub(crate) cid_len: usize,
    //// cid lifetime
    pub(crate) cid_lifetime: Option<Duration>,
}

impl CidState {
    /// Find the next timestamp when previously issued CID should be retired
    pub(crate) fn next_timeout(&mut self) -> Option<Instant> {
        self.retire_timestamp.front().map(|nc| {
            trace!("CID {} will expire at {:?}", nc.sequence, nc.timestamp);
            nc.timestamp
        })
    }

    /// Track the lifetime of issued cids in `retire_timestamp`
    pub(crate) fn track_lifetime(&mut self, new_cid_seq: u64, now: Instant) {
        match self.cid_lifetime {
            None => {}
            Some(lifetime) => {
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
        }
    }

    /// Update local CID state when previously issued CID is retired
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

        (current_retire_prior_to..self.retire_seq).any(|seq| self.active_seq.contains(&seq))
    }
}
