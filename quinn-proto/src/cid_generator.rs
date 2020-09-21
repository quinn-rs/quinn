use rand::RngCore;

use crate::shared::ConnectionId;
use crate::MAX_CID_SIZE;

/// Generates connection IDs for incoming connections
pub trait ConnectionIdGenerator: Send {
    /// Generates a new CID
    ///
    /// Connection IDs MUST NOT contain any information that can be used by
    //    an external observer (that is, one that does not cooperate with the
    //    issuer) to correlate them with other connection IDs for the same
    //    connection.
    fn generate_cid(&mut self) -> ConnectionId;
    /// Performs any validation if it is needed (e.g. HMAC, etc)
    ///
    /// Apply validation check on those CIDs that may still exist in hash table
    ///   but considered invalid by application-layer logic.
    /// e.g., We may want to limit the amount of time for which a CID is valid
    ///   in order to reduce the number of valid IDs that could be accumulated
    ///   by an attacker.
    fn validate_cid(&mut self, _cid: &ConnectionId) -> bool {
        true
    }
    /// Returns the length of a CID for cononections created by this generator
    fn cid_len(&self) -> usize;
}

/// CID filled with random number/byte
///
/// This struct generates random CID with a customized length.
#[derive(Debug, Clone, Copy)]
pub struct RandomConnectionIdGenerator {
    cid_len: usize,
}
impl Default for RandomConnectionIdGenerator {
    fn default() -> Self {
        Self { cid_len: 8 }
    }
}
impl RandomConnectionIdGenerator {
    /// Initialize Random CID generator with a fixed CID length (which must be less or equal to MAX_CID_SIZE)
    pub fn new(cid_len: usize) -> Self {
        debug_assert!(cid_len <= MAX_CID_SIZE);
        Self { cid_len }
    }
}
impl ConnectionIdGenerator for RandomConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes_arr = vec![0; self.cid_len];
        rand::thread_rng().fill_bytes(&mut bytes_arr);

        ConnectionId::new(&bytes_arr)
    }

    /// Provide the length of dst_cid in short header packet
    fn cid_len(&self) -> usize {
        self.cid_len
    }
}
