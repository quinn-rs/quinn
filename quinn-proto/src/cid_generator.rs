use rand::RngCore;

use crate::shared::ConnectionId;
use crate::MAX_CID_SIZE;

/// Generates connection IDs for incoming connections
pub trait ConnectionIdGenerator: Send {
    /// Generates a new CID
    fn generate_cid(&mut self) -> ConnectionId;
    /// Performs any validation if it is needed (e.g. HMAC, etc)
    fn validate_cid(&mut self, cid: &ConnectionId) -> bool;
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
        let mut res = ConnectionId {
            len: self.cid_len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        rand::thread_rng().fill_bytes(&mut res.bytes[..self.cid_len]);
        res
    }

    /// Cid is an array of random bytes. We only verify the length
    fn validate_cid(&mut self, cid: &ConnectionId) -> bool {
        cid.len as usize == self.cid_len
    }

    /// Provide the length of dst_cid in short header packet
    fn cid_len(&self) -> usize {
        self.cid_len
    }
}
