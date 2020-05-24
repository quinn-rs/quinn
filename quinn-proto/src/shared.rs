use std::{fmt, net::SocketAddr, time::Instant};

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;

use crate::{coding::BufExt, packet::PartialDecode, ResetToken, MAX_CID_SIZE};

/// Events sent from an Endpoint to a Connection
#[derive(Debug)]
pub struct ConnectionEvent(pub(crate) ConnectionEventInner);

#[derive(Debug)]
pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram {
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        first_decode: PartialDecode,
        remaining: Option<BytesMut>,
    },
    /// New connection identifiers have been issued for the Connection
    NewIdentifiers(Vec<IssuedCid>),
}

/// Events sent from a Connection to an Endpoint
#[derive(Debug)]
pub struct EndpointEvent(pub(crate) EndpointEventInner);

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub fn drained() -> Self {
        Self(EndpointEventInner::Drained)
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub fn is_drained(&self) -> bool {
        self.0 == EndpointEventInner::Drained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
    /// The reset token and/or address eligible for generating resets has been updated
    ResetToken(SocketAddr, ResetToken),
    /// The connection needs connection identifiers
    NeedIdentifiers(u64),
    /// Stop routing connection ID for this sequence number to the connection
    RetireConnectionId(u64),
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].clone_from_slice(&bytes);
        res
    }

    pub(crate) fn random<R: Rng>(rng: &mut R, len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        let mut rng_bytes = [0; MAX_CID_SIZE];
        rng.fill_bytes(&mut rng_bytes);
        res.bytes[..len].clone_from_slice(&rng_bytes[..len]);
        res
    }

    /// Decode from long header format
    pub(crate) fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        if len > MAX_CID_SIZE || buf.remaining() < len {
            return None;
        }
        let cid = ConnectionId::new(&buf.bytes()[..len]);
        buf.advance(len);
        Some(cid)
    }

    /// Encode in long header format
    pub(crate) fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    #[doc(hidden)]
    ECT0 = 0b10,
    #[doc(hidden)]
    ECT1 = 0b01,
    #[doc(hidden)]
    CE = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => ECT0,
            0b01 => ECT1,
            0b11 => CE,
            _ => {
                return None;
            }
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct IssuedCid {
    pub sequence: u64,
    pub id: ConnectionId,
    pub reset_token: ResetToken,
}
