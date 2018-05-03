use rand::{Rand, Rng};

use std::fmt;
use std::ops::Deref;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ConnectionId {
    pub len: u8,
    pub bytes: [u8; 18],
}

impl Copy for ConnectionId {}

impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() == 0 || (bytes.len() > 3 && bytes.len() < 19));
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; 18],
        };
        (&mut res.bytes[..bytes.len()]).clone_from_slice(bytes);
        res
    }

    pub fn cil(&self) -> u8 {
        if self.len > 0 {
            self.len - 3
        } else {
            self.len
        }
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for b in (&self.bytes[..self.len as usize]).iter() {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

impl Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Rand for ConnectionId {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut res = ConnectionId {
            len: GENERATED_CID_LENGTH,
            bytes: [0; 18],
        };
        rng.fill_bytes(&mut res.bytes[..res.len as usize]);
        res
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransportParameters {
    pub max_stream_data: u32,                    // 0x00
    pub max_data: u32,                           // 0x01
    pub max_streams_bidi: u32,                   // 0x02
    pub idle_timeout: u16,                       // 0x03
    pub max_packet_size: u16,                    // 0x05
    pub stateless_reset_token: Option<[u8; 16]>, // 0x06
    pub ack_delay_exponent: u8,                  // 0x07
    pub max_stream_id_uni: u32,                  // 0x08
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            max_stream_data: 131072,
            max_data: 1048576,
            max_streams_bidi: 0,
            idle_timeout: 300,
            max_packet_size: 65527,
            stateless_reset_token: None,
            ack_delay_exponent: 3,
            max_stream_id_uni: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub fn other(&self) -> Side {
        match *self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

impl Copy for Side {}

pub const DRAFT_11: u32 = 0xff00000b;
pub const GENERATED_CID_LENGTH: u8 = 8;
