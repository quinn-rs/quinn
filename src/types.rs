use rand::{thread_rng, Rng};

use std::mem;

use crypto::{PacketKey, Secret};
use frame::Frame;
use packet::{Header, LongType, Packet};

pub struct Endpoint {
    side: Side,
    pub dst_cid: u64,
    pub src_pn: u32,
    secret: Secret,
    prev_secret: Option<Secret>,
}

impl Endpoint {
    pub fn new(side: Side, secret: Option<Secret>) -> Self {
        let mut rng = thread_rng();
        let dst_cid = rng.gen();

        let secret = if side == Side::Client {
            debug_assert!(secret.is_none());
            Secret::Handshake(dst_cid)
        } else if let Some(secret) = secret {
            secret
        } else {
            panic!("need secret for client endpoint");
        };

        Endpoint {
            side,
            dst_cid,
            src_pn: rng.gen(),
            secret,
            prev_secret: None,
        }
    }

    pub(crate) fn encode_key(&self, h: &Header) -> PacketKey {
        if let Some(LongType::Handshake) = h.ptype() {
            if let Some(Secret::Handshake(_)) = self.prev_secret {
                return self.prev_secret.as_ref().unwrap().build_key(Side::Client);
            }
        }
        self.secret.build_key(self.side)
    }

    pub(crate) fn decode_key(&self, _: &Header) -> PacketKey {
        self.secret.build_key(self.side)
    }

    pub(crate) fn set_secret(&mut self, secret: Secret) {
        let old = mem::replace(&mut self.secret, secret);
        self.prev_secret = Some(old);
    }

    pub fn build_initial_packet(&mut self, payload: Vec<Frame>) -> Packet {
        let number = self.src_pn;
        self.src_pn += 1;
        Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                conn_id: self.dst_cid,
                version: DRAFT_10,
                number,
            },
            payload,
        }
    }

    pub fn build_handshake_packet(&mut self, payload: Vec<Frame>) -> Packet {
        let number = self.src_pn;
        self.src_pn += 1;
        Packet {
            header: Header::Long {
                ptype: LongType::Handshake,
                conn_id: self.dst_cid,
                version: DRAFT_10,
                number,
            },
            payload,
        }
    }
}

pub enum TransportParameter {
    InitialMaxStreamData(u32),
    InitialMaxData(u32),
    InitialMaxStreamIdBidi(u32),
    IdleTimeout(u16),
    OmitConnectionId,
    MaxPacketSize(u16),
    StatelessResetToken(Vec<u8>),
    AckDelayExponent(u8),
    InitialMaxStreamIdUni(u32),
}

#[derive(Clone, PartialEq)]
pub enum Side {
    Client,
    Server,
}

impl Copy for Side {}

pub const DRAFT_10: u32 = 0xff00000a;
