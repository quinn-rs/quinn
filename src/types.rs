use rand::{thread_rng, Rand, Rng};

use std::mem;
use std::ops::Deref;

use codec::BufLen;
use crypto::{PacketKey, Secret};
use frame::{Ack, AckFrame, Frame, StreamFrame};
use packet::{Header, LongType, Packet};
use tls::{ClientTls, QuicTls};

pub struct Endpoint<T> {
    side: Side,
    pub dst_cid: u64,
    pub src_pn: u32,
    secret: Secret,
    prev_secret: Option<Secret>,
    tls: T,
}

impl<T> Endpoint<T>
where
    T: QuicTls,
{
    pub fn new(tls: T, side: Side, secret: Option<Secret>) -> Self {
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
            tls,
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

    pub(crate) fn handle_handshake(&mut self, rsp: &Packet) -> Option<Packet> {
        self.dst_cid = rsp.conn_id().unwrap();
        let tls_frame = rsp.payload
            .iter()
            .filter_map(|f| match *f {
                Frame::Stream(ref f) => Some(f),
                _ => None,
            })
            .next()
            .unwrap();

        let (handshake, new_secret) = self.tls
            .process_handshake_messages(&tls_frame.data)
            .unwrap();
        if let Some(secret) = new_secret {
            self.set_secret(secret);
        }

        Some(self.build_handshake_packet(vec![
            Frame::Ack(AckFrame {
                largest: rsp.number(),
                ack_delay: 0,
                blocks: vec![Ack::Ack(0)],
            }),
            Frame::Stream(StreamFrame {
                id: 0,
                fin: false,
                offset: 0,
                len: Some(handshake.len() as u64),
                data: handshake,
            }),
        ]))
    }
}

impl Endpoint<ClientTls> {
    pub(crate) fn initial(&mut self, server: &str) -> Packet {
        let (handshake, new_secret) = self.tls.get_handshake(server).unwrap();
        if let Some(secret) = new_secret {
            self.set_secret(secret);
        }

        self.build_initial_packet(vec![
            Frame::Stream(StreamFrame {
                id: 0,
                fin: false,
                offset: 0,
                len: Some(handshake.len() as u64),
                data: handshake,
            }),
        ])
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId {
    pub len: u8,
    pub bytes: [u8; 18],
}

impl Copy for ConnectionId {}

impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Self {
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; 18],
        };
        (&mut res.bytes[..bytes.len()]).clone_from_slice(bytes);
        res
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
        let len = rng.gen_range(4u8, 18u8);
        let mut res = ConnectionId {
            len,
            bytes: [0; 18]
        };
        rng.fill_bytes(&mut res.bytes[..len as usize]);
        res
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
