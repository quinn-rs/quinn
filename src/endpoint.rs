use rand::{thread_rng, Rng};

use std::mem;
use std::ops::{Deref, DerefMut};

use codec::BufLen;
use crypto::{PacketKey, Secret};
use frame::{Ack, AckFrame, Frame, PaddingFrame, StreamFrame};
use packet::{Header, LongType, Packet, ShortType};
use tls;
use types::{ConnectionId, DRAFT_11, Side, GENERATED_CID_LENGTH};

pub struct Endpoint<T> {
    side: Side,
    pub dst_cid: ConnectionId,
    pub src_cid: ConnectionId,
    pub src_pn: u32,
    secret: Secret,
    prev_secret: Option<Secret>,
    tls: T,
}

impl<T, S> Endpoint<T>
where
    T: DerefMut + Deref<Target = S>,
    S: tls::Session,
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
            src_cid: rng.gen(),
            src_pn: rng.gen(),
            secret,
            prev_secret: None,
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self.secret {
            Secret::For1Rtt(_, _, _) => false,
            Secret::Handshake(_) => true,
        }
    }

    pub fn update_src_cid(&mut self) {
        self.src_cid = thread_rng().gen();
    }

    pub(crate) fn encode_key(&self, h: &Header) -> PacketKey {
        if let Some(LongType::Handshake) = h.ptype() {
            if let Some(ref secret @ Secret::Handshake(_)) = self.prev_secret {
                return secret.build_key(Side::Client);
            }
        }
        self.secret.build_key(self.side)
    }

    pub(crate) fn decode_key(&self, _: &Header) -> PacketKey {
        self.secret.build_key(self.side.other())
    }

    pub(crate) fn set_secret(&mut self, secret: Secret) {
        let old = mem::replace(&mut self.secret, secret);
        self.prev_secret = Some(old);
    }

    pub fn build_initial_packet(&mut self, mut payload: Vec<Frame>) -> Packet {
        let number = self.src_pn;
        self.src_pn += 1;

        let mut payload_len = payload.buf_len() + self.secret.tag_len();
        if payload_len < 1200 {
            payload.push(Frame::Padding(PaddingFrame(1200 - payload_len)));
            payload_len = 1200;
        }

        debug_assert_eq!(self.src_cid.len, GENERATED_CID_LENGTH);
        Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                version: DRAFT_11,
                dst_cid: self.dst_cid,
                src_cid: self.src_cid,
                len: payload_len as u64,
                number,
            },
            payload,
        }
    }

    pub fn build_handshake_packet(&mut self, payload: Vec<Frame>) -> Packet {
        let number = self.src_pn;
        self.src_pn += 1;

        debug_assert_eq!(self.src_cid.len, GENERATED_CID_LENGTH);
        Packet {
            header: Header::Long {
                ptype: LongType::Handshake,
                version: DRAFT_11,
                dst_cid: self.dst_cid,
                src_cid: self.src_cid,
                len: (payload.buf_len() + self.secret.tag_len()) as u64,
                number,
            },
            payload,
        }
    }

    fn build_short_packet(&mut self, payload: Vec<Frame>) -> Packet {
        let number = self.src_pn;
        self.src_pn += 1;

        debug_assert_eq!(self.src_cid.len, GENERATED_CID_LENGTH);
        Packet {
            header: Header::Short {
                key_phase: false,
                ptype: ShortType::Four,
                dst_cid: self.dst_cid,
                number: number,
            },
            payload,
        }
    }

    pub(crate) fn handle_handshake(&mut self, p: &Packet) -> Option<Packet> {
        match p.header {
            Header::Long { src_cid, .. } => {
                self.dst_cid = src_cid;
            }
            Header::Short { .. } => panic!("short packages not allowed for handshake"),
        }

        let tls_frame = p.payload
            .iter()
            .filter_map(|f| match *f {
                Frame::Stream(ref f) => Some(f),
                _ => None,
            })
            .next()
            .unwrap();

        let (handshake, new_secret) =
            tls::process_handshake_messages(&mut self.tls, Some(&tls_frame.data)).unwrap();
        if let Some(secret) = new_secret {
            self.set_secret(secret);
        }

        if handshake.is_empty() {
            return Some(self.build_short_packet(vec![
                Frame::Ack(AckFrame {
                    largest: p.number(),
                    ack_delay: 0,
                    blocks: vec![Ack::Ack(0)],
                }),
            ]));
        }

        Some(self.build_handshake_packet(vec![
            Frame::Ack(AckFrame {
                largest: p.number(),
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

impl Endpoint<tls::QuicClientTls> {
    pub(crate) fn initial(&mut self, server: &str) -> Packet {
        let (handshake, new_secret) = tls::start_handshake(&mut self.tls, server).unwrap();
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
