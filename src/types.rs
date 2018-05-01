use rand::{thread_rng, Rng};
use frame::Frame;
use packet::{Header, LongType, Packet};

pub struct Endpoint {
    pub dst_cid: u64,
    pub src_pn: u32,
}

impl Endpoint {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        Endpoint {
            dst_cid: rng.gen(),
            src_pn: rng.gen(),
        }
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

#[derive(PartialEq)]
pub enum Side {
    Client,
    Server,
}

pub const DRAFT_10: u32 = 0xff00000a;
