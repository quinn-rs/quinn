use rand::{thread_rng, Rng};

use std::collections::VecDeque;
use std::io::Cursor;
use std::mem;

use super::{QuicError, QuicResult, QUIC_VERSION};
use codec::{BufLen, Codec};
use crypto::{PacketKey, Secret};
use frame::{Ack, AckFrame, CloseFrame, Frame, PaddingFrame, PathFrame, StreamFrame};
use packet::{Header, LongType, Packet, PartialDecode, ShortType};
use parameters::{ClientTransportParameters, ServerTransportParameters};
use streams::{Dir, Streams};
use tls;
use types::{ConnectionId, PeerData, Side, GENERATED_CID_LENGTH};

pub struct Endpoint<T> {
    side: Side,
    state: State,
    local: PeerData,
    remote: PeerData,
    src_pn: u32,
    secret: Secret,
    prev_secret: Option<Secret>,
    streams: Streams,
    queue: VecDeque<Packet>,
    tls: T,
}

impl<T> Endpoint<T>
where
    T: tls::Session,
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
            state: State::Start,
            remote: PeerData::new(dst_cid),
            local: PeerData::new(rng.gen()),
            src_pn: rng.gen(),
            secret,
            prev_secret: None,
            streams: Streams::new(side),
            queue: VecDeque::new(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self.state {
            State::Connected => false,
            _ => true,
        }
    }

    pub fn queued(&mut self) -> Option<Packet> {
        self.queue.pop_front()
    }

    pub fn pick_unused_cid<F>(&mut self, is_used: F) -> ConnectionId
    where
        F: Fn(ConnectionId) -> bool,
    {
        while is_used(self.local.cid) {
            self.local.cid = thread_rng().gen();
        }
        self.local.cid
    }

    pub(crate) fn encode_key(&self, h: &Header) -> PacketKey {
        if let Some(LongType::Handshake) = h.ptype() {
            if let Some(ref secret @ Secret::Handshake(_)) = self.prev_secret {
                return secret.build_key(self.side);
            }
        }
        self.secret.build_key(self.side)
    }

    pub(crate) fn decode_key(&self, h: &Header) -> PacketKey {
        if let Some(LongType::Handshake) = h.ptype() {
            if let Some(ref secret @ Secret::Handshake(_)) = self.prev_secret {
                return secret.build_key(self.side.other());
            }
        }
        self.secret.build_key(self.side.other())
    }

    pub(crate) fn set_secret(&mut self, secret: Secret) {
        let old = mem::replace(&mut self.secret, secret);
        self.prev_secret = Some(old);
    }

    pub fn build_initial_packet(&mut self, mut payload: Vec<Frame>) {
        let number = self.src_pn;
        self.src_pn += 1;

        let mut payload_len = payload.buf_len() + self.secret.tag_len();
        if payload_len < 1200 {
            payload.push(Frame::Padding(PaddingFrame(1200 - payload_len)));
            payload_len = 1200;
        }

        debug_assert_eq!(self.local.cid.len, GENERATED_CID_LENGTH);
        self.queue.push_back(Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                version: QUIC_VERSION,
                dst_cid: self.remote.cid,
                src_cid: self.local.cid,
                len: payload_len as u64,
                number,
            },
            payload,
        });
    }

    pub fn build_handshake_packet(&mut self, payload: Vec<Frame>) {
        let number = self.src_pn;
        self.src_pn += 1;

        debug_assert_eq!(self.local.cid.len, GENERATED_CID_LENGTH);
        self.queue.push_back(Packet {
            header: Header::Long {
                ptype: LongType::Handshake,
                version: QUIC_VERSION,
                dst_cid: self.remote.cid,
                src_cid: self.local.cid,
                len: (payload.buf_len() + self.secret.tag_len()) as u64,
                number,
            },
            payload,
        });
    }

    fn build_short_packet(&mut self, payload: Vec<Frame>) {
        let number = self.src_pn;
        self.src_pn += 1;

        debug_assert_eq!(self.state, State::Connected);
        debug_assert_eq!(self.local.cid.len, GENERATED_CID_LENGTH);
        self.queue.push_back(Packet {
            header: Header::Short {
                key_phase: false,
                ptype: ShortType::Four,
                dst_cid: self.remote.cid,
                number: number,
            },
            payload,
        });
    }

    pub(crate) fn handle(&mut self, buf: &mut [u8]) -> QuicResult<()> {
        self.handle_partial(Packet::start_decode(buf))
    }

    pub(crate) fn handle_partial(&mut self, partial: PartialDecode) -> QuicResult<()> {
        let key = self.decode_key(&partial.header);
        self.handle_packet(partial.finish(&key)?)
    }

    fn handle_packet(&mut self, p: Packet) -> QuicResult<()> {
        match p.ptype() {
            Some(LongType::Initial) | Some(LongType::Handshake) => self.handle_handshake(&p),
            _ => Ok(()),
        }
    }

    pub(crate) fn handle_handshake(&mut self, p: &Packet) -> QuicResult<()> {
        match p.header {
            Header::Long {
                dst_cid, src_cid, ..
            } => match self.state {
                State::Start | State::InitialSent => {
                    self.remote.cid = src_cid;
                    self.state = State::Handshaking;
                }
                _ => if dst_cid != self.local.cid {
                    return Err(QuicError::General(format!(
                        "invalid destination CID {:?} received (expected {:?})",
                        dst_cid, self.local.cid
                    )));
                },
            },
            Header::Short { .. } => match self.state {
                State::Connected => {}
                _ => {
                    return Err(QuicError::General(format!(
                        "short header received in {:?} state",
                        self.state
                    )));
                }
            },
        }

        let mut payload = vec![
            Frame::Ack(AckFrame {
                largest: p.number(),
                ack_delay: 0,
                blocks: vec![Ack::Ack(0)],
            }),
        ];

        let mut wrote_handshake = false;
        for frame in p.payload.iter() {
            match frame {
                Frame::Stream(f) if f.id == 0 => {
                    let (handshake, new_secret) =
                        tls::process_handshake_messages(&mut self.tls, Some(&f.data))?;

                    let mut stream = self.streams.received(f.id).ok_or_else(|| {
                        QuicError::General(format!(
                            "no incoming packets allowed on stream {}",
                            f.id
                        ))
                    })?;
                    let offset = stream.get_offset();
                    stream.set_offset(offset + handshake.len() as u64);

                    if !handshake.is_empty() {
                        payload.push(Frame::Stream(StreamFrame {
                            id: 0,
                            fin: false,
                            offset,
                            len: Some(handshake.len() as u64),
                            data: handshake,
                        }));
                        wrote_handshake = true;
                    }

                    if let Some(secret) = new_secret {
                        self.set_secret(secret);
                        self.state = State::Connected;

                        let params = match self.tls.get_quic_transport_parameters() {
                            None => {
                                return Err(QuicError::General(
                                    "no transport parameters received".into(),
                                ));
                            }
                            Some(bytes) => {
                                let mut read = Cursor::new(bytes);
                                if self.side == Side::Client {
                                    ServerTransportParameters::decode(&mut read).parameters
                                } else {
                                    ClientTransportParameters::decode(&mut read).parameters
                                }
                            }
                        };

                        mem::replace(&mut self.remote.params, params);
                    }
                }
                Frame::PathChallenge(PathFrame(token)) => {
                    payload.push(Frame::PathResponse(PathFrame(token.clone())));
                }
                Frame::ApplicationClose(CloseFrame { code, reason }) => {
                    return Err(QuicError::ApplicationClose(*code, reason.clone()));
                }
                Frame::ConnectionClose(CloseFrame { code, reason }) => {
                    return Err(QuicError::ConnectionClose(*code, reason.clone()));
                }
                Frame::Ack(_)
                | Frame::Padding(_)
                | Frame::PathResponse(_)
                | Frame::Stream(_)
                | Frame::Ping => {}
            }
        }

        if self.state == State::Connected && !wrote_handshake {
            self.build_short_packet(payload)
        } else {
            self.build_handshake_packet(payload)
        }
        Ok(())
    }
}

impl Endpoint<tls::ClientSession> {
    pub(crate) fn initial(&mut self) -> QuicResult<()> {
        let (handshake, new_secret) = tls::process_handshake_messages(&mut self.tls, None)?;
        if let Some(secret) = new_secret {
            self.set_secret(secret);
        }

        let mut stream = self.streams.init_send(Dir::Bidi).ok_or_else(|| {
            QuicError::General("no bidirectional stream available for initial packet".into())
        })?;
        stream.set_offset(handshake.len() as u64);

        self.state = State::InitialSent;
        self.build_initial_packet(vec![
            Frame::Stream(StreamFrame {
                id: 0,
                fin: false,
                offset: 0,
                len: Some(handshake.len() as u64),
                data: handshake,
            }),
        ]);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum State {
    Start,
    InitialSent,
    Handshaking,
    Connected,
}
