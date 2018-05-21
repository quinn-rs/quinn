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

pub struct ConnectionState<T> {
    side: Side,
    state: State,
    local: PeerData,
    remote: PeerData,
    src_pn: u32,
    secret: Secret,
    prev_secret: Option<Secret>,
    pub streams: Streams,
    queue: VecDeque<Vec<u8>>,
    tls: T,
}

impl<T> ConnectionState<T>
where
    T: tls::Session + tls::QuicSide,
{
    pub fn new(tls: T, secret: Option<Secret>) -> Self {
        let mut rng = thread_rng();
        let dst_cid = rng.gen();
        let side = tls.side();

        let secret = if side == Side::Client {
            debug_assert!(secret.is_none());
            Secret::Handshake(dst_cid)
        } else if let Some(secret) = secret {
            secret
        } else {
            panic!("need secret for client conn_state");
        };

        let local = PeerData::new(rng.gen());
        let (num_recv_bidi, num_recv_uni) = (
            u64::from(local.params.max_streams_bidi),
            u64::from(local.params.max_stream_id_uni),
        );
        let (max_recv_bidi, max_recv_uni) = if side == Side::Client {
            (1 + 4 * num_recv_bidi, 3 + 4 * num_recv_uni)
        } else {
            (4 * num_recv_bidi, 1 + 4 * num_recv_uni)
        };

        let mut streams = Streams::new(side);
        streams.update_max_id(max_recv_bidi);
        streams.update_max_id(max_recv_uni);

        ConnectionState {
            tls,
            side,
            state: State::Start,
            remote: PeerData::new(dst_cid),
            local,
            src_pn: rng.gen(),
            secret,
            prev_secret: None,
            streams,
            queue: VecDeque::new(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self.state {
            State::Connected => false,
            _ => true,
        }
    }

    pub fn queued(&mut self) -> QuicResult<Option<&Vec<u8>>> {
        let mut frames = vec![];
        while let Some(frame) = self.streams.queued() {
            frames.push(frame);
        }

        if !frames.is_empty() {
            self.build_short_packet(frames)?
        }
        Ok(self.queue.front())
    }

    pub fn pop_queue(&mut self) {
        self.queue.pop_front();
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

    fn encode_key(&self, h: &Header) -> PacketKey {
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

    fn build_initial_packet(&mut self, mut payload: Vec<Frame>) -> QuicResult<()> {
        let number = self.src_pn;
        self.src_pn += 1;

        let mut payload_len = payload.buf_len() + self.secret.tag_len();
        if payload_len < 1200 {
            payload.push(Frame::Padding(PaddingFrame(1200 - payload_len)));
            payload_len = 1200;
        }

        let (dst_cid, src_cid) = (self.remote.cid, self.local.cid);
        debug_assert_eq!(src_cid.len, GENERATED_CID_LENGTH);
        self.queue_packet(Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                version: QUIC_VERSION,
                dst_cid,
                src_cid,
                len: payload_len as u64,
                number,
            },
            payload,
        })
    }

    fn build_handshake_packet(&mut self, payload: Vec<Frame>) -> QuicResult<()> {
        let number = self.src_pn;
        self.src_pn += 1;

        let len = (payload.buf_len() + self.secret.tag_len()) as u64;
        let (dst_cid, src_cid) = (self.remote.cid, self.local.cid);
        debug_assert_eq!(src_cid.len, GENERATED_CID_LENGTH);
        self.queue_packet(Packet {
            header: Header::Long {
                ptype: LongType::Handshake,
                version: QUIC_VERSION,
                dst_cid,
                src_cid,
                len,
                number,
            },
            payload,
        })
    }

    fn build_short_packet(&mut self, payload: Vec<Frame>) -> QuicResult<()> {
        let number = self.src_pn;
        self.src_pn += 1;

        let dst_cid = self.remote.cid;
        debug_assert_eq!(self.state, State::Connected);
        debug_assert_eq!(self.local.cid.len, GENERATED_CID_LENGTH);
        self.queue_packet(Packet {
            header: Header::Short {
                key_phase: false,
                ptype: ShortType::Four,
                dst_cid,
                number,
            },
            payload,
        })
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn queue_packet(&mut self, packet: Packet) -> QuicResult<()> {
        let key = self.encode_key(&packet.header);
        let len = packet.buf_len() + key.algorithm().tag_len();
        let mut buf = vec![0u8; len];
        packet.encode(&key, &mut buf)?;
        self.queue.push_back(buf);
        Ok(())
    }

    pub(crate) fn handle(&mut self, buf: &mut [u8]) -> QuicResult<()> {
        self.handle_partial(Packet::start_decode(buf))
    }

    pub(crate) fn handle_partial(&mut self, partial: PartialDecode) -> QuicResult<()> {
        let key = self.decode_key(&partial.header);
        self.handle_packet(partial.finish(&key)?)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    fn handle_packet(&mut self, p: Packet) -> QuicResult<()> {
        let dst_cid = match p.header {
            Header::Long {
                dst_cid, src_cid, ..
            } => match self.state {
                State::Start | State::InitialSent => {
                    self.remote.cid = src_cid;
                    dst_cid
                }
                _ => dst_cid,
            },
            Header::Short { dst_cid, .. } => if let State::Connected = self.state {
                dst_cid
            } else {
                return Err(QuicError::General(format!(
                    "short header received in {:?} state",
                    self.state
                )));
            },
        };

        if self.state != State::Start && dst_cid != self.local.cid {
            return Err(QuicError::General(format!(
                "invalid destination CID {:?} received (expected {:?})",
                dst_cid, self.local.cid
            )));
        }

        let mut payload = vec![
            Frame::Ack(AckFrame {
                largest: p.number(),
                ack_delay: 0,
                blocks: vec![Ack::Ack(0)],
            }),
        ];

        let mut received_tls = false;
        let mut wrote_handshake = false;
        for frame in &p.payload {
            match frame {
                Frame::Stream(f) if f.id == 0 => {
                    received_tls = true;
                    if let Some(frame) = self.handle_tls(Some(f))? {
                        payload.push(Frame::Stream(frame));
                        wrote_handshake = true;
                    }
                }
                Frame::PathChallenge(PathFrame(token)) => {
                    payload.push(Frame::PathResponse(PathFrame(*token)));
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
                | Frame::Ping
                | Frame::StreamIdBlocked(_) => {}
            }
        }

        match self.state {
            State::Start | State::InitialSent => {
                self.state = State::Handshaking;
            }
            State::Handshaking if !received_tls => {
                if let Some(frame) = self.handle_tls(None)? {
                    payload.push(Frame::Stream(frame));
                    wrote_handshake = true;
                }
            }
            _ => {}
        }

        if self.state == State::Connected && !wrote_handshake {
            self.build_short_packet(payload)
        } else {
            self.build_handshake_packet(payload)
        }
    }

    fn handle_tls(&mut self, frame: Option<&StreamFrame>) -> QuicResult<Option<StreamFrame>> {
        let (handshake, new_secret) =
            tls::process_handshake_messages(&mut self.tls, frame.map(|f| f.data.as_ref()))?;

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

            let (num_send_bidi, num_send_uni) = (
                u64::from(self.remote.params.max_streams_bidi),
                u64::from(self.remote.params.max_stream_id_uni),
            );
            let (max_send_bidi, max_send_uni) = if self.side == Side::Server {
                (1 + 4 * num_send_bidi, 3 + 4 * num_send_uni)
            } else {
                (4 * num_send_bidi, 1 + 4 * num_send_uni)
            };
            self.streams.update_max_id(max_send_bidi);
            self.streams.update_max_id(max_send_uni);
        }

        let mut stream = self.streams
            .received(0)
            .ok_or_else(|| QuicError::General("no incoming packets allowed on stream 0".into()))?;
        let offset = stream.get_offset();
        stream.set_offset(offset + handshake.len() as u64);

        if !handshake.is_empty() {
            Ok(Some(StreamFrame {
                id: 0,
                fin: false,
                offset,
                len: Some(handshake.len() as u64),
                data: handshake,
            }))
        } else {
            Ok(None)
        }
    }
}

impl ConnectionState<tls::ClientSession> {
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
        ])
    }
}

#[derive(Debug, PartialEq)]
enum State {
    Start,
    InitialSent,
    Handshaking,
    Connected,
}

#[cfg(test)]
pub mod tests {
    use super::{ClientTransportParameters, ConnectionId, ServerTransportParameters};
    use super::{tls, ConnectionState, Packet, Secret};
    use std::sync::Arc;

    #[test]
    fn test_encoded_handshake() {
        let mut c = client_conn_state();
        c.initial().unwrap();
        let mut c_initial = c.queued().unwrap().unwrap().clone();
        c.pop_queue();

        let mut s = server_conn_state(Packet::start_decode(&mut c_initial).dst_cid());
        s.handle(&mut c_initial).unwrap();

        let mut s_sh = s.queued().unwrap().unwrap().clone();
        s.pop_queue();
        c.handle(&mut s_sh).unwrap();

        let mut c_fin = c.queued().unwrap().unwrap().clone();
        c.pop_queue();
        s.handle(&mut c_fin).unwrap();

        let mut s_short = s.queued().unwrap().unwrap().clone();
        s.pop_queue();
        let c_short = {
            let partial = Packet::start_decode(&mut s_short);
            let key = c.decode_key(&partial.header);
            partial.finish(&key).unwrap()
        };
        assert_eq!(c_short.header.ptype(), None);
    }

    #[test]
    fn test_handshake() {
        let mut c = client_conn_state();
        c.initial().unwrap();
        let mut initial = c.queued().unwrap().unwrap().clone();
        c.pop_queue();

        let mut s = server_conn_state(Packet::start_decode(&mut initial).dst_cid());
        s.handle(&mut initial).unwrap();
        let mut server_hello = s.queued().unwrap().unwrap().clone();

        c.handle(&mut server_hello).unwrap();
        assert!(c.queued().unwrap().is_some());
    }

    pub fn server_conn_state(hs_cid: ConnectionId) -> ConnectionState<tls::ServerSession> {
        ConnectionState::new(
            tls::server_session(
                &Arc::new(tls::tests::server_config()),
                &ServerTransportParameters::default(),
            ),
            Some(Secret::Handshake(hs_cid)),
        )
    }

    pub fn client_conn_state() -> ConnectionState<tls::ClientSession> {
        ConnectionState::new(
            tls::client_session(
                Some(tls::tests::client_config()),
                "Localhost",
                &ClientTransportParameters::default(),
            ).unwrap(),
            None,
        )
    }
}
