use bytes::Buf;

use rand::{thread_rng, Rng};

use std::collections::VecDeque;
use std::io::Cursor;
use std::mem;

use super::{QuicError, QuicResult, QUIC_VERSION};
use codec::Codec;
use crypto::Secret;
use frame::{Ack, AckFrame, CloseFrame, Frame, PaddingFrame, PathFrame};
use packet::{Header, LongType, PartialDecode, ShortType};
use parameters::{ClientTransportParameters, ServerTransportParameters, TransportParameters};
use streams::{Dir, Streams};
use tls;
use types::{ConnectionId, Side, GENERATED_CID_LENGTH};

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
    control: VecDeque<Frame>,
    tls: T,
    pmtu: usize,
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
            control: VecDeque::new(),
            pmtu: IPV6_MIN_MTU,
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self.state {
            State::Connected => false,
            _ => true,
        }
    }

    pub fn queued(&mut self) -> QuicResult<Option<&Vec<u8>>> {
        self.queue_packet()?;
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

    pub(crate) fn set_secret(&mut self, secret: Secret) {
        let old = mem::replace(&mut self.secret, secret);
        self.prev_secret = Some(old);
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn queue_packet(&mut self) -> QuicResult<()> {
        let (dst_cid, src_cid) = (self.remote.cid, self.local.cid);
        debug_assert_eq!(src_cid.len, GENERATED_CID_LENGTH);
        let number = self.src_pn;
        self.src_pn += 1;

        let (ptype, new_state) = match self.state {
            State::Connected => (None, self.state),
            State::Handshaking => (Some(LongType::Handshake), self.state),
            State::InitialSent => (Some(LongType::Handshake), State::Handshaking),
            State::Start => if self.side == Side::Client {
                (Some(LongType::Initial), State::InitialSent)
            } else {
                (Some(LongType::Handshake), State::Handshaking)
            },
            State::FinalHandshake => (Some(LongType::Handshake), State::Connected),
        };

        let header_len = match ptype {
            Some(_) => (12 + (dst_cid.len + src_cid.len) as usize),
            None => (3 + dst_cid.len as usize),
        };

        let secret = if let Some(LongType::Handshake) = ptype {
            if let Some(ref secret @ Secret::Handshake(_)) = self.prev_secret {
                secret
            } else {
                &self.secret
            }
        } else {
            &self.secret
        };
        let key = secret.build_key(self.side);
        let tag_len = key.algorithm().tag_len();

        let mut buf = vec![0u8; self.pmtu];
        let payload_len = {
            let mut write = Cursor::new(&mut buf[header_len..self.pmtu - tag_len]);
            while let Some(frame) = self.control.pop_front() {
                frame.encode(&mut write);
            }
            self.streams.poll_send(&mut write);

            let mut payload_len = write.position() as usize;
            let initial_min_size = 1200 - header_len - tag_len;
            if ptype == Some(LongType::Initial) && payload_len < initial_min_size {
                Frame::Padding(PaddingFrame(initial_min_size - payload_len)).encode(&mut write);
                payload_len = initial_min_size;
            }
            payload_len
        };

        if payload_len == 0 {
            return Ok(());
        }

        let header = match ptype {
            Some(ltype) => Header::Long {
                ptype: ltype,
                version: QUIC_VERSION,
                dst_cid,
                src_cid,
                len: (payload_len + tag_len) as u64,
                number,
            },
            None => Header::Short {
                key_phase: false,
                ptype: ShortType::Two,
                dst_cid,
                number,
            },
        };
        {
            let mut write = Cursor::new(&mut buf[..header_len]);
            header.encode(&mut write);
        }

        let out_len = {
            let (header_buf, mut payload) = buf.split_at_mut(header_len);
            let mut in_out = &mut payload[..payload_len + tag_len];
            key.encrypt(number, &header_buf, in_out, tag_len)?
        };

        buf.truncate(header_len + out_len);
        self.queue.push_back(buf);
        self.state = new_state;
        Ok(())
    }

    pub(crate) fn handle(&mut self, buf: &mut [u8]) -> QuicResult<()> {
        self.handle_partial(PartialDecode::new(buf)?)
    }

    pub(crate) fn handle_partial(&mut self, partial: PartialDecode) -> QuicResult<()> {
        let PartialDecode {
            header,
            header_len,
            buf,
        } = partial;

        let key = {
            let secret = if let Some(LongType::Handshake) = header.ptype() {
                if let Some(ref secret @ Secret::Handshake(_)) = self.prev_secret {
                    secret
                } else {
                    &self.secret
                }
            } else {
                &self.secret
            };
            secret.build_key(self.side.other())
        };

        let payload = match header {
            Header::Long { number, .. } | Header::Short { number, .. } => {
                let (header_buf, payload_buf) = buf.split_at_mut(header_len);
                let decrypted = key.decrypt(number, &header_buf, payload_buf)?;
                let mut read = Cursor::new(decrypted);

                let mut payload = Vec::new();
                while read.has_remaining() {
                    let frame = Frame::decode(&mut read)?;
                    payload.push(frame);
                }
                payload
            }
            Header::Negotiation { .. } => vec![],
        };

        self.handle_packet(header, payload)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    fn handle_packet(&mut self, header: Header, payload: Vec<Frame>) -> QuicResult<()> {
        let (dst_cid, number) = match header {
            Header::Long {
                dst_cid,
                src_cid,
                number,
                ..
            } => match self.state {
                State::Start | State::InitialSent => {
                    self.remote.cid = src_cid;
                    (dst_cid, number)
                }
                _ => (dst_cid, number),
            },
            Header::Short {
                dst_cid, number, ..
            } => if let State::Connected = self.state {
                (dst_cid, number)
            } else {
                return Err(QuicError::General(format!(
                    "{:?} received short header in {:?} state",
                    self.side, self.state
                )));
            },
            Header::Negotiation { .. } => {
                return Err(QuicError::General(
                    "negotiation packet not handled by connections".into(),
                ));
            }
        };

        if self.state != State::Start && dst_cid != self.local.cid {
            return Err(QuicError::General(format!(
                "invalid destination CID {:?} received (expected {:?} in state {:?})",
                dst_cid, self.local.cid, self.state
            )));
        }

        let mut send_ack = false;
        for frame in &payload {
            match frame {
                Frame::Stream(f) => {
                    send_ack = true;
                    self.streams.received(f)?;
                    if f.id == 0 {
                        self.handle_tls()?;
                    }
                }
                Frame::PathChallenge(PathFrame(token)) => {
                    send_ack = true;
                    self.control
                        .push_back(Frame::PathResponse(PathFrame(*token)));
                }
                Frame::ApplicationClose(CloseFrame { code, reason }) => {
                    return Err(QuicError::ApplicationClose(*code, reason.clone()));
                }
                Frame::ConnectionClose(CloseFrame { code, reason }) => {
                    return Err(QuicError::ConnectionClose(*code, reason.clone()));
                }
                Frame::PathResponse(_) | Frame::Ping | Frame::StreamIdBlocked(_) => {
                    send_ack = true;
                }
                Frame::Ack(_) | Frame::Padding(_) => {}
            }
        }

        if send_ack {
            self.control.push_back(Frame::Ack(AckFrame {
                largest: number,
                ack_delay: 0,
                blocks: vec![Ack::Ack(0)],
            }));
        }

        Ok(())
    }

    fn handle_tls(&mut self) -> QuicResult<()> {
        let mut stream = match self.streams.get_stream(0) {
            Some(s) => s,
            None => {
                let stream = self.streams.init_send(Dir::Bidi)?;
                debug_assert_eq!(stream.id, 0);
                stream
            }
        };

        let data = stream.received()?;
        let (handshake, new_secret) = tls::process_handshake_messages(&mut self.tls, Some(&data))?;

        if let Some(secret) = new_secret {
            self.set_secret(secret);
            self.state = match self.side {
                Side::Client => State::FinalHandshake,
                Side::Server => State::Connected,
            };

            let params = match self.tls.get_quic_transport_parameters() {
                None => {
                    return Err(QuicError::General(
                        "no transport parameters received".into(),
                    ));
                }
                Some(bytes) => {
                    let mut read = Cursor::new(bytes);
                    if self.side == Side::Client {
                        ServerTransportParameters::decode(&mut read)?.parameters
                    } else {
                        ClientTransportParameters::decode(&mut read)?.parameters
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

        stream.send(&handshake)
    }
}

impl ConnectionState<tls::ClientSession> {
    pub(crate) fn initial(&mut self) -> QuicResult<()> {
        self.handle_tls()
    }
}

pub struct PeerData {
    pub cid: ConnectionId,
    pub params: TransportParameters,
}

impl PeerData {
    pub fn new(cid: ConnectionId) -> Self {
        PeerData {
            cid,
            params: TransportParameters::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Start,
    InitialSent,
    Handshaking,
    FinalHandshake,
    Connected,
}

const IPV6_MIN_MTU: usize = 1232;

#[cfg(test)]
pub mod tests {
    use super::{tls, ConnectionState, PartialDecode, Secret};
    use super::{ClientTransportParameters, ConnectionId, ServerTransportParameters};
    use std::sync::Arc;

    #[test]
    fn test_encoded_handshake() {
        let mut c = client_conn_state();
        c.initial().unwrap();
        let mut cp = c.queued().unwrap().unwrap().clone();
        c.pop_queue();

        let mut s = server_conn_state(PartialDecode::new(&mut cp).unwrap().dst_cid());
        s.handle(&mut cp).unwrap();
        let mut messages = Vec::new();
        gather(&mut s, &mut messages);

        let mut rt = 10;
        loop {
            for mut sp in messages.drain(..) {
                c.handle(&mut sp).unwrap();
            }

            gather(&mut c, &mut messages);

            for mut cp in messages.drain(..) {
                s.handle(&mut cp).unwrap();
            }

            gather(&mut s, &mut messages);

            let header = PartialDecode::new(messages.last_mut().unwrap())
                .unwrap()
                .header;
            if header.ptype().is_none() {
                break;
            }

            rt -= 1;
            if rt < 1 {
                panic!("short header not emitted within 10 round trips");
            }
        }
    }

    fn gather<T>(cs: &mut ConnectionState<T>, buf: &mut Vec<Vec<u8>>)
    where
        T: tls::Session + tls::QuicSide,
    {
        loop {
            let mut found = false;
            if let Some(packet) = cs.queued().unwrap() {
                buf.push(packet.clone());
                found = true;
            }
            if found {
                cs.pop_queue();
            } else {
                break;
            }
        }
    }

    #[test]
    fn test_handshake() {
        let mut c = client_conn_state();
        c.initial().unwrap();
        let mut initial = c.queued().unwrap().unwrap().clone();
        c.pop_queue();

        let mut s = server_conn_state(PartialDecode::new(&mut initial).unwrap().dst_cid());
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
