use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::Cursor,
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Waker},
};

use bytes::{Bytes, BytesMut};
use futures::{AsyncRead, Future, Poll, Stream};
use quinn::{IncomingBiStreams, IncomingUniStreams, RecvStream, SendStream};
use quinn_proto::{Side, StreamId};

use crate::{
    frame::FrameStream,
    proto::{
        connection::{Connection, DecodeResult, Error as ProtoError, PendingStreamType},
        frame::{HeadersFrame, HttpFrame},
        ErrorCode, StreamType,
    },
    streams::{NewUni, RecvUni, SendUni},
    Error, Settings,
};

const RECV_ENCODER_INITIAL_CAPACITY: usize = 20480;
const RECV_DECODER_INITIAL_CAPACITY: usize = 2048;

pub struct ConnectionDriver(pub(crate) ConnectionRef);

impl Future for ConnectionDriver {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut conn = self.0.h3.lock().unwrap();

        conn.poll_incoming_uni(cx)?;
        conn.poll_send(cx)?;
        conn.poll_recv_control(cx)?;
        conn.poll_recv_encoder(cx)?;
        conn.poll_recv_decoder(cx)?;
        conn.poll_incoming_bi(cx)?;
        conn.poll_send(cx)?;

        conn.reset_waker(cx);

        if conn.inner.is_closing() && conn.inner.requests_in_flight() == 0 {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionRef {
    pub h3: Arc<Mutex<ConnectionInner>>,
    pub quic: quinn::Connection,
}

impl ConnectionRef {
    pub fn new(
        quic: quinn::Connection,
        side: Side,
        uni_streams: IncomingUniStreams,
        bi_streams: IncomingBiStreams,
        settings: Settings,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            quic: quic.clone(),
            h3: Arc::new(Mutex::new(ConnectionInner {
                side,
                driver: None,
                quic: quic.clone(),
                incoming_bi: bi_streams,
                incoming_uni: uni_streams,
                pending_uni: VecDeque::with_capacity(3),
                inner: Connection::with_settings(settings)?,
                requests: VecDeque::with_capacity(16),
                requests_task: None,
                recv_control: None,
                recv_encoder: None,
                recv_decoder: None,
                blocked_streams: BTreeMap::new(),
                send_unis: [
                    SendUni::new(StreamType::CONTROL, quic.clone()),
                    SendUni::new(StreamType::ENCODER, quic.clone()),
                    SendUni::new(StreamType::DECODER, quic),
                ],
            })),
        })
    }
}

pub(crate) struct ConnectionInner {
    pub inner: Connection,
    pub requests: VecDeque<(SendStream, RecvStream)>,
    pub requests_task: Option<Waker>,
    side: Side,
    driver: Option<Waker>,
    quic: quinn::Connection,
    incoming_bi: IncomingBiStreams,
    incoming_uni: IncomingUniStreams,
    pending_uni: VecDeque<Option<RecvUni>>,
    recv_control: Option<FrameStream>,
    recv_encoder: Option<(RecvStream, BytesMut)>,
    recv_decoder: Option<(RecvStream, BytesMut)>,
    blocked_streams: BTreeMap<usize, HashMap<StreamId, Waker>>,
    send_unis: [SendUni; 3],
}

impl ConnectionInner {
    pub fn wake(&mut self) {
        if let Some(w) = self.driver.take() {
            w.wake();
        }
    }

    fn reset_waker(&mut self, cx: &mut Context) {
        if self.driver.is_none() {
            self.driver = Some(cx.waker().clone());
        }
    }

    pub fn decode_header(
        &mut self,
        cx: &mut Context,
        stream_id: StreamId,
        header: &HeadersFrame,
    ) -> Result<DecodeResult, Error> {
        self.inner
            .decode_header(stream_id, header)
            .map_err(|e| Error::peer(format!("decoding header failed: {:?}", e)))
            .map(|r| {
                match &r {
                    DecodeResult::Decoded(_) => self.wake(), // send header acknowledgement
                    DecodeResult::MissingRefs(required_ref) => {
                        self.blocked_streams
                            .entry(*required_ref)
                            .or_insert(HashMap::new())
                            .entry(stream_id)
                            .or_insert(cx.waker().clone());
                    }
                };
                r
            })
    }

    fn poll_incoming_bi(&mut self, cx: &mut Context) -> Result<(), Error> {
        loop {
            match Pin::new(&mut self.incoming_bi).poll_next(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Some(Err(e))) => return Err(e.into()),
                Poll::Ready(None) => {
                    return Err(Error::Peer("closed incoming bi".into()));
                }
                Poll::Ready(Some(Ok((mut send, mut recv)))) => match self.side {
                    Side::Client => {
                        self.set_error(
                            ErrorCode::STREAM_CREATION_ERROR,
                            "client does not accept bidirectional streams",
                        );
                        return Err(Error::Peer(
                            "client does not accept bidirectional streams".into(),
                        ));
                    }
                    Side::Server => {
                        if self.inner.is_closing() {
                            send.reset(ErrorCode::REQUEST_REJECTED.into());
                            let _ = recv.stop(ErrorCode::REQUEST_REJECTED.into());
                        } else {
                            self.inner.request_initiated(send.id());
                            self.requests.push_back((send, recv));
                            if let Some(t) = self.requests_task.take() {
                                t.wake();
                            }
                        }
                    }
                },
            }
        }
    }

    fn poll_incoming_uni(&mut self, cx: &mut Context) -> Result<(), Error> {
        loop {
            match Pin::new(&mut self.incoming_uni).poll_next(cx)? {
                Poll::Pending => break,
                Poll::Ready(None) => return Err(Error::Peer("closed incoming uni".into())),
                Poll::Ready(Some(recv)) => self.pending_uni.push_back(Some(RecvUni::new(recv))),
            }
        }

        self.poll_resolve_uni(cx)?;

        Ok(())
    }

    fn poll_resolve_uni(&mut self, cx: &mut Context) -> Result<(), Error> {
        let resolved: Vec<(usize, Result<NewUni, Error>)> = self
            .pending_uni
            .iter_mut()
            .enumerate()
            .filter_map(|(i, x)| {
                let mut pending = x.take().unwrap();
                match Pin::new(&mut pending).poll(cx) {
                    Poll::Ready(y) => Some((i, y)),
                    Poll::Pending => {
                        std::mem::replace(x, Some(pending));
                        None
                    }
                }
            })
            .collect();

        let mut removed = 0;

        for (i, res) in resolved {
            self.pending_uni.remove(i - removed);
            removed += 1;
            match res {
                Err(Error::UnknownStream(ty)) => println!("unknown stream type {}", ty),
                Err(e) => {
                    self.set_error(ErrorCode::STREAM_CREATION_ERROR, format!("{:?}", e));
                    return Err(e);
                }
                Ok(n) => self.on_uni_resolved(n)?,
            }
        }
        Ok(())
    }

    fn on_uni_resolved(&mut self, new_stream: NewUni) -> Result<(), Error> {
        match new_stream {
            NewUni::Control(stream) => match self.recv_control {
                None => {
                    self.recv_control = Some(stream);
                    Ok(())
                }
                Some(_) => {
                    self.set_error(
                        ErrorCode::STREAM_CREATION_ERROR,
                        "control stream already open",
                    );
                    Err(Error::Peer("control stream already open".into()))
                }
            },
            NewUni::Decoder(s) => match self.recv_decoder {
                None => {
                    self.recv_decoder =
                        Some((s, BytesMut::with_capacity(RECV_DECODER_INITIAL_CAPACITY)));
                    Ok(())
                }
                Some(_) => {
                    self.set_error(
                        ErrorCode::STREAM_CREATION_ERROR,
                        "decoder stream already open",
                    );
                    Err(Error::Peer("decoder stream already open".into()))
                }
            },
            NewUni::Encoder(s) => match self.recv_encoder {
                None => {
                    self.recv_encoder =
                        Some((s, BytesMut::with_capacity(RECV_ENCODER_INITIAL_CAPACITY)));
                    Ok(())
                }
                Some(_) => {
                    self.set_error(
                        ErrorCode::STREAM_CREATION_ERROR,
                        "encoder stream already open",
                    );
                    Err(Error::Peer("encoder stream already open".into()))
                }
            },
            NewUni::Push(_) => {
                println!("push stream ignored");
                Ok(())
            }
        }
    }

    fn poll_recv_control(&mut self, cx: &mut Context) -> Result<(), Error> {
        let mut control = match self.recv_control.as_mut() {
            None => return Ok(()),
            Some(c) => c,
        };

        loop {
            match Pin::new(&mut control).poll_next(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(None) => {
                    self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, "control in closed");
                    return Err(Error::Peer("control in closed".into()));
                }
                Poll::Ready(Some(Err(e))) => {
                    let (code, msg, err) = e.into();
                    self.set_error(code, msg.clone());
                    return Err(err);
                }
                Poll::Ready(Some(Ok(frame))) => {
                    match (self.inner.remote_settings().is_some(), self.side, frame) {
                        (_, _, HttpFrame::Settings(s)) => {
                            self.inner.set_remote_settings(s)?;
                        }
                        (true, Side::Client, HttpFrame::Goaway(id)) => {
                            self.inner.leave(StreamId(id));
                        }
                        (true, Side::Server, HttpFrame::CancelPush(_)) => {
                            println!("CANCEL_PUSH frame ignored");
                        }
                        (true, Side::Server, HttpFrame::MaxPushId(_)) => {
                            println!("MAX_PUSH_ID frame ignored");
                        }
                        (false, Side::Server, HttpFrame::CancelPush(_))
                        | (false, Side::Server, HttpFrame::MaxPushId(_))
                        | (false, Side::Client, HttpFrame::Goaway(_)) => {
                            self.set_error(ErrorCode::MISSING_SETTINGS, "missing settings");
                            return Err(Error::Peer("missing settings".into()));
                        }
                        f => {
                            self.set_error(
                                ErrorCode::FRAME_UNEXPECTED,
                                "unexpected frame type on control stream",
                            );
                            return Err(Error::Peer(format!(
                                "frame {:?} unexpected on control stream",
                                f
                            )));
                        }
                    }
                }
            }
        }
    }

    fn poll_recv_encoder(&mut self, cx: &mut Context) -> Result<(), Error> {
        let (mut recv_encoder, mut buffer) = match self.recv_encoder.as_mut() {
            None => return Ok(()),
            Some((ref mut s, ref mut b)) => (s, b),
        };

        loop {
            let mut read_buf = [0; RECV_ENCODER_INITIAL_CAPACITY];
            match Pin::new(&mut recv_encoder).poll_read(cx, &mut read_buf[..])? {
                Poll::Pending => break,
                Poll::Ready(0) => {
                    self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, "encoder closed");
                    return Err(Error::Peer("encoder stream closed".into()));
                }
                Poll::Ready(n) => {
                    buffer.extend_from_slice(&read_buf[..n]);
                    let (pos, max_received_ref) = {
                        let mut cur = Cursor::new(&mut buffer);
                        let max_received_ref = self.inner.on_recv_encoder(&mut cur)?;
                        (cur.position() as usize, max_received_ref + 1)
                    };

                    buffer.advance(pos);
                    buffer.reserve(buffer.capacity());

                    let blocked = self.blocked_streams.split_off(&max_received_ref);
                    let unblocked = mem::replace(&mut self.blocked_streams, blocked);
                    for (_, waker) in unblocked.into_iter().map(|(_, v)| v).flatten() {
                        waker.wake();
                    }
                }
            }
        }
        Ok(())
    }

    fn poll_recv_decoder(&mut self, cx: &mut Context) -> Result<(), Error> {
        let (mut recv_decoder, mut buffer) = match self.recv_decoder.as_mut() {
            None => return Ok(()),
            Some((ref mut s, ref mut b)) => (s, b),
        };

        loop {
            let mut read_buf = [0; RECV_DECODER_INITIAL_CAPACITY];
            match Pin::new(&mut recv_decoder).poll_read(cx, &mut read_buf[..])? {
                Poll::Pending => break,
                Poll::Ready(0) => {
                    self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, "decoder closed");
                    return Err(Error::Peer("decoder stream closed".into()));
                }
                Poll::Ready(n) => {
                    buffer.extend_from_slice(&read_buf[..n]);
                    let pos = {
                        let mut cur = Cursor::new(&mut buffer);
                        self.inner.on_recv_decoder(&mut cur)?;
                        cur.position() as usize
                    };
                    buffer.advance(pos);
                    buffer.reserve(buffer.capacity());
                }
            }
        }
        Ok(())
    }

    fn poll_send(&mut self, cx: &mut Context) -> Result<(), Error> {
        for ty in PendingStreamType::iter() {
            if let Some(data) = self.inner.pending_stream_take(ty) {
                self.send_unis[ty as usize].push(data);
            }
            match Pin::new(&mut self.send_unis[ty as usize]).poll(cx) {
                Poll::Ready(Err(err)) => {
                    self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, format!("{:?}", err));
                    return Err(err);
                }
                Poll::Ready(Ok(_)) => {
                    self.inner.pending_stream_release(ty);
                }
                Poll::Pending => return Ok(()),
            }
        }
        Ok(())
    }

    fn set_error<T: Into<Bytes>>(&mut self, code: ErrorCode, reason: T) {
        self.quic.close(code.into(), &reason.into());
    }
}
