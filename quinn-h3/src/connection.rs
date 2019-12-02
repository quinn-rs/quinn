use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    future::Future,
    io::{self, Cursor},
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::BytesMut;
use futures::{io::AsyncRead, Stream};
use quinn::{IncomingBiStreams, IncomingUniStreams, RecvStream, SendStream};
use quinn_proto::{Side, StreamId};

use crate::{
    frame::{self, FrameStream},
    proto::{
        self,
        connection::{
            Connection, DecodeResult, Error as ProtoError, Error as ConnectionError,
            PendingStreamType,
        },
        frame::{HeadersFrame, HttpFrame},
        ErrorCode, StreamType,
    },
    streams::{NewUni, RecvUni, SendUni},
    Error, Settings,
};

pub struct ConnectionDriver(pub(crate) ConnectionRef);

impl Future for ConnectionDriver {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let res = self.0.h3.lock().unwrap().drive(cx);
        match res {
            Ok(false) => Poll::Pending,
            Ok(true) => Poll::Ready(Ok(())),
            Err(DriverError(err, code, msg)) => {
                self.0.quic.close(code.into(), msg.as_bytes());
                Poll::Ready(Err(err))
            }
        }
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
                    SendUni::new(StreamType::CONTROL, quic.open_uni()),
                    SendUni::new(StreamType::ENCODER, quic.open_uni()),
                    SendUni::new(StreamType::DECODER, quic.open_uni()),
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
    fn drive(&mut self, cx: &mut Context) -> Result<bool, DriverError> {
        self.poll_incoming_uni(cx)?;
        self.poll_send(cx)?;
        self.poll_recv_control(cx)?;
        self.poll_recv_encoder(cx)?;
        self.poll_recv_decoder(cx)?;
        self.poll_incoming_bi(cx)?;
        self.poll_send(cx)?;

        self.reset_waker(cx);

        Ok(self.inner.is_closing() && self.inner.requests_in_flight() == 0)
    }

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
                    DecodeResult::Decoded(_, true) => self.wake(), // send header acknowledgement
                    DecodeResult::Decoded(_, _) => (),
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

    fn poll_incoming_bi(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        loop {
            match Pin::new(&mut self.incoming_bi).poll_next(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Some(Err(e))) => {
                    return Err(DriverError::new(
                        e,
                        ErrorCode::INTERNAL_ERROR,
                        "incoming bi error",
                    ))
                }
                Poll::Ready(None) => {
                    return Err(DriverError::internal("closed incoming bi"));
                }
                Poll::Ready(Some(Ok((mut send, mut recv)))) => match self.side {
                    Side::Client => {
                        return Err(DriverError::peer(
                            ErrorCode::STREAM_CREATION_ERROR,
                            "client does not accept bidirectional streams",
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

    fn poll_incoming_uni(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        loop {
            match Pin::new(&mut self.incoming_uni).poll_next(cx)? {
                Poll::Pending => break,
                Poll::Ready(None) => return Err(DriverError::internal("closed incoming uni")),
                Poll::Ready(Some(recv)) => self.pending_uni.push_back(Some(RecvUni::new(recv))),
            }
        }

        self.poll_resolve_uni(cx)?;

        Ok(())
    }

    fn poll_resolve_uni(&mut self, cx: &mut Context) -> Result<(), DriverError> {
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

        for (removed, (i, res)) in resolved.into_iter().enumerate() {
            self.pending_uni.remove(i - removed);
            match res {
                Err(Error::UnknownStream(ty)) => {
                    return Err(DriverError::peer(
                        ErrorCode::STREAM_CREATION_ERROR,
                        format!("unknown stream type {}", ty),
                    ))
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    return Err(DriverError::new(e, ErrorCode::STREAM_CREATION_ERROR, msg));
                }
                Ok(n) => self.on_uni_resolved(n)?,
            }
        }
        Ok(())
    }

    fn on_uni_resolved(&mut self, new_stream: NewUni) -> Result<(), DriverError> {
        match new_stream {
            NewUni::Control(stream) => match self.recv_control {
                None => {
                    self.recv_control = Some(stream);
                    Ok(())
                }
                Some(_) => Err(DriverError::peer(
                    ErrorCode::STREAM_CREATION_ERROR,
                    "control stream already open",
                )),
            },
            NewUni::Decoder(s) => match self.recv_decoder {
                None => {
                    self.recv_decoder =
                        Some((s, BytesMut::with_capacity(RECV_DECODER_INITIAL_CAPACITY)));
                    Ok(())
                }
                Some(_) => Err(DriverError::peer(
                    ErrorCode::STREAM_CREATION_ERROR,
                    "decoder stream already open",
                )),
            },
            NewUni::Encoder(s) => match self.recv_encoder {
                None => {
                    self.recv_encoder =
                        Some((s, BytesMut::with_capacity(RECV_ENCODER_INITIAL_CAPACITY)));
                    Ok(())
                }
                Some(_) => Err(DriverError::peer(
                    ErrorCode::STREAM_CREATION_ERROR,
                    "encoder stream already open",
                )),
            },
            NewUni::Push(_) => {
                println!("push stream ignored");
                Ok(())
            }
        }
    }

    fn poll_recv_control(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        let mut control = match self.recv_control.as_mut() {
            None => return Ok(()),
            Some(c) => c,
        };

        loop {
            match Pin::new(&mut control).poll_next(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(None) => {
                    return Err(DriverError::peer(
                        ErrorCode::CLOSED_CRITICAL_STREAM,
                        "control in closed",
                    ));
                }
                Poll::Ready(Some(Err(e))) => {
                    let code = e.code();
                    return Err(DriverError::new(e, code, ""));
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
                            return Err(DriverError::peer(
                                ErrorCode::MISSING_SETTINGS,
                                "missing settings",
                            ));
                        }
                        f => {
                            return Err(DriverError::peer(
                                ErrorCode::FRAME_UNEXPECTED,
                                format!("frame {:?} unexpected on control stream", f),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn poll_recv_encoder(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        let (mut recv_encoder, mut buffer) = match self.recv_encoder.as_mut() {
            None => return Ok(()),
            Some((ref mut s, ref mut b)) => (s, b),
        };

        loop {
            let mut read_buf = [0; RECV_ENCODER_INITIAL_CAPACITY];
            match Pin::new(&mut recv_encoder).poll_read(cx, &mut read_buf[..])? {
                Poll::Pending => break,
                Poll::Ready(0) => {
                    return Err(DriverError::peer(
                        ErrorCode::CLOSED_CRITICAL_STREAM,
                        "encoder closed",
                    ));
                }
                Poll::Ready(n) => {
                    buffer.extend_from_slice(&read_buf[..n]);
                    let (pos, max_received_ref) = {
                        let mut cur = Cursor::new(&mut buffer);
                        let max_received_ref = self.inner.on_recv_encoder(&mut cur)?;
                        (cur.position() as usize, max_received_ref + 1)
                    };

                    buffer.split_to(pos);
                    buffer.reserve(RECV_ENCODER_INITIAL_CAPACITY);

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

    fn poll_recv_decoder(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        let (mut recv_decoder, mut buffer) = match self.recv_decoder.as_mut() {
            None => return Ok(()),
            Some((ref mut s, ref mut b)) => (s, b),
        };

        loop {
            let mut read_buf = [0; RECV_DECODER_INITIAL_CAPACITY];
            match Pin::new(&mut recv_decoder).poll_read(cx, &mut read_buf[..])? {
                Poll::Pending => break,
                Poll::Ready(0) => {
                    return Err(DriverError::peer(
                        ErrorCode::CLOSED_CRITICAL_STREAM,
                        "decoder closed",
                    ));
                }
                Poll::Ready(n) => {
                    buffer.extend_from_slice(&read_buf[..n]);
                    let pos = {
                        let mut cur = Cursor::new(&mut buffer);
                        self.inner.on_recv_decoder(&mut cur)?;
                        cur.position() as usize
                    };
                    buffer.split_to(pos);
                    buffer.reserve(RECV_DECODER_INITIAL_CAPACITY);
                }
            }
        }
        Ok(())
    }

    fn poll_send(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        for ty in PendingStreamType::iter() {
            if let Some(data) = self.inner.pending_stream_take(ty) {
                self.send_unis[ty as usize].push(data);
            }
            match Pin::new(&mut self.send_unis[ty as usize]).poll(cx) {
                Poll::Ready(Err(err)) => {
                    return Err(DriverError::peer(
                        ErrorCode::CLOSED_CRITICAL_STREAM,
                        format!("{:?}", err),
                    ));
                }
                Poll::Ready(Ok(_)) => {
                    self.inner.pending_stream_release(ty);
                }
                Poll::Pending => return Ok(()),
            }
        }
        Ok(())
    }
}

struct DriverError(Error, ErrorCode, String);

impl DriverError {
    fn new<E: Into<Error>, T: Into<String>>(err: E, code: ErrorCode, msg: T) -> Self {
        DriverError(err.into(), code, msg.into())
    }

    fn peer<T: Into<String>>(code: ErrorCode, msg: T) -> Self {
        let msg = msg.into();
        DriverError(Error::Peer(msg.clone()), code, msg)
    }

    fn internal<T: Into<String>>(msg: T) -> Self {
        DriverError::new(
            Error::internal(msg),
            ErrorCode::INTERNAL_ERROR,
            "internal Error",
        )
    }
}

impl From<quinn::ConnectionError> for DriverError {
    fn from(err: quinn::ConnectionError) -> DriverError {
        DriverError::new(Error::Quic(err), ErrorCode::INTERNAL_ERROR, "")
    }
}

impl From<io::Error> for DriverError {
    fn from(err: io::Error) -> DriverError {
        DriverError::new(Error::Io(err), ErrorCode::INTERNAL_ERROR, "")
    }
}

impl From<frame::Error> for DriverError {
    fn from(err: frame::Error) -> DriverError {
        match err {
            frame::Error::Io(e) => e.into(),
            frame::Error::Proto(proto::frame::Error::Malformed) => {
                DriverError::peer(ErrorCode::FRAME_ERROR, "Malformed frame received")
            }
            frame::Error::Proto(proto::frame::Error::UnsupportedFrame) => {
                DriverError::peer(ErrorCode::FRAME_ERROR, "Unsupported frame received")
            }
            frame::Error::Proto(e) => DriverError::internal(format!("frame: {:?}", e)),
        }
    }
}

impl From<ConnectionError> for DriverError {
    fn from(err: ConnectionError) -> DriverError {
        match err {
            ConnectionError::Settings { reason } => {
                DriverError::peer(ErrorCode::SETTINGS_ERROR, reason)
            }
            ConnectionError::EncodeError { reason } => {
                DriverError::peer(ErrorCode::QPACK_DECODER_STREAM_ERROR, format!("{}", reason))
            }
            ConnectionError::DecodeError { reason } => {
                DriverError::peer(ErrorCode::QPACK_ENCODER_STREAM_ERROR, format!("{}", reason))
            }
            // Those are excepted to happen on in Requests / Responses, just return internal error
            ConnectionError::HeaderListTooLarge
            | ConnectionError::InvalidHeaderName(_)
            | ConnectionError::InvalidHeaderValue(_)
            | ConnectionError::InvalidRequest(_)
            | ConnectionError::InvalidResponse(_) => {
                DriverError::internal(format!("unexpected on driver: {:?}", err))
            }
        }
    }
}

const RECV_ENCODER_INITIAL_CAPACITY: usize = 20480;
const RECV_DECODER_INITIAL_CAPACITY: usize = 2048;
