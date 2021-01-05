use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    future::Future,
    io, mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BytesMut};
use futures::{io::AsyncRead, Stream};
use quinn::{IncomingBiStreams, IncomingUniStreams, RecvStream, SendStream};
use quinn_proto::{
    ConnectionClose, ConnectionError as QuicConnError, Side, StreamId, TransportErrorCode,
};
use tracing::{error, trace, trace_span, warn};

use crate::{
    frame::{self, FrameStream},
    proto::{
        self,
        connection::{Connection, DecodeResult, Error as ConnectionError, PendingStreamType},
        frame::{HeadersFrame, HttpFrame},
        headers::Header,
        settings::Error as SettingsError,
        ErrorCode, StreamType,
    },
    streams::{NewUni, RecvUni, SendUni},
    Error, Settings,
};

pub(crate) struct ConnectionDriver(pub(crate) ConnectionRef);

impl Future for ConnectionDriver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut conn = self.0.h3.lock().unwrap();
        match conn.drive(cx) {
            Ok(DriveState::Running) => Poll::Pending,
            Ok(DriveState::Closed) => {
                conn.terminate();
                Poll::Ready(())
            }
            Err(DriverError(err, code, msg)) => {
                match err.try_into_quic() {
                    // Send CONNECTION_CLOSE and log only if it's pertinent:
                    //   - Any Quic ConnectionError should have already closed the connection.
                    //   - Local close, or no error doesn't need to be logged.
                    //   - All other errors need logging and closing the underlying connection.
                    Some(QuicConnError::LocallyClosed)
                    | Some(QuicConnError::ApplicationClosed { .. })
                    | Some(QuicConnError::ConnectionClosed(ConnectionClose {
                        error_code: TransportErrorCode::NO_ERROR,
                        ..
                    })) => (),
                    Some(_) => error!("driver error: {}", err),
                    None => {
                        error!("driver error: {}", err);
                        self.0.quic.close(code.into(), msg.as_bytes());
                    }
                }
                conn.terminate();
                Poll::Ready(())
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
    ) -> Self {
        Self {
            quic: quic.clone(),
            h3: Arc::new(Mutex::new(ConnectionInner {
                side,
                driver: None,
                incoming_bi: bi_streams,
                incoming_uni: uni_streams,
                pending_uni: VecDeque::with_capacity(3),
                inner: Connection::new(side, settings),
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
                closed: false,
            })),
        }
    }
}

enum DriveState {
    Closed,
    Running,
}

pub(crate) struct ConnectionInner {
    pub inner: Connection,
    requests: VecDeque<(SendStream, RecvStream)>,
    requests_task: Option<Waker>,
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
    closed: bool,
}

impl ConnectionInner {
    fn drive(&mut self, cx: &mut Context) -> Result<DriveState, DriverError> {
        self.poll_incoming_uni(cx)?;
        self.poll_send(cx)?;
        self.poll_recv_control(cx)?;
        self.poll_recv_encoder(cx)?;
        self.poll_recv_decoder(cx)?;
        self.poll_incoming_bi(cx)?;
        self.poll_send(cx)?;

        self.reset_waker(cx);

        Ok(match self.inner.shutdown_complete() {
            true => DriveState::Closed,
            false => DriveState::Running,
        })
    }

    pub fn next_request(
        &mut self,
        cx: &mut Context,
    ) -> Result<Option<(SendStream, RecvStream)>, ()> {
        if self.closed {
            return Err(());
        }
        match self.requests.pop_front() {
            Some(x) => Ok(Some(x)),
            None => {
                self.requests_task = Some(cx.waker().clone());
                Ok(None)
            }
        }
    }

    pub fn cancel_request(&mut self, stream_id: StreamId) {
        self.inner.stream_cancel(stream_id);
        self.wake();
    }

    pub fn terminate(&mut self) {
        self.closed = true;

        if let Some(t) = self.requests_task.take() {
            t.wake();
        }

        let requests = mem::replace(&mut self.blocked_streams, BTreeMap::new());
        for (_, waker) in requests.into_iter().map(|(_, v)| v).flatten() {
            waker.wake();
        }
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

    pub fn poll_decode(
        &mut self,
        cx: &mut Context,
        stream_id: StreamId,
        header: &HeadersFrame,
    ) -> Poll<Result<Header, Error>> {
        let res = self
            .inner
            .decode_header(stream_id, header)
            .map_err(|e| Error::peer(format!("decoding header failed: {:?}", e)))?;
        match res {
            DecodeResult::Decoded(h, had_refs) => {
                if had_refs {
                    self.wake(); // send header acknowledgement
                }
                Poll::Ready(Ok(h))
            }
            DecodeResult::MissingRefs(required_ref) => {
                self.blocked_streams
                    .entry(required_ref)
                    .or_insert_with(HashMap::new)
                    .entry(stream_id)
                    .or_insert_with(|| cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_incoming_bi(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        loop {
            match Pin::new(&mut self.incoming_bi).poll_next(cx) {
                Poll::Pending | Poll::Ready(None) => return Ok(()),
                Poll::Ready(Some(Err(e))) => {
                    return Err(DriverError::new(
                        e,
                        ErrorCode::INTERNAL_ERROR,
                        "incoming bi error",
                    ))
                }
                Poll::Ready(Some(Ok((mut send, mut recv)))) => match self.side {
                    Side::Client => {
                        return Err(DriverError::peer(
                            ErrorCode::STREAM_CREATION_ERROR,
                            "client does not accept bidirectional streams",
                        ));
                    }
                    Side::Server => match self.inner.remote_stream_initiated(send.id()) {
                        Err(_) => {
                            let _ = send.reset(ErrorCode::REQUEST_REJECTED.into());
                            let _ = recv.stop(ErrorCode::REQUEST_REJECTED.into());
                        }
                        _ => {
                            self.requests.push_back((send, recv));
                            if let Some(t) = self.requests_task.take() {
                                t.wake();
                            }
                        }
                    },
                },
            }
        }
    }

    fn poll_incoming_uni(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        loop {
            match Pin::new(&mut self.incoming_uni).poll_next(cx)? {
                Poll::Pending => break,
                Poll::Ready(None) => return Ok(()),
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
            .filter_map(|(i, x)| match Pin::new(x.as_mut().unwrap()).poll(cx) {
                Poll::Ready(y) => {
                    *x = None;
                    Some((i, y))
                }
                Poll::Pending => None,
            })
            .collect();

        for (removed, (i, res)) in resolved.into_iter().enumerate() {
            self.pending_uni.remove(i - removed);
            match res {
                Err(Error::UnknownStream(ty)) => {
                    trace!("unknown stream type {}", ty);
                }
                Err(e) => {
                    let msg = format!("{:?}", e);
                    return Err(DriverError::new(e, ErrorCode::STREAM_CREATION_ERROR, msg));
                }
                Ok(n) => self.on_uni_resolved(cx, n)?,
            }
        }
        Ok(())
    }

    fn on_uni_resolved(&mut self, cx: &mut Context, new_stream: NewUni) -> Result<(), DriverError> {
        match new_stream {
            NewUni::Control(stream) => match self.recv_control {
                None => {
                    trace!("Got Control stream");
                    self.recv_control = Some(stream);
                    self.poll_recv_control(cx)?;
                    Ok(())
                }
                Some(_) => Err(DriverError::peer(
                    ErrorCode::STREAM_CREATION_ERROR,
                    "control stream already open",
                )),
            },
            NewUni::Decoder(s) => match self.recv_decoder {
                None => {
                    trace!("Got Decoder stream");
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
                    trace!("Got Encoder stream");
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
                warn!("push stream ignored");
                Ok(())
            }
            NewUni::Reserved => Ok(()),
        }
    }

    fn poll_recv_control(&mut self, cx: &mut Context) -> Result<(), DriverError> {
        let mut control = match self.recv_control.as_mut() {
            None => return Ok(()),
            Some(c) => c,
        };

        let span = trace_span!("control stream");
        let _guard = span.enter();

        loop {
            match Pin::new(&mut control).poll_next(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(None) => {
                    return Err(DriverError::peer(
                        ErrorCode::CLOSED_CRITICAL_STREAM,
                        "control stream closed",
                    ));
                }
                Poll::Ready(Some(Err(e))) => {
                    let code = e.code();
                    return Err(DriverError::new(e, code, ""));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    match (self.inner.remote_settings().is_some(), self.side, frame) {
                        (_, _, HttpFrame::Settings(s)) => {
                            trace!("Got Settings: {:#?}", s);
                            self.inner.set_remote_settings(Settings::from_frame(s)?)?;
                        }
                        (true, _, HttpFrame::Goaway(id)) => {
                            trace!("Got Goaway({:?})", id);
                            self.inner.leave(StreamId(id));
                        }
                        (true, Side::Server, HttpFrame::CancelPush(_)) => {
                            warn!("CANCEL_PUSH frame ignored");
                        }
                        (true, Side::Server, HttpFrame::MaxPushId(_)) => {
                            warn!("MAX_PUSH_ID frame ignored");
                        }
                        (true, _, HttpFrame::Reserved) => (),
                        (false, Side::Server, HttpFrame::CancelPush(_))
                        | (false, Side::Server, HttpFrame::MaxPushId(_))
                        | (false, _, HttpFrame::Reserved)
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

        let span = trace_span!("encoder stream");
        let _guard = span.enter();

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
                    let start = buffer.remaining();
                    let max_received_ref = self.inner.on_recv_encoder(&mut buffer)? + 1;
                    let end = buffer.remaining();
                    buffer.reserve(RECV_ENCODER_INITIAL_CAPACITY);
                    trace!(
                        "decoded {} bytes, buf capacity: {}",
                        start - end,
                        buffer.capacity()
                    );

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

        let span = trace_span!("decoder stream");
        let _guard = span.enter();

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
                    let start = buffer.remaining();
                    self.inner.on_recv_decoder(&mut buffer)?;
                    let end = buffer.remaining();
                    buffer.reserve(RECV_DECODER_INITIAL_CAPACITY);
                    trace!(
                        "decoded {} bytes, buf capacity: {}",
                        start - end,
                        buffer.capacity()
                    );
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
                    return Err(DriverError(
                        err,
                        ErrorCode::CLOSED_CRITICAL_STREAM,
                        "".into(),
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
            frame::Error::Proto(proto::frame::Error::UnsupportedFrame(t)) => DriverError::peer(
                ErrorCode::FRAME_ERROR,
                format!("Unsupported frame received: {:x}", t),
            ),
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
            ConnectionError::Aborted
            | ConnectionError::HeaderListTooLarge
            | ConnectionError::InvalidHeaderName(_)
            | ConnectionError::InvalidHeaderValue(_)
            | ConnectionError::InvalidRequest(_)
            | ConnectionError::InvalidResponse(_) => {
                DriverError::internal(format!("unexpected on driver: {:?}", err))
            }
        }
    }
}

impl From<SettingsError> for DriverError {
    fn from(e: SettingsError) -> Self {
        match e {
            SettingsError::Exceeded => DriverError::peer(
                ErrorCode::SETTINGS_ERROR,
                "Received too much settings entries",
            ),
            SettingsError::InvalidSettingId(id) => DriverError::peer(
                ErrorCode::SETTINGS_ERROR,
                format!("0x{:x}: unknown setting ID", id),
            ),
            SettingsError::InvalidSettingValue(id, val) => DriverError::peer(
                ErrorCode::SETTINGS_ERROR,
                format!("{}: invalid value for setting {:?}", val, id),
            ),
            SettingsError::Repeated(id) => DriverError::peer(
                ErrorCode::SETTINGS_ERROR,
                format!("{:?}: setting repeated in frame", id),
            ),
            SettingsError::Malformed => {
                DriverError::peer(ErrorCode::FRAME_ERROR, "Malformed frame received")
            }
        }
    }
}

const RECV_ENCODER_INITIAL_CAPACITY: usize = 20480;
const RECV_DECODER_INITIAL_CAPACITY: usize = 2048;
