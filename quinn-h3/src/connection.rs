use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};

use bytes::Bytes;
use futures::{Future, Poll, Stream};
use quinn::{IncomingBiStreams, IncomingUniStreams, RecvStream, SendStream};
use quinn_proto::Side;

use crate::{
    frame::FrameStream,
    proto::{
        connection::{Connection, Error as ProtoError},
        frame::HttpFrame,
    },
    streams::{NewUni, RecvUni, SendControlStream},
    Error, ErrorCode, Settings,
};

pub struct ConnectionDriver {
    conn: ConnectionRef,
    side: Side,
    incoming_bi: IncomingBiStreams,
    incoming_uni: IncomingUniStreams,
    pending_uni: VecDeque<Option<RecvUni>>,
    control: Option<FrameStream>,
    send_control: SendControlStream,
}

impl ConnectionDriver {
    pub(crate) fn new_client(
        conn: ConnectionRef,
        incoming_uni: IncomingUniStreams,
        incoming_bi: IncomingBiStreams,
    ) -> Self {
        Self {
            pending_uni: VecDeque::with_capacity(10),
            send_control: SendControlStream::new(conn.clone()),
            side: Side::Client,
            control: None,
            conn,
            incoming_uni,
            incoming_bi,
        }
    }

    pub(crate) fn new_server(
        conn: ConnectionRef,
        incoming_uni: IncomingUniStreams,
        incoming_bi: IncomingBiStreams,
    ) -> Self {
        Self {
            pending_uni: VecDeque::with_capacity(10),
            send_control: SendControlStream::new(conn.clone()),
            side: Side::Server,
            control: None,
            conn,
            incoming_uni,
            incoming_bi,
        }
    }

    fn set_error<T: Into<Bytes>>(&mut self, code: ErrorCode, reason: T) {
        self.conn.quic.close(code.into(), &reason.into());
    }

    fn poll_pending_uni(&mut self, cx: &mut Context) {
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

        for (i, res) in resolved {
            self.pending_uni.remove(i);
            match res {
                Err(Error::UnknownStream(ty)) => println!("unknown stream type {}", ty),
                Err(e) => {
                    self.set_error(ErrorCode::STREAM_CREATION_ERROR, format!("{:?}", e));
                }
                Ok(n) => match n {
                    NewUni::Control(stream) => match self.control {
                        None => self.control = Some(stream),
                        Some(_) => {
                            self.set_error(
                                ErrorCode::STREAM_CREATION_ERROR,
                                "control stream already open",
                            );
                        }
                    },
                    NewUni::Decoder(_) => println!("decoder stream ignored"),
                    NewUni::Encoder(_) => println!("encoder stream ignored"),
                    NewUni::Push(_) => println!("push stream ignored"),
                },
            }
        }
    }

    fn poll_control(&mut self, cx: &mut Context) {
        let mut control = match self.control.as_mut() {
            None => return,
            Some(c) => c,
        };

        match Pin::new(&mut control).poll_next(cx) {
            Poll::Ready(None) => {
                self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, "control closed")
            }
            Poll::Ready(Some(Err(e))) => {
                let (code, msg) = e.into();
                self.set_error(code, msg)
            }
            Poll::Ready(Some(Ok(frame))) => {
                let conn = &mut self.conn.h3;
                let has_remote_settings = conn.lock().unwrap().inner.remote_settings().is_some();

                match (has_remote_settings, self.side, frame) {
                    (_, _, HttpFrame::Settings(s)) => {
                        conn.lock().unwrap().inner.set_remote_settings(s);
                    }
                    (true, Side::Client, HttpFrame::Goaway(_)) => println!("GOAWAY frame ignored"),
                    (true, Side::Server, HttpFrame::CancelPush(_)) => {
                        println!("CANCEL_PUSH frame ignored")
                    }
                    (true, Side::Server, HttpFrame::MaxPushId(_)) => {
                        println!("MAX_PUSH_ID frame ignored")
                    }
                    (false, Side::Server, HttpFrame::CancelPush(_))
                    | (false, Side::Server, HttpFrame::MaxPushId(_))
                    | (false, Side::Client, HttpFrame::Goaway(_)) => {
                        self.set_error(ErrorCode::MISSING_SETTINGS, "missing settings")
                    }
                    _ => self.set_error(
                        ErrorCode::FRAME_UNEXPECTED,
                        "unexpected frame type on control stream",
                    ),
                }
            }
            Poll::Pending => (),
        }
    }
}

impl Future for ConnectionDriver {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Poll::Ready(Err(_err)) = Pin::new(&mut self.send_control).poll(cx) {
            self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, "control stream closed");
        }

        if let Poll::Ready(Some(recv)) = Pin::new(&mut self.incoming_uni).poll_next(cx)? {
            self.pending_uni.push_back(Some(RecvUni::new(recv)));
        }

        self.poll_pending_uni(cx);
        self.poll_control(cx);

        if let Poll::Ready(Some((mut send, mut recv))) =
            Pin::new(&mut self.incoming_bi).poll_next(cx)?
        {
            match self.side {
                Side::Client => self.set_error(
                    ErrorCode::STREAM_CREATION_ERROR,
                    "client does not accept bidirectional streams",
                ),
                Side::Server => {
                    let mut conn = self.conn.h3.lock().unwrap();
                    conn.requests.push_back((send, recv));
                    if let Some(t) = conn.requests_task.take() {
                        t.wake();
                    conn.inner.request_initiated(send.id());
                    }
                }
            }
        }

        Poll::Pending
    }
}

pub(crate) struct ConnectionInner {
    pub inner: Connection,
    pub requests: VecDeque<(SendStream, RecvStream)>,
    pub requests_task: Option<Waker>,
}

#[derive(Clone)]
pub(crate) struct ConnectionRef {
    pub h3: Arc<Mutex<ConnectionInner>>,
    pub quic: quinn::Connection,
}

impl ConnectionRef {
    pub fn new(quic: quinn::Connection, settings: Settings) -> Result<Self, ProtoError> {
        Ok(Self {
            h3: Arc::new(Mutex::new(ConnectionInner {
                inner: Connection::with_settings(settings)?,
                requests: VecDeque::with_capacity(16),
                requests_task: None,
            })),
            quic,
        })
    }
}
