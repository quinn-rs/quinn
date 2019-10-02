use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};

use futures::{Future, Poll, Stream};
use quinn::{IncomingBiStreams, IncomingUniStreams, RecvStream, SendStream};

use crate::{
    frame::FrameStream,
    proto::connection::{Connection, Error as ProtoError},
    streams::{NewUni, RecvUni},
    Error, ErrorCode, Settings,
};

pub struct ConnectionDriver {
    conn: ConnectionRef,
    incoming_bi: Option<IncomingBiStreams>,
    incoming_uni: IncomingUniStreams,
    pending_uni: VecDeque<Option<RecvUni>>,
    control: Option<FrameStream>,
    error: Option<(ErrorCode, String)>,
}

impl ConnectionDriver {
    pub(crate) fn new_client(
        conn: ConnectionRef,
        incoming_uni: IncomingUniStreams,
    ) -> Self {
        Self {
            pending_uni: VecDeque::with_capacity(10),
            incoming_bi: None,
            control: None,
            error: None,
            conn,
            incoming_uni,
        }
    }

    pub(crate) fn new_server(
        conn: ConnectionRef,
        incoming_uni: IncomingUniStreams,
        incoming_bi: IncomingBiStreams,
    ) -> Self {
        Self {
            pending_uni: VecDeque::with_capacity(10),
            incoming_bi: Some(incoming_bi),
            control: None,
            error: None,
            conn,
            incoming_uni,
        }
    }

    fn set_error(&mut self, code: ErrorCode, msg: String) {
        self.error = Some((code, msg.into()));
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
                                "control stream already open".into(),
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
                self.set_error(ErrorCode::CLOSED_CRITICAL_STREAM, "control closed".into())
            }
            Poll::Ready(Some(Err(e))) => {
                let (code, msg) = e.into();
                self.set_error(code, msg)
            }
            Poll::Ready(Some(Ok(frame))) => {
                let conn = &mut self.conn.h3;
                let has_remote_settings = conn.lock().unwrap().inner.remote_settings().is_some();

                match (has_remote_settings, frame) {
                    (_, HttpFrame::Settings(s)) => {
                        conn.lock().unwrap().inner.set_remote_settings(s);
                    }
                    (true, HttpFrame::Goaway(_)) => println!("GOAWAY frame ignored"),
                    (true, HttpFrame::CancelPush(_)) => println!("CANCEL_PUSH frame ignored"),
                    (true, HttpFrame::MaxPushId(_)) => println!("MAX_PUSH_ID frame ignored"),
                    (_, frame) => match frame {
                        HttpFrame::CancelPush(_)
                        | HttpFrame::Goaway(_)
                        | HttpFrame::MaxPushId(_) => {
                            self.set_error(ErrorCode::MISSING_SETTINGS, "missing settings".into())
                        }
                        _ => self.set_error(
                            ErrorCode::FRAME_UNEXPECTED,
                            "unexpected frame type on control stream".into(),
                        ),
                    },
                }
            }
            Poll::Pending => (),
        }
    }
}

impl Future for ConnectionDriver {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Poll::Ready(Some(recv)) = Pin::new(&mut self.incoming_uni).poll_next(cx)? {
            self.pending_uni.push_back(Some(RecvUni::new(recv)));
        }

        if let Some(ref mut incoming_bi) = self.incoming_bi {
            if let Poll::Ready(Some((send, recv))) = Pin::new(incoming_bi).poll_next(cx)? {
                let mut conn = self.conn.h3.lock().unwrap();
                conn.requests.push_back((send, recv));
                if let Some(t) = conn.requests_task.take() {
                    t.wake();
                }
            }
        }

        self.poll_pending_uni(cx);

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
