use crate::streams::SendUni;
use quinn_proto::StreamId;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Waker},
};

use bytes::Bytes;
use futures::{Future, Poll, Stream};
use quinn::{IncomingBiStreams, IncomingUniStreams, RecvStream, SendStream};
use quinn_proto::Side;

use crate::{
    frame::FrameStream,
    proto::{
        connection::{Connection, Error as ProtoError, PendingStreamType},
        frame::HttpFrame,
        ErrorCode, StreamType,
    },
    streams::{NewUni, RecvUni},
    Error, Settings,
};

pub struct ConnectionDriver(pub(crate) ConnectionRef);

impl Future for ConnectionDriver {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut conn = self.0.h3.lock().unwrap();

        conn.poll_incoming_uni(cx)?;
        conn.poll_send(cx)?;
        conn.poll_recv_control(cx)?;
        conn.poll_incoming_bi(cx)?;

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
                quic: quic.clone(),
                incoming_bi: bi_streams,
                incoming_uni: uni_streams,
                pending_uni: VecDeque::with_capacity(3),
                inner: Connection::with_settings(settings)?,
                requests: VecDeque::with_capacity(16),
                requests_task: None,
                recv_control: None,
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
    quic: quinn::Connection,
    incoming_bi: IncomingBiStreams,
    incoming_uni: IncomingUniStreams,
    pending_uni: VecDeque<Option<RecvUni>>,
    recv_control: Option<FrameStream>,
    send_unis: [SendUni; 3],
}

impl ConnectionInner {
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

        self.poll_resolve_uni(cx);

        Ok(())
    }

    fn poll_resolve_uni(&mut self, cx: &mut Context) {
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
                }
                Ok(n) => match n {
                    NewUni::Control(stream) => match self.recv_control {
                        None => self.recv_control = Some(stream),
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
                            self.inner.set_remote_settings(s);
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
