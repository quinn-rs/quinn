use std::{
    error::Error as StdError,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BufMut;
use futures::{future::FutureExt, ready, Stream as _};
use http_body::Body as HttpBody;
use pin_project::pin_project;
use quinn::{SendStream, VarInt};
use quinn_proto::StreamId;

use crate::{
    body::RecvBody,
    connection::ConnectionRef,
    frame::FrameStream,
    proto::{
        frame::{DataFrame, FrameHeader, HeadersFrame, HttpFrame, IntoPayload},
        headers::Header,
        ErrorCode,
    },
    streams::Reset,
    Error, HttpError,
};

/// Represent data transmission completion for a Response
///
/// This is yielded by [`Sender::send_response`]. It will encode and send the
/// headers, then send the body if any data is polled from [`HttpBody::poll_data()`].  It also
/// encodes and sends the trailer a similar way, if any.
///
/// [`Sender::send_response`]: crate::server::Sender::send_response()
#[pin_project(project = SendDataProj)]
pub struct SendData<B, P> {
    headers: Option<Header>,
    #[pin]
    body: B,
    #[pin]
    state: SendDataState<P>,
    conn: ConnectionRef,
    send: SendStream,
    stream_id: StreamId,
    finish: bool,
}

#[pin_project(project = SendDataStateProj)]
enum SendDataState<P> {
    Initial,
    Headers(WriteFrame<HeadersFrame>),
    PollBody,
    Write(WriteFrame<DataFrame<P>>),
    PollTrailers,
    Trailers(WriteFrame<HeadersFrame>),
    Closing,
    Finished,
}

impl<B> SendData<B, B::Data>
where
    B: HttpBody + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
{
    pub(crate) fn new(
        send: SendStream,
        conn: ConnectionRef,
        headers: Header,
        body: B,
        finish: bool,
    ) -> Self {
        Self {
            conn,
            body,
            finish,
            headers: Some(headers),
            stream_id: send.id(),
            send,
            state: SendDataState::Initial,
        }
    }

    /// Cancel the request
    ///
    /// The peer will receive a request error with `REQUEST_CANCELLED` code.
    pub fn cancel(&mut self) {
        let _ = self.send.reset(ErrorCode::REQUEST_CANCELLED.into());
        self.state = SendDataState::Finished;
    }

    /// Monitor stop sending signal from the peer
    ///
    /// This will return `Ready` when a STOP_SENDING frame from the peer has
    /// been received for this stream. Else, it will return `Pending` indefinitely.
    pub fn poll_stopped(&mut self, cx: &mut Context) -> Poll<Result<HttpError, Error>> {
        Poll::Ready(Ok(ready!(self.send.poll_stopped(cx)?).into()))
    }
}

impl<B> Future for SendData<B, B::Data>
where
    B: HttpBody + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
{
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            match &mut me.state.as_mut().project() {
                SendDataStateProj::Initial => {
                    // This initial computation is done here to report its failability to Future::Output.
                    let header = me.headers.take().expect("headers");
                    let write = write_headers_frame(header, *me.stream_id, &me.conn)?;
                    me.state.set(SendDataState::Headers(write));
                }
                SendDataStateProj::Headers(headers) => {
                    ready!(headers.poll_send(&mut *me.send, cx))?;
                    me.state.set(SendDataState::PollBody);
                }
                SendDataStateProj::PollBody => {
                    let next = match ready!(Pin::new(&mut me.body).poll_data(cx)) {
                        None => SendDataState::PollTrailers,
                        Some(Err(e)) => return Poll::Ready(Err(Error::body(e.into()))),
                        Some(Ok(d)) => {
                            SendDataState::Write(WriteFrame::new(DataFrame { payload: d }))
                        }
                    };
                    me.state.set(next);
                }
                SendDataStateProj::Write(write) => {
                    ready!(write.poll_send(&mut *me.send, cx))?;
                    me.state.set(SendDataState::PollBody);
                }
                SendDataStateProj::PollTrailers => {
                    match ready!(Pin::new(&mut me.body).poll_trailers(cx))
                        .map_err(|_| todo!())
                        .unwrap()
                    {
                        None => me.state.set(SendDataState::Closing),
                        Some(h) => {
                            let header = Header::trailer(h);
                            let write = write_headers_frame(header, *me.stream_id, &me.conn)?;
                            me.state.set(SendDataState::Trailers(write));
                        }
                    }
                }
                SendDataStateProj::Trailers(trailers) => {
                    ready!(trailers.poll_send(&mut *me.send, cx))?;
                    me.state.set(SendDataState::Closing);
                }
                SendDataStateProj::Closing => {
                    ready!(Pin::new(me.send).poll_finish(cx))?;
                    if *me.finish {
                        let mut conn = me.conn.h3.lock().unwrap();
                        conn.inner.remote_stream_finished(*me.stream_id);
                        conn.wake();
                    }
                    return Poll::Ready(Ok(()));
                }
                SendDataStateProj::Finished => return Poll::Ready(Ok(())),
            };
        }
    }
}

pub(crate) fn write_headers_frame(
    header: Header,
    stream: StreamId,
    conn: &ConnectionRef,
) -> Result<WriteFrame<HeadersFrame>, Error> {
    let conn = &mut conn.h3.lock().unwrap();
    let frame = conn.inner.encode_header(stream, header)?;
    conn.wake();

    Ok(WriteFrame::new(frame))
}

pub(crate) struct WriteFrame<F> {
    state: WriteFrameState,
    frame: F,
    header: [u8; VarInt::MAX_SIZE * 2],
    header_len: usize,
}

enum WriteFrameState {
    Header(usize),
    Payload,
    Finished,
}

impl<F> WriteFrame<F>
where
    F: FrameHeader + IntoPayload,
{
    pub(crate) fn new(frame: F) -> Self {
        let mut buf = [0u8; VarInt::MAX_SIZE * 2];
        let remaining = {
            let mut cur = &mut buf[..];
            frame.encode_header(&mut cur);
            cur.remaining_mut()
        };

        Self {
            frame,
            state: WriteFrameState::Header(0),
            header: buf,
            header_len: buf.len() - remaining,
        }
    }

    pub(crate) fn poll_send(
        &mut self,
        send: &mut SendStream,
        cx: &mut Context,
    ) -> Poll<Result<(), quinn::WriteError>> {
        loop {
            match self.state {
                WriteFrameState::Finished => panic!("polled after finish"),
                WriteFrameState::Header(mut start) => {
                    let wrote = ready!(send
                        .write(&self.header[start..self.header_len])
                        .poll_unpin(cx)?);
                    start += wrote;

                    if start < self.header_len {
                        self.state = WriteFrameState::Header(start);
                        continue;
                    }
                    self.state = WriteFrameState::Payload;
                }
                WriteFrameState::Payload => {
                    let p = self.frame.into_payload();
                    match ready!(send.write(p.chunk()).poll_unpin(cx)) {
                        Err(e) => return Poll::Ready(Err(e)),
                        Ok(wrote) => {
                            p.advance(wrote);
                            if p.has_remaining() {
                                continue;
                            }
                        }
                    }

                    self.state = WriteFrameState::Finished;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

pub struct RecvData {
    state: RecvDataState,
    conn: ConnectionRef,
    recv: Option<FrameStream>,
    stream_id: StreamId,
}

enum RecvDataState {
    Receiving,
    Decoding(DecodeHeaders),
    Finished,
}

impl RecvData {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        Self {
            conn,
            stream_id,
            recv: Some(recv),
            state: RecvDataState::Receiving,
        }
    }

    pub fn reset(&mut self, err_code: ErrorCode) {
        if let Some(ref mut r) = self.recv {
            r.reset(err_code);
        }
    }
}

impl Future for RecvData {
    type Output = Result<(Header, RecvBody), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                RecvDataState::Receiving => {
                    match ready!(Pin::new(self.recv.as_mut().unwrap()).poll_next(cx)) {
                        Some(Ok(HttpFrame::Reserved)) => continue,
                        Some(Ok(HttpFrame::Headers(h))) => {
                            self.state = RecvDataState::Decoding(DecodeHeaders::new(
                                h,
                                self.conn.clone(),
                                self.stream_id,
                            ));
                        }
                        Some(Err(e)) => {
                            self.recv.as_mut().unwrap().reset(e.code());
                            return Poll::Ready(Err(e.into()));
                        }
                        Some(Ok(f)) => {
                            self.recv
                                .as_mut()
                                .unwrap()
                                .reset(ErrorCode::FRAME_UNEXPECTED);
                            return Poll::Ready(Err(Error::Peer(format!(
                                "First frame is not headers: {:?}",
                                f
                            ))));
                        }
                        None => {
                            return Poll::Ready(Err(Error::peer("Stream end unexpected")));
                        }
                    };
                }
                RecvDataState::Decoding(ref mut decode) => {
                    let headers = ready!(Pin::new(decode).poll(cx))?;
                    let recv =
                        RecvBody::new(self.conn.clone(), self.stream_id, self.recv.take().unwrap());
                    self.state = RecvDataState::Finished;
                    return Poll::Ready(Ok((headers, recv)));
                }
                RecvDataState::Finished => panic!("polled after finished"),
            }
        }
    }
}

pub struct DecodeHeaders {
    frame: Option<HeadersFrame>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl DecodeHeaders {
    pub(crate) fn new(frame: HeadersFrame, conn: ConnectionRef, stream_id: StreamId) -> Self {
        Self {
            conn,
            stream_id,
            frame: Some(frame),
        }
    }
}

impl Future for DecodeHeaders {
    type Output = Result<Header, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.frame {
            None => Poll::Ready(Err(crate::Error::internal("frame none"))),
            Some(ref frame) => {
                let mut conn = self.conn.h3.lock().unwrap();
                conn.poll_decode(cx, self.stream_id, frame)
            }
        }
    }
}
