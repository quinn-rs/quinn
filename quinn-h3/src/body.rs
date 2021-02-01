use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{future, ready, Stream};
use http::HeaderMap;
use http_body::Body as HttpBody;
use quinn_proto::StreamId;

use crate::{
    connection::ConnectionRef,
    frame::FrameStream,
    proto::{
        frame::{HeadersFrame, HttpFrame},
        ErrorCode,
    },
    streams::Reset,
    Error,
};

/// Simple body representation
///
/// It is intended to be constructed from common types such as `&str`, and be passed
/// to [`http::Request<B>`] or [`http::Response<B>`] as the B parameter. It's is intended
/// as a convenient way to send simple and small bodies.
///
/// [`http::Request<B>`]: https://docs.rs/http/*/http/request/index.html
/// [`http::Response<B>`]: https://docs.rs/http/*/http/response/index.html
pub struct Body(pub(crate) Option<Bytes>);

impl From<()> for Body {
    fn from(_: ()) -> Self {
        Body(None)
    }
}

impl From<Bytes> for Body {
    fn from(buf: Bytes) -> Self {
        Body(Some(buf))
    }
}

impl From<&str> for Body {
    fn from(buf: &str) -> Self {
        Body(Some(Bytes::copy_from_slice(buf.as_ref())))
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;
    fn poll_data(
        mut self: Pin<&mut Self>,
        _: &mut Context,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        match self.0.take() {
            Some(b) => Poll::Ready(Some(Ok(b))),
            None => Poll::Ready(None),
        }
    }
    fn poll_trailers(
        self: Pin<&mut Self>,
        _: &mut Context,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
    }
}

/// HTTP/3 body reception stream
///
/// Crate's [`http_body::Body`] implementation. It enables you to read the body and its trailers.
///
/// This is emited as part of a [`Request<RecvBody>`] on the server side and [`Response<RecvBody>`]
/// on client's one.
///
/// Note that body shall be read entirely before polling for trailers.
pub struct RecvBody {
    conn: ConnectionRef,
    stream_id: StreamId,
    recv: FrameStream,
    trailers: Option<HeadersFrame>,
}

impl RecvBody {
    pub(crate) fn new(conn: ConnectionRef, stream_id: StreamId, recv: FrameStream) -> Self {
        Self {
            conn,
            stream_id,
            recv,
            trailers: None,
        }
    }

    /// Convenience method to read the entire body in one call
    pub async fn read_to_end(&mut self) -> Result<Bytes, Error> {
        let mut body = BytesMut::with_capacity(10_240);

        let mut me = self;
        let res: Result<(), Error> = future::poll_fn(|cx| {
            while let Some(d) = ready!(Pin::new(&mut me).poll_data(cx)) {
                body.extend(d?);
            }
            Poll::Ready(Ok(()))
        })
        .await;
        res?;

        Ok(body.freeze())
    }

    /// Read the body chunk by chunk
    ///
    /// This will return the next available chunk if any.
    pub async fn data(&mut self) -> Option<Result<Bytes, Error>> {
        let mut me = self;
        future::poll_fn(|cx| Pin::new(&mut me).poll_data(cx)).await
    }

    /// Receive and decode trailers
    ///
    /// Note: shall not be called before consuming the whole body.
    pub async fn trailers(&mut self) -> Result<Option<HeaderMap>, Error> {
        let mut me = self;
        Ok(future::poll_fn(|cx| Pin::new(&mut me).poll_trailers(cx)).await?)
    }

    /// Cancel a request or response
    ///
    /// The peer will receive a request error with `REQUEST_CANCELLED` code.
    pub fn cancel(&mut self) {
        self.recv.reset(ErrorCode::REQUEST_CANCELLED);
    }

    pub(super) fn into_inner(self) -> FrameStream {
        self.recv
    }
}

impl HttpBody for RecvBody {
    type Data = bytes::Bytes;
    type Error = Error;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        loop {
            return match ready!(Pin::new(&mut self.recv).poll_next(cx)) {
                None => Poll::Ready(None),
                Some(Ok(HttpFrame::Reserved)) => continue,
                Some(Ok(HttpFrame::Data(d))) => Poll::Ready(Some(Ok(d.payload))),
                Some(Ok(HttpFrame::Headers(t))) => {
                    self.trailers = Some(t);
                    Poll::Ready(None)
                }
                Some(Err(e)) => {
                    self.recv.reset(e.code());
                    Poll::Ready(Some(Err(e.into())))
                }
                Some(Ok(f)) => {
                    self.recv.reset(ErrorCode::FRAME_UNEXPECTED);
                    Poll::Ready(Some(Err(Error::Peer(format!(
                        "Invalid frame type in body: {:?}",
                        f
                    )))))
                }
            };
        }
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        if self.trailers.is_none() {
            return Poll::Ready(Ok(None));
        }

        let header = {
            let mut conn = self.conn.h3.lock().unwrap();
            ready!(conn.poll_decode(cx, self.stream_id, self.trailers.as_ref().unwrap()))?
        };
        self.trailers = None;

        Poll::Ready(Ok(Some(header.into_fields())))
    }
}

impl fmt::Debug for RecvBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvBody")
            .field("stream", &self.stream_id)
            .finish()
    }
}
