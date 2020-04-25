use std::{
    cmp,
    io::{self, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{io::AsyncRead, stream::Stream};
use http::HeaderMap;
use http_body::Body as HttpBody;
use quinn_proto::StreamId;

use crate::{
    connection::ConnectionRef,
    frame::FrameStream,
    headers::DecodeHeaders,
    proto::{
        frame::{HeadersFrame, HttpFrame},
        headers::Header,
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

/// Read the body of a request or response
///
/// This lets you stream a received body through [`AsyncRead`]. You can also use [`data()`] for
/// a less composable, but more efficient way to receive the body.
///
/// It it emitted by [`client::RecvResponse`] and [`server::RecvRequest`] futures.
///
/// This object manages the request nominal termination when originated from [`client::RecvResponse`].
/// You must be careful not to drop it until your client app is done with this request.
///
/// [`AsyncRead`]: https://docs.rs/futures/*/futures/io/trait.AsyncRead.html
/// [`data()`]: #method.data
/// [`client::RecvResponse`]: client/struct.RecvResponse.html
/// [`server::RecvRequest`]: server/struct.RecvRequest.html
pub struct BodyReader {
    recv: Option<FrameStream>,
    trailers: Option<HeadersFrame>,
    conn: ConnectionRef,
    stream_id: StreamId,
    buf: Option<Bytes>,
    finish_request: bool,
}

impl BodyReader {
    pub(crate) fn new(
        recv: FrameStream,
        conn: ConnectionRef,
        stream_id: StreamId,
        finish_request: bool,
    ) -> Self {
        BodyReader {
            conn,
            stream_id,
            finish_request,
            buf: None,
            trailers: None,
            recv: Some(recv),
        }
    }

    /// Receive a chunk of data
    ///
    /// This method is the fastest way of receiving a body's data, as it returns references to the
    /// underlying QUIC reordered data directly. [`AsyncRead`] has an internal buffer and works
    /// by copying it into the user's buffers, which can represent unwanted overhead for some
    /// applications.
    ///
    /// ```
    /// # use anyhow::Result;
    /// # use bytes::Bytes;
    /// # fn do_stuff(bytes: &Bytes) {}
    /// use quinn_h3::BodyReader;
    ///
    /// async fn consume_body(body_reader: &mut BodyReader) -> Result<()> {
    ///     while let Some(result) = body_reader.data().await {
    ///        do_stuff(&result?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`AsyncRead`]: https://docs.rs/futures/*/futures/io/trait.AsyncRead.html
    pub async fn data(&mut self) -> Option<Result<Bytes, Error>> {
        futures_util::future::poll_fn(move |cx| self.poll_read(cx)).await
    }

    /// Try to receive the trailers
    ///
    /// If a trailer block has been received after the body, this method will decode it and
    /// return `Some()`. This value is populated by reading methods: [`data()`] and
    /// `AsyncRead::poll_read()`. So this returns `None` when the body has not been completely
    /// consumed with either of them.
    ///
    /// ```
    /// # use anyhow::Result;
    /// # use bytes::Bytes;
    /// # fn do_stuff(bytes: &Bytes) {}
    /// use futures::AsyncReadExt;
    /// use quinn_h3::BodyReader;
    ///
    /// async fn get_trailers(body_reader: &mut BodyReader) -> Result<()> {
    ///     // Consume the body to the end
    ///     let mut body = String::new();
    ///     body_reader.read_to_string(&mut body).await?;
    ///
    ///     // Get the trailers if any
    ///     if let Some(trailers) = body_reader.trailers().await {
    ///         println!("trailers: {:?}", trailers?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`data()`]: #method.data
    pub async fn trailers(&mut self) -> Option<Result<Header, Error>> {
        let trailers = self.trailers.take();
        let Self {
            conn, stream_id, ..
        } = &self;
        match trailers {
            None => None,
            Some(t) => Some(DecodeHeaders::new(t, conn.clone(), *stream_id).await),
        }
    }

    /// Cancel the request or response associated with this body
    ///
    /// The peer will receive a request error with `REQUEST_CANCELLED` code.
    pub fn cancel(mut self) {
        if let Some(mut recv) = self.recv.take() {
            recv.reset(ErrorCode::REQUEST_CANCELLED);
        }
    }

    #[doc(hidden)]
    pub fn poll_read(&mut self, cx: &mut Context) -> Poll<Option<Result<Bytes, Error>>> {
        if let Some(data) = self.buf.take() {
            return Poll::Ready(Some(Ok(data))); // return buffered data in case user called AsyncRead before
        }

        loop {
            return match Pin::new(self.recv.as_mut().unwrap()).poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(Ok(HttpFrame::Reserved))) => continue,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Ok(HttpFrame::Data(d)))) => Poll::Ready(Some(Ok(d.payload))),
                Poll::Ready(Some(Ok(HttpFrame::Headers(d)))) => {
                    self.trailers = Some(d);
                    Poll::Ready(None)
                }
                Poll::Ready(Some(Err(e))) => {
                    self.recv.take().unwrap().reset(e.code());
                    Poll::Ready(Some(Err(e.into())))
                }
                Poll::Ready(Some(Ok(f))) => {
                    self.recv.take().unwrap().reset(ErrorCode::FRAME_UNEXPECTED);
                    Poll::Ready(Some(Err(Error::Peer(format!(
                        "Invalid frame type in body: {:?}",
                        f
                    )))))
                }
            };
        }
    }

    fn buf_read(&mut self, buf: &mut [u8]) -> usize {
        match self.buf {
            None => 0,
            Some(ref mut b) => {
                let size = cmp::min(buf.len(), b.len());
                buf[..size].copy_from_slice(&b.split_to(size));
                if b.is_empty() {
                    self.buf = None;
                }
                size
            }
        }
    }

    fn buf_put(&mut self, buf: Bytes) {
        assert!(self.buf.is_none());
        self.buf = Some(buf)
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let size = self.buf_read(buf);
        if size == buf.len() {
            return Poll::Ready(Ok(size));
        }

        loop {
            return match Pin::new(self.recv.as_mut().unwrap()).poll_next(cx) {
                Poll::Ready(Some(Ok(HttpFrame::Reserved))) => continue,
                Poll::Ready(None) => Poll::Ready(Ok(size)),
                Poll::Pending => {
                    if size > 0 {
                        Poll::Ready(Ok(size))
                    } else {
                        Poll::Pending
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.recv.take().unwrap().reset(e.code());
                    Poll::Ready(Err(io::Error::new(
                        ErrorKind::Other,
                        format!("read error: {:?}", e),
                    )))
                }
                Poll::Ready(Some(Ok(HttpFrame::Data(mut d)))) => {
                    if d.payload.len() >= buf.len() - size {
                        let tail = d.payload.split_off(buf.len() - size);
                        self.buf_put(tail);
                    }
                    buf[size..size + d.payload.len()].copy_from_slice(&d.payload);
                    Poll::Ready(Ok(size + d.payload.len()))
                }
                Poll::Ready(Some(Ok(HttpFrame::Headers(d)))) => {
                    self.trailers = Some(d);
                    Poll::Ready(Ok(size))
                }
                Poll::Ready(Some(Ok(_))) => {
                    self.recv.take().unwrap().reset(ErrorCode::FRAME_UNEXPECTED);
                    Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "received an invalid frame type",
                    )))
                }
            };
        }
    }
}

impl tokio::io::AsyncRead for BodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncRead::poll_read(self, cx, buf)
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        if self.finish_request {
            self.conn
                .h3
                .lock()
                .unwrap()
                .inner
                .request_finished(self.stream_id);
        }
    }
}
