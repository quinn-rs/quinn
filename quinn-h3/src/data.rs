use std::{
    error::Error as StdError,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use http_body::Body as HttpBody;
use pin_project::{pin_project, project};
use quinn::SendStream;
use quinn_proto::StreamId;

use crate::{
    connection::ConnectionRef,
    frame::WriteFrame,
    headers::SendHeaders,
    proto::{frame::DataFrame, headers::Header, ErrorCode},
    Error,
};

/// Represent data transmission completion for a Request or a Response
///
/// This is yielded by [`SendRequest`] and [`SendResponse`]. It will encode and send
/// the headers, then send the body if any data is polled from [`HttpBody::poll_data()`].
/// It also encodes and sends the trailer a similar way, if any.
#[pin_project]
pub struct SendData<B, P> {
    headers: Option<Header>,
    #[pin]
    body: B,
    #[pin]
    state: SendDataState<P>,
    conn: ConnectionRef,
    send: Option<SendStream>,
    stream_id: StreamId,
    finish: bool,
}

#[pin_project]
enum SendDataState<P> {
    Initial,
    Headers(SendHeaders),
    PollBody,
    Write(#[pin] WriteFrame<DataFrame<P>>),
    PollTrailers,
    Trailers(SendHeaders),
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
            send: Some(send),
            state: SendDataState::Initial,
        }
    }

    /// Cancel the request
    ///
    /// The peer will receive a request error with `REQUEST_CANCELLED` code.
    pub fn cancel(&mut self) {
        self.state = SendDataState::Finished;
        match self.state {
            SendDataState::Write(ref mut w) => {
                w.reset(ErrorCode::REQUEST_CANCELLED);
            }
            SendDataState::Trailers(ref mut w) => {
                w.reset(ErrorCode::REQUEST_CANCELLED);
            }
            _ => {
                if let Some(ref mut send) = self.send.take() {
                    send.reset(ErrorCode::REQUEST_CANCELLED.into());
                }
            }
        }
        self.state = SendDataState::Finished;
    }
}

impl<B> Future for SendData<B, B::Data>
where
    B: HttpBody + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
{
    type Output = Result<(), Error>;

    #[project]
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            #[project]
            match &mut me.state.as_mut().project() {
                SendDataState::Initial => {
                    // This initial computaion is done here to report its failability to Future::Output.
                    let header = me.headers.take().expect("headers");
                    me.state.set(SendDataState::Headers(SendHeaders::new(
                        header,
                        &me.conn,
                        me.send.take().expect("send"),
                        *me.stream_id,
                    )?));
                }
                SendDataState::Headers(ref mut send) => {
                    *me.send = Some(ready!(Pin::new(send).poll(cx))?);
                    me.state.set(SendDataState::PollBody);
                }
                SendDataState::PollBody => {
                    let next = match ready!(Pin::new(&mut me.body).poll_data(cx)) {
                        None => SendDataState::PollTrailers,
                        Some(Err(e)) => return Poll::Ready(Err(Error::body(e.into()))),
                        Some(Ok(d)) => {
                            let send = me.send.take().expect("send");
                            let data = DataFrame { payload: d };
                            SendDataState::Write(WriteFrame::new(send, data))
                        }
                    };
                    me.state.set(next);
                }
                SendDataState::Write(ref mut write) => {
                    *me.send = Some(ready!(Pin::new(write).poll(cx))?);
                    me.state.set(SendDataState::PollBody);
                }
                SendDataState::PollTrailers => {
                    match ready!(Pin::new(&mut me.body).poll_trailers(cx))
                        .map_err(|_| todo!())
                        .unwrap()
                    {
                        None => me.state.set(SendDataState::Closing),
                        Some(h) => {
                            me.state.set(SendDataState::Trailers(SendHeaders::new(
                                Header::trailer(h),
                                &me.conn,
                                me.send.take().expect("send"),
                                *me.stream_id,
                            )?));
                        }
                    }
                }
                SendDataState::Trailers(send) => {
                    *me.send = Some(ready!(Pin::new(send).poll(cx))?);
                    me.state.set(SendDataState::Closing);
                }
                SendDataState::Closing => {
                    ready!(Pin::new(me.send.as_mut().unwrap()).poll_finish(cx))?;
                    if *me.finish {
                        let mut conn = me.conn.h3.lock().unwrap();
                        conn.inner.request_finished(*me.stream_id);
                    }
                    return Poll::Ready(Ok(()));
                }
                SendDataState::Finished => return Poll::Ready(Ok(())),
            };
        }
    }
}
