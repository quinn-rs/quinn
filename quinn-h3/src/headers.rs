use std::{pin::Pin, task::Context};

use futures::{Future, Poll};
use quinn::SendStream;
use quinn_proto::StreamId;

use crate::{
    connection::ConnectionRef,
    frame::WriteFrame,
    proto::{connection::DecodeResult, frame::HeadersFrame, headers::Header, ErrorCode},
    Error,
};

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

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        match self.frame {
            None => Poll::Ready(Err(crate::Error::Internal("frame none"))),
            Some(ref frame) => {
                let result = self
                    .conn
                    .h3
                    .lock()
                    .unwrap()
                    .inner
                    .decode_header(self.stream_id, frame);

                match result {
                    Ok(DecodeResult::MissingRefs(_)) => Poll::Pending, // Stream is blocked
                    Ok(DecodeResult::Decoded(decoded)) => Poll::Ready(Ok(decoded)),
                    Err(e) => {
                        Poll::Ready(Err(Error::peer(format!("decoding header failed: {:?}", e))))
                    }
                }
            }
        }
    }
}

pub(crate) struct SendHeaders(WriteFrame);

impl SendHeaders {
    pub fn new(
        header: Header,
        conn: &ConnectionRef,
        send: SendStream,
        stream_id: StreamId,
    ) -> Result<Self, Error> {
        let frame = {
            let conn = &mut conn.h3.lock().unwrap().inner;
            conn.encode_header(stream_id, header)?
        };

        Ok(Self(WriteFrame::new(send, frame)))
    }

    pub fn reset(self, err_code: ErrorCode) {
        self.0.reset(err_code);
    }
}

impl<'a> Future for SendHeaders {
    type Output = Result<SendStream, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(Into::into)
    }
}
