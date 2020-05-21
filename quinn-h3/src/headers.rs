use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use quinn_proto::StreamId;

use crate::{
    connection::ConnectionRef,
    proto::{frame::HeadersFrame, headers::Header},
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
