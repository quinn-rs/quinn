use futures::{Async, Future, Poll};
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
    type Item = Header;
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.frame {
            None => Err(crate::Error::Internal("frame none")),
            Some(ref frame) => {
                let result = self
                    .conn
                    .h3
                    .lock()
                    .unwrap()
                    .inner
                    .decode_header(self.stream_id, frame);

                match result {
                    Ok(None) => Ok(Async::NotReady),
                    Ok(Some(decoded)) => Ok(Async::Ready(decoded)),
                    Err(e) => Err(Error::peer(format!("decoding header failed: {:?}", e))),
                }
            }
        }
    }
}
