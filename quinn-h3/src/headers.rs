use futures::{try_ready, Async, Future, Poll};
use quinn::SendStream;
use quinn_proto::StreamId;
use tokio_io::io::WriteAll;

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

pub(crate) struct SendHeaders(WriteAll<SendStream, Vec<u8>>);

impl SendHeaders {
    pub fn new(
        header: Header,
        conn: &ConnectionRef,
        send: SendStream,
        stream_id: StreamId,
    ) -> Result<Self, Error> {
        let block = {
            let conn = &mut conn.h3.lock().unwrap().inner;
            conn.encode_header(stream_id, header)?
        };

        let mut encoded = Vec::new();
        block.encode(&mut encoded);

        Ok(Self(tokio_io::io::write_all(send, encoded)))
    }
}

impl Future for SendHeaders {
    type Item = SendStream;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (send, _) = try_ready!(self.0.poll());
        Ok(Async::Ready(send))
    }
}
