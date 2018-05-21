use futures::future::Future;

use QuicError;
use streams::Streams;

pub fn start(streams: Streams) -> impl Future<Item = Streams, Error = QuicError> {
    println!("REQUEST STREAM 2");
    streams.request_stream(2)
}
