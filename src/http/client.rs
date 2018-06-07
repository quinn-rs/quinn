use futures::future::Future;

use streams::Streams;
use QuicError;

pub fn start(streams: Streams) -> impl Future<Item = Streams, Error = QuicError> {
    println!("REQUEST STREAM 2");
    streams.request_stream(2)
}
