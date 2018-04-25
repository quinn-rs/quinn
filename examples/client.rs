extern crate futures;
extern crate quinn;

use futures::Future;

use std::env;

fn main() {
    let server = env::args().nth(1).expect("need server name as an argument");
    println!("RESULT: {:?}", quinn::QuicStream::connect(&server, 4433).wait());
}
