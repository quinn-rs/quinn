extern crate quinn;

use std::env;

fn main() {
    let server = env::args().nth(1).unwrap();
    let mut client = quinn::Client::new();
    client.connect(&server, 4433);
}
