extern crate quinn;

use std::env;

fn main() {
    let server = env::args().nth(1).unwrap();
    quinn::connect(&server, 4433);
}
