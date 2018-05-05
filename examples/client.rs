extern crate futures;
extern crate quinn;

use futures::Future;

use std::env;

fn main() {
    let server = env::args().nth(1).expect("need server name as an argument");
    println!(
        "RESULT: {:?}",
        quinn::Client::connect(&server, 4433)
            .unwrap()
            .and_then(|_| {
                println!("client is connected");
                futures::future::ok(())
            })
            .wait(),
    );
}
