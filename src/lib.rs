extern crate rand;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;

mod tls;
mod types;

pub fn connect(server: &str) {
    let mut client = tls::Client::new(server);
    println!("{:?}", client.get_handshake());
}
