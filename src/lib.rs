extern crate rand;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;

use rustls::Session;

//use rand::Rng;
use std::sync::Arc;

pub use self::types::Packet;

mod types;


pub fn connect(server: &str) {
    //let mut rng = rand::thread_rng();
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    let tls_config = Arc::new(config);
    let pki_server_name = webpki::DNSNameRef::try_from_ascii_str(server).unwrap();
    let mut tls_client = rustls::ClientSession::new(&tls_config, pki_server_name);
    let mut buf = Vec::new();
    println!("{:?}", tls_client.write_tls(&mut buf));
    println!("{:?}", buf);
}
