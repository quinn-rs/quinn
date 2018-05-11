extern crate quinn;
extern crate rustls;

use rustls::internal::pemfile;
use std::{fs::File, io::BufReader};

fn main() {
    let mut certs = {
        let f = File::open("server.crt").expect("cannot open 'server.crt'");
        let mut reader = BufReader::new(f);
        pemfile::certs(&mut reader).expect("cannot read certificates")
    };

    certs.extend_from_slice(&{
        let f = File::open("intermediate.pem").expect("cannot open 'intermediate.pem'");
        let mut reader = BufReader::new(f);
        pemfile::certs(&mut reader).expect("cannot read certificates")
    });

    let key = {
        let f = File::open("server.key").expect("cannot open 'server.key'");
        let mut reader = BufReader::new(f);
        pemfile::rsa_private_keys(&mut reader).expect("cannot read private keys")
    };

    let tls_config = quinn::tls::build_server_config(certs, key[0].clone());
    quinn::Server::new("0.0.0.0", 4433, tls_config)
        .unwrap()
        .run()
        .unwrap();
}
