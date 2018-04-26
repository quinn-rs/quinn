extern crate untrusted;

use rand::{thread_rng, ThreadRng};

use rustls::internal::pemfile;

use std::{fs::File, io::{BufReader, Read}};
use std::sync::Arc;

use client::ClientStreamState;
use server::ServerStreamState;
use tls;
use types::Endpoint;

use self::untrusted::Input;

use webpki;

#[test]
fn test_handshake() {
    let mut rng = thread_rng();
    let mut cs = client_state(&mut rng);
    let mut ss = server_state(&mut rng);

    let initial = cs.initial("example.com");
    let server_hello = ss.handle(&initial).unwrap();
    assert!(cs.handle(&server_hello).is_some());
}

fn server_state(mut rng: &mut ThreadRng) -> ServerStreamState {
    let certs = {
        let f = File::open("certs/server.chain").expect("cannot open 'certs/server.chain'");
        let mut reader = BufReader::new(f);
        pemfile::certs(&mut reader).expect("cannot read certificates")
    };

    let keys = {
        let f = File::open("certs/server.rsa").expect("cannot open 'certs/server.rsa'");
        let mut reader = BufReader::new(f);
        pemfile::rsa_private_keys(&mut reader).expect("cannot read private keys")
    };

    let endpoint = Endpoint::new(&mut rng);
    let addr = "0.0.0.0:0".parse().unwrap();
    let tls_config = Arc::new(tls::build_server_config(certs, keys[0].clone()));
    ServerStreamState::new(endpoint, &addr, &tls_config)
}

fn client_state(mut rng: &mut ThreadRng) -> ClientStreamState {
    let mut endpoint = Endpoint::new(&mut rng);
    endpoint.hs_cid = endpoint.dst_cid;

    let tls = {
        let mut f = File::open("certs/ca.der").expect("cannot open 'certs/ca.der'");
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).expect("error while reading");

        let anchor =
            webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&bytes)).unwrap();
        let anchor_vec = vec![anchor];
        let config = tls::build_client_config(Some(&webpki::TLSServerTrustAnchors(&anchor_vec)));
        tls::Client::with_config(config)
    };

    ClientStreamState { endpoint, tls }
}
