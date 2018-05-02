extern crate untrusted;

use rustls::internal::pemfile;

use std::{fs::File, io::{BufReader, Read}};
use std::sync::Arc;

use crypto::Secret;
use endpoint::Endpoint;
use packet::Packet;
use tls::{ClientTls, ServerTls};
use types::{ConnectionId, Side};

use self::untrusted::Input;

use webpki;

#[test]
fn test_encoded_handshake() {
    let mut c = client_endpoint();
    let initial = c.initial("example.com");
    let mut buf = vec![0u8; 1600];
    initial.encode(&c.encode_key(&initial.header), &mut buf);

    let partial = Packet::start_decode(&mut buf);
    assert_eq!(initial.header, partial.header);

    let hs_cid = partial.dst_cid();
    let s = server_endpoint(hs_cid);
    let key = s.decode_key(&partial.header);
    let _ = partial.finish(&key);
}

#[test]
fn test_handshake() {
    let mut c = client_endpoint();
    let initial = c.initial("example.com");

    let mut s = server_endpoint(initial.dst_cid());
    let server_hello = s.handle_handshake(&initial).unwrap();
    assert!(c.handle_handshake(&server_hello).is_some());
}

fn server_endpoint(hs_cid: ConnectionId) -> Endpoint<ServerTls> {
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

    let tls_config = Arc::new(ServerTls::build_config(certs, keys[0].clone()));
    Endpoint::new(
        ServerTls::with_config(&tls_config),
        Side::Server,
        Some(Secret::Handshake(hs_cid)),
    )
}

fn client_endpoint() -> Endpoint<ClientTls> {
    let tls = {
        let mut f = File::open("certs/ca.der").expect("cannot open 'certs/ca.der'");
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).expect("error while reading");

        let anchor =
            webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&bytes)).unwrap();
        let anchor_vec = vec![anchor];
        let config = ClientTls::build_config(Some(&webpki::TLSServerTrustAnchors(&anchor_vec)));
        ClientTls::with_config(config)
    };

    Endpoint::new(tls, Side::Client, None)
}
