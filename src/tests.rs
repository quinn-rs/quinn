extern crate untrusted;

use futures::Future;

use rustls::internal::pemfile;

use std::{fs::File, io::{BufReader, Read}};
use std::sync::Arc;

use tokio::executor::current_thread::CurrentThread;

use client::ConnectFuture;
use crypto::Secret;
use endpoint::Endpoint;
use packet::Packet;
use server::Server;
use tls;
use types::{ConnectionId, Side};

use self::untrusted::Input;

use webpki;

#[test]
fn test_client_connect_resolves() {
    let server = Server::new("0.0.0.0", 4433, build_server_config()).unwrap();
    let connector = ConnectFuture::new(client_endpoint(), "localhost", 4433).unwrap();
    let mut exec = CurrentThread::new();
    exec.spawn(server.map_err(|_| ()));
    exec.block_on(connector).unwrap();
}

#[test]
fn test_encoded_handshake() {
    let mut c = client_endpoint();
    let c_initial = c.initial("example.com").unwrap();
    let mut buf = vec![0u8; 1600];
    c_initial
        .encode(&c.encode_key(&c_initial.header), &mut buf)
        .unwrap();

    let mut s = server_endpoint(c_initial.dst_cid());
    let s_initial = {
        let partial = Packet::start_decode(&mut buf);
        assert_eq!(c_initial.header, partial.header);

        let key = s.decode_key(&partial.header);
        partial.finish(&key).unwrap()
    };

    let s_sh = s.handle_handshake(&s_initial).unwrap().unwrap();
    s_sh.encode(&s.encode_key(&s_sh.header), &mut buf).unwrap();

    let c_sh = {
        let partial = Packet::start_decode(&mut buf);
        assert_eq!(s_sh.header, partial.header);

        let key = c.decode_key(&partial.header);
        partial.finish(&key).unwrap()
    };

    let c_fin = c.handle_handshake(&c_sh).unwrap().unwrap();
    c_fin
        .encode(&c.encode_key(&c_fin.header), &mut buf)
        .unwrap();

    let s_fin = {
        let partial = Packet::start_decode(&mut buf);
        assert_eq!(c_fin.header, partial.header);

        let key = s.decode_key(&partial.header);
        partial.finish(&key).unwrap()
    };

    let short = s.handle_handshake(&s_fin).unwrap().unwrap();
    assert_eq!(short.ptype(), None);
}

#[test]
fn test_handshake() {
    let mut c = client_endpoint();
    let initial = c.initial("example.com").unwrap();

    let mut s = server_endpoint(initial.dst_cid());
    let server_hello = s.handle_handshake(&initial).unwrap().unwrap();
    assert!(c.handle_handshake(&server_hello).unwrap().is_some());
}

fn server_endpoint(hs_cid: ConnectionId) -> Endpoint<tls::QuicServerTls> {
    Endpoint::new(
        tls::server_session(&Arc::new(build_server_config())),
        Side::Server,
        Some(Secret::Handshake(hs_cid)),
    )
}

fn build_server_config() -> tls::ServerConfig {
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

    tls::build_server_config(certs, keys[0].clone())
}

fn client_endpoint() -> Endpoint<tls::QuicClientTls> {
    let tls = {
        let mut f = File::open("certs/ca.der").expect("cannot open 'certs/ca.der'");
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).expect("error while reading");

        let anchor =
            webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&bytes)).unwrap();
        let anchor_vec = vec![anchor];
        let config = tls::build_client_config(Some(&webpki::TLSServerTrustAnchors(&anchor_vec)));
        tls::client_session(Some(config))
    };

    Endpoint::new(tls, Side::Client, None)
}
