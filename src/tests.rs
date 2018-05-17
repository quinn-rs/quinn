extern crate untrusted;

use futures::Future;

use rustls::internal::pemfile;

use std::sync::Arc;
use std::{fs::File, io::{BufReader, Read}};

use tokio::executor::current_thread::CurrentThread;

use client;
use crypto::Secret;
use endpoint::Endpoint;
use packet::Packet;
use parameters::{ClientTransportParameters, ServerTransportParameters};
use server::Server;
use tls;
use types::ConnectionId;

use self::untrusted::Input;

use webpki;

#[test]
fn test_client_connect_resolves() {
    let server = Server::new("0.0.0.0", 4433, build_server_config()).unwrap();
    let connector = client::ConnectFuture::new(client_endpoint(), "localhost", 4433).unwrap();
    let mut exec = CurrentThread::new();
    exec.spawn(server.map_err(|_| ()));
    exec.block_on(connector).unwrap();
}

#[test]
fn test_encoded_handshake() {
    let mut c = client_endpoint();
    c.initial().unwrap();
    let mut c_initial = c.queued().unwrap().unwrap().clone();
    c.pop_queue();

    let mut s = server_endpoint(Packet::start_decode(&mut c_initial).dst_cid());
    s.handle(&mut c_initial).unwrap();

    let mut s_sh = s.queued().unwrap().unwrap().clone();
    s.pop_queue();
    c.handle(&mut s_sh).unwrap();

    let mut c_fin = c.queued().unwrap().unwrap().clone();
    c.pop_queue();
    s.handle(&mut c_fin).unwrap();

    let mut s_short = s.queued().unwrap().unwrap().clone();
    s.pop_queue();
    let c_short = {
        let partial = Packet::start_decode(&mut s_short);
        let key = c.decode_key(&partial.header);
        partial.finish(&key).unwrap()
    };
    assert_eq!(c_short.ptype(), None);
}

#[test]
fn test_handshake() {
    let mut c = client_endpoint();
    c.initial().unwrap();
    let mut initial = c.queued().unwrap().unwrap().clone();
    c.pop_queue();

    let mut s = server_endpoint(Packet::start_decode(&mut initial).dst_cid());
    s.handle(&mut initial).unwrap();
    let mut server_hello = s.queued().unwrap().unwrap().clone();

    c.handle(&mut server_hello).unwrap();
    assert!(c.queued().unwrap().is_some());
}

fn server_endpoint(hs_cid: ConnectionId) -> Endpoint<tls::ServerSession> {
    Endpoint::new(
        tls::server_session(
            &Arc::new(build_server_config()),
            &ServerTransportParameters::default(),
        ),
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

fn client_endpoint() -> Endpoint<tls::ClientSession> {
    let tls = {
        let mut f = File::open("certs/ca.der").expect("cannot open 'certs/ca.der'");
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).expect("error while reading");

        let anchor =
            webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&bytes)).unwrap();
        let anchor_vec = vec![anchor];
        let config = tls::build_client_config(Some(&webpki::TLSServerTrustAnchors(&anchor_vec)));
        tls::client_session(
            Some(config),
            "localhost",
            &ClientTransportParameters::default(),
        ).unwrap()
    };

    Endpoint::new(tls, None)
}
