use crc::crc32;
use futures::unsync::oneshot;
use futures::{Future, Stream};
use rand::{self, RngCore};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use tokio::runtime::current_thread::{self, Runtime};
use unwrap::unwrap;

struct TestContext {
    /// Keep track of how many messages we've already received so that we'd know when test is
    /// finished.
    received_messages: usize,
    expected_messages: usize,
    done_tx: Option<oneshot::Sender<()>>,

    /// Hold connections so that streams wouldn't be closed prematurely
    connections: Vec<quinn::Connection>,
}

impl TestContext {
    /// Constructs test context and returns test completion receiver as well..
    fn shared() -> (Rc<RefCell<Self>>, oneshot::Receiver<()>) {
        let (done_tx, done_rx) = oneshot::channel();
        (
            Rc::new(RefCell::new(Self {
                received_messages: 0,
                expected_messages: 0,
                connections: Default::default(),
                done_tx: Some(done_tx),
            })),
            done_rx,
        )
    }
}

#[test]
#[ignore]
fn connect_n_nodes_to_1_and_send_1mb_data() {
    let mut runtime = unwrap!(Runtime::new());

    let (cfg, listener_cert) = configure_listener();
    let mut ep_builder = quinn::Endpoint::new();
    ep_builder.listen(cfg);
    let (driver, endpoint, incoming_conns) = unwrap!(ep_builder.bind(&("127.0.0.1", 0)));
    runtime.spawn(driver.map_err(|e| panic!("Listener IO error: {}", e)));
    let listener_addr = unwrap!(endpoint.local_addr());

    let (ctx, done_rx) = TestContext::shared();
    ctx.borrow_mut().expected_messages = 50;

    let ctx2 = ctx.clone();
    let read_incoming_data = incoming_conns
        .map_err(|()| panic!("Listener failed"))
        .for_each(move |(conn_driver, _conn, incoming)| {
            current_thread::spawn(conn_driver.map_err(|_| ()));

            let ctx = ctx2.clone();
            let task = incoming
                .map_err(move |e| panic!("Incoming streams failed: {}", e))
                .for_each(move |stream| {
                    read_from_peer(stream, ctx.clone());
                    Ok(())
                })
                .then(move |_| Ok(()));
            current_thread::spawn(task);

            Ok(())
        });
    runtime.spawn(read_incoming_data);

    let client_cfg = configure_connector(&listener_cert);

    for _ in 0..ctx.borrow_mut().expected_messages {
        let data = random_data_with_hash(1024 * 1024);
        let ctx = ctx.clone();
        let task = unwrap!(endpoint.connect_with(&client_cfg, &listener_addr, "Test"))
            .map_err(|e| panic!("Connection failed: {}", e))
            .and_then(move |(conn_driver, conn, _)| {
                current_thread::spawn(conn_driver.map_err(|_| ()));
                write_to_peer(&conn, data);
                ctx.borrow_mut().connections.push(conn);
                Ok(())
            });
        runtime.spawn(task);
    }

    let _ = unwrap!(runtime.block_on(done_rx));
}

fn read_from_peer(stream: quinn::NewStream, ctx: Rc<RefCell<TestContext>>) {
    let stream = match stream {
        quinn::NewStream::Bi(_bi) => panic!("Unexpected bidirectional stream here"),
        quinn::NewStream::Uni(uni) => uni,
    };

    let task = quinn::read_to_end(stream, 1024 * 1024 * 5)
        .map_err(|e| panic!("read_to_end() failed: {}", e))
        .and_then(move |(_stream, data)| {
            assert!(hash_correct(&data));
            ctx.borrow_mut().received_messages += 1;
            if ctx.borrow().received_messages == ctx.borrow().expected_messages {
                // TODO(povilas): unblock main thread
                println!("done. All checks passed.");
                unwrap!(unwrap!(ctx.borrow_mut().done_tx.take()).send(()));
            }
            Ok(())
        })
        .then(|_| Ok(()));
    current_thread::spawn(task);
}

fn write_to_peer(conn: &quinn::Connection, data: Vec<u8>) {
    let task = conn
        .open_uni()
        .map_err(|e| panic!("Failed to open unidirection stream: {}", e))
        .and_then(move |o_stream| {
            tokio::io::write_all(o_stream, data).map_err(|e| panic!("write_all() failed: {}", e))
        })
        .and_then(move |(o_stream, _)| {
            tokio::io::shutdown(o_stream).map_err(|e| panic!("shutdown() failed: {}", e))
        })
        .map(|_| ());
    current_thread::spawn(task);
}

/// Builds client configuration. Trusts given node certificate.
fn configure_connector(node_cert: &[u8]) -> quinn::ClientConfig {
    let mut peer_cfg_builder = quinn::ClientConfigBuilder::new();
    let their_cert = unwrap!(quinn::Certificate::from_der(&node_cert));
    unwrap!(peer_cfg_builder.add_certificate_authority(their_cert));
    let mut peer_cfg = peer_cfg_builder.build();
    let transport_config = unwrap!(Arc::get_mut(&mut peer_cfg.transport));
    transport_config.idle_timeout = 0;
    transport_config.keep_alive_interval = 10_000;

    peer_cfg
}

/// Builds listener configuration along with its certificate.
fn configure_listener() -> (quinn::ServerConfig, Vec<u8>) {
    let (our_cert_der, our_priv_key) = gen_cert();
    let our_cert = unwrap!(quinn::Certificate::from_der(&our_cert_der));

    let our_cfg = Default::default();
    let mut our_cfg_builder = quinn::ServerConfigBuilder::new(our_cfg);
    unwrap!(our_cfg_builder.certificate(
        quinn::CertificateChain::from_certs(vec![our_cert]),
        our_priv_key
    ));
    let mut our_cfg = our_cfg_builder.build();
    let transport_config = unwrap!(Arc::get_mut(&mut our_cfg.transport_config));
    transport_config.idle_timeout = 0;
    transport_config.keep_alive_interval = 1000;

    (our_cfg, our_cert_der)
}

fn gen_cert() -> (Vec<u8>, quinn::PrivateKey) {
    let cert = rcgen::generate_simple_self_signed(vec!["Test".to_string()]);
    let key = unwrap!(quinn::PrivateKey::from_der(
        &cert.serialize_private_key_der()
    ));
    (cert.serialize_der(), key)
}

/// Constructs a buffer with random bytes of given size prefixed with a hash of this data.
fn random_data_with_hash(size: usize) -> Vec<u8> {
    let mut data = random_vec(size + 4);
    let hash = crc32::checksum_ieee(&data[4..]);
    // write hash in big endian
    data[0] = (hash >> 24) as u8;
    data[1] = ((hash >> 16) & 0xff) as u8;
    data[2] = ((hash >> 8) & 0xff) as u8;
    data[3] = (hash & 0xff) as u8;
    data
}

/// Checks if given data buffer hash is correct. Hash itself is a 4 byte prefix in the data.
fn hash_correct(data: &[u8]) -> bool {
    let encoded_hash = ((data[0] as u32) << 24)
        | ((data[1] as u32) << 16)
        | ((data[2] as u32) << 8)
        | data[3] as u32;
    let actual_hash = crc32::checksum_ieee(&data[4..]);
    encoded_hash == actual_hash
}

#[allow(unsafe_code)]
fn random_vec(size: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(size);
    unsafe { ret.set_len(size) };
    rand::thread_rng().fill_bytes(&mut ret[..]);
    ret
}
