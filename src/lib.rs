extern crate bytes;
extern crate futures;
extern crate rand;
extern crate rustls;
extern crate tokio_io;
extern crate webpki;
extern crate webpki_roots;

use rand::{Rng, thread_rng};

use self::proto::{Frame, Header, LongType, Packet, StreamFrame};

mod proto;
mod tls;
mod types;

pub fn connect(server: &str) {
    let mut client = tls::Client::new(server);
    let mut rng = thread_rng();
    let conn_id: u64 = rng.gen();
    let number: u32 = rng.gen();

    let handshake = client.get_handshake();
    let packet = Packet {
        header: Header::Long {
            ptype: LongType::Initial,
            conn_id,
            version: 1,
        },
        number,
        payload: vec![
            Frame::Stream(StreamFrame {
                id: 0,
                offset: None,
                length: Some(handshake.len() as u64),
                data: handshake,
            }),
        ],
    };
}
