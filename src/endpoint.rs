use std::collections::HashMap;
use std::io;
use std::net::SocketAddrV6;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, ByteOrder, BigEndian};
use rand::{distributions, OsRng, Rng};
use rand::distributions::Sample;
use rustls;
use webpki;
use slab::Slab;

pub struct ConnectionHandle(usize);

pub struct Endpoint {
    rng: OsRng,
    initial_packet_number: distributions::Range<u64>,
    // Nonempty iff we're listening for incoming connections
    tls_server: Option<Arc<rustls::ServerConfig>>,
    connection_ids: HashMap<ConnectionId, usize>,
    outgoing: Vec<Box<[u8]>>,
    connections: Slab<Connection>,
}

impl Endpoint {
    /// Create an endpoint for outgoing connections only
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            rng: OsRng::new()?,
            initial_packet_number: distributions::Range::new(0, 2u64.pow(32) - 1024),
            tls_server: None,
            connection_ids: HashMap::new(),
            outgoing: Vec::new(),
            connections: Slab::new(),
        })
    }

    /// Create an endpoint that accepts incoming connections
    pub fn listen(tls_server: Arc<rustls::ServerConfig>) -> io::Result<Self> {
        Ok(Self {
            tls_server: Some(tls_server),
            ..Self::new()?
        })
    }

    pub fn handle(&mut self, remote: SocketAddrV6, local: SocketAddrV6, packet: Bytes) {
        #[derive(Debug)]
        enum Header {
            Long { version: u32, connection: ConnectionId },
            Short { connection: Option<ConnectionId> },
        }

        let mut packet = io::Cursor::new(packet);
        let flags = packet.get_u8();
        let long_header = flags & 0x80 != 0;
        let header = if long_header {
            if packet.bytes().len() < 16 { return; }
            Header::Long {
                connection: ConnectionId(packet.get_u64::<BigEndian>()),
                version: packet.get_u32::<BigEndian>(),
            }
        } else {
            if packet.bytes().len() < 4 { return; }
            let omit_connection_id = flags & 0x40 != 0;
            Header::Short {
                connection: if omit_connection_id { None } else { Some(ConnectionId(packet.get_u64::<BigEndian>())) },
            }
        };

        //
        // Handle packet on existing connection, if any
        //

        match header {
            Header::Long { connection: ref id, .. } | Header::Short { connection: Some(ref id) } => {
                if let Some(&i) = self.connection_ids.get(id) {
                    self.connections[i].handle(packet.into_inner());
                    return;
                }
            }
            _ => {}
        }

        //
        // Potentially create a new connection
        //

        if self.tls_server.is_none() { return; }
        if let Header::Long { version, connection } = header {
            if version == 1 {
                if flags & 0b01111111 != 0x7F || packet.get_ref().len() < 1200 {
                    // Not an initial packet
                    // MAY buffer these a little for better 0RTT behavior
                    return;
                }
                self.handle_init(packet.into_inner());
            } else {
                // Negotiate versions
                let mut buf = Vec::<u8>::new();
                buf.reserve_exact(17);
                buf.put_u8(0);  // flags
                buf.put_u64::<BigEndian>(connection.0);
                buf.put_u32::<BigEndian>(0); // version negotiation packet
                buf.put_u32::<BigEndian>(1); // supported version
                self.outgoing.push(buf.into_boxed_slice());
            }
        } else {
            // No version, no known connection? No service.
            return;
        }
    }

    pub fn connect(&mut self, local: SocketAddrV6, tls: &Arc<rustls::ClientConfig>, remote: SocketAddrV6, hostname: webpki::DNSNameRef) -> ConnectionHandle {
        let i = self.connections.insert(Connection {
            tls: Box::new(rustls::ClientSession::new(tls, hostname)),
            id: ConnectionId(self.rng.gen()),
            tx_packet_number: self.initial_packet_number.sample(&mut self.rng).into(),
        });
        self.connection_ids.insert(self.connections[i].id, i);
        // TODO: Queue initial packet, retransmit timer?
        ConnectionHandle(i)
    }

    fn handle_init(&mut self, packet: Bytes) {
        let initial_id = ConnectionId(BigEndian::read_u64(&packet[1..9]));
        let packet_number = BigEndian::read_u32(&packet[13..17]);
        let mut packet = io::Cursor::new(packet);
        packet.advance(17);
        // TODO: Read stream 0 frames to tls context??
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct ConnectionId(u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct HandshakeId {
    remote: SocketAddrV6,
    local: SocketAddrV6,
}

struct Connection {
    id: ConnectionId,
    tls: Box<rustls::Session>,
    tx_packet_number: u64,
}

impl Connection {
    fn handle(&mut self, packet: Bytes) {
        
    }
}
