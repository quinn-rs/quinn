use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

use bytes::{BufMut, Bytes, BytesMut, ByteOrder, BigEndian};
use rand::{distributions, OsRng, Rng};
use rand::distributions::Sample;
use slab::Slab;
use openssl;
use openssl::ssl::{SslContext, SslMethod, SslOptions, SslMode, Ssl, SslRef, SslStream, HandshakeError, MidHandshakeSslStream, SslStreamBuilder};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use failure::Error;
use blake2::Blake2b;
use digest::{Input, VariableOutput};
use constant_time_eq::constant_time_eq;
use bincode;
use slog::Logger;

use memory_stream::MemoryStream;
use {frame, Frame, from_bytes, BytesExt};

type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ConnectionHandle(usize);

pub struct Config {
    pub listen: Option<ListenConfig>,
    pub valid_cookie_life: Duration,
}

pub struct ListenConfig {
    pub private_key: PKey<Private>,
    pub cert: X509,
}

impl Default for Config {
    fn default() -> Self { Self {
        listen: None,
        valid_cookie_life: Duration::from_secs(60),
    }}
}

pub struct Endpoint {
    log: Logger,
    rng: OsRng,
    initial_packet_number: distributions::Range<u64>,
    tls: SslContext,
    connection_ids: HashMap<ConnectionId, usize>,
    connections: Slab<Connection>,
    config: Config,
    events: VecDeque<Event>,
    io: VecDeque<Io>,
}

const VERSION: u32 = 0xff000009;
const MIN_INITIAL_SIZE: usize = 1200;

impl Endpoint {
    /// Create an endpoint for outgoing connections only
    pub fn new(log: Logger, config: Config) -> Result<Self> {
        let mut rng = OsRng::new()?;
        let cookie_factory = Arc::new(CookieFactory::new(&mut rng));

        let mut tls = SslContext::builder(SslMethod::tls())?;
        tls.set_options(
            SslOptions::NO_COMPRESSION | SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 |
            SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2 | SslOptions::DONT_INSERT_EMPTY_FRAGMENTS
        );
        tls.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);
        tls.set_mode(
            SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE | SslMode::RELEASE_BUFFERS
        );
        tls.set_default_verify_paths()?;
        {
            let cookie_factory = cookie_factory.clone();
            tls.set_cookie_generate_cb(move |tls, buf| Ok(cookie_factory.generate(tls, buf)));
        }
        tls.set_cookie_verify_cb(move |tls, cookie| cookie_factory.verify(tls, cookie));

        if let Some(ref listen) = config.listen {
            tls.set_private_key(&listen.private_key)?;
            tls.set_certificate(&listen.cert)?;
            tls.check_private_key()?;
        }

        let tls = tls.build();

        Ok(Self {
            log, rng, config, tls,
            initial_packet_number: distributions::Range::new(0, 2u64.pow(32) - 1024),
            connection_ids: HashMap::new(),
            connections: Slab::new(),
            events: VecDeque::new(),
            io: VecDeque::new(),
        })
    }

    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn poll_io(&mut self) -> Option<Io> {
        self.io.pop_front()
    }

    pub fn handle(&mut self, remote: SocketAddrV6, local: SocketAddrV6, data: Bytes) {
        let packet = match Packet::decode(data.clone()) {
            Ok(x) => x,
            Err(HeaderError::UnsupportedVersion(id)) => {
                // Negotiate versions
                let mut buf = Vec::<u8>::new();
                buf.reserve_exact(17);
                buf.put_u8(0b10000000);  // flags
                buf.put_u64::<BigEndian>(id.0);
                buf.put_u32::<BigEndian>(0); // version negotiation packet
                buf.put_u32::<BigEndian>(0x0a1a2a3a); // reserved version
                buf.put_u32::<BigEndian>(VERSION); // supported version
                self.transmit(remote, buf.into());
                return;
            }
            Err(_) => {
                trace!(self.log, "dropping packet with malformed header");
                return;
            }
        };

        //
        // Handle packet on existing connection, if any
        //

        if let Some(&i) = match packet.header {
            Header::Long { ref id, .. } | Header::Short { id: Some(ref id), .. } | Header::VersionNegotiate { ref id } => self.connection_ids.get(id),
            _ => None
        } {
            self.handle_connected(ConnectionHandle(i), remote, packet);
            return;
        }

        //
        // Potentially create a new connection
        //

        if self.config.listen.is_none() {
            trace!(self.log, "dropping packet from unknown connection");
            return;
        }
        if let Header::Long { ty, id, number } = packet.header {
            // MAY buffer non-initial packets a little for better 0RTT behavior
            if ty == packet::INITIAL && data.len() >= MIN_INITIAL_SIZE {
                self.handle_initial(remote, id, number, packet.payload);
                return;
            }
        }
        // No version, no known connection? No service.
        trace!(self.log, "dropping non-initial packet from unknown connection");
    }

    pub fn connect(&mut self, local: SocketAddrV6, remote: SocketAddrV6) -> Result<ConnectionHandle> {
        let mut tls = Ssl::new(&self.tls)?;
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { remote });
        let tls = match tls.connect(MemoryStream::new()) {
            Ok(_) => unreachable!(),
            Err(HandshakeError::WouldBlock(tls)) => tls,
            Err(e) => return Err(e.into()),
        };
        let conn = self.add_connection(tls);

        let mut buf = Vec::<u8>::new();
        buf.reserve_exact(MIN_INITIAL_SIZE);
        encode_long_header(&mut buf, packet::INITIAL, self.connections[conn.0].id, self.connections[conn.0].get_tx_number() as u32);
        match self.connections[conn.0].state.as_mut().unwrap() {
            &mut State::Handshake(ref mut x) => frame::stream(&mut buf, 0, None, true, false, &x.tls.get_mut().take_outgoing()),
            _ => unreachable!()
        }
        if buf.len() < MIN_INITIAL_SIZE {
            buf.resize(MIN_INITIAL_SIZE, frame::tag::PADDING);
        }
        self.transmit(remote, buf.into());
        Ok(conn)
    }

    fn transmit(&mut self, destination: SocketAddrV6, packet: Box<[u8]>) {
        self.io.push_back(Io::Transmit { destination, packet });
    }

    fn add_connection(&mut self, tls: MidHandshakeSslStream<MemoryStream>) -> ConnectionHandle {
        let mut streams = HashMap::with_capacity(1);
        streams.insert(0, Stream::new());
        let i = self.connections.insert(Connection {
            state: Some(State::Handshake(state::Handshake { tls })),
            id: ConnectionId(self.rng.gen()),
            tx_packet_number: self.initial_packet_number.sample(&mut self.rng).into(),
            streams,
        });
        self.connection_ids.insert(self.connections[i].id, i);
        ConnectionHandle(i)
    }

    fn handle_initial(&mut self, remote: SocketAddrV6, id: ConnectionId, packet_number: u32, payload: Bytes) {
        let mut stream = MemoryStream::new();
        for frame in frame::Iter::new(payload) {
            match frame {
                Frame::Padding => {}
                Frame::Stream { id, data, .. } => {
                    if id != 0 { return; } // Invalid packet
                    stream.extend_incoming(&data[..]);
                }
                _ => { return; } // Invalid packet
            }
        }

        let mut tls = Ssl::new(&self.tls).unwrap(); // TODO: is this reliable?
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { remote });
        let mut tls = SslStreamBuilder::new(tls, stream);
        match tls.stateless() {
            Ok(()) => {
                match tls.accept() {
                    Ok(_) => unreachable!(),
                    Err(HandshakeError::WouldBlock(tls)) => {
                        trace!(self.log, "stateless handshake complete");
                        let id = self.add_connection(tls);
                        self.events.push_back(Event::Connected(id));
                    }
                    Err(e) => {
                        debug!(self.log, "accept failed"; "reason" => %e);
                    }
                }
            }
            Err(e) => {
                trace!(self.log, "stateless handshake failed"; "reason" => %e);
                let data = tls.get_mut().take_outgoing();
                if data.len() != 0 {
                    trace!(self.log, "responding statelessly");
                    let mut buf = Vec::<u8>::new();
                    buf.reserve_exact(17 + data.len());
                    encode_long_header(&mut buf, packet::RETRY, id, packet_number);
                    frame::stream(&mut buf, 0, None, true, false, &data);
                    self.transmit(remote, buf.into());
                } else {
                    debug!(self.log, "stateless handshake failed"; "reason" => %e);
                }
            }
        }
    }

    fn handle_connected(&mut self, conn: ConnectionHandle, remote: SocketAddrV6, packet: Packet) {
        trace!(self.log, "connection got packet"; "id" => conn.0, "len" => packet.payload.len());
        match self.connections[conn.0].state.take().unwrap() {
            State::Handshake(mut state) => {
                match packet.header {
                    Header::Long { ty: packet::RETRY, .. } => {} // Proceed with handshake
                    Header::Long { .. } => { unimplemented!() }
                    Header::VersionNegotiate { .. } => {
                        // TODO: MUST ignore if supported version is listed
                        self.connections.remove(conn.0);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::VersionMismatch });
                        return;
                    }
                    // TODO: SHOULD buffer these.
                    Header::Short { .. } => {
                        self.connections[conn.0].state = Some(State::Handshake(state));
                        return;
                    }
                }
                for frame in frame::Iter::new(packet.payload) {
                    match frame {
                        Frame::Padding => {}
                        Frame::Stream { id: 0, data, .. } => {
                            state.tls.get_mut().extend_incoming(&data[..]);
                        }
                        _ => {
                            // Is silently ignoring inappropriate/invalid frames correct?
                            debug!(self.log, "unexpected frame in RETRY"; "frame" => ?frame);
                        } 
                    }
                }
                self.connections[conn.0].state = Some(match state.tls.handshake() {
                    Ok(tls) => {
                        trace!(self.log, "handshake complete");
                        self.events.push_back(Event::Connected(conn));
                        State::Established(state::Established { tls })
                    }
                    Err(HandshakeError::WouldBlock(mut tls)) => {
                        trace!(self.log, "handshake retry");
                        let mut buf = Vec::<u8>::new();
                        buf.reserve_exact(MIN_INITIAL_SIZE);
                        encode_long_header(&mut buf, packet::INITIAL, self.connections[conn.0].id, self.connections[conn.0].get_tx_number() as u32);
                        frame::stream(&mut buf, 0, None, true, false, &tls.get_mut().take_outgoing());
                        if buf.len() < MIN_INITIAL_SIZE {
                            buf.resize(MIN_INITIAL_SIZE, frame::tag::PADDING);
                        }
                        self.transmit(remote, buf.into());
                        State::Handshake(state::Handshake { tls })
                    },
                    Err(e) => {
                        debug!(self.log, "handshake failed"; "reason" => %e);
                        self.connections.remove(conn.0);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::HandshakeFailed(e.into()) });
                        return;
                    }
                })
            }
            State::Established(state) => {
                // TODO
                self.connections[conn.0].state = Some(State::Established(state))
            }
        }
    }
}

fn encode_long_header(buf: &mut Vec<u8>, ty: u8, id: ConnectionId, packet: u32) {
    buf.put_u8(0b10000000 | ty);
    buf.put_u64::<BigEndian>(id.0);
    buf.put_u32::<BigEndian>(VERSION);
    buf.put_u32::<BigEndian>(packet)
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
    state: Option<State>,
    tx_packet_number: u64,
    streams: HashMap<u64, Stream>,
}

impl Connection {
    fn get_tx_number(&mut self) -> u64 {
        let x = self.tx_packet_number;
        self.tx_packet_number += 1;
        // TODO: Handle packet number overflow
        x
    }
}

struct Stream {
}

impl Stream {
    fn new() -> Self { Self {} }
}

enum Header {
    Long {
        ty: u8,
        id: ConnectionId,
        number: u32,
    },
    Short {
        ty: u8,
        id: Option<ConnectionId>,
        number: u32,
    },
    VersionNegotiate {
        id: ConnectionId
    }
}

struct Packet {
    header: Header,
    payload: Bytes,
}

#[derive(Copy, Clone, Debug, Fail)]
enum HeaderError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion(ConnectionId),
    #[fail(display = "invalid header")]
    InvalidHeader,
}

impl From<from_bytes::TooShort> for HeaderError {
    fn from(_: from_bytes::TooShort) -> Self { HeaderError::InvalidHeader }
}

impl Packet {
    fn decode(mut packet: Bytes) -> ::std::result::Result<Self, HeaderError> {
        let ty = packet.take::<u8>()?;
        let long = ty & 0x80 != 0;
        let ty = ty & !0x80;
        if long {
            let id = ConnectionId(packet.take()?);
            let version: u32 = packet.take()?;
            Ok(match version {
                0 => Packet {
                    header: Header::VersionNegotiate { id },
                    payload: packet,
                },
                VERSION => Packet {
                    header: Header::Long { ty, id, number: packet.take()? },
                    payload: packet,
                },
                _ => return Err(HeaderError::UnsupportedVersion(id)),
            })
        } else {
            let id = if ty & 0x40 == 0 { Some(ConnectionId(packet.take()?)) } else { None };
            let short_ty = ty & 0b00011111;
            let number = match short_ty {
                0x1F => packet.take::<u8>()? as u32,
                0x1E => packet.take::<u16>()? as u32,
                0x1D => packet.take::<u32>()?,
                _ => { return Err(HeaderError::InvalidHeader); }
            };
            Ok(Packet {
                header: Header::Short { ty, id, number },
                payload: packet
            })
        }
    }
}

enum State {
    Handshake(state::Handshake),
    Established(state::Established),
}

mod state {
    use super::*;

    pub struct Handshake {
        pub tls: MidHandshakeSslStream<MemoryStream>,
    }

    pub struct Established {
        pub tls: SslStream<MemoryStream>,
    }
}

struct CookieFactory {
    mac_key: [u8; 64]
}

const COOKIE_MAC_BYTES: usize = 64;

// remote ip and port are taken from the underlying transport
#[derive(Serialize, Deserialize)]
struct Cookie {
    timestamp: u64,
}

impl CookieFactory {
    fn new<R: Rng>(rng: &mut R) -> Self {
        let mut mac_key = [0; 64];
        rng.fill_bytes(&mut mac_key);
        Self {
            mac_key
        }
    }

    fn generate(&self, tls: &mut SslRef, out: &mut [u8]) -> usize {
        let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
        let cookie = Cookie {
            timestamp: duration_ms(SystemTime::now().duration_since(UNIX_EPOCH).unwrap()),
        };
        let cap = out.len();
        let (len, out) = {
            let mut cursor = io::Cursor::new(out);
            bincode::serialize_into(&mut cursor, &cookie, bincode::Bounded((cap - COOKIE_MAC_BYTES) as u64)).unwrap();
            (cursor.position() as usize, cursor.into_inner())
        };
        let mac = self.generate_mac(conn, &out[0..len]);
        out[len..len+COOKIE_MAC_BYTES].copy_from_slice(&mac);
        len + COOKIE_MAC_BYTES
    }

    fn generate_mac(&self, conn: &ConnectionInfo, data: &[u8]) -> [u8; COOKIE_MAC_BYTES] {
        let mut mac = Blake2b::new_keyed(&self.mac_key, COOKIE_MAC_BYTES);
        mac.process(&conn.remote.ip().octets());
        {
            let mut buf = [0; 2];
            BigEndian::write_u16(&mut buf, conn.remote.port());
            mac.process(&buf);
        }
        mac.process(data);
        let mut result = [0; COOKIE_MAC_BYTES];
        mac.variable_result(&mut result).unwrap();
        result
    }

    fn verify(&self, tls: &mut SslRef, cookie_data: &[u8]) -> bool {
        if cookie_data.len() < COOKIE_MAC_BYTES { return false; }
        let (cookie_data, mac) = cookie_data.split_at(cookie_data.len() - COOKIE_MAC_BYTES);
        let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
        let expected = self.generate_mac(conn, cookie_data);
        if !constant_time_eq(&mac, &expected) { return false; }
        let cookie = if let Ok(x) = bincode::deserialize::<Cookie>(cookie_data) { x } else { return false; };
        // TODO: Finite lifetime
        true
    }
}

fn duration_ms(d: Duration) -> u64 {
    d.as_secs() * 1000 + (d.subsec_nanos() / 1000_000) as u64
}

struct ConnectionInfo {
    remote: SocketAddrV6,
}

lazy_static! {
    static ref CONNECTION_INFO_INDEX: openssl::ex_data::Index<Ssl, ConnectionInfo> = Ssl::new_ex_index().unwrap();
}

#[derive(Debug)]
pub enum Event {
    Connected(ConnectionHandle),
    ConnectionLost {
        connection: ConnectionHandle,
        reason: ConnectionError
    },
}

#[derive(Debug)]
pub enum Io {
    Transmit {
        destination: SocketAddrV6,
        packet: Box<[u8]>,
    },
}

#[derive(Debug, Fail)]
pub enum ConnectionError {
    #[fail(display = "peer doesn't implement any supported version")]
    VersionMismatch,
    #[fail(display = "handshake failed")]
    HandshakeFailed(Error),
}

mod packet {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
}
