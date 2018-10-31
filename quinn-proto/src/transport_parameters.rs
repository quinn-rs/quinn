use std::{
    mem,
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut};

use coding::{BufExt, BufMutExt};
use endpoint::Config;
use packet::ConnectionId;
use {TransportError, MAX_CID_SIZE, MIN_CID_SIZE, VERSION};

// Apply a given macro to a list of all the transport parameters having simple integer types, along with their codes and
// default values. Using this helps us avoid error-prone duplication of the contained information across decoding,
// encoding, and the `Default` impl. Whenever we want to do something with transport parameters, we'll handle the bulk
// of cases by writing a macro that takes a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro!{
            // name (id): type = default,
            initial_max_stream_data_bidi_local(0x0000): u32 = 0,
            initial_max_stream_data_bidi_remote(0x000a): u32 = 0,
            initial_max_stream_data_uni(0x000b): u32 = 0,
            initial_max_data(0x0001): u32 = 0,

            initial_max_bidi_streams(0x0002): u16 = 0,
            initial_max_uni_streams(0x0008): u16 = 0,

            idle_timeout(0x0003): u16 = 0,
            max_packet_size(0x0005): u16 = 65527,
            ack_delay_exponent(0x0007): u8 = 3,
            max_ack_delay(0x000c): u8 = 25,
        }
    };
}

macro_rules! make_struct {
    {$($name:ident ($code:expr) : $ty:ty = $default:expr,)*} => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $(pub $name : $ty,)*

            pub disable_migration: bool,
        }

        impl Default for TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            fn default() -> Self {
                Self {
                    $($name: $default,)*

                    disable_migration: false,
                }
            }
        }
    }
}

apply_params!(make_struct);

impl TransportParameters {
    pub fn new(config: &Config) -> Self {
        TransportParameters {
            initial_max_bidi_streams: config.max_remote_bi_streams,
            initial_max_uni_streams: config.max_remote_uni_streams,
            initial_max_data: config.receive_window,
            initial_max_stream_data_bidi_local: config.stream_receive_window,
            initial_max_stream_data_bidi_remote: config.stream_receive_window,
            initial_max_stream_data_uni: config.stream_receive_window,
            idle_timeout: config.idle_timeout,
            max_ack_delay: 0, // Unimplemented
            ..Self::default()
        }
    }
}

pub struct ClientTransportParameters {
    pub params: TransportParameters,
}

pub struct ServerTransportParameters {
    pub params: TransportParameters,
    pub original_connection_id: Option<ConnectionId>,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub preferred_address: Option<PreferredAddress>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PreferredAddress {
    address: SocketAddr,
    connection_id: ConnectionId,
    stateless_reset_token: [u8; 16],
}

impl PreferredAddress {
    fn wire_size(&self) -> u16 {
        let ip_len = match self.address {
            SocketAddr::V4(_) => 4,
            SocketAddr::V6(_) => 16,
        };
        2 + ip_len + 3 + self.connection_id.len() as u16 + 16
    }

    fn write<W: BufMut>(&self, w: &mut W) {
        match self.address {
            SocketAddr::V4(ref x) => {
                w.write::<u8>(4);
                w.write::<u8>(4);
                w.put_slice(&x.ip().octets());
            }
            SocketAddr::V6(ref x) => {
                w.write::<u8>(6);
                w.write::<u8>(16);
                w.put_slice(&x.ip().octets());
            }
        }
        w.write::<u16>(self.address.port());
        w.write::<u8>(self.connection_id.len() as u8);
        w.put_slice(&self.connection_id);
        w.put_slice(&self.stateless_reset_token);
    }

    fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        if r.remaining() < 2 {
            return Err(Error::Malformed);
        }
        let ip_ver = r.get::<u8>().unwrap();
        let ip_len = r.get::<u8>().unwrap();
        if r.remaining() < ip_len as usize {
            return Err(Error::Malformed);
        }
        let ip = match (ip_ver, ip_len) {
            (4, 4) => {
                let mut bytes = [0; 4];
                r.copy_to_slice(&mut bytes);
                IpAddr::V4(bytes.into())
            }
            (6, 16) => {
                let mut bytes = [0; 16];
                r.copy_to_slice(&mut bytes);
                IpAddr::V6(bytes.into())
            }
            _ => {
                return Err(Error::Malformed);
            }
        };
        if r.remaining() < 3 {
            return Err(Error::Malformed);
        }
        let port = r.get::<u16>().unwrap();
        let cid_len = r.get::<u8>().unwrap();
        if r.remaining() < cid_len as usize
            || (cid_len != 0 && (cid_len < MIN_CID_SIZE as u8 || cid_len > MAX_CID_SIZE as u8))
        {
            return Err(Error::Malformed);
        }
        let mut stage = [0; MAX_CID_SIZE];
        r.copy_to_slice(&mut stage[0..cid_len as usize]);
        let cid = ConnectionId::new(&stage[0..cid_len as usize]);
        if r.remaining() < 16 {
            return Err(Error::Malformed);
        }
        let mut token = [0; 16];
        r.copy_to_slice(&mut token);
        Ok(Self {
            address: SocketAddr::new(ip, port),
            connection_id: cid,
            stateless_reset_token: token,
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Fail)]
pub enum Error {
    #[fail(display = "version negotiation was tampered with")]
    VersionNegotiation,
    #[fail(display = "parameter had illegal value")]
    IllegalValue,
    #[fail(display = "parameters were malformed")]
    Malformed,
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::VersionNegotiation => TransportError::VERSION_NEGOTIATION_ERROR,
            Error::IllegalValue | Error::Malformed => TransportError::TRANSPORT_PARAMETER_ERROR,
        }
    }
}

// State to check for duplicate transport parameters.
macro_rules! param_state {
    {$($name:ident ($code:expr) : $ty:ty = $default:expr,)*} => {
        struct ParamState {
            $($name: bool,)*
        }
    }
}
apply_params!(param_state);

impl TransportParameters {
    pub fn write<W: BufMut>(&self, w: &mut W) {
        macro_rules! write_params {
            {$($name:ident ($code:expr) : $ty:ty = $default:expr,)*} => {
                $(
                    if self.$name != $default {
                        w.write::<u16>($code);
                        w.write::<u16>(mem::size_of::<$ty>() as u16);
                        w.write(self.$name);
                    }
                )*
            }
        }
        apply_params!(write_params);

        if self.disable_migration {
            w.write::<u16>(0x0009);
            w.write::<u16>(0);
        }
    }

    pub fn read<R: Buf>(&mut self, id: u16, len: u16, r: &mut R, got: &mut ParamState) -> Result<(), Error> {
        if id == 0x0009 {
            if len != 0 || self.disable_migration {
                return Err(Error::Malformed);
            }
            self.disable_migration = true;
        }
        else {
            macro_rules! parse {
                {$($name:ident ($code:expr) : $ty:ty = $default:expr,)*} => {
                    match id {
                        $($code => {
                            if len != mem::size_of::<$ty>() as u16 || got.$name { return Err(Error::Malformed); }
                            self.$name = r.get().unwrap();
                            got.$name = true;
                        })*
                        _ => r.advance(len as usize),
                    }
                }
            }
            apply_params!(parse);
        }

        if self.ack_delay_exponent > 20 {
            return Err(Error::IllegalValue);
        }

        Ok(())
    }
}

impl ClientTransportParameters {
    pub fn new(config: &Config) -> Self {
        ClientTransportParameters {
            params: TransportParameters::new(config)
        }
    }

    pub fn write<W: BufMut>(&self, w: &mut W) {
        w.write::<u32>(VERSION); // Initially requested version

        let mut buf = Vec::new();

        self.params.write(&mut buf);

        w.write::<u16>(buf.len() as u16);
        w.put_slice(&buf);
    }

    pub fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        if r.remaining() < 26 {
            return Err(Error::Malformed);
        }
        // We only support one version, so there is no validation to do here.
        r.get::<u32>().unwrap();

        let params_len = r.get::<u16>().unwrap();
        if params_len as usize != r.remaining() {
            return Err(Error::Malformed);
        }

        let params_len = r.get::<u16>().unwrap();
        if params_len as usize != r.remaining() {
            return Err(Error::Malformed);
        }

        let mut params = TransportParameters::default();

        // State to check for duplicate transport parameters.
        macro_rules! make_guard {
            {$($name:ident ($code:expr) : $ty:ty = $default:expr,)*} => {{
                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(make_guard);

        while r.has_remaining() {
            if r.remaining() < 4 {
                return Err(Error::Malformed);
            }
            let id = r.get::<u16>().unwrap();
            let len = r.get::<u16>().unwrap();
            if r.remaining() < len as usize {
                return Err(Error::Malformed);
            }

            match id {
                0x000d => return Err(Error::Malformed),
                0x0006 => return Err(Error::Malformed),
                0x0004 => return Err(Error::Malformed),
                _ => params.read(id, len, r, &mut got)?
            }
        }

        Ok(ClientTransportParameters {params})
    }
}

impl ServerTransportParameters {
    pub fn write<W: BufMut>(&self, w: &mut W) {
        w.write::<u32>(VERSION); // Negotiated version
        w.write::<u8>(8); // Bytes of supported versions
        w.write::<u32>(0x0a1a_2a3a); // Reserved version
        w.write::<u32>(VERSION); // Real supported version

        let mut buf = Vec::new();

        self.params.write(&mut buf);

        if let Some(ref x) = self.original_connection_id {
            buf.write::<u16>(0x000d);
            buf.write::<u16>(x.len() as u16);
            buf.put_slice(x);
        }

        if let Some(ref x) = self.stateless_reset_token {
            buf.write::<u16>(0x0006);
            buf.write::<u16>(16);
            buf.put_slice(x);
        }

        if let Some(ref x) = self.preferred_address {
            buf.write::<u16>(0x0004);
            buf.write::<u16>(x.wire_size());
            x.write(&mut buf);
        }

        w.write::<u16>(buf.len() as u16);
        w.put_slice(&buf);
    }

    pub fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        if r.remaining() < 31 {
            return Err(Error::Malformed);
        }
        let negotiated = r.get::<u32>().unwrap();
        if negotiated != VERSION {
            return Err(Error::VersionNegotiation);
        }
        let supported_bytes = r.get::<u8>().unwrap();
        if supported_bytes < 4 || supported_bytes > 252 || supported_bytes % 4 != 0 {
            return Err(Error::Malformed);
        }
        let mut found = false;
        for _ in 0..(supported_bytes / 4) {
            found |= r.get::<u32>().unwrap() == negotiated;
        }
        if !found {
            return Err(Error::VersionNegotiation);
        }

        let params_len = r.get::<u16>().unwrap();
        if params_len as usize != r.remaining() {
            return Err(Error::Malformed);
        }

        let mut params = TransportParameters::default();
        let mut server_params = ServerTransportParameters {
            params,
            original_connection_id: None,
            stateless_reset_token: None,
            preferred_address: None,
        };

        // State to check for duplicate transport parameters.
        macro_rules! make_guard {
            {$($name:ident ($code:expr) : $ty:ty = $default:expr,)*} => {{
                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(make_guard);

        while r.has_remaining() {
            if r.remaining() < 4 {
                return Err(Error::Malformed);
            }
            let id = r.get::<u16>().unwrap();
            let len = r.get::<u16>().unwrap();
            if r.remaining() < len as usize {
                return Err(Error::Malformed);
            }

            match id {
                0x000d => {
                    if len < MIN_CID_SIZE as u16
                        || len > MAX_CID_SIZE as u16
                        || server_params.original_connection_id.is_some()
                    {
                        return Err(Error::Malformed);
                    }
                    let mut staging = [0; MAX_CID_SIZE];
                    r.copy_to_slice(&mut staging[0..len as usize]);
                    server_params.original_connection_id =
                        Some(ConnectionId::new(&staging[0..len as usize]));
                }
                0x0006 => {
                    if len != 16 || server_params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; 16];
                    r.copy_to_slice(&mut tok);
                    server_params.stateless_reset_token = Some(tok);
                }
                0x0004 => {
                    if server_params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    server_params.preferred_address =
                        Some(PreferredAddress::read(&mut r.take(len as usize))?);
                }
                _ => params.read(id, len, r, &mut got)?
            }
        }

        server_params.params = params;
        Ok(server_params)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::IntoBuf;

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        
        let config = Config {
            max_remote_bi_streams: 16,
            max_remote_uni_streams: 16,
            max_packet_size: 1200,
            ..Config::default()
        };

        let server_params = ServerTransportParameters {
            params: TransportParameters::new(&config),
            preferred_address: Some(PreferredAddress {
                address: SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), 42),
                connection_id: ConnectionId::new(&[]),
                stateless_reset_token: [0xab; 16],
            }),
            original_connection_id: None,
            stateless_reset_token: None,
        };

        server_params.write(&mut buf);
        assert_eq!(
            ServerTransportParameters::read(&mut buf.into_buf()).unwrap(),
            server_params
        );
    }
}
