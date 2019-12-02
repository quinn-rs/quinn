use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use bytes::{buf::ext::BufExt as _, Buf, BufMut};
use err_derive::Error;

use crate::{
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    crypto,
    shared::{ConnectionId, ResetToken, ServerConfig},
    Side, TransportConfig, TransportError, VarInt, MAX_CID_SIZE, REM_CID_COUNT, RESET_TOKEN_SIZE,
};

// Apply a given macro to a list of all the transport parameters having integer types, along with
// their codes and default values. Using this helps us avoid error-prone duplication of the
// contained information across decoding, encoding, and the `Default` impl. Whenever we want to do
// something with transport parameters, we'll handle the bulk of cases by writing a macro that takes
// a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro! {
            // name (id) = default,
            idle_timeout(0x0001) = 0,
            max_packet_size(0x0003) = 65527,

            initial_max_data(0x0004) = 0,
            initial_max_stream_data_bidi_local(0x0005) = 0,
            initial_max_stream_data_bidi_remote(0x0006) = 0,
            initial_max_stream_data_uni(0x0007) = 0,

            initial_max_streams_bidi(0x0008) = 0,
            initial_max_streams_uni(0x0009) = 0,

            ack_delay_exponent(0x000a) = 3,
            max_ack_delay(0x000b) = 25,
            active_connection_id_limit(0x000e) = 0,
        }
    };
}

macro_rules! make_struct {
    {$($name:ident ($code:expr) = $default:expr,)*} => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $(pub $name : u64,)*

            pub disable_active_migration: bool,
            pub max_datagram_frame_size: Option<VarInt>,

            // Server-only
            pub original_connection_id: Option<ConnectionId>,
            pub stateless_reset_token: Option<ResetToken>,
            pub preferred_address: Option<PreferredAddress>,
        }

        impl Default for TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            fn default() -> Self {
                Self {
                    $($name: $default,)*

                    disable_active_migration: false,
                    max_datagram_frame_size: None,

                    original_connection_id: None,
                    stateless_reset_token: None,
                    preferred_address: None,
                }
            }
        }
    }
}

apply_params!(make_struct);

impl TransportParameters {
    pub fn new<S>(config: &TransportConfig, server_config: Option<&ServerConfig<S>>) -> Self
    where
        S: crypto::Session,
    {
        TransportParameters {
            initial_max_streams_bidi: config.stream_window_bidi,
            initial_max_streams_uni: config.stream_window_uni,
            initial_max_data: config.receive_window,
            initial_max_stream_data_bidi_local: config.stream_receive_window,
            initial_max_stream_data_bidi_remote: config.stream_receive_window,
            initial_max_stream_data_uni: config.stream_receive_window,
            idle_timeout: config.idle_timeout,
            max_ack_delay: 0,
            disable_active_migration: server_config.map_or(false, |c| !c.migration),
            active_connection_id_limit: REM_CID_COUNT,
            max_datagram_frame_size: config
                .datagram_receive_buffer_size
                .map(|x| (x.min(u16::max_value().into()) as u16).into()),
            ..Self::default()
        }
    }

    /// Check that these parameters are legal when resuming from
    /// certain cached parameters
    pub fn validate_0rtt(&self, cached: &TransportParameters) -> Result<(), TransportError> {
        if cached.initial_max_data < self.initial_max_data
            || cached.initial_max_stream_data_bidi_local < self.initial_max_stream_data_bidi_local
            || cached.initial_max_stream_data_bidi_remote < self.initial_max_stream_data_bidi_remote
            || cached.initial_max_stream_data_uni < self.initial_max_stream_data_uni
            || cached.initial_max_streams_bidi < self.initial_max_streams_bidi
            || cached.initial_max_streams_uni < self.initial_max_streams_uni
            || cached.max_datagram_frame_size < self.max_datagram_frame_size
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "0-RTT accepted with incompatible transport parameters",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PreferredAddress {
    address_v4: Option<SocketAddrV4>,
    address_v6: Option<SocketAddrV6>,
    connection_id: ConnectionId,
    stateless_reset_token: [u8; RESET_TOKEN_SIZE],
}

impl PreferredAddress {
    fn wire_size(&self) -> u16 {
        4 + 2 + 16 + 2 + 1 + self.connection_id.len() as u16 + 16
    }

    fn write<W: BufMut>(&self, w: &mut W) {
        w.write(self.address_v4.map_or(Ipv4Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v4.map_or(0, |x| x.port()));
        w.write(self.address_v6.map_or(Ipv6Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v6.map_or(0, |x| x.port()));
        w.write::<u8>(self.connection_id.len() as u8);
        w.put_slice(&self.connection_id);
        w.put_slice(&self.stateless_reset_token);
    }

    fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        let ip_v4 = r.get::<Ipv4Addr>()?;
        let port_v4 = r.get::<u16>()?;
        let ip_v6 = r.get::<Ipv6Addr>()?;
        let port_v6 = r.get::<u16>()?;
        let cid_len = r.get::<u8>()?;
        if r.remaining() < cid_len as usize || cid_len > MAX_CID_SIZE as u8 {
            return Err(Error::Malformed);
        }
        let mut stage = [0; MAX_CID_SIZE];
        r.copy_to_slice(&mut stage[0..cid_len as usize]);
        let cid = ConnectionId::new(&stage[0..cid_len as usize]);
        if r.remaining() < 16 {
            return Err(Error::Malformed);
        }
        let mut token = [0; RESET_TOKEN_SIZE];
        r.copy_to_slice(&mut token);
        let address_v4 = if ip_v4.is_unspecified() && port_v4 == 0 {
            None
        } else {
            Some(SocketAddrV4::new(ip_v4, port_v4))
        };
        let address_v6 = if ip_v6.is_unspecified() && port_v6 == 0 {
            None
        } else {
            Some(SocketAddrV6::new(ip_v6, port_v6, 0, 0))
        };
        if address_v4.is_none() && address_v6.is_none() {
            return Err(Error::IllegalValue);
        }
        Ok(Self {
            address_v4,
            address_v6,
            connection_id: cid,
            stateless_reset_token: token,
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum Error {
    #[error(display = "version negotiation was tampered with")]
    VersionNegotiation,
    #[error(display = "parameter had illegal value")]
    IllegalValue,
    #[error(display = "parameters were malformed")]
    Malformed,
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::VersionNegotiation => TransportError::VERSION_NEGOTIATION_ERROR(""),
            Error::IllegalValue => TransportError::TRANSPORT_PARAMETER_ERROR("illegal value"),
            Error::Malformed => TransportError::TRANSPORT_PARAMETER_ERROR("malformed"),
        }
    }
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Error::Malformed
    }
}

impl TransportParameters {
    pub fn write<W: BufMut>(&self, w: &mut W) {
        let mut buf = Vec::new();

        macro_rules! write_params {
            {$($name:ident ($code:expr) = $default:expr,)*} => {
                $(
                    if self.$name != $default {
                        buf.write::<u16>($code);
                        buf.write::<u16>(VarInt::from_u64(self.$name).expect("value too large").size() as u16);
                        buf.write_var(self.$name);
                    }
                )*
            }
        }
        apply_params!(write_params);

        // Add a reserved parameter to keep people on their toes
        buf.write::<u16>(31 * 5 + 27);
        buf.write::<u16>(0);

        if let Some(ref x) = self.original_connection_id {
            buf.write::<u16>(0x0000);
            buf.write::<u16>(x.len() as u16);
            buf.put_slice(x);
        }

        if let Some(ref x) = self.stateless_reset_token {
            buf.write::<u16>(0x0002);
            buf.write::<u16>(16);
            buf.put_slice(x);
        }

        if self.disable_active_migration {
            buf.write::<u16>(0x000c);
            buf.write::<u16>(0);
        }

        if let Some(x) = self.max_datagram_frame_size {
            buf.write::<u16>(0x0020);
            buf.write::<u16>(x.size() as u16);
            buf.write(x);
        }

        if let Some(ref x) = self.preferred_address {
            buf.write::<u16>(0x000d);
            buf.write::<u16>(x.wire_size());
            x.write(&mut buf);
        }

        w.write::<u16>(buf.len() as u16);
        w.put_slice(&buf);
    }

    pub fn read<R: Buf>(side: Side, r: &mut R) -> Result<Self, Error> {
        // Initialize to protocol-specified defaults
        let mut params = TransportParameters::default();

        let params_len = r.get::<u16>()?;
        if params_len as usize != r.remaining() {
            return Err(Error::Malformed);
        }

        // State to check for duplicate transport parameters.
        macro_rules! param_state {
            {$($name:ident ($code:expr) = $default:expr,)*} => {{
                struct ParamState {
                    $($name: bool,)*
                }

                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(param_state);

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
                0x0000 => {
                    if len > MAX_CID_SIZE as u16 || params.original_connection_id.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut staging = [0; MAX_CID_SIZE];
                    r.copy_to_slice(&mut staging[0..len as usize]);
                    params.original_connection_id =
                        Some(ConnectionId::new(&staging[0..len as usize]));
                }
                0x0002 => {
                    if len != 16 || params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; RESET_TOKEN_SIZE];
                    r.copy_to_slice(&mut tok);
                    params.stateless_reset_token = Some(tok.into());
                }
                0x000c => {
                    if len != 0 || params.disable_active_migration {
                        return Err(Error::Malformed);
                    }
                    params.disable_active_migration = true;
                }
                0x000d => {
                    if params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.preferred_address =
                        Some(PreferredAddress::read(&mut r.take(len as usize))?);
                }
                0x0020 => {
                    if len > 8 || params.max_datagram_frame_size.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.max_datagram_frame_size = Some(r.get().unwrap());
                }
                _ => {
                    macro_rules! parse {
                        {$($name:ident ($code:expr) = $default:expr,)*} => {
                            match id {
                                $($code => {
                                    params.$name = r.get_var()?;
                                    if len != VarInt::from_u64(params.$name).unwrap().size() as u16 || got.$name { return Err(Error::Malformed); }
                                    got.$name = true;
                                })*
                                _ => r.advance(len as usize),
                            }
                        }
                    }
                    apply_params!(parse);
                }
            }
        }

        // Semantic validation
        if params.ack_delay_exponent > 20
            || params.max_ack_delay >= 1 << 14
            || (side.is_server()
                && (params.original_connection_id.is_some()
                    || params.stateless_reset_token.is_some()
                    || params.preferred_address.is_some()))
        {
            return Err(Error::IllegalValue);
        }

        Ok(params)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        let params = TransportParameters {
            initial_max_streams_bidi: 16,
            initial_max_streams_uni: 16,
            ack_delay_exponent: 2,
            max_packet_size: 1200,
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: None,
                connection_id: ConnectionId::new(&[]),
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE],
            }),
            ..TransportParameters::default()
        };
        params.write(&mut buf);
        assert_eq!(
            TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap(),
            params
        );
    }
}
