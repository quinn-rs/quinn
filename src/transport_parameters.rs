//! QUIC connection transport parameters
//!
//! The `TransportParameters` type is used to represent the transport parameters
//! negotiated by peers while establishing a QUIC connection. This process
//! happens as part of the establishment of the TLS session. As such, the types
//! contained in this modules should generally only be referred to by custom
//! implementations of the `crypto::Session` trait.

use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use bytes::{Buf, BufMut};
use rand::{Rng as _, RngCore, seq::SliceRandom as _};
use thiserror::Error;

use crate::{
    LOC_CID_COUNT, MAX_CID_SIZE, MAX_STREAM_COUNT, RESET_TOKEN_SIZE, ResetToken, Side,
    TIMER_GRANULARITY, TransportError, VarInt,
    cid_generator::ConnectionIdGenerator,
    cid_queue::CidQueue,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    config::{EndpointConfig, ServerConfig, TransportConfig},
    shared::ConnectionId,
};

// Apply a given macro to a list of all the transport parameters having integer types, along with
// their codes and default values. Using this helps us avoid error-prone duplication of the
// contained information across decoding, encoding, and the `Default` impl. Whenever we want to do
// something with transport parameters, we'll handle the bulk of cases by writing a macro that
// takes a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro! {
            // #[doc] name (id) = default,
            /// Milliseconds, disabled if zero
            max_idle_timeout(MaxIdleTimeout) = 0,
            /// Limits the size of UDP payloads that the endpoint is willing to receive
            max_udp_payload_size(MaxUdpPayloadSize) = 65527,

            /// Initial value for the maximum amount of data that can be sent on the connection
            initial_max_data(InitialMaxData) = 0,
            /// Initial flow control limit for locally-initiated bidirectional streams
            initial_max_stream_data_bidi_local(InitialMaxStreamDataBidiLocal) = 0,
            /// Initial flow control limit for peer-initiated bidirectional streams
            initial_max_stream_data_bidi_remote(InitialMaxStreamDataBidiRemote) = 0,
            /// Initial flow control limit for unidirectional streams
            initial_max_stream_data_uni(InitialMaxStreamDataUni) = 0,

            /// Initial maximum number of bidirectional streams the peer may initiate
            initial_max_streams_bidi(InitialMaxStreamsBidi) = 0,
            /// Initial maximum number of unidirectional streams the peer may initiate
            initial_max_streams_uni(InitialMaxStreamsUni) = 0,

            /// Exponent used to decode the ACK Delay field in the ACK frame
            ack_delay_exponent(AckDelayExponent) = 3,
            /// Maximum amount of time in milliseconds by which the endpoint will delay sending
            /// acknowledgments
            max_ack_delay(MaxAckDelay) = 25,
            /// Maximum number of connection IDs from the peer that an endpoint is willing to store
            active_connection_id_limit(ActiveConnectionIdLimit) = 2,
        }
    };
}

macro_rules! make_struct {
    {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
        /// Transport parameters used to negotiate connection-level preferences between peers
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $($(#[$doc])* pub(crate) $name : VarInt,)*

            /// Does the endpoint support active connection migration
            pub(crate) disable_active_migration: bool,
            /// Maximum size for datagram frames
            pub(crate) max_datagram_frame_size: Option<VarInt>,
            /// The value that the endpoint included in the Source Connection ID field of the first
            /// Initial packet it sends for the connection
            pub(crate) initial_src_cid: Option<ConnectionId>,
            /// The endpoint is willing to receive QUIC packets containing any value for the fixed
            /// bit
            pub(crate) grease_quic_bit: bool,

            /// Minimum amount of time in microseconds by which the endpoint is able to delay
            /// sending acknowledgments
            ///
            /// If a value is provided, it implies that the endpoint supports QUIC Acknowledgement
            /// Frequency
            pub(crate) min_ack_delay: Option<VarInt>,

            /// NAT traversal configuration for this connection
            ///
            /// NAT traversal configuration for this connection
            ///
            /// When present, indicates support for QUIC NAT traversal extension
            pub(crate) nat_traversal: Option<NatTraversalConfig>,

            /// Address discovery configuration for this connection
            ///
            /// When present, indicates support for QUIC Address Discovery extension
            pub(crate) address_discovery: Option<AddressDiscoveryConfig>,

            // Server-only
            /// The value of the Destination Connection ID field from the first Initial packet sent
            /// by the client
            pub(crate) original_dst_cid: Option<ConnectionId>,
            /// The value that the server included in the Source Connection ID field of a Retry
            /// packet
            pub(crate) retry_src_cid: Option<ConnectionId>,
            /// Token used by the client to verify a stateless reset from the server
            pub(crate) stateless_reset_token: Option<ResetToken>,
            /// The server's preferred address for communication after handshake completion
            pub(crate) preferred_address: Option<PreferredAddress>,
            /// The randomly generated reserved transport parameter to sustain future extensibility
            /// of transport parameter extensions.
            /// When present, it is included during serialization but ignored during deserialization.
            pub(crate) grease_transport_parameter: Option<ReservedTransportParameter>,

            /// Defines the order in which transport parameters are serialized.
            ///
            /// This field is initialized only for outgoing `TransportParameters` instances and
            /// is set to `None` for `TransportParameters` received from a peer.
            pub(crate) write_order: Option<[u8; TransportParameterId::SUPPORTED.len()]>,
        }

        // We deliberately don't implement the `Default` trait, since that would be public, and
        // downstream crates should never construct `TransportParameters` except by decoding those
        // supplied by a peer.
        impl TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            pub(crate) fn default() -> Self {
                Self {
                    $($name: VarInt::from_u32($default),)*

                    disable_active_migration: false,
                    max_datagram_frame_size: None,
                    initial_src_cid: None,
                    grease_quic_bit: false,
                    min_ack_delay: None,
                    nat_traversal: None,
                    address_discovery: None,

                    original_dst_cid: None,
                    retry_src_cid: None,
                    stateless_reset_token: None,
                    preferred_address: None,
                    grease_transport_parameter: None,
                    write_order: None,
                }
            }
        }
    }
}

apply_params!(make_struct);

impl TransportParameters {
    pub(crate) fn new(
        config: &TransportConfig,
        endpoint_config: &EndpointConfig,
        cid_gen: &dyn ConnectionIdGenerator,
        initial_src_cid: ConnectionId,
        server_config: Option<&ServerConfig>,
        rng: &mut impl RngCore,
    ) -> Self {
        Self {
            initial_src_cid: Some(initial_src_cid),
            initial_max_streams_bidi: config.max_concurrent_bidi_streams,
            initial_max_streams_uni: config.max_concurrent_uni_streams,
            initial_max_data: config.receive_window,
            initial_max_stream_data_bidi_local: config.stream_receive_window,
            initial_max_stream_data_bidi_remote: config.stream_receive_window,
            initial_max_stream_data_uni: config.stream_receive_window,
            max_udp_payload_size: endpoint_config.max_udp_payload_size,
            max_idle_timeout: config.max_idle_timeout.unwrap_or(VarInt(0)),
            disable_active_migration: server_config.is_some_and(|c| !c.migration),
            active_connection_id_limit: if cid_gen.cid_len() == 0 {
                2 // i.e. default, i.e. unsent
            } else {
                CidQueue::LEN as u32
            }
            .into(),
            max_datagram_frame_size: config
                .datagram_receive_buffer_size
                .map(|x| (x.min(u16::MAX.into()) as u16).into()),
            grease_quic_bit: endpoint_config.grease_quic_bit,
            min_ack_delay: Some(
                VarInt::from_u64(u64::try_from(TIMER_GRANULARITY.as_micros()).unwrap()).unwrap(),
            ),
            grease_transport_parameter: Some(ReservedTransportParameter::random(rng)),
            write_order: Some({
                let mut order = std::array::from_fn(|i| i as u8);
                order.shuffle(rng);
                order
            }),
            nat_traversal: config.nat_traversal_config.clone(),
            address_discovery: None, // TODO: Wire up to config when needed
            ..Self::default()
        }
    }

    /// Check that these parameters are legal when resuming from
    /// certain cached parameters
    pub(crate) fn validate_resumption_from(&self, cached: &Self) -> Result<(), TransportError> {
        if cached.active_connection_id_limit > self.active_connection_id_limit
            || cached.initial_max_data > self.initial_max_data
            || cached.initial_max_stream_data_bidi_local > self.initial_max_stream_data_bidi_local
            || cached.initial_max_stream_data_bidi_remote > self.initial_max_stream_data_bidi_remote
            || cached.initial_max_stream_data_uni > self.initial_max_stream_data_uni
            || cached.initial_max_streams_bidi > self.initial_max_streams_bidi
            || cached.initial_max_streams_uni > self.initial_max_streams_uni
            || cached.max_datagram_frame_size > self.max_datagram_frame_size
            || cached.grease_quic_bit && !self.grease_quic_bit
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "0-RTT accepted with incompatible transport parameters",
            ));
        }
        Ok(())
    }

    /// Maximum number of CIDs to issue to this peer
    ///
    /// Consider both a) the active_connection_id_limit from the other end; and
    /// b) LOC_CID_COUNT used locally
    pub(crate) fn issue_cids_limit(&self) -> u64 {
        self.active_connection_id_limit.0.min(LOC_CID_COUNT)
    }

    /// Get the NAT traversal configuration for this connection
    ///
    /// This is a public accessor method for tests and external code that need to
    /// examine the negotiated NAT traversal parameters.
    pub fn nat_traversal_config(&self) -> Option<&NatTraversalConfig> {
        self.nat_traversal.as_ref()
    }
}

/// NAT traversal configuration for a QUIC connection
///
/// This configuration is negotiated as part of the transport parameters and
/// enables QUIC NAT traversal extension functionality.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NatTraversalConfig {
    /// Role of this endpoint in NAT traversal coordination
    pub(crate) role: NatTraversalRole,
    /// Maximum number of candidate addresses to exchange
    pub(crate) max_candidates: VarInt,
    /// Timeout for coordination protocol in milliseconds
    pub(crate) coordination_timeout: VarInt,
    /// Maximum number of concurrent traversal attempts
    pub(crate) max_concurrent_attempts: VarInt,
    /// Peer ID for this endpoint (used for relay functionality)
    pub(crate) peer_id: Option<[u8; 32]>,
}

// Note: NatTraversalConfig is encoded/decoded according to draft-seemann-quic-nat-traversal-01
// which uses a simple format (empty value from client, 1-byte concurrency limit from server)
// rather than a complex custom encoding.
impl NatTraversalConfig {
    /// Create a new NAT traversal configuration
    ///
    /// This is a public constructor for creating NAT traversal configurations
    /// in tests and external code.
    pub fn new(
        role: NatTraversalRole,
        max_candidates: VarInt,
        coordination_timeout: VarInt,
        max_concurrent_attempts: VarInt,
        peer_id: Option<[u8; 32]>,
    ) -> Self {
        Self {
            role,
            max_candidates,
            coordination_timeout,
            max_concurrent_attempts,
            peer_id,
        }
    }

    /// Get the role for this NAT traversal configuration
    pub fn role(&self) -> NatTraversalRole {
        self.role
    }

    /// Get the maximum number of candidates
    pub fn max_candidates(&self) -> VarInt {
        self.max_candidates
    }

    /// Get the coordination timeout
    pub fn coordination_timeout(&self) -> VarInt {
        self.coordination_timeout
    }

    /// Get the maximum concurrent attempts
    pub fn max_concurrent_attempts(&self) -> VarInt {
        self.max_concurrent_attempts
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> Option<[u8; 32]> {
        self.peer_id
    }

    /// Validate NAT traversal configuration for consistency
    pub fn validate(&self) -> Result<(), Error> {
        // Validate max_candidates is reasonable
        if self.max_candidates.0 == 0 || self.max_candidates.0 > 100 {
            return Err(Error::IllegalValue);
        }

        // Validate coordination timeout is reasonable (1s to 60s)
        if self.coordination_timeout.0 < 1000 || self.coordination_timeout.0 > 60000 {
            return Err(Error::IllegalValue);
        }

        // Validate max_concurrent_attempts is reasonable
        if self.max_concurrent_attempts.0 == 0 || self.max_concurrent_attempts.0 > 10 {
            return Err(Error::IllegalValue);
        }

        Ok(())
    }
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(8),
            coordination_timeout: VarInt::from_u32(10000), // 10 seconds
            max_concurrent_attempts: VarInt::from_u32(3),
            peer_id: None,
        }
    }
}

/// Configuration for QUIC Address Discovery extension
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressDiscoveryConfig {
    /// Whether address discovery is enabled
    pub(crate) enabled: bool,
    /// Maximum rate of OBSERVED_ADDRESS frames per path (per second)
    /// Value is limited to 6 bits (0-63)
    pub(crate) max_observation_rate: u8,
    /// Whether to observe addresses for all paths or just primary
    pub(crate) observe_all_paths: bool,
}

impl AddressDiscoveryConfig {
    /// Create a new address discovery configuration
    pub fn new(enabled: bool, max_observation_rate: u8, observe_all_paths: bool) -> Self {
        Self {
            enabled,
            max_observation_rate: max_observation_rate.min(63), // Limit to 6 bits
            observe_all_paths,
        }
    }
    
    /// Apply bootstrap settings for more aggressive observation
    pub fn apply_bootstrap_settings(&mut self) {
        // Enable address discovery if not already enabled
        self.enabled = true;
        // Set maximum allowed observation rate
        self.max_observation_rate = 63; // Maximum 6-bit value
        // Observe all paths for bootstrap nodes
        self.observe_all_paths = true;
    }
}

impl Default for AddressDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default
            max_observation_rate: 10,
            observe_all_paths: false,
        }
    }
}

/// Role of an endpoint in NAT traversal coordination
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NatTraversalRole {
    /// Client endpoint (initiates connections, on-demand)
    Client,
    /// Server endpoint (accepts connections, always reachable)
    Server {
        /// Whether this server can act as a relay for other connections
        can_relay: bool,
    },
    /// Bootstrap/relay endpoint (publicly reachable, coordinates traversal)
    Bootstrap,
}

/// A server's preferred address
///
/// This is communicated as a transport parameter during TLS session establishment.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct PreferredAddress {
    pub(crate) address_v4: Option<SocketAddrV4>,
    pub(crate) address_v6: Option<SocketAddrV6>,
    pub(crate) connection_id: ConnectionId,
    pub(crate) stateless_reset_token: ResetToken,
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
            stateless_reset_token: token.into(),
        })
    }
}

/// Errors encountered while decoding `TransportParameters`
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum Error {
    /// Parameters that are semantically invalid
    #[error("parameter had illegal value")]
    IllegalValue,
    /// Catch-all error for problems while decoding transport parameters
    #[error("parameters were malformed")]
    Malformed,
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::IllegalValue => Self::TRANSPORT_PARAMETER_ERROR("illegal value"),
            Error::Malformed => Self::TRANSPORT_PARAMETER_ERROR("malformed"),
        }
    }
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Self::Malformed
    }
}

impl TransportParameters {
    /// Encode `TransportParameters` into buffer
    pub fn write<W: BufMut>(&self, w: &mut W) {
        for idx in self
            .write_order
            .as_ref()
            .unwrap_or(&std::array::from_fn(|i| i as u8))
        {
            let id = TransportParameterId::SUPPORTED[*idx as usize];
            match id {
                TransportParameterId::ReservedTransportParameter => {
                    if let Some(param) = self.grease_transport_parameter {
                        param.write(w);
                    }
                }
                TransportParameterId::StatelessResetToken => {
                    if let Some(ref x) = self.stateless_reset_token {
                        w.write_var(id as u64);
                        w.write_var(16);
                        w.put_slice(x);
                    }
                }
                TransportParameterId::DisableActiveMigration => {
                    if self.disable_active_migration {
                        w.write_var(id as u64);
                        w.write_var(0);
                    }
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    if let Some(x) = self.max_datagram_frame_size {
                        w.write_var(id as u64);
                        w.write_var(x.size() as u64);
                        w.write(x);
                    }
                }
                TransportParameterId::PreferredAddress => {
                    if let Some(ref x) = self.preferred_address {
                        w.write_var(id as u64);
                        w.write_var(x.wire_size() as u64);
                        x.write(w);
                    }
                }
                TransportParameterId::OriginalDestinationConnectionId => {
                    if let Some(ref cid) = self.original_dst_cid {
                        w.write_var(id as u64);
                        w.write_var(cid.len() as u64);
                        w.put_slice(cid);
                    }
                }
                TransportParameterId::InitialSourceConnectionId => {
                    if let Some(ref cid) = self.initial_src_cid {
                        w.write_var(id as u64);
                        w.write_var(cid.len() as u64);
                        w.put_slice(cid);
                    }
                }
                TransportParameterId::RetrySourceConnectionId => {
                    if let Some(ref cid) = self.retry_src_cid {
                        w.write_var(id as u64);
                        w.write_var(cid.len() as u64);
                        w.put_slice(cid);
                    }
                }
                TransportParameterId::GreaseQuicBit => {
                    if self.grease_quic_bit {
                        w.write_var(id as u64);
                        w.write_var(0);
                    }
                }
                TransportParameterId::MinAckDelayDraft07 => {
                    if let Some(x) = self.min_ack_delay {
                        w.write_var(id as u64);
                        w.write_var(x.size() as u64);
                        w.write(x);
                    }
                }
                TransportParameterId::NatTraversal => {
                    if let Some(ref config) = self.nat_traversal {
                        // Per draft-seemann-quic-nat-traversal-01:
                        // - Client sends empty value to indicate support
                        // - Server sends concurrency limit (1 byte)
                        match config.role {
                            NatTraversalRole::Client => {
                                // Client sends empty value
                                w.write_var(id as u64);
                                w.write_var(0); // Empty value
                            }
                            NatTraversalRole::Server { can_relay: _ } => {
                                // Server sends concurrency limit
                                w.write_var(id as u64);
                                w.write_var(1); // 1 byte for concurrency limit
                                // Use max_concurrent_attempts as concurrency limit
                                let limit = config.max_concurrent_attempts.0.min(255) as u8;
                                w.put_u8(limit);
                            }
                            NatTraversalRole::Bootstrap => {
                                // Bootstrap endpoints act as servers
                                w.write_var(id as u64);
                                w.write_var(1); // 1 byte for concurrency limit
                                let limit = config.max_concurrent_attempts.0.min(255) as u8;
                                w.put_u8(limit);
                            }
                        }
                    }
                }
                TransportParameterId::AddressDiscovery => {
                    if let Some(ref config) = self.address_discovery {
                        if config.enabled {
                            w.write_var(id as u64);
                            w.write_var(1); // 1 byte for config
                            // Encode as: enabled(1 bit) | observe_all_paths(1 bit) | max_rate(6 bits)
                            let config_byte = 0x80 | // enabled bit always set when writing
                                              (if config.observe_all_paths { 0x40 } else { 0 }) |
                                              (config.max_observation_rate & 0x3F);
                            w.put_u8(config_byte);
                        }
                    }
                }
                id => {
                    macro_rules! write_params {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                            match id {
                                $(TransportParameterId::$id => {
                                    if self.$name.0 != $default {
                                        w.write_var(id as u64);
                                        w.write(VarInt::try_from(self.$name.size()).unwrap());
                                        w.write(self.$name);
                                    }
                                })*,
                                _ => {
                                    // This should never be reached for supported parameters
                                    // All supported parameters should be handled in specific match arms above
                                    panic!("Unsupported transport parameter reached write implementation: {id:?}");
                                }
                            }
                        }
                    }
                    apply_params!(write_params);
                }
            }
        }
    }

    /// Decode `TransportParameters` from buffer
    pub fn read<R: Buf>(side: Side, r: &mut R) -> Result<Self, Error> {
        // Initialize to protocol-specified defaults
        let mut params = Self::default();

        // State to check for duplicate transport parameters.
        macro_rules! param_state {
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {{
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
            let id = r.get_var()?;
            let len = r.get_var()?;
            if (r.remaining() as u64) < len {
                return Err(Error::Malformed);
            }
            let len = len as usize;
            let Ok(id) = TransportParameterId::try_from(id) else {
                // unknown transport parameters are ignored
                r.advance(len);
                continue;
            };

            match id {
                TransportParameterId::OriginalDestinationConnectionId => {
                    decode_cid(len, &mut params.original_dst_cid, r)?
                }
                TransportParameterId::StatelessResetToken => {
                    if len != 16 || params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; RESET_TOKEN_SIZE];
                    r.copy_to_slice(&mut tok);
                    params.stateless_reset_token = Some(tok.into());
                }
                TransportParameterId::DisableActiveMigration => {
                    if len != 0 || params.disable_active_migration {
                        return Err(Error::Malformed);
                    }
                    params.disable_active_migration = true;
                }
                TransportParameterId::PreferredAddress => {
                    if params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.preferred_address = Some(PreferredAddress::read(&mut r.take(len))?);
                }
                TransportParameterId::InitialSourceConnectionId => {
                    decode_cid(len, &mut params.initial_src_cid, r)?
                }
                TransportParameterId::RetrySourceConnectionId => {
                    decode_cid(len, &mut params.retry_src_cid, r)?
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    if len > 8 || params.max_datagram_frame_size.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.max_datagram_frame_size = Some(r.get().unwrap());
                }
                TransportParameterId::GreaseQuicBit => match len {
                    0 => params.grease_quic_bit = true,
                    _ => return Err(Error::Malformed),
                },
                TransportParameterId::MinAckDelayDraft07 => {
                    params.min_ack_delay = Some(r.get().unwrap())
                }
                TransportParameterId::NatTraversal => {
                    if params.nat_traversal.is_some() {
                        return Err(Error::Malformed);
                    }
                    // Per draft-seemann-quic-nat-traversal-01:
                    // - Empty value (len=0) from client indicates support
                    // - 1 byte value from server is concurrency limit
                    match (side, len) {
                        (Side::Server, 0) => {
                            // Client sent empty value - they support NAT traversal
                            params.nat_traversal = Some(NatTraversalConfig {
                                role: NatTraversalRole::Client,
                                max_candidates: VarInt::from_u32(8), // Default
                                coordination_timeout: VarInt::from_u32(10000), // Default 10s
                                max_concurrent_attempts: VarInt::from_u32(3), // Default
                                peer_id: None,
                            });
                        }
                        (Side::Client, 1) => {
                            // Server sent concurrency limit
                            let limit = r.get::<u8>()?;
                            params.nat_traversal = Some(NatTraversalConfig {
                                role: NatTraversalRole::Server { can_relay: false }, // Determined later
                                max_candidates: VarInt::from_u32(8),                 // Default
                                coordination_timeout: VarInt::from_u32(10000),       // Default 10s
                                max_concurrent_attempts: VarInt::from_u32(limit as u32),
                                peer_id: None,
                            });
                        }
                        _ => {
                            // Invalid combination
                            return Err(Error::Malformed);
                        }
                    }
                }
                TransportParameterId::AddressDiscovery => {
                    if params.address_discovery.is_some() {
                        return Err(Error::Malformed);
                    }
                    // Address discovery sends 1 byte config
                    if len != 1 {
                        return Err(Error::Malformed);
                    }
                    let config_byte = r.get::<u8>()?;
                    // Decode: enabled(1 bit) | observe_all_paths(1 bit) | max_rate(6 bits)
                    params.address_discovery = Some(AddressDiscoveryConfig {
                        enabled: (config_byte & 0x80) != 0,
                        max_observation_rate: config_byte & 0x3F,
                        observe_all_paths: (config_byte & 0x40) != 0,
                    });
                }
                _ => {
                    macro_rules! parse {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                            match id {
                                $(TransportParameterId::$id => {
                                    let value = r.get::<VarInt>()?;
                                    if len != value.size() || got.$name { return Err(Error::Malformed); }
                                    params.$name = value.into();
                                    got.$name = true;
                                })*
                                _ => r.advance(len),
                            }
                        }
                    }
                    apply_params!(parse);
                }
            }
        }

        // Semantic validation

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.26.1
        if params.ack_delay_exponent.0 > 20
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.28.1
            || params.max_ack_delay.0 >= 1 << 14
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-6.2.1
            || params.active_connection_id_limit.0 < 2
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.10.1
            || params.max_udp_payload_size.0 < 1200
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-2
            || params.initial_max_streams_bidi.0 > MAX_STREAM_COUNT
            || params.initial_max_streams_uni.0 > MAX_STREAM_COUNT
            // https://www.ietf.org/archive/id/draft-ietf-quic-ack-frequency-08.html#section-3-4
            || params.min_ack_delay.is_some_and(|min_ack_delay| {
                // min_ack_delay uses microseconds, whereas max_ack_delay uses milliseconds
                min_ack_delay.0 > params.max_ack_delay.0 * 1_000
            })
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-8
            || (side.is_server()
                && (params.original_dst_cid.is_some()
                    || params.preferred_address.is_some()
                    || params.retry_src_cid.is_some()
                    || params.stateless_reset_token.is_some()))
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.38.1
            || params
                .preferred_address.is_some_and(|x| x.connection_id.is_empty())
        {
            return Err(Error::IllegalValue);
        }

        // NAT traversal parameter validation
        if let Some(ref nat_config) = params.nat_traversal {
            // Validate NAT traversal configuration
            if let Err(_) = nat_config.validate() {
                return Err(Error::IllegalValue);
            }

            // Validate role-specific constraints
            match nat_config.role {
                NatTraversalRole::Server { .. } | NatTraversalRole::Bootstrap => {
                    // Server/Bootstrap roles should only be received by clients
                    if side.is_server() {
                        return Err(Error::IllegalValue);
                    }
                }
                NatTraversalRole::Client => {
                    // Client role should only be received by servers
                    if side.is_client() {
                        return Err(Error::IllegalValue);
                    }
                }
            }
        }

        Ok(params)
    }
}

/// A reserved transport parameter.
///
/// It has an identifier of the form 31 * N + 27 for the integer value of N.
/// Such identifiers are reserved to exercise the requirement that unknown transport parameters be ignored.
/// The reserved transport parameter has no semantics and can carry arbitrary values.
/// It may be included in transport parameters sent to the peer, and should be ignored when received.
///
/// See spec: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1>
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct ReservedTransportParameter {
    /// The reserved identifier of the transport parameter
    id: VarInt,

    /// Buffer to store the parameter payload
    payload: [u8; Self::MAX_PAYLOAD_LEN],

    /// The number of bytes to include in the wire format from the `payload` buffer
    payload_len: usize,
}

impl ReservedTransportParameter {
    /// Generates a transport parameter with a random payload and a reserved ID.
    ///
    /// The implementation is inspired by quic-go and quiche:
    /// 1. <https://github.com/quic-go/quic-go/blob/3e0a67b2476e1819752f04d75968de042b197b56/internal/wire/transport_parameters.go#L338-L344>
    /// 2. <https://github.com/google/quiche/blob/cb1090b20c40e2f0815107857324e99acf6ec567/quiche/quic/core/crypto/transport_parameters.cc#L843-L860>
    fn random(rng: &mut impl RngCore) -> Self {
        let id = Self::generate_reserved_id(rng);

        let payload_len = rng.gen_range(0..Self::MAX_PAYLOAD_LEN);

        let payload = {
            let mut slice = [0u8; Self::MAX_PAYLOAD_LEN];
            rng.fill_bytes(&mut slice[..payload_len]);
            slice
        };

        Self {
            id,
            payload,
            payload_len,
        }
    }

    fn write(&self, w: &mut impl BufMut) {
        w.write_var(self.id.0);
        w.write_var(self.payload_len as u64);
        w.put_slice(&self.payload[..self.payload_len]);
    }

    /// Generates a random reserved identifier of the form `31 * N + 27`, as required by RFC 9000.
    /// Reserved transport parameter identifiers are used to test compliance with the requirement
    /// that unknown transport parameters must be ignored by peers.
    /// See: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1> and <https://www.rfc-editor.org/rfc/rfc9000.html#section-22.3>
    fn generate_reserved_id(rng: &mut impl RngCore) -> VarInt {
        let id = {
            let rand = rng.gen_range(0u64..(1 << 62) - 27);
            let n = rand / 31;
            31 * n + 27
        };
        debug_assert!(
            id % 31 == 27,
            "generated id does not have the form of 31 * N + 27"
        );
        VarInt::from_u64(id).expect(
            "generated id does fit into range of allowed transport parameter IDs: [0; 2^62)",
        )
    }

    /// The maximum length of the payload to include as the parameter payload.
    /// This value is not a specification-imposed limit but is chosen to match
    /// the limit used by other implementations of QUIC, e.g., quic-go and quiche.
    const MAX_PAYLOAD_LEN: usize = 16;
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportParameterId {
    // https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table
    OriginalDestinationConnectionId = 0x00,
    MaxIdleTimeout = 0x01,
    StatelessResetToken = 0x02,
    MaxUdpPayloadSize = 0x03,
    InitialMaxData = 0x04,
    InitialMaxStreamDataBidiLocal = 0x05,
    InitialMaxStreamDataBidiRemote = 0x06,
    InitialMaxStreamDataUni = 0x07,
    InitialMaxStreamsBidi = 0x08,
    InitialMaxStreamsUni = 0x09,
    AckDelayExponent = 0x0A,
    MaxAckDelay = 0x0B,
    DisableActiveMigration = 0x0C,
    PreferredAddress = 0x0D,
    ActiveConnectionIdLimit = 0x0E,
    InitialSourceConnectionId = 0x0F,
    RetrySourceConnectionId = 0x10,

    // Smallest possible ID of reserved transport parameter https://datatracker.ietf.org/doc/html/rfc9000#section-22.3
    ReservedTransportParameter = 0x1B,

    // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
    MaxDatagramFrameSize = 0x20,

    // https://www.rfc-editor.org/rfc/rfc9287.html#section-3
    GreaseQuicBit = 0x2AB2,

    // https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency#section-10.1
    MinAckDelayDraft07 = 0xFF04DE1B,

    // NAT Traversal Extension - draft-seemann-quic-nat-traversal-01
    // Transport parameter ID from the IETF draft specification
    NatTraversal = 0x3d7e9f0bca12fea6,

    // Address Discovery Extension - draft-ietf-quic-address-discovery-00
    // Transport parameter ID in experimental range
    AddressDiscovery = 0x1f00,
}

impl TransportParameterId {
    /// Array with all supported transport parameter IDs
    const SUPPORTED: [Self; 23] = [
        Self::MaxIdleTimeout,
        Self::MaxUdpPayloadSize,
        Self::InitialMaxData,
        Self::InitialMaxStreamDataBidiLocal,
        Self::InitialMaxStreamDataBidiRemote,
        Self::InitialMaxStreamDataUni,
        Self::InitialMaxStreamsBidi,
        Self::InitialMaxStreamsUni,
        Self::AckDelayExponent,
        Self::MaxAckDelay,
        Self::ActiveConnectionIdLimit,
        Self::ReservedTransportParameter,
        Self::StatelessResetToken,
        Self::DisableActiveMigration,
        Self::MaxDatagramFrameSize,
        Self::PreferredAddress,
        Self::OriginalDestinationConnectionId,
        Self::InitialSourceConnectionId,
        Self::RetrySourceConnectionId,
        Self::GreaseQuicBit,
        Self::MinAckDelayDraft07,
        Self::NatTraversal,
        Self::AddressDiscovery,
    ];
}

impl std::cmp::PartialEq<u64> for TransportParameterId {
    fn eq(&self, other: &u64) -> bool {
        *other == (*self as u64)
    }
}

impl TryFrom<u64> for TransportParameterId {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let param = match value {
            id if Self::MaxIdleTimeout == id => Self::MaxIdleTimeout,
            id if Self::MaxUdpPayloadSize == id => Self::MaxUdpPayloadSize,
            id if Self::InitialMaxData == id => Self::InitialMaxData,
            id if Self::InitialMaxStreamDataBidiLocal == id => Self::InitialMaxStreamDataBidiLocal,
            id if Self::InitialMaxStreamDataBidiRemote == id => {
                Self::InitialMaxStreamDataBidiRemote
            }
            id if Self::InitialMaxStreamDataUni == id => Self::InitialMaxStreamDataUni,
            id if Self::InitialMaxStreamsBidi == id => Self::InitialMaxStreamsBidi,
            id if Self::InitialMaxStreamsUni == id => Self::InitialMaxStreamsUni,
            id if Self::AckDelayExponent == id => Self::AckDelayExponent,
            id if Self::MaxAckDelay == id => Self::MaxAckDelay,
            id if Self::ActiveConnectionIdLimit == id => Self::ActiveConnectionIdLimit,
            id if Self::ReservedTransportParameter == id => Self::ReservedTransportParameter,
            id if Self::StatelessResetToken == id => Self::StatelessResetToken,
            id if Self::DisableActiveMigration == id => Self::DisableActiveMigration,
            id if Self::MaxDatagramFrameSize == id => Self::MaxDatagramFrameSize,
            id if Self::PreferredAddress == id => Self::PreferredAddress,
            id if Self::OriginalDestinationConnectionId == id => {
                Self::OriginalDestinationConnectionId
            }
            id if Self::InitialSourceConnectionId == id => Self::InitialSourceConnectionId,
            id if Self::RetrySourceConnectionId == id => Self::RetrySourceConnectionId,
            id if Self::GreaseQuicBit == id => Self::GreaseQuicBit,
            id if Self::MinAckDelayDraft07 == id => Self::MinAckDelayDraft07,
            id if Self::NatTraversal == id => Self::NatTraversal,
            id if Self::AddressDiscovery == id => Self::AddressDiscovery,
            _ => return Err(()),
        };
        Ok(param)
    }
}

fn decode_cid(len: usize, value: &mut Option<ConnectionId>, r: &mut impl Buf) -> Result<(), Error> {
    if len > MAX_CID_SIZE || value.is_some() || r.remaining() < len {
        return Err(Error::Malformed);
    }

    *value = Some(ConnectionId::from_buf(r, len));
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nat_traversal_transport_parameter_encoding_decoding() {
        // Test draft-compliant NAT traversal parameter encoding/decoding

        // Test 1: Client sends empty value, server reads it
        let client_config = NatTraversalConfig {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(8),
            coordination_timeout: VarInt::from_u32(5000),
            max_concurrent_attempts: VarInt::from_u32(3),
            peer_id: None,
        };

        let mut client_params = TransportParameters::default();
        client_params.nat_traversal = Some(client_config);

        let mut encoded = Vec::new();
        client_params.write(&mut encoded);

        // Server reads client params
        let server_decoded = TransportParameters::read(Side::Server, &mut encoded.as_slice())
            .expect("Failed to decode client transport parameters");

        // Server should see that client supports NAT traversal
        assert!(server_decoded.nat_traversal.is_some());
        let server_view = server_decoded.nat_traversal.unwrap();
        assert!(matches!(server_view.role, NatTraversalRole::Client));

        // Test 2: Server sends concurrency limit, client reads it
        let server_config = NatTraversalConfig {
            role: NatTraversalRole::Server { can_relay: false },
            max_candidates: VarInt::from_u32(16),
            coordination_timeout: VarInt::from_u32(10000),
            max_concurrent_attempts: VarInt::from_u32(5),
            peer_id: None,
        };

        let mut server_params = TransportParameters::default();
        server_params.nat_traversal = Some(server_config);

        let mut encoded = Vec::new();
        server_params.write(&mut encoded);

        // Client reads server params
        let client_decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode server transport parameters");

        // Client should see server's concurrency limit
        assert!(client_decoded.nat_traversal.is_some());
        let client_view = client_decoded.nat_traversal.unwrap();
        assert!(matches!(client_view.role, NatTraversalRole::Server { .. }));
        assert_eq!(client_view.max_concurrent_attempts, VarInt::from_u32(5));
    }

    #[test]
    fn test_nat_traversal_parameter_without_peer_id() {
        // Test client-side NAT traversal config (sends empty value)
        let config = NatTraversalConfig {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(4),
            coordination_timeout: VarInt::from_u32(3000),
            max_concurrent_attempts: VarInt::from_u32(2),
            peer_id: None,
        };

        let mut params = TransportParameters::default();
        params.nat_traversal = Some(config);

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        // Server reads client's parameters
        let decoded_params = TransportParameters::read(Side::Server, &mut encoded.as_slice())
            .expect("Failed to decode transport parameters");

        let decoded_config = decoded_params
            .nat_traversal
            .expect("NAT traversal config should be present");

        assert_eq!(decoded_config.role, NatTraversalRole::Client);
        assert!(decoded_config.peer_id.is_none());

        // Test server-side NAT traversal config (sends concurrency limit)
        let server_config = NatTraversalConfig {
            role: NatTraversalRole::Server { can_relay: true },
            max_candidates: VarInt::from_u32(8),
            coordination_timeout: VarInt::from_u32(5000),
            max_concurrent_attempts: VarInt::from_u32(4),
            peer_id: None,
        };

        let mut server_params = TransportParameters::default();
        server_params.nat_traversal = Some(server_config);

        let mut server_encoded = Vec::new();
        server_params.write(&mut server_encoded);

        // Client reads server's parameters
        let decoded_server_params =
            TransportParameters::read(Side::Client, &mut server_encoded.as_slice())
                .expect("Failed to decode server transport parameters");

        let decoded_server_config = decoded_server_params
            .nat_traversal
            .expect("Server NAT traversal config should be present");

        match decoded_server_config.role {
            NatTraversalRole::Server { can_relay } => {
                // The protocol doesn't encode can_relay, so it's always false when decoded
                assert!(!can_relay);
            }
            _ => panic!("Expected server role"),
        }
        assert_eq!(
            decoded_server_config.max_concurrent_attempts,
            VarInt::from_u32(4)
        );
    }

    #[test]
    fn test_transport_parameters_without_nat_traversal() {
        // Test that transport parameters work without NAT traversal config
        let mut params = TransportParameters::default();
        params.nat_traversal = None;

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        let decoded_params = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode transport parameters");

        assert!(decoded_params.nat_traversal.is_none());
    }

    #[test]
    fn test_nat_traversal_draft_compliant_encoding() {
        // Test draft-seemann-quic-nat-traversal-01 compliant encoding

        // Test 1: Client sends empty value
        let client_config = NatTraversalConfig {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(8),
            coordination_timeout: VarInt::from_u32(10000),
            max_concurrent_attempts: VarInt::from_u32(3),
            peer_id: None,
        };

        let mut client_params = TransportParameters::default();
        client_params.nat_traversal = Some(client_config);

        let mut encoded = Vec::new();
        client_params.write(&mut encoded);

        // Verify the encoded data contains empty value for client
        // Find the NAT traversal parameter in the encoded data
        use bytes::Buf;
        let mut cursor = &encoded[..];
        while cursor.has_remaining() {
            let id = VarInt::from_u64(cursor.get_var().unwrap()).unwrap();
            let len = VarInt::from_u64(cursor.get_var().unwrap()).unwrap();
            if id.0 == 0x3d7e9f0bca12fea6 {
                // Found NAT traversal parameter
                assert_eq!(len.0, 0, "Client should send empty value");
                break;
            }
            // Skip this parameter
            cursor.advance(len.0 as usize);
        }

        // Test 2: Server sends 1-byte concurrency limit
        let server_config = NatTraversalConfig {
            role: NatTraversalRole::Server { can_relay: true },
            max_candidates: VarInt::from_u32(16),
            coordination_timeout: VarInt::from_u32(10000),
            max_concurrent_attempts: VarInt::from_u32(5),
            peer_id: None,
        };

        let mut server_params = TransportParameters::default();
        server_params.nat_traversal = Some(server_config);

        let mut encoded = Vec::new();
        server_params.write(&mut encoded);

        // Verify the encoded data contains 1-byte value for server
        let mut cursor = &encoded[..];
        while cursor.has_remaining() {
            let id = VarInt::from_u64(cursor.get_var().unwrap()).unwrap();
            let len = VarInt::from_u64(cursor.get_var().unwrap()).unwrap();
            if id.0 == 0x3d7e9f0bca12fea6 {
                // Found NAT traversal parameter
                assert_eq!(len.0, 1, "Server should send 1-byte value");
                let limit = cursor.chunk()[0];
                assert_eq!(limit, 5, "Server should send concurrency limit");
                break;
            }
            // Skip this parameter
            cursor.advance(len.0 as usize);
        }
    }

    #[test]
    fn test_nat_traversal_draft_compliant_decoding() {
        use bytes::BufMut;

        // Test 1: Decode empty value from client
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(0); // Empty value

        let params = TransportParameters::read(Side::Server, &mut buf.as_slice())
            .expect("Failed to decode transport parameters");

        let config = params
            .nat_traversal
            .expect("NAT traversal should be present");
        assert_eq!(config.role, NatTraversalRole::Client);
        assert_eq!(config.max_candidates, VarInt::from_u32(8)); // Default value
        assert_eq!(config.coordination_timeout, VarInt::from_u32(10000)); // Default value
        assert_eq!(config.max_concurrent_attempts, VarInt::from_u32(3)); // Default value

        // Test 2: Decode 1-byte concurrency limit from server
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(1); // 1-byte value
        buf.put_u8(7); // Concurrency limit of 7

        let params = TransportParameters::read(Side::Client, &mut buf.as_slice())
            .expect("Failed to decode transport parameters");

        let config = params
            .nat_traversal
            .expect("NAT traversal should be present");
        match config.role {
            NatTraversalRole::Server { can_relay } => {
                assert!(!can_relay); // Default to false
            }
            _ => panic!("Expected Server role"),
        }
        assert_eq!(config.max_concurrent_attempts, VarInt::from_u32(7));

        // Test 3: Invalid length should fail
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(2); // Invalid 2-byte value
        buf.put_u8(7);
        buf.put_u8(8);

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err(), "Should fail with invalid length");
    }

    #[test]
    fn test_nat_traversal_parameter_id() {
        // Verify the correct parameter ID is used
        assert_eq!(
            TransportParameterId::NatTraversal as u64,
            0x3d7e9f0bca12fea6
        );
    }

    #[test]
    fn test_nat_traversal_config_validation() {
        // Test valid configuration
        let valid_config = NatTraversalConfig {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(8),
            coordination_timeout: VarInt::from_u32(5000),
            max_concurrent_attempts: VarInt::from_u32(3),
            peer_id: None,
        };
        assert!(valid_config.validate().is_ok());

        // Test invalid max_candidates (too low)
        let invalid_config = NatTraversalConfig {
            max_candidates: VarInt::from_u32(0),
            ..valid_config
        };
        assert!(invalid_config.validate().is_err());

        // Test invalid max_candidates (too high)
        let invalid_config = NatTraversalConfig {
            max_candidates: VarInt::from_u32(101),
            ..valid_config
        };
        assert!(invalid_config.validate().is_err());

        // Test invalid coordination_timeout (too low)
        let invalid_config = NatTraversalConfig {
            coordination_timeout: VarInt::from_u32(500),
            ..valid_config
        };
        assert!(invalid_config.validate().is_err());

        // Test invalid coordination_timeout (too high)
        let invalid_config = NatTraversalConfig {
            coordination_timeout: VarInt::from_u32(70000),
            ..valid_config
        };
        assert!(invalid_config.validate().is_err());

        // Test invalid max_concurrent_attempts (too low)
        let invalid_config = NatTraversalConfig {
            max_concurrent_attempts: VarInt::from_u32(0),
            ..valid_config
        };
        assert!(invalid_config.validate().is_err());

        // Test invalid max_concurrent_attempts (too high)
        let invalid_config = NatTraversalConfig {
            max_concurrent_attempts: VarInt::from_u32(11),
            ..valid_config
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_nat_traversal_role_validation() {
        use bytes::BufMut;

        // Test client role validation - should fail when received by client
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(0); // Empty value (client role)

        // Client receiving client role should fail
        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(
            result.is_err(),
            "Client should not accept client role from peer"
        );

        // Server receiving client role should succeed
        let result = TransportParameters::read(Side::Server, &mut buf.as_slice());
        assert!(result.is_ok(), "Server should accept client role from peer");

        // Test server role validation - should fail when received by server
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(1); // 1-byte value (server role)
        buf.put_u8(5); // Concurrency limit

        // Server receiving server role should fail
        let result = TransportParameters::read(Side::Server, &mut buf.as_slice());
        assert!(
            result.is_err(),
            "Server should not accept server role from peer"
        );

        // Client receiving server role should succeed
        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_ok(), "Client should accept server role from peer");
    }

    #[test]
    fn test_nat_traversal_parameter_combinations() {
        // Test that NAT traversal works with other transport parameters
        let nat_config = NatTraversalConfig {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(10),
            coordination_timeout: VarInt::from_u32(8000),
            max_concurrent_attempts: VarInt::from_u32(4),
            peer_id: Some([42u8; 32]),
        };

        let mut params = TransportParameters::default();
        params.nat_traversal = Some(nat_config);
        params.max_idle_timeout = VarInt::from_u32(30000);
        params.initial_max_data = VarInt::from_u32(1048576);
        params.grease_quic_bit = true;

        // Test encoding
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        assert!(!encoded.is_empty());

        // Test decoding
        let decoded = TransportParameters::read(Side::Server, &mut encoded.as_slice())
            .expect("Should decode successfully");

        // Verify NAT traversal config is preserved
        let decoded_config = decoded
            .nat_traversal
            .expect("NAT traversal should be present");
        assert_eq!(decoded_config.role, NatTraversalRole::Client);
        assert_eq!(decoded_config.max_candidates, VarInt::from_u32(8)); // Default value

        // Verify other parameters are preserved
        assert_eq!(decoded.max_idle_timeout, VarInt::from_u32(30000));
        assert_eq!(decoded.initial_max_data, VarInt::from_u32(1048576));
        assert!(decoded.grease_quic_bit);
    }

    #[test]
    fn test_nat_traversal_default_config() {
        let default_config = NatTraversalConfig::default();

        assert_eq!(default_config.role, NatTraversalRole::Client);
        assert_eq!(default_config.max_candidates, VarInt::from_u32(8));
        assert_eq!(default_config.coordination_timeout, VarInt::from_u32(10000));
        assert_eq!(default_config.max_concurrent_attempts, VarInt::from_u32(3));
        assert!(default_config.peer_id.is_none());

        // Default config should be valid
        assert!(default_config.validate().is_ok());
    }

    #[test]
    fn test_nat_traversal_endpoint_role_negotiation() {
        // Test complete client-server negotiation

        // 1. Client creates parameters with NAT traversal support
        let client_config = NatTraversalConfig {
            role: NatTraversalRole::Client,
            max_candidates: VarInt::from_u32(12),
            coordination_timeout: VarInt::from_u32(7000),
            max_concurrent_attempts: VarInt::from_u32(5),
            peer_id: None,
        };

        let mut client_params = TransportParameters::default();
        client_params.nat_traversal = Some(client_config);

        // 2. Client encodes and sends to server
        let mut client_encoded = Vec::new();
        client_params.write(&mut client_encoded);

        // 3. Server receives and decodes client parameters
        let server_received =
            TransportParameters::read(Side::Server, &mut client_encoded.as_slice())
                .expect("Server should decode client params");

        // Server should see client role
        let server_view = server_received
            .nat_traversal
            .expect("NAT traversal should be present");
        assert_eq!(server_view.role, NatTraversalRole::Client);

        // 4. Server creates response with server role
        let server_config = NatTraversalConfig {
            role: NatTraversalRole::Server { can_relay: true },
            max_candidates: VarInt::from_u32(16),
            coordination_timeout: VarInt::from_u32(12000),
            max_concurrent_attempts: VarInt::from_u32(8),
            peer_id: Some([123u8; 32]),
        };

        let mut server_params = TransportParameters::default();
        server_params.nat_traversal = Some(server_config);

        // 5. Server encodes and sends to client
        let mut server_encoded = Vec::new();
        server_params.write(&mut server_encoded);

        // 6. Client receives and decodes server parameters
        let client_received =
            TransportParameters::read(Side::Client, &mut server_encoded.as_slice())
                .expect("Client should decode server params");

        // Client should see server role with concurrency limit
        let client_view = client_received
            .nat_traversal
            .expect("NAT traversal should be present");
        match client_view.role {
            NatTraversalRole::Server { can_relay } => {
                assert!(!can_relay); // Default to false in decoded params
            }
            _ => panic!("Expected server role"),
        }
        assert_eq!(client_view.max_concurrent_attempts, VarInt::from_u32(8));
    }

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        let params = TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[])),
            original_dst_cid: Some(ConnectionId::new(&[])),
            initial_max_streams_bidi: 16u32.into(),
            initial_max_streams_uni: 16u32.into(),
            ack_delay_exponent: 2u32.into(),
            max_udp_payload_size: 1200u32.into(),
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 24, 0, 0)),
                connection_id: ConnectionId::new(&[0x42]),
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
            }),
            grease_quic_bit: true,
            min_ack_delay: Some(2_000u32.into()),
            ..TransportParameters::default()
        };
        params.write(&mut buf);
        assert_eq!(
            TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap(),
            params
        );
    }

    #[test]
    fn reserved_transport_parameter_generate_reserved_id() {
        use rand::rngs::mock::StepRng;
        let mut rngs = [
            StepRng::new(0, 1),
            StepRng::new(1, 1),
            StepRng::new(27, 1),
            StepRng::new(31, 1),
            StepRng::new(u32::MAX as u64, 1),
            StepRng::new(u32::MAX as u64 - 1, 1),
            StepRng::new(u32::MAX as u64 + 1, 1),
            StepRng::new(u32::MAX as u64 - 27, 1),
            StepRng::new(u32::MAX as u64 + 27, 1),
            StepRng::new(u32::MAX as u64 - 31, 1),
            StepRng::new(u32::MAX as u64 + 31, 1),
            StepRng::new(u64::MAX, 1),
            StepRng::new(u64::MAX - 1, 1),
            StepRng::new(u64::MAX - 27, 1),
            StepRng::new(u64::MAX - 31, 1),
            StepRng::new(1 << 62, 1),
            StepRng::new((1 << 62) - 1, 1),
            StepRng::new((1 << 62) + 1, 1),
            StepRng::new((1 << 62) - 27, 1),
            StepRng::new((1 << 62) + 27, 1),
            StepRng::new((1 << 62) - 31, 1),
            StepRng::new((1 << 62) + 31, 1),
        ];
        for rng in &mut rngs {
            let id = ReservedTransportParameter::generate_reserved_id(rng);
            assert!(id.0 % 31 == 27)
        }
    }

    #[test]
    fn reserved_transport_parameter_ignored_when_read() {
        let mut buf = Vec::new();
        let reserved_parameter = ReservedTransportParameter::random(&mut rand::thread_rng());
        assert!(reserved_parameter.payload_len < ReservedTransportParameter::MAX_PAYLOAD_LEN);
        assert!(reserved_parameter.id.0 % 31 == 27);

        reserved_parameter.write(&mut buf);
        assert!(!buf.is_empty());
        let read_params = TransportParameters::read(Side::Server, &mut buf.as_slice()).unwrap();
        assert_eq!(read_params, TransportParameters::default());
    }

    #[test]
    fn read_semantic_validation() {
        #[allow(clippy::type_complexity)]
        let illegal_params_builders: Vec<Box<dyn FnMut(&mut TransportParameters)>> = vec![
            Box::new(|t| {
                // This min_ack_delay is bigger than max_ack_delay!
                let min_ack_delay = t.max_ack_delay.0 * 1_000 + 1;
                t.min_ack_delay = Some(VarInt::from_u64(min_ack_delay).unwrap())
            }),
            Box::new(|t| {
                // Preferred address can only be sent by senders (and we are reading the transport
                // params as a client)
                t.preferred_address = Some(PreferredAddress {
                    address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                    address_v6: None,
                    connection_id: ConnectionId::new(&[]),
                    stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
                })
            }),
        ];

        for mut builder in illegal_params_builders {
            let mut buf = Vec::new();
            let mut params = TransportParameters::default();
            builder(&mut params);
            params.write(&mut buf);

            assert_eq!(
                TransportParameters::read(Side::Server, &mut buf.as_slice()),
                Err(Error::IllegalValue)
            );
        }
    }

    #[test]
    fn resumption_params_validation() {
        let high_limit = TransportParameters {
            initial_max_streams_uni: 32u32.into(),
            ..TransportParameters::default()
        };
        let low_limit = TransportParameters {
            initial_max_streams_uni: 16u32.into(),
            ..TransportParameters::default()
        };
        high_limit.validate_resumption_from(&low_limit).unwrap();
        low_limit.validate_resumption_from(&high_limit).unwrap_err();
    }

    #[test]
    fn test_address_discovery_parameter_id() {
        // Test that ADDRESS_DISCOVERY parameter ID is defined correctly
        assert_eq!(TransportParameterId::AddressDiscovery as u64, 0x1f00);
    }

    #[test]
    fn test_address_discovery_config_struct() {
        // Test AddressDiscoveryConfig struct creation and fields
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 10,
            observe_all_paths: false,
        };
        
        assert!(config.enabled);
        assert_eq!(config.max_observation_rate, 10);
        assert!(!config.observe_all_paths);
    }

    #[test]
    fn test_address_discovery_config_new() {
        // Test constructor with rate limiting
        let config = AddressDiscoveryConfig::new(true, 100, true);
        assert!(config.enabled);
        assert_eq!(config.max_observation_rate, 63); // Should be clamped to 63
        assert!(config.observe_all_paths);
    }

    #[test]
    fn test_transport_parameters_with_address_discovery() {
        // Test that TransportParameters can hold address_discovery field
        let mut params = TransportParameters::default();
        assert!(params.address_discovery.is_none());
        
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 5,
            observe_all_paths: true,
        };
        
        params.address_discovery = Some(config);
        assert!(params.address_discovery.is_some());
        
        let stored_config = params.address_discovery.as_ref().unwrap();
        assert!(stored_config.enabled);
        assert_eq!(stored_config.max_observation_rate, 5);
        assert!(stored_config.observe_all_paths);
    }

    #[test]
    fn test_address_discovery_parameter_encoding() {
        // Test encoding of address discovery transport parameter
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 10,
            observe_all_paths: false,
        };
        
        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        // The encoded data should contain our parameter
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_address_discovery_parameter_roundtrip() {
        // Test encoding and decoding of address discovery parameter
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 15,
            observe_all_paths: true,
        };
        
        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        // Decode as peer
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode transport parameters");
        
        assert!(decoded.address_discovery.is_some());
        let decoded_config = decoded.address_discovery.as_ref().unwrap();
        assert!(decoded_config.enabled);
        assert_eq!(decoded_config.max_observation_rate, 15);
        assert!(decoded_config.observe_all_paths);
    }

    #[test]
    fn test_address_discovery_disabled_by_default() {
        // Test that address discovery is disabled by default
        let params = TransportParameters::default();
        assert!(params.address_discovery.is_none());
    }

    #[test]
    fn test_address_discovery_max_rate_limits() {
        // Test that max_observation_rate is limited to valid range (0-63)
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 63, // Maximum 6-bit value
            observe_all_paths: false,
        };
        
        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        let decoded = TransportParameters::read(Side::Server, &mut encoded.as_slice())
            .expect("Failed to decode");
        
        let decoded_config = decoded.address_discovery.as_ref().unwrap();
        assert_eq!(decoded_config.max_observation_rate, 63);
    }

    #[test]
    fn test_address_discovery_disabled_not_encoded() {
        // Test that disabled address discovery is not encoded
        let config = AddressDiscoveryConfig {
            enabled: false,
            max_observation_rate: 10,
            observe_all_paths: false,
        };
        
        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        // Should decode with no address discovery since enabled=false
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");
        
        // Since we don't encode when disabled, it should be None after decoding
        assert!(decoded.address_discovery.is_none());
    }

    #[test]
    fn test_address_discovery_serialization_roundtrip() {
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 42,
            observe_all_paths: true,
        };
        
        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");
        
        assert!(decoded.address_discovery.is_some());
        let decoded_config = decoded.address_discovery.unwrap();
        assert_eq!(decoded_config.enabled, config.enabled);
        assert_eq!(decoded_config.max_observation_rate, config.max_observation_rate);
        assert_eq!(decoded_config.observe_all_paths, config.observe_all_paths);
    }

    #[test]
    fn test_address_discovery_rate_truncation() {
        // Test that values > 63 are truncated to 6 bits
        let config = AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 255, // Will be truncated to 63 (0x3F)
            observe_all_paths: true,
        };
        
        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");
        
        let decoded_config = decoded.address_discovery.unwrap();
        assert_eq!(decoded_config.max_observation_rate, 63); // 255 & 0x3F = 63
    }

    #[test]
    fn test_address_discovery_bit_encoding() {
        // Test all combinations of flags
        let test_cases = vec![
            (true, false, 0),    // enabled only
            (true, true, 0),     // enabled + observe_all_paths
            (true, false, 25),   // enabled + rate
            (true, true, 50),    // all flags + rate
        ];
        
        for (enabled, observe_all, rate) in test_cases {
            let config = AddressDiscoveryConfig {
                enabled,
                max_observation_rate: rate,
                observe_all_paths: observe_all,
            };
            
            let mut params = TransportParameters::default();
            params.address_discovery = Some(config);
            
            let mut encoded = Vec::new();
            params.write(&mut encoded);
            
            let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
                .expect("Failed to decode");
            
            let decoded_config = decoded.address_discovery.unwrap();
            assert_eq!(decoded_config.enabled, enabled);
            assert_eq!(decoded_config.observe_all_paths, observe_all);
            assert_eq!(decoded_config.max_observation_rate, rate);
        }
    }

    #[test]
    fn test_address_discovery_malformed_length() {
        use bytes::BufMut;
        
        // Create a malformed parameter with wrong length
        let mut encoded = Vec::new();
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(2); // Wrong length - should be 1
        encoded.put_u8(0x80); // Some data
        encoded.put_u8(0x00); // Extra byte
        
        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Malformed));
    }

    #[test]
    fn test_address_discovery_duplicate_parameter() {
        use bytes::BufMut;
        
        // Create parameters with duplicate address discovery
        let mut encoded = Vec::new();
        
        // First occurrence
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(1);
        encoded.put_u8(0x80); // enabled=true
        
        // Duplicate occurrence
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(1);
        encoded.put_u8(0xC0); // Different config
        
        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Malformed));
    }

    #[test]
    fn test_address_discovery_with_other_parameters() {
        // Test that address discovery works alongside other transport parameters
        let mut params = TransportParameters::default();
        params.max_idle_timeout = VarInt::from_u32(30000);
        params.initial_max_data = VarInt::from_u32(1_000_000);
        params.address_discovery = Some(AddressDiscoveryConfig {
            enabled: true,
            max_observation_rate: 15,
            observe_all_paths: true,
        });
        
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");
        
        // Check all parameters are preserved
        assert_eq!(decoded.max_idle_timeout, params.max_idle_timeout);
        assert_eq!(decoded.initial_max_data, params.initial_max_data);
        assert!(decoded.address_discovery.is_some());
        
        let decoded_config = decoded.address_discovery.unwrap();
        assert_eq!(decoded_config.enabled, true);
        assert_eq!(decoded_config.max_observation_rate, 15);
        assert_eq!(decoded_config.observe_all_paths, true);
    }
    
    // Include comprehensive tests module
    mod comprehensive_tests {
        include!("transport_parameters/tests.rs");
    }
}
