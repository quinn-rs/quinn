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

mod error_handling;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod integration_tests;

use error_handling::*;

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
    {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr_2021,)*} => {
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

            /// RFC NAT traversal format support
            ///
            /// When true, indicates support for RFC-compliant NAT traversal frame formats
            pub(crate) rfc_nat_traversal: bool,

            /// Address discovery configuration for this connection
            ///
            /// When present, indicates support for QUIC Address Discovery extension
            pub(crate) address_discovery: Option<AddressDiscoveryConfig>,

            /// Post-Quantum Cryptography algorithms supported by this endpoint
            ///
            /// When present, indicates support for PQC algorithms
            pub(crate) pqc_algorithms: Option<PqcAlgorithms>,

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
                    rfc_nat_traversal: false,
                    address_discovery: None,
                    pqc_algorithms: None,

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
            min_ack_delay: Some({
                let micros = TIMER_GRANULARITY.as_micros();
                // TIMER_GRANULARITY should always fit in u64 and be less than 2^62
                let micros_u64 = u64::try_from(micros).unwrap_or_else(|_| {
                    tracing::error!("Timer granularity {} micros exceeds u64::MAX", micros);
                    1_000_000 // Default to 1 second
                });
                VarInt::from_u64_bounded(micros_u64)
            }),
            grease_transport_parameter: Some(ReservedTransportParameter::random(rng)),
            write_order: Some({
                let mut order = std::array::from_fn(|i| i as u8);
                order.shuffle(rng);
                order
            }),
            nat_traversal: config.nat_traversal_config.clone(),
            rfc_nat_traversal: config.nat_traversal_config.is_some(), // Enable RFC format when NAT traversal is enabled
            address_discovery: config.address_discovery_config,
            pqc_algorithms: config.pqc_algorithms.clone(),
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

    /// Check if RFC-compliant NAT traversal frames are supported
    ///
    /// Returns true if both endpoints support RFC NAT traversal
    pub fn supports_rfc_nat_traversal(&self) -> bool {
        self.rfc_nat_traversal
    }

    /// Get the PQC algorithms configuration for this connection
    ///
    /// This is a public accessor method for tests and external code that need to
    /// examine the negotiated PQC algorithm support.
    pub fn pqc_algorithms(&self) -> Option<&PqcAlgorithms> {
        self.pqc_algorithms.as_ref()
    }
}

/// NAT traversal configuration for a QUIC connection
///
/// This configuration is negotiated as part of the transport parameters and
/// enables QUIC NAT traversal extension functionality.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NatTraversalConfig {
    /// Client supports NAT traversal (sends empty parameter)
    ClientSupport,
    /// Server supports NAT traversal with specified concurrency limit
    ServerSupport {
        /// Maximum concurrent path validation attempts (must be > 0)
        concurrency_limit: VarInt,
    },
}

// Note: NatTraversalConfig is encoded/decoded according to draft-seemann-quic-nat-traversal-01
// which uses a simple format (empty value from client, 1-byte concurrency limit from server)
// rather than a complex custom encoding.
impl NatTraversalConfig {
    /// Create a client configuration
    pub fn client() -> Self {
        Self::ClientSupport
    }

    /// Create a server configuration with concurrency limit
    pub fn server(concurrency_limit: VarInt) -> Result<Self, TransportError> {
        if concurrency_limit.0 == 0 {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "concurrency_limit must be greater than 0",
            ));
        }
        if concurrency_limit.0 > 100 {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "concurrency_limit must not exceed 100",
            ));
        }
        Ok(Self::ServerSupport { concurrency_limit })
    }

    /// Get the concurrency limit if this is a server config
    pub fn concurrency_limit(&self) -> Option<VarInt> {
        match self {
            Self::ClientSupport => None,
            Self::ServerSupport { concurrency_limit } => Some(*concurrency_limit),
        }
    }

    /// Check if this is a client configuration
    pub fn is_client(&self) -> bool {
        matches!(self, Self::ClientSupport)
    }

    /// Check if this is a server configuration  
    pub fn is_server(&self) -> bool {
        matches!(self, Self::ServerSupport { .. })
    }
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self::ClientSupport
    }
}

/// Configuration for QUIC Address Discovery extension
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressDiscoveryConfig {
    /// 0: The node is willing to provide address observations to its peer,
    /// but is not interested in receiving address observations itself.
    SendOnly,
    /// 1: The node is interested in receiving address observations,
    /// but it is not willing to provide address observations.
    ReceiveOnly,
    /// 2: The node is interested in receiving address observations,
    /// and it is willing to provide address observations.
    SendAndReceive,
}

/// Post-Quantum Cryptography algorithms configuration
///
/// This parameter advertises which PQC algorithms are supported by the endpoint.
/// When both endpoints support PQC, they can negotiate the use of quantum-resistant algorithms.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PqcAlgorithms {
    /// ML-KEM-768 (NIST FIPS 203) support for key encapsulation
    pub ml_kem_768: bool,
    /// ML-DSA-65 (NIST FIPS 204) support for digital signatures
    pub ml_dsa_65: bool,
    /// Hybrid X25519+ML-KEM-768 key exchange
    pub hybrid_x25519_ml_kem: bool,
    /// Hybrid Ed25519+ML-DSA-65 signatures
    pub hybrid_ed25519_ml_dsa: bool,
}

impl AddressDiscoveryConfig {
    /// Get the numeric value for this configuration as per IETF spec
    pub fn to_value(&self) -> VarInt {
        match self {
            Self::SendOnly => VarInt::from_u32(0),
            Self::ReceiveOnly => VarInt::from_u32(1),
            Self::SendAndReceive => VarInt::from_u32(2),
        }
    }

    /// Create from numeric value as per IETF spec
    pub fn from_value(value: VarInt) -> Result<Self, Error> {
        match value.into_inner() {
            0 => Ok(Self::SendOnly),
            1 => Ok(Self::ReceiveOnly),
            2 => Ok(Self::SendAndReceive),
            _ => Err(Error::Malformed),
        }
    }
}

impl Default for AddressDiscoveryConfig {
    fn default() -> Self {
        // Default to send and receive for maximum compatibility
        Self::SendAndReceive
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
                        // Per draft-seemann-quic-nat-traversal-02:
                        // - Client sends empty value to indicate support
                        // - Server sends VarInt concurrency limit
                        match config {
                            NatTraversalConfig::ClientSupport => {
                                // Client sends empty value
                                w.write_var(id as u64);
                                w.write_var(0); // Empty value
                            }
                            NatTraversalConfig::ServerSupport { concurrency_limit } => {
                                // Server sends concurrency limit as VarInt
                                w.write_var(id as u64);
                                w.write_var(concurrency_limit.size() as u64);
                                w.write_var(concurrency_limit.0);
                            }
                        }
                    }
                }
                TransportParameterId::AddressDiscovery => {
                    if let Some(ref config) = self.address_discovery {
                        w.write_var(id as u64);
                        let value = config.to_value();
                        w.write_var(value.size() as u64);
                        w.write_var(value.into_inner());
                    }
                }
                TransportParameterId::RfcNatTraversal => {
                    if self.rfc_nat_traversal {
                        // Send empty parameter to indicate support
                        w.write_var(id as u64);
                        w.write_var(0); // Empty value
                    }
                }
                TransportParameterId::PqcAlgorithms => {
                    if let Some(ref algorithms) = self.pqc_algorithms {
                        w.write_var(id as u64);
                        // Encode as bit field: 4 bits for 4 algorithms
                        let mut value = 0u8;
                        if algorithms.ml_kem_768 {
                            value |= 1 << 0;
                        }
                        if algorithms.ml_dsa_65 {
                            value |= 1 << 1;
                        }
                        if algorithms.hybrid_x25519_ml_kem {
                            value |= 1 << 2;
                        }
                        if algorithms.hybrid_ed25519_ml_dsa {
                            value |= 1 << 3;
                        }
                        w.write_var(1u64); // Length is always 1 byte
                        w.write(value);
                    }
                }
                id => {
                    macro_rules! write_params {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr_2021,)*} => {
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
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr_2021,)*} => {{
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
                    // Per draft-seemann-quic-nat-traversal-02:
                    // - Empty value (len=0) from client indicates support
                    // - VarInt value from server is concurrency limit
                    match (side, len) {
                        (Side::Server, 0) => {
                            // Client sent empty value - they support NAT traversal
                            params.nat_traversal = Some(NatTraversalConfig::ClientSupport);
                        }
                        (Side::Client, _) if len > 0 => {
                            // Server sent concurrency limit as VarInt
                            let limit = r.get_var()?;
                            if limit == 0 {
                                return Err(Error::IllegalValue);
                            }
                            params.nat_traversal = Some(NatTraversalConfig::ServerSupport {
                                concurrency_limit: VarInt::from_u64(limit)
                                    .map_err(|_| Error::IllegalValue)?,
                            });
                        }
                        _ => {
                            // Invalid combination of side and parameter value
                            return Err(Error::IllegalValue);
                        }
                    }
                }
                TransportParameterId::AddressDiscovery => {
                    if params.address_discovery.is_some() {
                        return Err(Error::Malformed);
                    }
                    let value = r.get_var()?;
                    let varint = VarInt::from_u64(value).map_err(|_| Error::Malformed)?;
                    params.address_discovery = Some(AddressDiscoveryConfig::from_value(varint)?);
                }
                TransportParameterId::RfcNatTraversal => {
                    if params.rfc_nat_traversal {
                        return Err(Error::Malformed);
                    }
                    if len != 0 {
                        // Must be empty parameter
                        return Err(Error::Malformed);
                    }
                    params.rfc_nat_traversal = true;
                }
                TransportParameterId::PqcAlgorithms => {
                    if params.pqc_algorithms.is_some() {
                        return Err(Error::Malformed);
                    }
                    if len != 1 {
                        return Err(Error::Malformed);
                    }
                    let value = r.get::<u8>()?;
                    params.pqc_algorithms = Some(PqcAlgorithms {
                        ml_kem_768: (value & (1 << 0)) != 0,
                        ml_dsa_65: (value & (1 << 1)) != 0,
                        hybrid_x25519_ml_kem: (value & (1 << 2)) != 0,
                        hybrid_ed25519_ml_dsa: (value & (1 << 3)) != 0,
                    });
                }
                _ => {
                    macro_rules! parse {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr_2021,)*} => {
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

        // Semantic validation with detailed error reporting

        // Validate individual parameters
        validate_ack_delay_exponent(params.ack_delay_exponent.0 as u8)
            .map_err(|_| Error::IllegalValue)?;

        validate_max_ack_delay(params.max_ack_delay).map_err(|_| Error::IllegalValue)?;

        validate_active_connection_id_limit(params.active_connection_id_limit)
            .map_err(|_| Error::IllegalValue)?;

        validate_max_udp_payload_size(params.max_udp_payload_size)
            .map_err(|_| Error::IllegalValue)?;

        // Stream count validation
        if params.initial_max_streams_bidi.0 > MAX_STREAM_COUNT {
            TransportParameterErrorHandler::log_validation_failure(
                "initial_max_streams_bidi",
                params.initial_max_streams_bidi.0,
                &format!("must be <= {MAX_STREAM_COUNT}"),
                "RFC 9000 Section 4.6-2",
            );
            return Err(Error::IllegalValue);
        }
        if params.initial_max_streams_uni.0 > MAX_STREAM_COUNT {
            TransportParameterErrorHandler::log_validation_failure(
                "initial_max_streams_uni",
                params.initial_max_streams_uni.0,
                &format!("must be <= {MAX_STREAM_COUNT}"),
                "RFC 9000 Section 4.6-2",
            );
            return Err(Error::IllegalValue);
        }

        // Min/max ack delay validation
        validate_min_ack_delay(params.min_ack_delay, params.max_ack_delay)
            .map_err(|_| Error::IllegalValue)?;

        // Server-only parameter validation
        validate_server_only_params(side, &params).map_err(|_| Error::IllegalValue)?;

        // Preferred address validation
        if let Some(ref pref_addr) = params.preferred_address {
            if pref_addr.connection_id.is_empty() {
                TransportParameterErrorHandler::log_semantic_error(
                    "preferred_address with empty connection_id",
                    "RFC 9000 Section 18.2-4.38.1",
                );
                return Err(Error::IllegalValue);
            }
        }

        // NAT traversal parameter validation with detailed logging
        if let Some(ref nat_config) = params.nat_traversal {
            // Validate NAT traversal configuration based on side
            match (side, nat_config) {
                // Server should receive ClientSupport from client
                (Side::Server, NatTraversalConfig::ClientSupport) => {
                    // Valid - log successful negotiation
                    tracing::debug!("Server received valid ClientSupport NAT traversal parameter");
                }
                // Client should receive ServerSupport from server
                (Side::Client, NatTraversalConfig::ServerSupport { concurrency_limit }) => {
                    // Valid - log successful negotiation
                    tracing::debug!(
                        "Client received valid ServerSupport with concurrency_limit: {}",
                        concurrency_limit
                    );
                }
                // Invalid combinations
                (Side::Server, NatTraversalConfig::ServerSupport { .. }) => {
                    TransportParameterErrorHandler::log_nat_traversal_error(
                        side,
                        "ServerSupport",
                        "ClientSupport",
                    );
                    return Err(Error::IllegalValue);
                }
                (Side::Client, NatTraversalConfig::ClientSupport) => {
                    TransportParameterErrorHandler::log_nat_traversal_error(
                        side,
                        "ClientSupport",
                        "ServerSupport",
                    );
                    return Err(Error::IllegalValue);
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

    // RFC NAT Traversal Format Support
    // Indicates support for RFC-compliant NAT traversal frame formats
    RfcNatTraversal = 0x3d7e9f0bca12fea8,

    // Address Discovery Extension - draft-ietf-quic-address-discovery-00
    // Transport parameter ID from the specification
    AddressDiscovery = 0x9f81a176,
    // Post-Quantum Cryptography Algorithms
    // Using experimental range for now (will be assigned by IANA)
    PqcAlgorithms = 0x50C0,
}

impl TransportParameterId {
    /// Array with all supported transport parameter IDs
    const SUPPORTED: [Self; 25] = [
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
        Self::RfcNatTraversal,
        Self::AddressDiscovery,
        Self::PqcAlgorithms,
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
            id if Self::RfcNatTraversal == id => Self::RfcNatTraversal,
            id if Self::AddressDiscovery == id => Self::AddressDiscovery,
            id if Self::PqcAlgorithms == id => Self::PqcAlgorithms,
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
        let client_config = NatTraversalConfig::ClientSupport;

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
        assert!(matches!(server_view, NatTraversalConfig::ClientSupport));

        // Test 2: Server sends concurrency limit, client reads it
        let server_config = NatTraversalConfig::ServerSupport {
            concurrency_limit: VarInt::from_u32(5),
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
        assert!(matches!(
            client_view,
            NatTraversalConfig::ServerSupport { .. }
        ));
        assert_eq!(client_view.concurrency_limit(), Some(VarInt::from_u32(5)));
    }

    #[test]
    fn test_nat_traversal_parameter_without_peer_id() {
        // Test client-side NAT traversal config (sends empty value)
        let config = NatTraversalConfig::ClientSupport;

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

        assert!(matches!(decoded_config, NatTraversalConfig::ClientSupport));

        // Test server-side NAT traversal config (sends concurrency limit)
        let server_config = NatTraversalConfig::ServerSupport {
            concurrency_limit: VarInt::from_u32(4),
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

        assert!(matches!(
            decoded_server_config,
            NatTraversalConfig::ServerSupport { concurrency_limit } if concurrency_limit == VarInt::from_u32(4)
        ));
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
        let client_config = NatTraversalConfig::ClientSupport;

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
        let server_config = NatTraversalConfig::ServerSupport {
            concurrency_limit: VarInt::from_u32(5),
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
        // Test 1: Decode empty value from client
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(0); // Empty value

        let params = TransportParameters::read(Side::Server, &mut buf.as_slice())
            .expect("Failed to decode transport parameters");

        let config = params
            .nat_traversal
            .expect("NAT traversal should be present");
        assert!(matches!(config, NatTraversalConfig::ClientSupport));

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
        assert!(matches!(
            config,
            NatTraversalConfig::ServerSupport { concurrency_limit } if concurrency_limit == VarInt::from_u32(7)
        ));

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
    fn test_nat_traversal_simple_encoding() {
        // Test the simplified NAT traversal encoding per draft-seemann-quic-nat-traversal-02

        // Test 1: Client sends empty parameter
        let mut client_params = TransportParameters::default();
        client_params.nat_traversal = Some(NatTraversalConfig::ClientSupport);

        let mut encoded = Vec::new();
        client_params.write(&mut encoded);

        // Verify it can be decoded by server
        let decoded = TransportParameters::read(Side::Server, &mut encoded.as_slice())
            .expect("Should decode client params");
        assert!(matches!(
            decoded.nat_traversal,
            Some(NatTraversalConfig::ClientSupport)
        ));

        // Test 2: Server sends concurrency limit
        let mut server_params = TransportParameters::default();
        server_params.nat_traversal = Some(NatTraversalConfig::ServerSupport {
            concurrency_limit: VarInt::from_u32(10),
        });

        let mut encoded = Vec::new();
        server_params.write(&mut encoded);

        // Verify it can be decoded by client
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Should decode server params");

        match decoded.nat_traversal {
            Some(NatTraversalConfig::ServerSupport { concurrency_limit }) => {
                assert_eq!(concurrency_limit, VarInt::from_u32(10));
            }
            _ => panic!("Expected ServerSupport variant"),
        }
    }

    #[test]
    fn test_nat_traversal_config_validation() {
        // Test valid client configuration
        let client_config = NatTraversalConfig::ClientSupport;
        assert!(client_config.is_client());
        assert_eq!(client_config.concurrency_limit(), None);

        // Test valid server configuration
        let server_config = NatTraversalConfig::server(VarInt::from_u32(5)).unwrap();
        assert!(server_config.is_server());
        assert_eq!(server_config.concurrency_limit(), Some(VarInt::from_u32(5)));

        // Test invalid server configuration (concurrency limit = 0)
        let result = NatTraversalConfig::server(VarInt::from_u32(0));
        assert!(result.is_err());

        // Test invalid server configuration (concurrency limit > 100)
        let result = NatTraversalConfig::server(VarInt::from_u32(101));
        assert!(result.is_err());

        // Test valid server configurations at boundaries
        let min_server = NatTraversalConfig::server(VarInt::from_u32(1)).unwrap();
        assert_eq!(min_server.concurrency_limit(), Some(VarInt::from_u32(1)));

        let max_server = NatTraversalConfig::server(VarInt::from_u32(100)).unwrap();
        assert_eq!(max_server.concurrency_limit(), Some(VarInt::from_u32(100)));
    }

    #[test]
    fn test_nat_traversal_role_validation() {
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
        let nat_config = NatTraversalConfig::ClientSupport;

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
        assert!(matches!(decoded_config, NatTraversalConfig::ClientSupport));

        // Verify other parameters are preserved
        assert_eq!(decoded.max_idle_timeout, VarInt::from_u32(30000));
        assert_eq!(decoded.initial_max_data, VarInt::from_u32(1048576));
        assert!(decoded.grease_quic_bit);
    }

    #[test]
    fn test_nat_traversal_default_config() {
        let default_config = NatTraversalConfig::default();

        assert!(matches!(default_config, NatTraversalConfig::ClientSupport));
        assert!(default_config.is_client());
        assert_eq!(default_config.concurrency_limit(), None);
    }

    #[test]
    fn test_nat_traversal_endpoint_role_negotiation() {
        // Test complete client-server negotiation

        // 1. Client creates parameters with NAT traversal support
        let client_config = NatTraversalConfig::ClientSupport;

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
        assert!(matches!(server_view, NatTraversalConfig::ClientSupport));

        // 4. Server creates response with server role
        let server_config = NatTraversalConfig::ServerSupport {
            concurrency_limit: VarInt::from_u32(8),
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
        assert!(matches!(
            client_view,
            NatTraversalConfig::ServerSupport { concurrency_limit } if concurrency_limit == VarInt::from_u32(8)
        ));
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
        assert_eq!(TransportParameterId::AddressDiscovery as u64, 0x9f81a176);
    }

    #[test]
    fn test_address_discovery_config_struct() {
        // Test AddressDiscoveryConfig enum variants
        let send_only = AddressDiscoveryConfig::SendOnly;
        let receive_only = AddressDiscoveryConfig::ReceiveOnly;
        let send_receive = AddressDiscoveryConfig::SendAndReceive;

        assert_eq!(send_only.to_value(), VarInt::from_u32(0));
        assert_eq!(receive_only.to_value(), VarInt::from_u32(1));
        assert_eq!(send_receive.to_value(), VarInt::from_u32(2));
    }

    #[test]
    fn test_address_discovery_config_from_value() {
        // Test from_value conversion
        assert_eq!(
            AddressDiscoveryConfig::from_value(VarInt::from_u32(0)).unwrap(),
            AddressDiscoveryConfig::SendOnly
        );
        assert_eq!(
            AddressDiscoveryConfig::from_value(VarInt::from_u32(1)).unwrap(),
            AddressDiscoveryConfig::ReceiveOnly
        );
        assert_eq!(
            AddressDiscoveryConfig::from_value(VarInt::from_u32(2)).unwrap(),
            AddressDiscoveryConfig::SendAndReceive
        );
        assert!(AddressDiscoveryConfig::from_value(VarInt::from_u32(3)).is_err());
    }

    #[test]
    fn test_transport_parameters_with_address_discovery() {
        // Test that TransportParameters can hold address_discovery field
        let mut params = TransportParameters::default();
        assert!(params.address_discovery.is_none());

        let config = AddressDiscoveryConfig::SendAndReceive;

        params.address_discovery = Some(config);
        assert!(params.address_discovery.is_some());

        let stored_config = params.address_discovery.as_ref().unwrap();
        assert_eq!(*stored_config, AddressDiscoveryConfig::SendAndReceive);
    }

    #[test]
    fn test_address_discovery_parameter_encoding() {
        // Test encoding of address discovery transport parameter
        let config = AddressDiscoveryConfig::SendAndReceive;

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
        let config = AddressDiscoveryConfig::ReceiveOnly;

        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        // Decode as peer
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode transport parameters");

        assert!(decoded.address_discovery.is_some());
        let decoded_config = decoded.address_discovery.as_ref().unwrap();
        assert_eq!(*decoded_config, AddressDiscoveryConfig::ReceiveOnly);
    }

    #[test]
    fn test_address_discovery_disabled_by_default() {
        // Test that address discovery is disabled by default
        let params = TransportParameters::default();
        assert!(params.address_discovery.is_none());
    }

    #[test]
    fn test_address_discovery_all_variants() {
        // Test all address discovery variants roundtrip correctly
        for variant in [
            AddressDiscoveryConfig::SendOnly,
            AddressDiscoveryConfig::ReceiveOnly,
            AddressDiscoveryConfig::SendAndReceive,
        ] {
            let mut params = TransportParameters::default();
            params.address_discovery = Some(variant);

            let mut encoded = Vec::new();
            params.write(&mut encoded);

            let decoded = TransportParameters::read(Side::Server, &mut encoded.as_slice())
                .expect("Failed to decode");

            assert_eq!(decoded.address_discovery, Some(variant));
        }
    }

    #[test]
    fn test_address_discovery_none_not_encoded() {
        // Test that None address discovery is not encoded
        let mut params = TransportParameters::default();
        params.address_discovery = None;

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");
        assert!(decoded.address_discovery.is_none());
    }

    #[test]
    fn test_address_discovery_serialization_roundtrip() {
        let config = AddressDiscoveryConfig::SendOnly;

        let mut params = TransportParameters::default();
        params.address_discovery = Some(config);
        params.initial_max_data = VarInt::from_u32(1_000_000);

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");

        assert_eq!(
            decoded.address_discovery,
            Some(AddressDiscoveryConfig::SendOnly)
        );
        assert_eq!(decoded.initial_max_data, VarInt::from_u32(1_000_000));
    }

    #[test]
    fn test_address_discovery_invalid_value() {
        // Test that invalid values are rejected

        let mut encoded = Vec::new();
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(1); // Length
        encoded.write_var(3); // Invalid value (only 0, 1, 2 are valid)

        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_address_discovery_edge_cases() {
        // Test edge cases for address discovery

        // Test empty parameter (zero-length)
        let mut encoded = Vec::new();
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(0); // Zero length

        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());

        // Test value too large
        let mut encoded = Vec::new();
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(1); // Length
        encoded.put_u8(255); // Invalid value (only 0, 1, 2 are valid)

        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_address_discovery_malformed_length() {
        // Create a malformed parameter with wrong length
        let mut encoded = Vec::new();
        encoded.write_var(TransportParameterId::AddressDiscovery as u64);
        encoded.write_var(1); // Says 1 byte but no data follows

        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Malformed));
    }

    #[test]
    fn test_address_discovery_duplicate_parameter() {
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
        params.address_discovery = Some(AddressDiscoveryConfig::SendAndReceive);

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");

        // Check all parameters are preserved
        assert_eq!(decoded.max_idle_timeout, params.max_idle_timeout);
        assert_eq!(decoded.initial_max_data, params.initial_max_data);
        assert_eq!(
            decoded.address_discovery,
            Some(AddressDiscoveryConfig::SendAndReceive)
        );
    }

    #[test]
    fn test_pqc_algorithms_transport_parameter() {
        // Test that PQC algorithms can be encoded and decoded correctly
        let mut params = TransportParameters::default();
        params.pqc_algorithms = Some(PqcAlgorithms {
            ml_kem_768: true,
            ml_dsa_65: false,
            hybrid_x25519_ml_kem: true,
            hybrid_ed25519_ml_dsa: true,
        });

        // Encode
        let mut encoded = Vec::new();
        params.write(&mut encoded);

        // Decode
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");

        // Verify
        assert!(decoded.pqc_algorithms.is_some());
        let pqc = decoded.pqc_algorithms.unwrap();
        assert!(pqc.ml_kem_768);
        assert!(!pqc.ml_dsa_65);
        assert!(pqc.hybrid_x25519_ml_kem);
        assert!(pqc.hybrid_ed25519_ml_dsa);
    }

    #[test]
    fn test_pqc_algorithms_all_combinations() {
        // Test all possible combinations of PQC algorithm flags
        for ml_kem in [false, true] {
            for ml_dsa in [false, true] {
                for hybrid_kex in [false, true] {
                    for hybrid_sig in [false, true] {
                        let mut params = TransportParameters::default();
                        params.pqc_algorithms = Some(PqcAlgorithms {
                            ml_kem_768: ml_kem,
                            ml_dsa_65: ml_dsa,
                            hybrid_x25519_ml_kem: hybrid_kex,
                            hybrid_ed25519_ml_dsa: hybrid_sig,
                        });

                        // Encode and decode
                        let mut encoded = Vec::new();
                        params.write(&mut encoded);
                        let decoded =
                            TransportParameters::read(Side::Client, &mut encoded.as_slice())
                                .expect("Failed to decode");

                        // Verify
                        let pqc = decoded.pqc_algorithms.unwrap();
                        assert_eq!(pqc.ml_kem_768, ml_kem);
                        assert_eq!(pqc.ml_dsa_65, ml_dsa);
                        assert_eq!(pqc.hybrid_x25519_ml_kem, hybrid_kex);
                        assert_eq!(pqc.hybrid_ed25519_ml_dsa, hybrid_sig);
                    }
                }
            }
        }
    }

    #[test]
    fn test_pqc_algorithms_not_sent_when_none() {
        // Test that PQC algorithms parameter is not sent when None
        let mut params = TransportParameters::default();
        params.pqc_algorithms = None;

        let mut encoded = Vec::new();
        params.write(&mut encoded);

        // Check that the parameter ID doesn't appear in the encoding
        // (Can't easily check for exact bytes due to VarInt encoding)
        let decoded = TransportParameters::read(Side::Client, &mut encoded.as_slice())
            .expect("Failed to decode");
        assert!(decoded.pqc_algorithms.is_none());
    }

    #[test]
    fn test_pqc_algorithms_duplicate_parameter() {
        // Test that duplicate PQC algorithms parameters are rejected
        let mut encoded = Vec::new();

        // Write a valid parameter
        encoded.write_var(TransportParameterId::PqcAlgorithms as u64);
        encoded.write_var(1u64); // Length
        encoded.write(0b1111u8); // All algorithms enabled

        // Write duplicate
        encoded.write_var(TransportParameterId::PqcAlgorithms as u64);
        encoded.write_var(1u64);
        encoded.write(0b0000u8);

        // Should fail to decode
        let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Malformed));
    }

    // Include comprehensive tests module
    mod comprehensive_tests {
        include!("transport_parameters/tests.rs");
    }
}
