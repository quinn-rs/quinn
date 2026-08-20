use std::{any::Any, collections::VecDeque, io, str, sync::Arc};

use crate::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};
use bytes::BytesMut;
pub use rustls::Error;
#[cfg(feature = "__rustls-post-quantum-test")]
use rustls::crypto::kx::NamedGroup;
use rustls::{
    self, TlsInputBuffer,
    client::danger::ServerVerifier,
    crypto::{
        CipherSuite, CryptoProvider, Identity,
        cipher::{AeadKey, Iv},
    },
    error::AlertDescription,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    quic::{
        ClientConnection, Connection as _, DirectionalKeys, HeaderProtectionKey, KeyChange,
        NeedsInput, PacketKey, QuicEvent, Secrets, ServerConnection, ServerHandshake,
        Side as QuicSide, Suite, Version,
    },
};
#[cfg(feature = "platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;

impl From<Side> for QuicSide {
    fn from(s: Side) -> Self {
        match s {
            Side::Client => Self::Client,
            Side::Server => Self::Server,
        }
    }
}

/// A rustls TLS session
pub struct TlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    exporter: Option<rustls::KeyingMaterialExporter>,
    inner: QuicConnection,
    input: HandshakeInput,
    pending_events: VecDeque<QuicEvent>,
    suite: Suite,
}

#[derive(Default)]
struct HandshakeInput {
    bytes: Vec<u8>,
    offset: usize,
    consumed: usize,
}

impl HandshakeInput {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        if self.offset != 0 {
            self.bytes.drain(..self.offset);
            self.offset = 0;
        }
        self.bytes.extend_from_slice(bytes);
    }

    fn len(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn consumed(&self) -> usize {
        self.consumed
    }
}

impl TlsInputBuffer for HandshakeInput {
    fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.offset..]
    }

    fn discard(&mut self, num_bytes: usize) {
        assert!(num_bytes <= self.len());
        self.offset += num_bytes;
        self.consumed += num_bytes;
        if self.offset == self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
    }

    fn received_close_notify(&mut self) {}

    fn has_seen_eof(&self) -> bool {
        false
    }
}

fn transport_error_from_rustls(e: Error) -> TransportError {
    if let Ok(alert) = AlertDescription::try_from(&e) {
        TransportError {
            code: TransportErrorCode::crypto(alert.into()),
            frame: None,
            reason: e.to_string(),
            crypto: Some(Arc::new(e)),
        }
    } else {
        TransportError::PROTOCOL_VIOLATION(format!("TLS error: {e}"))
    }
}

/// A rustls QUIC handshake paused after reading ClientHello.
pub struct Accepted {
    inner: rustls::quic::Accepted,
    input: HandshakeInput,
    initial_crypto_offset: u64,
}

impl Accepted {
    /// Get the ClientHello for this connection.
    pub fn client_hello(&self) -> rustls::server::ClientHello<'_> {
        self.inner.client_hello()
    }

    pub(crate) fn initial_crypto_offset(&self) -> u64 {
        self.initial_crypto_offset
    }
}

/// Reads a rustls QUIC ClientHello before a server configuration is selected.
pub(crate) struct Acceptor {
    state: Option<NeedsInput>,
    input: HandshakeInput,
}

impl Acceptor {
    pub(crate) fn new(version: u32) -> Result<Self, UnsupportedVersion> {
        Ok(Self {
            state: Some(ServerHandshake::start(interpret_version(version)?)),
            input: HandshakeInput::default(),
        })
    }

    pub(crate) fn read_hs(&mut self, plaintext: &[u8]) -> Result<Option<Accepted>, TransportError> {
        self.input.extend_from_slice(plaintext);
        loop {
            let before = self.input.len();
            let Some(state) = self.state.take() else {
                return Err(TransportError::INTERNAL_ERROR(
                    "rustls acceptor used after completion",
                ));
            };
            let mut events = Vec::new();
            let state = state
                .process(&mut self.input, &mut events)
                .map_err(transport_error_from_rustls)?;
            if !events.is_empty() {
                return Err(TransportError::INTERNAL_ERROR(
                    "rustls emitted data before config selection",
                ));
            }
            match state {
                ServerHandshake::NeedsInput(state) => {
                    self.state = Some(state);
                    if self.input.is_empty() || self.input.len() == before {
                        return Ok(None);
                    }
                }
                ServerHandshake::Accepted(inner) => {
                    let initial_crypto_offset = (self.input.consumed() + self.input.len()) as u64;
                    return Ok(Some(Accepted {
                        inner,
                        input: std::mem::take(&mut self.input),
                        initial_crypto_offset,
                    }));
                }
                ServerHandshake::VerifyClientIdentity(_) | ServerHandshake::Complete(_) => {
                    return Err(TransportError::INTERNAL_ERROR(
                        "rustls advanced past ClientHello without a server config",
                    ));
                }
                _ => {
                    return Err(TransportError::INTERNAL_ERROR(
                        "rustls returned an unsupported server handshake state",
                    ));
                }
            }
        }
    }
}

impl TlsSession {
    fn side(&self) -> Side {
        self.inner.side()
    }

    fn required_handshake_data_is_ready(&self) -> bool {
        #[cfg(feature = "__rustls-post-quantum-test")]
        {
            self.inner.negotiated_key_exchange_group().is_some()
        }
        #[cfg(not(feature = "__rustls-post-quantum-test"))]
        {
            true
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        #[cfg(feature = "__rustls-post-quantum-test")]
        let negotiated_key_exchange_group = self
            .inner
            .negotiated_key_exchange_group()
            .expect("key exchange group is negotiated");

        Some(Box::new(HandshakeData {
            protocol: self.inner.alpn_protocol().map(|x| x.into()),
            server_name: self.inner.server_name().map(str::to_owned),
            protocol_version: match &self.inner {
                QuicConnection::Client(session) => session.protocol_version(),
                QuicConnection::Server(session) => session.protocol_version(),
                QuicConnection::ServerHandshake(session) => session.protocol_version(),
            }
            .map(|x| -> Box<dyn Any> { Box::new(x) }),
            cipher_suite: match &self.inner {
                QuicConnection::Client(session) => session.negotiated_cipher_suite(),
                QuicConnection::Server(session) => session.negotiated_cipher_suite(),
                QuicConnection::ServerHandshake(session) => session.negotiated_cipher_suite(),
            }
            .map(|suite| -> Box<dyn Any> { Box::new(suite.suite()) }),
            #[cfg(feature = "__rustls-post-quantum-test")]
            negotiated_key_exchange_group,
        }))
    }

    /// For the rustls `TlsSession`, the `Any` type is `rustls::crypto::Identity<'static>`
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner
            .peer_identity()
            .cloned()
            .map(|identity| -> Box<dyn Any> { Box::new(identity) })
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.is_early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.input.extend_from_slice(buf);
        loop {
            let before = self.input.len();
            self.inner
                .read_hs(&mut self.input)
                .map_err(transport_error_from_rustls)?;
            self.inner.drain_events(&mut self.pending_events);
            if self.input.is_empty() || self.input.len() == before {
                break;
            }
        }
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = self.inner.server_name().is_some();
            if (self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking())
                && self.required_handshake_data_is_ready()
            {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.drain_events(&mut self.pending_events);
        let keys = loop {
            match self.pending_events.pop_front()? {
                QuicEvent::Message(message) => buf.extend_from_slice(&message),
                QuicEvent::KeyChange(key_change) => {
                    break match key_change {
                        KeyChange::Handshake { keys } => keys,
                        KeyChange::OneRtt { keys, next } => {
                            self.next_secrets = Some(next);
                            keys
                        }
                    };
                }
                event => unreachable!("unsupported rustls QUIC event: {event:?}"),
            }
        };

        Some(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(16) else {
            return false;
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(&orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        retry_key_for_version(self.version, &self.suite)
            .decrypt_in_place(0, aad, tag, None)
            .is_ok()
    }

    fn export_keying_material(
        &mut self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        if self.exporter.is_none() {
            self.exporter = Some(
                self.inner
                    .exporter()
                    .map_err(|_| ExportKeyingMaterialError)?,
            );
        }

        self.exporter
            .as_ref()
            .expect("exporter is set")
            .derive(label, Some(context), output)
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

enum QuicConnection {
    Client(ClientConnection),
    Server(ServerConnection),
    ServerHandshake(ServerHandshakeConnection),
}

enum ServerHandshakeState {
    NeedsInput(NeedsInput),
    Complete(ServerConnection),
    Failed(Error),
}

struct ServerHandshakeConnection {
    state: Option<ServerHandshakeState>,
    pending_events: VecDeque<QuicEvent>,
    snapshot: ServerHandshakeSnapshot,
}

#[derive(Default)]
struct ServerHandshakeSnapshot {
    alpn_protocol: Option<Vec<u8>>,
    peer_identity: Option<Identity<'static>>,
    quic_transport_parameters: Option<Vec<u8>>,
    server_name: Option<String>,
    protocol_version: Option<rustls::enums::ProtocolVersion>,
    negotiated_cipher_suite: Option<rustls::SupportedCipherSuite>,
    #[cfg(feature = "__rustls-post-quantum-test")]
    negotiated_key_exchange_group: Option<NamedGroup>,
}

impl ServerHandshakeSnapshot {
    fn update_from_needs_input(&mut self, state: &NeedsInput) {
        if let Some(protocol) = state.alpn_protocol() {
            self.alpn_protocol = Some(protocol.as_ref().to_vec());
        }
        if let Some(identity) = state.peer_identity() {
            self.peer_identity = Some(identity.identity().clone());
        }
        if let Some(params) = state.quic_transport_parameters() {
            self.quic_transport_parameters = Some(params.to_vec());
        }
        if let Some(server_name) = state.server_name() {
            self.server_name = Some(server_name.as_ref().to_owned());
        }
        if let Some(version) = state.protocol_version() {
            self.protocol_version = Some(version);
        }
        if let Some(suite) = state.negotiated_cipher_suite() {
            self.negotiated_cipher_suite = Some(suite);
        }
        #[cfg(feature = "__rustls-post-quantum-test")]
        if let Some(group) = state.negotiated_key_exchange_group() {
            self.negotiated_key_exchange_group = Some(group.name());
        }
    }

    fn update_from_complete(&mut self, state: &ServerConnection) {
        if let Some(protocol) = state.alpn_protocol() {
            self.alpn_protocol = Some(protocol.as_ref().to_vec());
        }
        if let Some(identity) = state.peer_identity() {
            self.peer_identity = Some(identity.identity().clone());
        }
        if let Some(params) = state.quic_transport_parameters() {
            self.quic_transport_parameters = Some(params.to_vec());
        }
        if let Some(server_name) = state.server_name() {
            self.server_name = Some(server_name.as_ref().to_owned());
        }
        if let Some(version) = state.protocol_version() {
            self.protocol_version = Some(version);
        }
        if let Some(suite) = state.negotiated_cipher_suite() {
            self.negotiated_cipher_suite = Some(suite);
        }
        #[cfg(feature = "__rustls-post-quantum-test")]
        if let Some(group) = state.negotiated_key_exchange_group() {
            self.negotiated_key_exchange_group = Some(group.name());
        }
    }
}

impl ServerHandshakeConnection {
    fn new(state: ServerHandshake, events: Vec<QuicEvent>) -> Result<Self, Error> {
        let mut this = Self {
            state: None,
            pending_events: events.into(),
            snapshot: ServerHandshakeSnapshot::default(),
        };
        let _ = this.set_state(state)?;
        Ok(this)
    }

    /// Store `state`, returning whether synchronous client identity verification advanced the
    /// handshake without consuming input.
    fn set_state(&mut self, mut state: ServerHandshake) -> Result<bool, Error> {
        let mut verified_client_identity = false;
        loop {
            match state {
                ServerHandshake::NeedsInput(state) => {
                    self.snapshot.update_from_needs_input(&state);
                    self.state = Some(ServerHandshakeState::NeedsInput(state));
                    return Ok(verified_client_identity);
                }
                ServerHandshake::VerifyClientIdentity(verify) => {
                    verified_client_identity = true;
                    state = match verify.use_verifier_trait() {
                        Ok(state) => state,
                        Err(error) => return self.fail(error),
                    };
                }
                ServerHandshake::Complete(state) => {
                    self.snapshot.update_from_complete(&state);
                    self.state = Some(ServerHandshakeState::Complete(state));
                    return Ok(false);
                }
                ServerHandshake::Accepted(_) => {
                    return self.fail(Error::General(
                        "server config was requested more than once".into(),
                    ));
                }
                _ => {
                    return self.fail(Error::General(
                        "rustls returned an unsupported server handshake state".into(),
                    ));
                }
            }
        }
    }

    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.pending_events.clear();
        self.state = Some(ServerHandshakeState::Failed(error.clone()));
        Err(error)
    }

    fn read_hs(&mut self, input: &mut dyn TlsInputBuffer) -> Result<(), Error> {
        let Some(state) = self.state.take() else {
            return self.fail(Error::General("rustls handshake state missing".into()));
        };
        match state {
            ServerHandshakeState::NeedsInput(state) => {
                let mut events = Vec::new();
                match state.process(input, &mut events) {
                    Ok(state) => {
                        self.pending_events.extend(events);
                        if self.set_state(state)? {
                            // `NeedsInput::process()` stops when client identity verification is
                            // required. The verifier transition itself consumes no input, and
                            // rustls can already have CertificateVerify/Finished buffered from the
                            // same CRYPTO chunk. Give the resulting state one immediate chance to
                            // process that buffered data even when Quinn's input buffer is empty.
                            self.read_hs(input)
                        } else {
                            Ok(())
                        }
                    }
                    Err(error) => self.fail(error),
                }
            }
            ServerHandshakeState::Complete(mut state) => {
                let result = state.read_hs(input);
                self.snapshot.update_from_complete(&state);
                match result {
                    Ok(()) => {
                        self.state = Some(ServerHandshakeState::Complete(state));
                        Ok(())
                    }
                    Err(error) => self.fail(error),
                }
            }
            ServerHandshakeState::Failed(error) => self.fail(error),
        }
    }

    fn drain_events(&mut self, events: &mut VecDeque<QuicEvent>) {
        events.append(&mut self.pending_events);
        if let Some(ServerHandshakeState::Complete(state)) = &mut self.state {
            events.extend(state.events());
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        self.snapshot.alpn_protocol.as_deref()
    }

    fn peer_identity(&self) -> Option<&Identity<'static>> {
        self.snapshot.peer_identity.as_ref()
    }

    fn zero_rtt_keys(&self) -> Option<DirectionalKeys> {
        match self.state.as_ref()? {
            ServerHandshakeState::NeedsInput(state) => state.zero_rtt_keys(),
            ServerHandshakeState::Complete(state) => state.zero_rtt_keys(),
            ServerHandshakeState::Failed(_) => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match self.state.as_ref() {
            None => false,
            Some(ServerHandshakeState::Failed(_)) => false,
            Some(ServerHandshakeState::NeedsInput(_)) => true,
            Some(ServerHandshakeState::Complete(state)) => state.is_handshaking(),
        }
    }

    fn quic_transport_parameters(&self) -> Option<&[u8]> {
        self.snapshot.quic_transport_parameters.as_deref()
    }

    fn server_name(&self) -> Option<&str> {
        self.snapshot.server_name.as_deref()
    }

    fn protocol_version(&self) -> Option<rustls::enums::ProtocolVersion> {
        self.snapshot.protocol_version
    }

    fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        self.snapshot.negotiated_cipher_suite
    }

    #[cfg(feature = "__rustls-post-quantum-test")]
    fn negotiated_key_exchange_group(&self) -> Option<NamedGroup> {
        self.snapshot.negotiated_key_exchange_group
    }

    fn exporter(&mut self) -> Result<rustls::KeyingMaterialExporter, Error> {
        match self.state.as_mut() {
            Some(ServerHandshakeState::NeedsInput(_)) | None => Err(Error::HandshakeNotComplete),
            Some(ServerHandshakeState::Complete(state)) => state.exporter(),
            Some(ServerHandshakeState::Failed(error)) => Err(error.clone()),
        }
    }
}

impl QuicConnection {
    fn side(&self) -> Side {
        match self {
            Self::Client(_) => Side::Client,
            Self::Server(_) | Self::ServerHandshake(_) => Side::Server,
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Client(session) => session.alpn_protocol(),
            Self::Server(session) => session.alpn_protocol(),
            Self::ServerHandshake(session) => return session.alpn_protocol(),
        }
        .map(AsRef::as_ref)
    }

    fn peer_identity(&self) -> Option<&Identity<'static>> {
        match self {
            Self::Client(session) => session.peer_identity(),
            Self::Server(session) => session.peer_identity(),
            Self::ServerHandshake(session) => return session.peer_identity(),
        }
        .map(|identity| identity.identity())
    }

    fn zero_rtt_keys(&self) -> Option<DirectionalKeys> {
        match self {
            Self::Client(session) => session.zero_rtt_keys(),
            Self::Server(session) => session.zero_rtt_keys(),
            Self::ServerHandshake(session) => session.zero_rtt_keys(),
        }
    }

    fn is_early_data_accepted(&self) -> Option<bool> {
        match self {
            Self::Client(session) => Some(session.is_early_data_accepted()),
            Self::Server(_) | Self::ServerHandshake(_) => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(session) => session.is_handshaking(),
            Self::Server(session) => session.is_handshaking(),
            Self::ServerHandshake(session) => session.is_handshaking(),
        }
    }

    fn read_hs(&mut self, input: &mut dyn TlsInputBuffer) -> Result<(), Error> {
        match self {
            Self::Client(session) => session.read_hs(input),
            Self::Server(session) => session.read_hs(input),
            Self::ServerHandshake(session) => session.read_hs(input),
        }
    }

    fn drain_events(&mut self, events: &mut VecDeque<QuicEvent>) {
        match self {
            Self::Client(session) => events.extend(session.events()),
            Self::Server(session) => events.extend(session.events()),
            Self::ServerHandshake(session) => session.drain_events(events),
        }
    }

    fn quic_transport_parameters(&self) -> Option<&[u8]> {
        match self {
            Self::Client(session) => session.quic_transport_parameters(),
            Self::Server(session) => session.quic_transport_parameters(),
            Self::ServerHandshake(session) => session.quic_transport_parameters(),
        }
    }

    fn server_name(&self) -> Option<&str> {
        match self {
            Self::Client(_) => None,
            Self::Server(session) => session.server_name().map(AsRef::as_ref),
            Self::ServerHandshake(session) => session.server_name(),
        }
    }

    #[cfg(feature = "__rustls-post-quantum-test")]
    fn negotiated_key_exchange_group(&self) -> Option<NamedGroup> {
        match self {
            Self::Client(session) => session.negotiated_key_exchange_group(),
            Self::Server(session) => session.negotiated_key_exchange_group(),
            Self::ServerHandshake(session) => return session.negotiated_key_exchange_group(),
        }
        .map(|group| group.name())
    }

    fn exporter(&mut self) -> Result<rustls::KeyingMaterialExporter, Error> {
        match self {
            Self::Client(session) => session.exporter(),
            Self::Server(session) => session.exporter(),
            Self::ServerHandshake(session) => session.exporter(),
        }
    }
}

impl HeaderKey for Box<dyn HeaderProtectionKey> {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// Authentication data for (rustls) TLS session
#[non_exhaustive]
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
    /// The protocol version negotiated with the peer, if any
    pub protocol_version: Option<Box<dyn Any>>,
    /// The cipher suite negotiated with the peer, if any
    pub cipher_suite: Option<Box<dyn Any>>,
    /// The key exchange group negotiated with the peer
    #[cfg(feature = "__rustls-post-quantum-test")]
    pub negotiated_key_exchange_group: NamedGroup,
}

/// A QUIC-compatible TLS client configuration
///
/// Quinn implicitly constructs a `QuicClientConfig` with reasonable defaults within
/// [`ClientConfig::with_root_certificates()`][root_certs] and
/// [`ClientConfig::try_with_platform_verifier()`][platform].
/// Alternatively, `QuicClientConfig`'s [`TryFrom`] implementation can be used to wrap around a
/// custom [`rustls::ClientConfig`], in which case care should be taken around certain points:
///
/// - If `enable_early_data` is not set to true, then sending 0-RTT data will not be possible on
///   outgoing connections.
/// - The [`rustls::ClientConfig`] must have TLS 1.3 support enabled for conversion to succeed.
///
/// The object in the `resumption` field of the inner [`rustls::ClientConfig`] determines whether
/// calling `into_0rtt` on outgoing connections returns `Ok` or `Err`. It typically allows
/// `into_0rtt` to proceed if it recognizes the server name, and defaults to an in-memory cache of
/// 256 server names.
///
/// [root_certs]: crate::config::ClientConfig::with_root_certificates()
/// [platform]: crate::config::ClientConfig::try_with_platform_verifier()
pub struct QuicClientConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl QuicClientConfig {
    #[cfg(feature = "platform-verifier")]
    pub(crate) fn with_platform_verifier() -> Result<Self, Error> {
        let mut inner = rustls::ClientConfig::builder(configured_provider())
            .with_platform_verifier()?
            .with_no_client_auth()
            .expect("default providers are valid for QUIC");

        inner.enable_early_data = true;
        Ok(Self {
            // We're confident that the default providers contain TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize a sane QUIC-compatible TLS client configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled. Advanced users can use any [`rustls::ClientConfig`] that
    /// satisfies this requirement.
    pub(crate) fn new(verifier: Arc<dyn ServerVerifier>) -> Self {
        let inner = Self::inner(verifier);
        Self {
            // We're confident that the default providers contain TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        }
    }

    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub fn with_initial(
        inner: Arc<rustls::ClientConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.inner.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self { inner, initial }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    pub(crate) fn inner(verifier: Arc<dyn ServerVerifier>) -> rustls::ClientConfig {
        Self::inner_with_provider(verifier, configured_provider())
    }

    pub(crate) fn inner_with_provider(
        verifier: Arc<dyn ServerVerifier>,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::builder(provider)
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
            .expect("default providers are valid for QUIC");

        config.enable_early_data = true;
        config
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        Ok(Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            exporter: None,
            inner: QuicConnection::Client(
                ClientConnection::new(
                    self.inner.clone(),
                    version,
                    ServerName::try_from(server_name)
                        .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?
                        .to_owned(),
                    to_vec(params),
                )
                .unwrap(),
            ),
            input: HandshakeInput::default(),
            pending_events: VecDeque::new(),
            suite: self.initial,
        }))
    }
}

impl TryFrom<rustls::ClientConfig> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ClientConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ClientConfig>> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ClientConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

/// The initial cipher suite (AES-128-GCM-SHA256) is not available
///
/// When the cipher suite is supplied `with_initial()`, it must be
/// [`CipherSuite::TLS13_AES_128_GCM_SHA256`]. When the cipher suite is derived from a config's
/// [`CryptoProvider`], that provider must reference a cipher suite with the same ID.
#[derive(Clone, Debug)]
pub struct NoInitialCipherSuite {
    /// Whether the initial cipher suite was supplied by the caller
    specific: bool,
}

impl std::fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.specific {
            true => "invalid cipher suite specified",
            false => "no initial cipher suite found",
        })
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// A QUIC-compatible TLS server configuration
///
/// Quinn implicitly constructs a `QuicServerConfig` with reasonable defaults within
/// [`ServerConfig::with_single_cert()`][single]. Alternatively, `QuicServerConfig`'s [`TryFrom`]
/// implementation or `with_initial` method can be used to wrap around a custom
/// [`rustls::ServerConfig`], in which case care should be taken around certain points:
///
/// - If `max_early_data_size` is not set to `u32::MAX`, the server will not be able to accept
///   incoming 0-RTT data. QUIC prohibits `max_early_data_size` values other than 0 or `u32::MAX`.
/// - The `rustls::ServerConfig` must have TLS 1.3 support enabled for conversion to succeed.
///
/// [single]: crate::config::ServerConfig::with_single_cert()
pub struct QuicServerConfig {
    inner: Arc<rustls::ServerConfig>,
    initial: Suite,
}

impl QuicServerConfig {
    pub(crate) fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Error> {
        let inner = Self::inner(cert_chain, key)?;
        Ok(Self {
            // We're confident that the default providers contain TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub fn with_initial(
        inner: Arc<rustls::ServerConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.inner.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self { inner, initial }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    /// Initialize a sane QUIC-compatible TLS server configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled, and that the maximum early data size is either 0 or
    /// `u32::MAX`. Advanced users can use any [`rustls::ServerConfig`] that satisfies these
    /// requirements.
    pub(crate) fn inner(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<rustls::ServerConfig, Error> {
        Self::inner_with_provider(cert_chain, key, configured_provider())
    }

    pub(crate) fn inner_with_provider(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        provider: Arc<CryptoProvider>,
    ) -> Result<rustls::ServerConfig, Error> {
        let mut inner = rustls::ServerConfig::builder(provider)
            .with_no_client_auth()
            .with_single_cert(Arc::new(Identity::from_cert_chain(cert_chain)?), key)?;

        inner.max_early_data_size = u32::MAX;
        Ok(inner)
    }
}

impl TryFrom<rustls::ServerConfig> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ServerConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ServerConfig>> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ServerConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            exporter: None,
            inner: QuicConnection::Server(
                ServerConnection::new(self.inner.clone(), version, to_vec(params)).unwrap(),
            ),
            input: HandshakeInput::default(),
            pending_events: VecDeque::new(),
            suite: self.initial,
        })
    }

    fn start_session_from_accepted(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
        accepted: Accepted,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        // Safe: `start_session_from_accepted()` is never called if `initial_keys()` rejected
        // `version`.
        let version = interpret_version(version).unwrap();
        let Accepted { inner, input, .. } = accepted;
        let mut events = Vec::new();
        let state = inner
            .choose_config(self.inner.clone(), to_vec(params), &mut events)
            .map_err(transport_error_from_rustls)?;
        let inner =
            ServerHandshakeConnection::new(state, events).map_err(transport_error_from_rustls)?;

        Ok(Box::new(TlsSession {
            version,
            // The staged acceptor already consumed ClientHello, so the server-side handshake
            // metadata is immediately available without replaying Initial CRYPTO.
            got_handshake_data: true,
            next_secrets: None,
            exporter: None,
            inner: QuicConnection::ServerHandshake(inner),
            input,
            pending_events: VecDeque::new(),
            suite: self.initial,
        }))
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(&orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let tag = retry_key_for_version(version, &self.initial)
            .encrypt_in_place(0, &pseudo_packet, &mut [], None)
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

fn retry_key_for_version(version: Version, initial_suite: &Suite) -> Box<dyn PacketKey> {
    let (nonce, key) = match version {
        Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
        _ => unreachable!(),
    };

    initial_suite
        .quic
        .packet_key(AeadKey::from(key), Iv::from(nonce))
}

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

pub(crate) fn initial_suite_from_provider(provider: &Arc<CryptoProvider>) -> Option<Suite> {
    provider
        .tls13_cipher_suites
        .iter()
        .find_map(|&suite| match suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Suite::try_from(suite).ok(),
            _ => None,
        })
}

pub(crate) fn configured_provider() -> Arc<CryptoProvider> {
    #[cfg(all(feature = "rustls-aws-lc-rs", not(feature = "rustls-ring")))]
    let provider = rustls_aws_lc_rs::DEFAULT_PROVIDER;
    #[cfg(feature = "rustls-ring")]
    let provider = rustls_ring::DEFAULT_PROVIDER;
    Arc::new(provider)
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

pub(crate) fn initial_keys(
    version: Version,
    dst_cid: ConnectionId,
    side: Side,
    suite: &Suite,
) -> Keys {
    let keys = suite.keys(&dst_cid, side.into(), version);
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}

impl crypto::PacketKey for Box<dyn PacketKey> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self
            .encrypt_in_place(packet, &*header, payload, None)
            .unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .decrypt_in_place(packet, header, payload.as_mut(), None)
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        (**self).confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        (**self).integrity_limit()
    }
}

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_server_handshake_is_a_stable_terminal_state() {
        let mut connection = ServerHandshakeConnection {
            state: None,
            pending_events: VecDeque::from([QuicEvent::Message(vec![1, 2, 3])]),
            snapshot: ServerHandshakeSnapshot {
                alpn_protocol: Some(b"test".to_vec()),
                quic_transport_parameters: Some(vec![4, 5, 6]),
                server_name: Some("localhost".into()),
                protocol_version: Some(rustls::enums::ProtocolVersion::TLSv1_3),
                ..ServerHandshakeSnapshot::default()
            },
        };
        let error = Error::General("fatal test error".into());

        assert_eq!(connection.fail::<()>(error.clone()), Err(error.clone()));
        assert!(!connection.is_handshaking());
        assert_eq!(connection.alpn_protocol(), Some(b"test".as_slice()));
        assert_eq!(connection.server_name(), Some("localhost"));
        assert_eq!(
            connection.protocol_version(),
            Some(rustls::enums::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            connection.quic_transport_parameters(),
            Some([4, 5, 6].as_slice())
        );
        assert!(connection.peer_identity().is_none());
        assert!(connection.zero_rtt_keys().is_none());
        match connection.exporter() {
            Err(actual) => assert_eq!(actual, error),
            Ok(_) => panic!("failed handshake unexpectedly produced an exporter"),
        }

        let mut input = HandshakeInput::default();
        assert_eq!(connection.read_hs(&mut input), Err(error));
        let mut events = VecDeque::new();
        connection.drain_events(&mut events);
        assert!(events.is_empty());
    }
}
