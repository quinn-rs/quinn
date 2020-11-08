/// Statistics about packets transmitted on a connection
#[derive(Default)]
#[non_exhaustive]
pub struct PacketTransmissionStats {
    /// The amount of packets transmitted on a connection
    pub packets: u64,
    /// The total amount of bytes transmitted on a connection
    pub bytes: u64,
}

impl std::fmt::Debug for PacketTransmissionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketTransmissionStats")
            .field("packets", &self.packets)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// Statistics about frames transmitted or received on a connection
#[derive(Default)]
#[non_exhaustive]
pub struct FrameStats {
    pub acks: u64,
    pub crypto: u64,
    pub datagram: u64,
    pub handshake_done: u8,
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub new_connection_id: u64,
    pub path_challenge: u64,
    pub path_response: u64,
    pub ping: u64,
    pub reset_stream: u64,
    pub retire_connection_id: u64,
    pub stop_sending: u64,
    pub stream: u64,
}

impl std::fmt::Debug for FrameStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameStats")
            .field("ACK", &self.acks)
            .field("CRYPTO", &self.crypto)
            .field("DATAGRAM", &self.datagram)
            .field("HANDSHAKE_DONE", &self.handshake_done)
            .field("MAX_DATA", &self.max_data)
            .field("MAX_STREAM_DATA", &self.max_stream_data)
            .field("MAX_STREAMS_BIDI", &self.max_streams_bidi)
            .field("MAX_STREAMS_UNI", &self.max_streams_uni)
            .field("NEW_CONNECTION_ID", &self.new_connection_id)
            .field("PATH_CHALLENGE", &self.path_challenge)
            .field("PATH_RESPONSE", &self.path_response)
            .field("PING", &self.ping)
            .field("RESET_STREAM", &self.reset_stream)
            .field("RETIRE_CONNECTION_ID", &self.retire_connection_id)
            .field("STOP_SENDING", &self.stop_sending)
            .field("STREAM", &self.stream)
            .finish()
    }
}

/// Connection statistics
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ConnectionStats {
    pub packet_tx: PacketTransmissionStats,
    pub frame_tx: FrameStats,
}
