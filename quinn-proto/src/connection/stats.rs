//! Connection statistics

use crate::{frame::Frame, Dir};
use std::time::Duration;

/// Statistics about UDP datagrams transmitted or received on a connection
#[derive(Default, Debug, Copy, Clone)]
#[non_exhaustive]
pub struct UdpStats {
    /// The amount of UDP datagrams observed
    pub datagrams: u64,
    /// The total amount of bytes which have been transferred inside UDP datagrams
    pub bytes: u64,
    /// The amount of transmit calls which have been performed
    ///
    /// This can mismatch the amount of datagrams in case GSO is utilized for
    /// transmitting data.
    pub transmits: u64,
}

/// Statistics about frames transmitted or received on a connection
#[derive(Default, Copy, Clone)]
#[non_exhaustive]
pub struct FrameStats {
    pub acks: u64,
    pub crypto: u64,
    pub connection_close: u64,
    pub data_blocked: u64,
    pub datagram: u64,
    pub handshake_done: u8,
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub new_connection_id: u64,
    pub new_token: u64,
    pub path_challenge: u64,
    pub path_response: u64,
    pub ping: u64,
    pub reset_stream: u64,
    pub retire_connection_id: u64,
    pub stream_data_blocked: u64,
    pub streams_blocked_bidi: u64,
    pub streams_blocked_uni: u64,
    pub stop_sending: u64,
    pub stream: u64,
}

impl FrameStats {
    pub(crate) fn record(&mut self, frame: &Frame) {
        match frame {
            Frame::Padding => {}
            Frame::Ping => self.ping += 1,
            Frame::Ack(_) => self.acks += 1,
            Frame::ResetStream(_) => self.reset_stream += 1,
            Frame::StopSending(_) => self.stop_sending += 1,
            Frame::Crypto(_) => self.crypto += 1,
            Frame::Datagram(_) => self.datagram += 1,
            Frame::NewToken { .. } => self.new_token += 1,
            Frame::MaxData(_) => self.max_data += 1,
            Frame::MaxStreamData { .. } => self.max_stream_data += 1,
            Frame::MaxStreams { dir, .. } => {
                if *dir == Dir::Bi {
                    self.max_streams_bidi += 1;
                } else {
                    self.max_streams_uni += 1;
                }
            }
            Frame::DataBlocked { .. } => self.data_blocked += 1,
            Frame::Stream(_) => self.stream += 1,
            Frame::StreamDataBlocked { .. } => self.stream_data_blocked += 1,
            Frame::StreamsBlocked { dir, .. } => {
                if *dir == Dir::Bi {
                    self.streams_blocked_bidi += 1;
                } else {
                    self.streams_blocked_uni += 1;
                }
            }
            Frame::NewConnectionId(_) => self.new_connection_id += 1,
            Frame::RetireConnectionId { .. } => self.retire_connection_id += 1,
            Frame::PathChallenge(_) => self.path_challenge += 1,
            Frame::PathResponse(_) => self.path_response += 1,
            Frame::Close(_) => self.connection_close += 1,
            Frame::HandshakeDone => self.handshake_done += 1,
            Frame::Invalid { .. } => {}
        }
    }
}

impl std::fmt::Debug for FrameStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameStats")
            .field("ACK", &self.acks)
            .field("CONNECTION_CLOSE", &self.connection_close)
            .field("CRYPTO", &self.crypto)
            .field("DATA_BLOCKED", &self.data_blocked)
            .field("DATAGRAM", &self.datagram)
            .field("HANDSHAKE_DONE", &self.handshake_done)
            .field("MAX_DATA", &self.max_data)
            .field("MAX_STREAM_DATA", &self.max_stream_data)
            .field("MAX_STREAMS_BIDI", &self.max_streams_bidi)
            .field("MAX_STREAMS_UNI", &self.max_streams_uni)
            .field("NEW_CONNECTION_ID", &self.new_connection_id)
            .field("NEW_TOKEN", &self.new_token)
            .field("PATH_CHALLENGE", &self.path_challenge)
            .field("PATH_RESPONSE", &self.path_response)
            .field("PING", &self.ping)
            .field("RESET_STREAM", &self.reset_stream)
            .field("RETIRE_CONNECTION_ID", &self.retire_connection_id)
            .field("STREAM_DATA_BLOCKED", &self.stream_data_blocked)
            .field("STREAMS_BLOCKED_BIDI", &self.streams_blocked_bidi)
            .field("STREAMS_BLOCKED_UNI", &self.streams_blocked_uni)
            .field("STOP_SENDING", &self.stop_sending)
            .field("STREAM", &self.stream)
            .finish()
    }
}

/// Statistics related to a transmission path
#[derive(Debug, Default, Copy, Clone)]
#[non_exhaustive]
pub struct PathStats {
    /// Current best estimate of this connection's latency (round-trip-time)
    pub rtt: Duration,
    /// Current congestion window of the connection
    pub cwnd: u64,
    /// Congestion events on the connection
    pub congestion_events: u64,
    /// The amount of packets lost on this path
    pub lost_packets: u64,
    /// The amount of bytes lost on this path
    pub lost_bytes: u64,
    /// The amount of packets sent on this path
    pub sent_packets: u64,
}

/// Connection statistics
#[derive(Debug, Default, Copy, Clone)]
#[non_exhaustive]
pub struct ConnectionStats {
    /// Statistics about UDP datagrams transmitted on a connection
    pub udp_tx: UdpStats,
    /// Statistics about UDP datagrams received on a connection
    pub udp_rx: UdpStats,
    /// Statistics about frames transmitted on a connection
    pub frame_tx: FrameStats,
    /// Statistics about frames received on a connection
    pub frame_rx: FrameStats,
    /// Statistics related to the current transmission path
    pub path: PathStats,
}
