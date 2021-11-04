use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    frame::{Datagram, FrameStruct},
    packet::SpaceId,
    TransportError,
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl<'a> Datagrams<'a> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent
    pub fn send(&mut self, data: Bytes) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        while self.conn.datagrams.outgoing_total > self.conn.config.datagram_send_buffer_size {
            let prev = self
                .conn
                .datagrams
                .outgoing
                .pop_front()
                .expect("datagrams.outgoing_total desynchronized");
            trace!(len = prev.data.len(), "dropping outgoing datagram");
            self.conn.datagrams.outgoing_total -= prev.data.len();
        }
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.outgoing.push_back(Datagram { data });
        Ok(())
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // This is usually 1162 bytes, but we shouldn't document that without a doctest.
        let max_size = self.conn.path.max_udp_payload_size as usize
            - 1                 // flags byte
            - self.conn.rem_cids.active().len()
            - 4                 // worst-case packet number size
            - self.conn.spaces[SpaceId::Data].crypto.as_ref().map_or_else(|| &self.conn.zero_rtt_crypto.as_ref().unwrap().packet, |x| &x.packet.local).tag_len()
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<Datagram>,
    pub(super) outgoing: VecDeque<Datagram>,
    pub(super) outgoing_total: usize,
}

impl DatagramState {
    pub fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.recv_buffered == 0;
        while datagram.data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    pub fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
        let datagram = match self.outgoing.pop_front() {
            Some(x) => x,
            None => return false,
        };

        if buf.len() + datagram.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        self.outgoing_total -= datagram.data.len();
        datagram.encode(true, buf);
        true
    }

    pub fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        self.recv_buffered -= x.len();
        Some(x)
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
}
