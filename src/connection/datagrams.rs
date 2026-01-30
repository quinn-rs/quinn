// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    TransportError,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            while self.conn.datagrams.outgoing_total > self.conn.config.datagram_send_buffer_size {
                let prev = self
                    .conn
                    .datagrams
                    .outgoing
                    .pop_front()
                    .expect("datagrams.outgoing_total desynchronized");
                debug!(
                    len = prev.data.len(),
                    "dropping outgoing datagram (send buffer full)"
                );
                self.conn.datagrams.outgoing_total -= prev.data.len();
            }
        } else if self.conn.datagrams.outgoing_total + data.len()
            > self.conn.config.datagram_send_buffer_size
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
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
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
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

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

/// Result of receiving a datagram, including any drops that occurred
#[derive(Debug, Clone, Copy, Default)]
pub struct DatagramReceivedResult {
    /// Whether the receive buffer was empty before this datagram
    pub was_empty: bool,
    /// Number of old datagrams that were dropped to make room
    pub dropped_count: usize,
    /// Total bytes of dropped datagrams
    pub dropped_bytes: usize,
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<Datagram>,
    pub(super) outgoing: VecDeque<Datagram>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<DatagramReceivedResult, TransportError> {
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
        let mut dropped_count = 0;
        let mut dropped_bytes = 0;

        while datagram.data.len() + self.recv_buffered > window {
            if let Some(dropped) = self.recv() {
                dropped_count += 1;
                dropped_bytes += dropped.len();
                debug!(
                    dropped_count,
                    dropped_bytes,
                    recv_buffered = self.recv_buffered,
                    incoming_len = datagram.data.len(),
                    window,
                    "dropping stale datagram (buffer full) - application not reading fast enough"
                );
            } else {
                // Buffer is empty but still can't fit - shouldn't happen with valid window
                break;
            }
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back(datagram);
        Ok(DatagramReceivedResult {
            was_empty,
            dropped_count,
            dropped_bytes,
        })
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) {
        self.outgoing.retain(|datagram| {
            let result = datagram.data.len() < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing_total -= datagram.data.len();
            }
            result
        });
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
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

        trace!(len = datagram.data.len(), "DATAGRAM");

        self.outgoing_total -= datagram.data.len();
        datagram.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
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
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_received_no_drop() {
        let mut state = DatagramState::default();
        let window = Some(1024);

        // Add a small datagram that fits
        let datagram = Datagram {
            data: Bytes::from(vec![0u8; 100]),
        };
        let result = state.received(datagram, &window).unwrap();

        assert!(result.was_empty);
        assert_eq!(result.dropped_count, 0);
        assert_eq!(result.dropped_bytes, 0);
        assert_eq!(state.recv_buffered, 100);
    }

    #[test]
    fn test_datagram_received_with_drop() {
        let mut state = DatagramState::default();
        let window = Some(1024);

        // Fill the buffer with a datagram
        let datagram1 = Datagram {
            data: Bytes::from(vec![0u8; 800]),
        };
        let result1 = state.received(datagram1, &window).unwrap();
        assert!(result1.was_empty);
        assert_eq!(result1.dropped_count, 0);

        // Add another datagram that would exceed the window
        let datagram2 = Datagram {
            data: Bytes::from(vec![1u8; 500]),
        };
        let result2 = state.received(datagram2, &window).unwrap();

        // Should have dropped the first datagram to make room
        assert!(!result2.was_empty);
        assert_eq!(result2.dropped_count, 1);
        assert_eq!(result2.dropped_bytes, 800);

        // Buffer should now contain only the second datagram
        assert_eq!(state.recv_buffered, 500);
        assert_eq!(state.incoming.len(), 1);
    }

    #[test]
    fn test_datagram_received_multiple_drops() {
        let mut state = DatagramState::default();
        let window = Some(1024);

        // Fill with multiple small datagrams
        for i in 0..5 {
            let datagram = Datagram {
                data: Bytes::from(vec![i as u8; 200]),
            };
            state.received(datagram, &window).unwrap();
        }

        // Buffer should have 1000 bytes (5 x 200)
        assert_eq!(state.recv_buffered, 1000);
        assert_eq!(state.incoming.len(), 5);

        // Add a large datagram that requires dropping multiple old ones
        let large_datagram = Datagram {
            data: Bytes::from(vec![99u8; 900]),
        };
        let result = state.received(large_datagram, &window).unwrap();

        // Should have dropped 5 datagrams (1000 bytes) to fit 900 bytes
        assert_eq!(result.dropped_count, 5);
        assert_eq!(result.dropped_bytes, 1000);
        assert_eq!(state.recv_buffered, 900);
        assert_eq!(state.incoming.len(), 1);
    }

    #[test]
    fn test_datagram_received_disabled() {
        let mut state = DatagramState::default();
        let window = None; // Datagrams disabled

        let datagram = Datagram {
            data: Bytes::from(vec![0u8; 100]),
        };
        let result = state.received(datagram, &window);

        assert!(result.is_err());
    }

    #[test]
    fn test_datagram_received_oversized() {
        let mut state = DatagramState::default();
        let window = Some(100);

        // Datagram larger than window
        let datagram = Datagram {
            data: Bytes::from(vec![0u8; 200]),
        };
        let result = state.received(datagram, &window);

        assert!(result.is_err());
    }
}
