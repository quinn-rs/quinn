use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::{Connection, Event};
use crate::{
    Instant, TransportError,
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
    /// The datagram is discarded before packet generation when `deadline <= now`, using the
    /// time passed to [`Connection::poll_transmit`]. `None` means no expiration. Expiration does
    /// not schedule a timer or cancel already generated packets.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(
        &mut self,
        data: Bytes,
        drop: bool,
        deadline: Option<Instant>,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if data.len() > max
            || data
                .len()
                .checked_add(size_of::<QueuedDatagram>())
                .is_none_or(|size| size > send_buffer_size)
        {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn
                .datagrams
                .outgoing
                .make_space_for(data.len(), send_buffer_size);
        } else if !self
            .conn
            .datagrams
            .outgoing
            .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing.push_back(QueuedDatagram {
            frame: Datagram { data },
            deadline,
        });
        Ok(())
    }

    /// Discard queued datagrams that no longer fit the active path, waking blocked senders.
    pub(super) fn drop_oversized(&mut self) {
        let Some(max_datagram_size) = self.max_size() else {
            return;
        };
        if !self
            .conn
            .datagrams
            .outgoing
            .drop_oversized(max_datagram_size)
            || !self.conn.datagrams.send_blocked
        {
            return;
        }

        self.conn.datagrams.send_blocked = false;
        self.conn.events.push_back(Event::DatagramsUnblocked);
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
            .saturating_sub(self.conn.datagrams.outgoing.memory_used())
            .saturating_sub(size_of::<QueuedDatagram>())
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) incoming: DatagramBuffer,
    pub(super) outgoing: DatagramSendBuffer,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    pub(super) fn received(
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

        let size_with_overhead = datagram.data.len() + size_of::<Datagram>();

        if size_with_overhead > window {
            // A valid frame can still exceed the local memory budget because of queue metadata.
            debug!("dropping datagram exceeding receive memory budget");
            return Ok(false);
        }

        let was_empty = self.incoming.is_empty();
        while self.incoming.memory_used() + size_with_overhead > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        Some(x)
    }
}

#[derive(Default)]
pub(super) struct DatagramBuffer {
    queue: VecDeque<Datagram>,
    payload_bytes: usize,
}

impl DatagramBuffer {
    fn push_back(&mut self, datagram: Datagram) {
        self.payload_bytes += datagram.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<Datagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.data.len();
        Some(datagram)
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len() * size_of::<Datagram>())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Default)]
pub(super) struct DatagramSendBuffer {
    queue: VecDeque<QueuedDatagram>,
    payload_bytes: usize,
    /// Lower bound on queued deadlines. Sending or dropping a datagram may leave this stale,
    /// causing an extra scan at that deadline rather than a scan on every removal.
    next_deadline: Option<Instant>,
}

impl DatagramSendBuffer {
    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        self.queue.retain(|datagram| {
            let result = datagram.frame.data.len() <= max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.frame.data.len(),
                    max_payload
                );
                self.payload_bytes -= datagram.frame.data.len();
                dropped_any = true;
            }
            result
        });
        if self.is_empty() {
            self.next_deadline = None;
        }
        dropped_any
    }

    /// Discard expired outgoing datagrams, preserving the order of the remaining entries.
    pub(super) fn drop_expired(&mut self, now: Instant) -> bool {
        // If the next_deadline is in the future, don't scan at all.
        if !self.next_deadline.is_some_and(|deadline| deadline <= now) {
            return false;
        }
        self.next_deadline = None;
        let mut dropped_any = false;
        self.queue.retain(|datagram| {
            if datagram.deadline.is_some_and(|deadline| deadline <= now) {
                trace!(len = datagram.frame.data.len(), "dropping expired datagram");
                self.payload_bytes -= datagram.frame.data.len();
                dropped_any = true;
                return false;
            }
            if let Some(deadline) = datagram.deadline {
                self.next_deadline = Some(self.next_deadline.map_or(deadline, |x| x.min(deadline)));
            }
            true
        });
        dropped_any
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from this buffer
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
        let Some(datagram) = self.pop_front() else {
            return false;
        };

        if buf.len() + datagram.frame.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.payload_bytes += datagram.frame.data.len();
            self.queue.push_front(datagram);
            return false;
        }

        trace!(len = datagram.frame.data.len(), "DATAGRAM");
        datagram.frame.encode(true, buf);
        if self.is_empty() {
            self.next_deadline = None;
        }
        true
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.queue
            .front()
            .is_some_and(|x| x.frame.size(true) <= max_size)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn push_back(&mut self, datagram: QueuedDatagram) {
        if self.is_empty() {
            self.next_deadline = datagram.deadline;
        } else if let Some(deadline) = datagram.deadline {
            self.next_deadline = Some(self.next_deadline.map_or(deadline, |x| x.min(deadline)));
        }
        self.payload_bytes += datagram.frame.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<QueuedDatagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.frame.data.len();
        Some(datagram)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.pop_front() else {
                break;
            };
            trace!(len = prev.frame.data.len(), "dropping outgoing datagram");
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self
            .memory_used()
            .checked_add(datagram_len)
            .and_then(|size| size.checked_add(size_of::<QueuedDatagram>()))
        else {
            return false;
        };

        total <= send_buffer_size
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len() * size_of::<QueuedDatagram>())
    }
}

struct QueuedDatagram {
    frame: Datagram,
    deadline: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_buffer_reserves_metadata_for_each_datagram() {
        let mut buffer = DatagramSendBuffer::default();
        let limit = 2 * size_of::<QueuedDatagram>() + 10;
        buffer.push_back(QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(b"first"),
            },
            deadline: None,
        });
        assert!(buffer.has_send_buffer_space(5, limit));
        assert!(!buffer.has_send_buffer_space(6, limit));
        assert!(!buffer.has_send_buffer_space(usize::MAX, usize::MAX));
        buffer.make_space_for(6, limit);
        assert!(buffer.is_empty());
        assert!(buffer.has_send_buffer_space(6, limit));
        assert!(!buffer.has_send_buffer_space(0, size_of::<QueuedDatagram>() - 1));
        assert!(buffer.has_send_buffer_space(0, size_of::<QueuedDatagram>()));
    }

    #[test]
    fn expiration_preserves_order_and_accounts_for_memory() {
        let now = Instant::now();
        let later = now + crate::Duration::from_secs(1);
        let mut buffer = DatagramSendBuffer::default();
        for (data, deadline) in [
            (&b"later"[..], Some(later)),
            (&b"past"[..], Some(now - crate::Duration::from_secs(1))),
            (&b"none"[..], None),
            (&b"now"[..], Some(now)),
        ] {
            buffer.push_back(QueuedDatagram {
                frame: Datagram {
                    data: Bytes::from_static(data),
                },
                deadline,
            });
        }

        assert!(buffer.drop_expired(now));
        assert_eq!(buffer.queue.len(), 2);
        assert_eq!(buffer.queue[0].frame.data, &b"later"[..]);
        assert_eq!(buffer.queue[1].frame.data, &b"none"[..]);
        assert_eq!(buffer.payload_bytes, 9);
        assert_eq!(buffer.memory_used(), 9 + 2 * size_of::<QueuedDatagram>());
        assert_eq!(buffer.next_deadline, Some(later));
        assert!(!buffer.drop_expired(now));
        assert!(buffer.drop_expired(later));
        assert_eq!(buffer.queue.len(), 1);
        assert_eq!(buffer.queue[0].frame.data, &b"none"[..]);
        assert_eq!(buffer.payload_bytes, 4);
        assert_eq!(buffer.next_deadline, None);
    }

    #[test]
    fn expiration_tracks_earlier_deadlines() {
        let now = Instant::now();
        let later = now + crate::Duration::from_secs(1);
        let mut buffer = DatagramSendBuffer::default();
        for deadline in [None, Some(later), Some(now)] {
            buffer.push_back(QueuedDatagram {
                frame: Datagram {
                    data: Bytes::from_static(b"data"),
                },
                deadline,
            });
            assert_eq!(buffer.next_deadline, deadline);
        }
        assert!(buffer.drop_expired(now));
        assert_eq!(buffer.queue.len(), 2);
        assert_eq!(buffer.next_deadline, Some(later));
        assert!(buffer.drop_expired(later));
        assert_eq!(buffer.queue.len(), 1);
        assert_eq!(buffer.next_deadline, None);
    }

    #[test]
    fn expiration_without_due_deadlines_preserves_queue() {
        let now = Instant::now();
        for deadline in [None, Some(now + crate::Duration::from_secs(1))] {
            let mut buffer = DatagramSendBuffer::default();
            buffer.push_back(QueuedDatagram {
                frame: Datagram {
                    data: Bytes::from_static(b"data"),
                },
                deadline,
            });
            assert!(!buffer.drop_expired(now));
            assert_eq!(buffer.next_deadline, deadline);
            assert_eq!(buffer.queue.len(), 1);
            assert_eq!(buffer.queue[0].frame.data, &b"data"[..]);
            assert_eq!(buffer.payload_bytes, 4);
        }
    }

    #[test]
    fn expiration_after_removing_earliest_datagram() {
        let now = Instant::now();
        let later = now + crate::Duration::from_secs(1);
        for removal in ["send", "capacity", "size"] {
            let mut buffer = DatagramSendBuffer::default();
            for (data, deadline) in [(&b"first"[..], now), (&b"next"[..], later)] {
                buffer.push_back(QueuedDatagram {
                    frame: Datagram {
                        data: Bytes::from_static(data),
                    },
                    deadline: Some(deadline),
                });
            }
            match removal {
                "send" => assert!(buffer.write(&mut Vec::new(), 1200)),
                "capacity" => buffer.make_space_for(1, 5 + 2 * size_of::<QueuedDatagram>()),
                "size" => assert!(buffer.drop_oversized(4)),
                _ => unreachable!(),
            }
            assert_eq!(buffer.queue.len(), 1);
            assert_eq!(buffer.queue[0].frame.data, &b"next"[..]);
            assert!(!buffer.drop_expired(now));
            assert_eq!(buffer.next_deadline, Some(later));
            assert!(buffer.drop_expired(later));
            assert!(buffer.is_empty());
            assert_eq!(buffer.memory_used(), 0);
            assert_eq!(buffer.next_deadline, None);
        }
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(&[0; 7]),
            },
            deadline: None,
        });
        state.outgoing.push_back(QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(&[0; 2]),
            },
            deadline: None,
        });

        state
            .outgoing
            .make_space_for(4, 10 + 2 * size_of::<QueuedDatagram>());

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].frame.data.len(), 2);
        assert_eq!(state.outgoing.payload_bytes, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.queue.push_back(QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(&[0]),
            },
            deadline: None,
        });
        state.outgoing.payload_bytes = usize::MAX - 1;

        state.outgoing.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing.payload_bytes, usize::MAX - 2);
    }

    #[test]
    fn empty_frame_flood_limit() {
        let mut state = DatagramState::default();
        let datagram = Datagram { data: Bytes::new() };
        let window = 100;
        loop {
            let initial_count = state.incoming.queue.len();
            state.received(datagram.clone(), &Some(window)).unwrap();
            assert!(state.incoming.queue.len() * size_of::<Datagram>() <= window);
            if state.incoming.queue.len() == initial_count {
                // Datagrams are getting dropped
                break;
            }
        }
    }

    #[test]
    fn drop_oversized_keeps_datagrams_at_limit() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(&[0; 10]),
            },
            deadline: None,
        });
        state.outgoing.push_back(QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(&[0; 11]),
            },
            deadline: None,
        });

        assert!(state.outgoing.drop_oversized(10));

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].frame.data.len(), 10);
        assert_eq!(state.outgoing.payload_bytes, 10);
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
