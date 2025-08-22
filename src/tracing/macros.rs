// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Zero-cost macros for tracing
//!
//! These macros compile to nothing when the trace feature is disabled.

/// Primary trace event macro - compiles to nothing when disabled
#[macro_export]
macro_rules! trace_event {
    ($log:expr_2021, $event:expr_2021) => {
        #[cfg(feature = "trace")]
        $log.log($event)
    };
}

/// Trace a packet sent event
#[macro_export]
macro_rules! trace_packet_sent {
    ($log:expr_2021, $trace_id:expr_2021, $size:expr_2021, $num:expr_2021) => {
        $crate::trace_event!(
            $log,
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::PacketSent {
                    size: $size as u32,
                    packet_num: $num,
                    _padding: [0u8; 56],
                },
                ..Default::default()
            }
        )
    };
}

/// Trace a packet received event
#[macro_export]
macro_rules! trace_packet_received {
    ($log:expr_2021, $trace_id:expr_2021, $size:expr_2021, $num:expr_2021) => {
        $crate::trace_event!(
            $log,
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::PacketReceived {
                    size: $size as u32,
                    packet_num: $num,
                    _padding: [0u8; 56],
                },
                ..Default::default()
            }
        )
    };
}

/// Trace a stream opened event
#[macro_export]
macro_rules! trace_stream_opened {
    ($log:expr_2021, $trace_id:expr_2021, $stream_id:expr_2021) => {
        $crate::trace_event!(
            $log,
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::StreamOpened {
                    stream_id: $stream_id,
                    _padding: [0u8; 56],
                },
                ..Default::default()
            }
        )
    };
}

/// Trace a connection established event
#[macro_export]
macro_rules! trace_conn_established {
    ($log:expr_2021, $trace_id:expr_2021, $rtt:expr_2021) => {
        $crate::trace_event!(
            $log,
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::ConnEstablished {
                    rtt: $rtt as u32,
                    _padding: [0u8; 60],
                },
                ..Default::default()
            }
        )
    };
}

/// Conditional code block that only compiles with trace feature
#[macro_export]
macro_rules! if_trace {
    ($($body:tt)*) => {
        #[cfg(feature = "trace")]
        {
            $($body)*
        }
    };
}

/// Trace an observed address event
#[macro_export]
macro_rules! trace_observed_address_sent {
    ($log:expr_2021, $trace_id:expr_2021, $addr:expr_2021, $path_id:expr_2021) => {
        $crate::trace_event!($log, {
            let (addr_bytes, addr_type) = $crate::tracing::socket_addr_to_bytes($addr);
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::ObservedAddressSent {
                    addr_bytes,
                    addr_type,
                    path_id: $path_id as u32,
                    _padding: [0u8; 41],
                },
                ..Default::default()
            }
        })
    };
}

/// Trace an observed address received
#[macro_export]
macro_rules! trace_observed_address_received {
    ($log:expr_2021, $trace_id:expr_2021, $addr:expr_2021, $path_id:expr_2021) => {
        $crate::trace_event!($log, {
            let (addr_bytes, addr_type) = $crate::tracing::socket_addr_to_bytes($addr);
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::ObservedAddressReceived {
                    addr_bytes,
                    addr_type,
                    from_peer: [0u8; 32], // TODO: Get actual peer ID
                    _padding: [0u8; 13],
                },
                ..Default::default()
            }
        })
    };
}

/// Trace a NAT traversal candidate discovered
#[macro_export]
macro_rules! trace_candidate_discovered {
    ($log:expr_2021, $trace_id:expr_2021, $addr:expr_2021, $priority:expr_2021) => {
        $crate::trace_event!($log, {
            let (addr_bytes, addr_type) = $crate::tracing::socket_addr_to_bytes($addr);
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::CandidateDiscovered {
                    addr_bytes,
                    addr_type,
                    priority: $priority as u32,
                    _padding: [0u8; 41],
                },
                ..Default::default()
            }
        })
    };
}

/// Trace hole punching started
#[macro_export]
macro_rules! trace_hole_punching_started {
    ($log:expr_2021, $trace_id:expr_2021, $peer:expr_2021) => {
        $crate::trace_event!(
            $log,
            $crate::tracing::Event {
                timestamp: $crate::tracing::timestamp_now(),
                trace_id: $trace_id,
                event_data: $crate::tracing::EventData::HolePunchingStarted {
                    peer: $peer,
                    _padding: [0u8; 32],
                },
                ..Default::default()
            }
        )
    };
}

#[cfg(test)]
mod tests {
    use crate::tracing::{EventLog, TraceId};

    #[test]
    fn test_trace_macros() {
        let _log = EventLog::new();
        let _trace_id = TraceId::new();

        // These should compile whether trace is enabled or not
        trace_packet_sent!(&_log, _trace_id, 1200, 42);
        trace_packet_received!(&_log, _trace_id, 1200, 43);
        trace_stream_opened!(&_log, _trace_id, 1);
        trace_conn_established!(&_log, _trace_id, 25);

        if_trace! {
            // This code only exists when trace is enabled
            #[cfg(feature = "trace")]
            let _count = _log.event_count();
        }
    }
}
