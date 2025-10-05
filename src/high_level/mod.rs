// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! High-level async API for QUIC
//!
//! This module provides a high-level, tokio-based async API built on top of the low-level
//! protocol implementation. It was ported from the quinn crate to provide a more ergonomic
//! interface for QUIC connections.

use std::sync::Arc;

mod connection;
mod endpoint;
mod incoming;
mod mutex;
mod recv_stream;
mod runtime;
mod send_stream;
mod work_limiter;

// Re-export the main types
pub use self::connection::{
    AcceptBi, AcceptUni, Connecting, Connection, OpenBi, OpenUni, ReadDatagram, SendDatagram,
    SendDatagramError, ZeroRttAccepted,
};
pub use self::endpoint::{Accept, Endpoint, EndpointStats};
pub use self::incoming::{Incoming, IncomingFuture, RetryError};
pub use self::recv_stream::{ReadError, ReadExactError, ReadToEndError, RecvStream, ResetError};
pub use self::runtime::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller, default_runtime};
pub use self::send_stream::{SendStream, StoppedError, WriteError};

// Runtime-specific exports
#[cfg(feature = "runtime-smol")]
pub use self::runtime::SmolRuntime;
#[cfg(feature = "runtime-tokio")]
pub use self::runtime::TokioRuntime;

// Connection event type used internally
#[derive(Debug)]
pub(crate) enum ConnectionEvent {
    Close {
        error_code: crate::VarInt,
        reason: bytes::Bytes,
    },
    Proto(crate::shared::ConnectionEvent),
    Rebind(Arc<dyn AsyncUdpSocket>),
}

// Helper function for UDP transmit conversion
pub(crate) fn udp_transmit<'a>(t: &crate::Transmit, buffer: &'a [u8]) -> quinn_udp::Transmit<'a> {
    quinn_udp::Transmit {
        destination: t.destination,
        ecn: t.ecn.map(udp_ecn),
        contents: buffer,
        segment_size: t.segment_size,
        src_ip: t.src_ip,
    }
}

fn udp_ecn(ecn: crate::EcnCodepoint) -> quinn_udp::EcnCodepoint {
    match ecn {
        crate::EcnCodepoint::Ect0 => quinn_udp::EcnCodepoint::Ect0,
        crate::EcnCodepoint::Ect1 => quinn_udp::EcnCodepoint::Ect1,
        crate::EcnCodepoint::Ce => quinn_udp::EcnCodepoint::Ce,
    }
}

/// Maximum number of datagrams processed in send/recv calls to make before moving on to other processing
///
/// This helps ensure we don't starve anything when the CPU is slower than the link.
/// Value is selected by picking a low number which didn't degrade throughput in benchmarks.
pub(crate) const IO_LOOP_BOUND: usize = 160;

/// The maximum amount of time that should be spent in `recvmsg()` calls per endpoint iteration
///
/// 50us are chosen so that an endpoint iteration with a 50us sendmsg limit blocks
/// the runtime for a maximum of about 100us.
/// Going much lower does not yield any noticeable difference, since a single `recvmmsg`
/// batch of size 32 was observed to take 30us on some systems.
pub(crate) const RECV_TIME_BOUND: crate::Duration = crate::Duration::from_micros(50);
