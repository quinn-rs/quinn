/// Component-specific logging functions
///
/// Provides specialized logging for different components of the QUIC stack
use std::collections::HashMap;
use tracing::{debug, trace};

use crate::{ConnectionId, Frame};

use super::{ConnectionInfo, FrameInfo, LogEvent, NatTraversalInfo, TransportParamInfo, logger};

/// Connection event types
#[derive(Debug, Clone, Copy)]
pub enum ConnectionEventType {
    Initiated,
    HandshakeStarted,
    HandshakeCompleted,
    Established,
    Migrated,
    Closed,
    Lost,
    Stalled,
}

/// Frame event types
#[derive(Debug, Clone, Copy)]
pub enum FrameEventType {
    Sent,
    Received,
    Dropped,
    Retransmitted,
    Acknowledged,
}

/// Transport parameter event types
#[derive(Debug, Clone, Copy)]
pub enum TransportParamEventType {
    Sent,
    Received,
    Negotiated,
    Rejected,
    Invalid,
}

/// NAT traversal event types
#[derive(Debug, Clone, Copy)]
pub enum NatTraversalEventType {
    Started,
    CandidateDiscovered,
    CandidateValidated,
    HolePunchingStarted,
    HolePunchingSucceeded,
    HolePunchingFailed,
    Completed,
    Failed,
}

/// Log a connection event
pub fn log_connection_event(event_type: ConnectionEventType, conn_info: &ConnectionInfo) {
    let message = match event_type {
        ConnectionEventType::Initiated => "connection.initiated",
        ConnectionEventType::HandshakeStarted => "connection.handshake_started",
        ConnectionEventType::HandshakeCompleted => "connection.handshake_completed",
        ConnectionEventType::Established => "connection.established",
        ConnectionEventType::Migrated => "connection.migrated",
        ConnectionEventType::Closed => "connection.closed",
        ConnectionEventType::Lost => "connection.lost",
        ConnectionEventType::Stalled => "connection.stalled",
    };

    let mut fields = HashMap::new();
    fields.insert("conn_id".to_string(), format!("{:?}", conn_info.id));
    fields.insert("remote_addr".to_string(), conn_info.remote_addr.to_string());
    fields.insert("role".to_string(), format!("{:?}", conn_info.role));
    fields.insert("event_type".to_string(), format!("{event_type:?}"));

    let level = match event_type {
        ConnectionEventType::Lost | ConnectionEventType::Stalled => tracing::Level::WARN,
        ConnectionEventType::Closed => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level,
        target: "ant_quic::connection".to_string(),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log a frame event
pub fn log_frame_event(event_type: FrameEventType, frame_info: &FrameInfo) {
    let message = match event_type {
        FrameEventType::Sent => "frame.sent",
        FrameEventType::Received => "frame.received",
        FrameEventType::Dropped => "frame.dropped",
        FrameEventType::Retransmitted => "frame.retransmitted",
        FrameEventType::Acknowledged => "frame.acknowledged",
    };

    let mut fields = HashMap::new();
    fields.insert(
        "frame_type".to_string(),
        format!("{:?}", frame_info.frame_type),
    );
    fields.insert("size".to_string(), frame_info.size.to_string());
    if let Some(pn) = frame_info.packet_number {
        fields.insert("packet_number".to_string(), pn.to_string());
    }
    fields.insert("event_type".to_string(), format!("{event_type:?}"));

    let level = match event_type {
        FrameEventType::Dropped => tracing::Level::WARN,
        _ => tracing::Level::TRACE,
    };

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level,
        target: "ant_quic::frame".to_string(),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log a transport parameter event
pub fn log_transport_param_event(
    event_type: TransportParamEventType,
    param_info: &TransportParamInfo,
) {
    let message = match event_type {
        TransportParamEventType::Sent => "transport_param.sent",
        TransportParamEventType::Received => "transport_param.received",
        TransportParamEventType::Negotiated => "transport_param.negotiated",
        TransportParamEventType::Rejected => "transport_param.rejected",
        TransportParamEventType::Invalid => "transport_param.invalid",
    };

    let mut fields = HashMap::new();
    fields.insert("param_id".to_string(), format!("{:?}", param_info.param_id));
    fields.insert("side".to_string(), format!("{:?}", param_info.side));
    if let Some(value) = &param_info.value {
        fields.insert("value_len".to_string(), value.len().to_string());
    }
    fields.insert("event_type".to_string(), format!("{event_type:?}"));

    let level = match event_type {
        TransportParamEventType::Rejected | TransportParamEventType::Invalid => {
            tracing::Level::WARN
        }
        _ => tracing::Level::DEBUG,
    };

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level,
        target: "ant_quic::transport_params".to_string(),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log a NAT traversal event
pub fn log_nat_traversal_event(event_type: NatTraversalEventType, nat_info: &NatTraversalInfo) {
    let message = match event_type {
        NatTraversalEventType::Started => "nat_traversal.started",
        NatTraversalEventType::CandidateDiscovered => "nat_traversal.candidate_discovered",
        NatTraversalEventType::CandidateValidated => "nat_traversal.candidate_validated",
        NatTraversalEventType::HolePunchingStarted => "nat_traversal.hole_punching_started",
        NatTraversalEventType::HolePunchingSucceeded => "nat_traversal.hole_punching_succeeded",
        NatTraversalEventType::HolePunchingFailed => "nat_traversal.hole_punching_failed",
        NatTraversalEventType::Completed => "nat_traversal.completed",
        NatTraversalEventType::Failed => "nat_traversal.failed",
    };

    let mut fields = HashMap::new();
    fields.insert("role".to_string(), format!("{:?}", nat_info.role));
    fields.insert("remote_addr".to_string(), nat_info.remote_addr.to_string());
    fields.insert(
        "candidate_count".to_string(),
        nat_info.candidate_count.to_string(),
    );
    fields.insert("event_type".to_string(), format!("{event_type:?}"));

    let level = match event_type {
        NatTraversalEventType::HolePunchingFailed | NatTraversalEventType::Failed => {
            tracing::Level::WARN
        }
        NatTraversalEventType::HolePunchingSucceeded | NatTraversalEventType::Completed => {
            tracing::Level::INFO
        }
        _ => tracing::Level::DEBUG,
    };

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level,
        target: "ant_quic::nat_traversal".to_string(),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log error with full context
pub fn log_error_with_context(error: &dyn std::error::Error, context: super::ErrorContext) {
    let mut fields = HashMap::new();
    fields.insert("component".to_string(), context.component.to_string());
    fields.insert("operation".to_string(), context.operation.to_string());

    if let Some(conn_id) = context.connection_id {
        fields.insert("conn_id".to_string(), format!("{conn_id:?}"));
    }

    // Add error chain
    let mut error_chain = Vec::new();
    let mut current_error: &dyn std::error::Error = error;
    error_chain.push(current_error.to_string());

    while let Some(source) = current_error.source() {
        error_chain.push(source.to_string());
        current_error = source;
    }

    fields.insert("error_chain".to_string(), error_chain.join(" -> "));

    for (key, value) in context.additional_fields {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level: tracing::Level::ERROR,
        target: format!("ant_quic::{}", context.component),
        message: error.to_string(),
        fields,
        span_id: None,
    });
}

/// Log detailed frame information
pub(crate) fn log_frame_details(frame: &Frame, direction: &str, conn_id: &ConnectionId) {
    trace!(
        target: "ant_quic::frame::details",
        conn_id = ?conn_id,
        direction = direction,
        frame_type = ?frame.ty(),
        "Processing frame"
    );

    match frame {
        Frame::ObservedAddress(addr) => {
            debug!(
                target: "ant_quic::frame::observed_address",
                conn_id = ?conn_id,
                sequence_number = addr.sequence_number.0,
                address = ?addr.address,
                "OBSERVED_ADDRESS frame"
            );
        }
        Frame::AddAddress(addr) => {
            debug!(
                target: "ant_quic::frame::add_address",
                conn_id = ?conn_id,
                sequence = addr.sequence.0,
                address = ?addr.address,
                priority = addr.priority.0,
                "ADD_ADDRESS frame"
            );
        }
        Frame::PunchMeNow(punch) => {
            debug!(
                target: "ant_quic::frame::punch_me_now",
                conn_id = ?conn_id,
                target_sequence = punch.target_sequence.0,
                round = punch.round.0,
                "PUNCH_ME_NOW frame"
            );
        }
        _ => {
            trace!(
                target: "ant_quic::frame::other",
                conn_id = ?conn_id,
                frame_type = ?frame.ty(),
                "Standard QUIC frame"
            );
        }
    }
}

/// Log packet-level events
pub fn log_packet_event(
    event: &str,
    conn_id: &ConnectionId,
    packet_number: u64,
    size: usize,
    details: Vec<(&str, &str)>,
) {
    let mut fields = HashMap::new();
    fields.insert("conn_id".to_string(), format!("{conn_id:?}"));
    fields.insert("packet_number".to_string(), packet_number.to_string());
    fields.insert("size".to_string(), size.to_string());

    for (key, value) in details {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level: tracing::Level::TRACE,
        target: "ant_quic::packet".to_string(),
        message: event.to_string(),
        fields,
        span_id: None,
    });
}

/// Log stream events
pub fn log_stream_event(
    event: &str,
    conn_id: &ConnectionId,
    stream_id: crate::StreamId,
    details: Vec<(&str, &str)>,
) {
    let mut fields = HashMap::new();
    fields.insert("conn_id".to_string(), format!("{conn_id:?}"));
    fields.insert("stream_id".to_string(), format!("{stream_id}"));

    for (key, value) in details {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: crate::Instant::now(),
        level: tracing::Level::DEBUG,
        target: "ant_quic::stream".to_string(),
        message: event.to_string(),
        fields,
        span_id: None,
    });
}
