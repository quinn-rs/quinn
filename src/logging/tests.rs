// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

#[cfg(test)]
mod tests {

    use crate::{
        ConnectionId,
        Duration,
        Instant,
        Side,
        TransportError,
        // v0.13.0: NatTraversalRole removed - all nodes are symmetric P2P nodes
        frame::FrameType,
        logging::{
            ConnectionEventType, ConnectionInfo, ConnectionRole, DebugContext, ErrorContext,
            FrameEventType, FrameInfo, InfoContext, LatencyMetrics, LogEvent, LogFilter,
            NatTraversalEventType, NatTraversalInfo, RateLimiter, ThroughputMetrics, TraceContext,
            TransportParamEventType, TransportParamInfo, WarningContext, create_connection_span,
            create_frame_span, log_connection_event, log_debug, log_error, log_error_with_context,
            log_frame_event, log_info, log_latency_metrics, log_nat_traversal_event,
            log_throughput_metrics, log_trace, log_transport_param_event, log_warning,
        },
        transport_parameters::TransportParameterId,
    };
    use tracing::Level;

    use std::sync::{Arc, Mutex};

    // Removed unused mock collector scaffolding

    #[test]
    fn test_structured_logging() {
        // Test structured logging with fields - just verify no panic
        log_connection_event(
            ConnectionEventType::Established,
            &ConnectionInfo {
                id: ConnectionId::new(&[1, 2, 3, 4]),
                remote_addr: "127.0.0.1:8080".parse().unwrap(),
                role: ConnectionRole::Client,
            },
        );
    }

    #[test]
    fn test_log_levels() {
        // Test different log levels - just verify no panic
        log_error("test error", ErrorContext::default());
        log_warning("test warning", WarningContext::default());
        log_info("test info", InfoContext::default());
        log_debug("test debug", DebugContext::default());
        log_trace("test trace", TraceContext::default());
    }

    #[test]
    fn test_component_specific_logging() {
        // Test frame logging
        log_frame_event(
            FrameEventType::Sent,
            &FrameInfo {
                frame_type: FrameType::OBSERVED_ADDRESS_IPV4,
                size: 42,
                packet_number: Some(123),
            },
        );

        // Test transport parameter logging
        log_transport_param_event(
            TransportParamEventType::Negotiated,
            &TransportParamInfo {
                param_id: TransportParameterId::AddressDiscovery,
                value: Some(vec![1, 2, 3]),
                side: Side::Client,
            },
        );

        // Test NAT traversal logging
        // v0.13.0: role field removed - all nodes are symmetric P2P nodes
        log_nat_traversal_event(
            NatTraversalEventType::HolePunchingStarted,
            &NatTraversalInfo {
                remote_addr: "192.168.1.100:9000".parse().unwrap(),
                candidate_count: 4,
            },
        );
    }

    #[test]
    fn test_performance_metrics_logging() {
        // Test throughput logging
        log_throughput_metrics(&ThroughputMetrics {
            bytes_sent: 1_000_000,
            bytes_received: 2_000_000,
            duration: Duration::from_secs(10),
            packets_sent: 1000,
            packets_received: 2000,
        });

        // Test latency logging
        log_latency_metrics(&LatencyMetrics {
            rtt: Duration::from_millis(50),
            min_rtt: Duration::from_millis(20),
            max_rtt: Duration::from_millis(100),
            smoothed_rtt: Duration::from_millis(45),
        });
    }

    #[test]
    fn test_connection_lifecycle_logging() {
        let conn_info = ConnectionInfo {
            id: ConnectionId::new(&[5, 6, 7, 8]),
            remote_addr: "10.0.0.1:443".parse().unwrap(),
            role: ConnectionRole::Server,
        };

        // Test full lifecycle
        log_connection_event(ConnectionEventType::Initiated, &conn_info);
        log_connection_event(ConnectionEventType::HandshakeStarted, &conn_info);
        log_connection_event(ConnectionEventType::HandshakeCompleted, &conn_info);
        log_connection_event(ConnectionEventType::Established, &conn_info);
        log_connection_event(ConnectionEventType::Closed, &conn_info);
    }

    #[test]
    fn test_error_context_logging() {
        // Test with error chain
        let transport_error = TransportError {
            code: crate::TransportErrorCode::CONNECTION_REFUSED,
            frame: None,
            reason: "connection refused".to_string(),
        };

        log_error_with_context(
            &transport_error,
            ErrorContext {
                component: "endpoint",
                operation: "connect",
                connection_id: Some(ConnectionId::new(&[9, 10, 11, 12])),
                additional_fields: vec![("remote_addr", "192.168.1.1:8080"), ("retry_count", "3")],
            },
        );
    }

    #[test]
    fn test_log_filtering() {
        // Test module-based filtering
        let filter = LogFilter::new()
            .with_module("ant_quic::connection", Level::DEBUG)
            .with_module("ant_quic::frame", Level::TRACE)
            .with_module("ant_quic::endpoint", Level::INFO);

        assert_eq!(
            filter.level_for("ant_quic::connection::mod"),
            Some(Level::DEBUG)
        );
        assert_eq!(
            filter.level_for("ant_quic::frame::encoding"),
            Some(Level::TRACE)
        );
        assert_eq!(filter.level_for("ant_quic::endpoint"), Some(Level::INFO));
        assert_eq!(filter.level_for("ant_quic::unknown"), None);
    }

    #[test]
    fn test_json_formatting() {
        let event = LogEvent {
            timestamp: Instant::now(),
            level: Level::INFO,
            target: "ant_quic::connection".to_string(),
            message: "connection established".to_string(),
            fields: vec![
                ("conn_id".to_string(), "abcd1234".to_string()),
                ("remote_addr".to_string(), "10.0.0.1:443".to_string()),
                ("duration_ms".to_string(), "150".to_string()),
            ]
            .into_iter()
            .collect(),
            span_id: Some("conn_123".to_string()),
        };

        let json = crate::logging::formatters::format_as_json(&event);
        assert!(json.contains(r#""level":"INFO""#));
        assert!(json.contains(r#""target":"ant_quic::connection""#));
        assert!(json.contains(r#""message":"connection established""#));
        assert!(json.contains(r#""conn_id":"abcd1234""#));
    }

    #[test]
    fn test_span_integration() {
        let conn_span = create_connection_span(&ConnectionId::new(&[1, 2, 3, 4]));

        conn_span.in_scope(|| {
            log_info("operation within connection span", InfoContext::default());
        });

        // Nested spans
        let frame_span = create_frame_span(FrameType::OBSERVED_ADDRESS_IPV4);
        conn_span.in_scope(|| {
            frame_span.in_scope(|| {
                log_debug("processing frame", DebugContext::default());
            });
        });
    }

    #[test]
    fn test_rate_limiting() {
        let rate_limiter = RateLimiter::new(
            10,                     // max 10 messages
            Duration::from_secs(1), // per second
        );

        // Should allow first 10 messages
        for _i in 0..10 {
            assert!(rate_limiter.should_log(Level::INFO));
        }

        // Should deny 11th message
        assert!(!rate_limiter.should_log(Level::INFO));

        // Should always allow ERROR level
        assert!(rate_limiter.should_log(Level::ERROR));
    }
}
