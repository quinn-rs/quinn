//! Integration tests for relay protocol end-to-end functionality.

use ant_quic::relay::session_manager::SessionEvent;
use ant_quic::relay::{
    RelayAuthenticator, RelayConnection, RelayConnectionConfig, RelayError, RelayResult,
    RelayStatisticsCollector, SessionConfig, SessionManager,
};
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn test_multi_session_management() -> RelayResult<()> {
    let config = SessionConfig {
        max_sessions: 5,
        default_timeout: Duration::from_secs(60),
        ..Default::default()
    };

    let (session_manager, mut event_receiver) = SessionManager::new(config);
    let keypair = SigningKey::generate(&mut rand::thread_rng());
    let authenticator = RelayAuthenticator::with_key(keypair.clone());

    // Create multiple sessions concurrently
    let mut session_ids = Vec::new();

    for i in 0..3 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 12345 + i).parse().unwrap();

        // Use the same keypair as the authenticator for this session
        session_manager.add_trusted_key(addr, keypair.verifying_key());

        let auth_token = authenticator.create_token(1048576, 60)?;

        let session_id = session_manager.request_session(
            addr,
            format!("peer_connection_id_{}", i).into_bytes(),
            auth_token,
        )?;

        session_ids.push(session_id);
    }

    // Verify all session events were generated
    for _ in 0..3 {
        let event = timeout(Duration::from_millis(100), event_receiver.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Event receiver closed");

        match event {
            SessionEvent::SessionRequested { session_id, .. } => {
                assert!(session_ids.contains(&session_id));
            }
            _ => panic!("Expected SessionRequested event"),
        }
    }

    assert_eq!(session_ids.len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_relay_connections() -> RelayResult<()> {
    let config = RelayConnectionConfig {
        bandwidth_limit: 10485760, // 10 MB/s
        max_frame_size: 65536,     // 64 KB
        ..Default::default()
    };

    let mut connections = Vec::new();
    let mut event_receivers = Vec::new();

    // Create multiple relay connections
    for i in 0..3 {
        let peer_addr: SocketAddr = format!("127.0.0.1:{}", 12345 + i).parse().unwrap();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let (_action_sender, action_receiver) = mpsc::unbounded_channel();

        let connection = RelayConnection::new(
            i as u32 + 1,
            peer_addr,
            config.clone(),
            event_sender,
            action_receiver,
        );

        connections.push(connection);
        event_receivers.push(event_receiver);
    }

    // Test concurrent data sending
    let handles: Vec<_> = connections
        .into_iter()
        .enumerate()
        .map(|(i, connection)| {
            tokio::spawn(async move {
                let data = vec![i as u8; 1000];
                connection.send_data(data).unwrap();

                assert!(connection.is_active());
                assert_eq!(connection.session_id(), i as u32 + 1);
            })
        })
        .collect();

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    Ok(())
}

#[tokio::test]
async fn test_relay_statistics_integration() -> RelayResult<()> {
    let collector = RelayStatisticsCollector::new();

    // Simulate relay operations
    tokio::spawn({
        let collector = collector.clone();
        async move {
            for i in 0..10 {
                // Simulate auth attempts (70% success rate)
                if i % 10 < 7 {
                    collector.record_auth_attempt(true, None);
                } else {
                    collector.record_auth_attempt(false, Some("simulated auth failure"));
                }

                // Simulate some rate limiting
                if i % 5 == 0 {
                    collector.record_rate_limit(false); // blocked
                } else {
                    collector.record_rate_limit(true); // allowed
                }

                // Simulate occasional errors
                if i % 8 == 0 {
                    collector.record_error("protocol_error");
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });

    // Wait for operations to complete
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify statistics
    let stats = collector.collect_statistics();

    assert_eq!(stats.auth_stats.successful_auths, 7);
    assert_eq!(stats.auth_stats.failed_auths, 3);
    assert_eq!(stats.rate_limit_stats.requests_blocked, 2);
    assert_eq!(stats.error_stats.protocol_errors, 2);

    Ok(())
}

#[tokio::test]
async fn test_session_lifecycle_integration() -> RelayResult<()> {
    let (session_manager, mut event_receiver) = SessionManager::new(SessionConfig::default());

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let keypair = SigningKey::generate(&mut rand::thread_rng());
    let authenticator = RelayAuthenticator::with_key(keypair.clone());

    session_manager.add_trusted_key(client_addr, keypair.verifying_key());

    // Create auth token
    let auth_token = authenticator.create_token(1048576, 300)?;

    // Request session
    let session_id = session_manager.request_session(
        client_addr,
        b"integration_test_peer".to_vec(),
        auth_token,
    )?;

    // Verify session request event
    let event = timeout(Duration::from_millis(100), event_receiver.recv())
        .await
        .expect("Timeout waiting for event")
        .expect("Event receiver closed");

    match event {
        SessionEvent::SessionRequested {
            session_id: id,
            client_addr: addr,
            peer_connection_id,
            ..
        } => {
            assert_eq!(id, session_id);
            assert_eq!(addr, client_addr);
            assert_eq!(peer_connection_id, b"integration_test_peer");
        }
        _ => panic!("Expected SessionRequested event"),
    }

    Ok(())
}

#[tokio::test]
async fn test_relay_error_handling_integration() -> RelayResult<()> {
    let collector = RelayStatisticsCollector::new();

    // Test various error scenarios
    let errors = vec!["protocol_error", "auth_failed", "resource_exhausted"];

    for error in errors {
        collector.record_error(error);
    }

    let stats = collector.collect_statistics();

    assert_eq!(stats.error_stats.protocol_errors, 1);
    assert_eq!(stats.error_stats.auth_failures, 1);
    assert_eq!(stats.error_stats.resource_exhausted, 1);

    Ok(())
}

#[tokio::test]
async fn test_relay_authentication_integration() -> RelayResult<()> {
    let authenticator1 = RelayAuthenticator::new();
    let authenticator2 = RelayAuthenticator::new();

    // Test cross-authenticator verification
    let token1 = authenticator1.create_token(1048576, 300)?;
    let token2 = authenticator2.create_token(1048576, 300)?;

    // Verify with correct keys
    assert!(token1.verify(authenticator1.verifying_key()).is_ok());
    assert!(token2.verify(authenticator2.verifying_key()).is_ok());

    // Verify with wrong keys (should fail)
    assert!(token1.verify(authenticator2.verifying_key()).is_err());
    assert!(token2.verify(authenticator1.verifying_key()).is_err());

    Ok(())
}

#[tokio::test]
async fn test_session_manager_cleanup_integration() -> RelayResult<()> {
    let config = SessionConfig {
        max_sessions: 10,
        default_timeout: Duration::from_millis(100), // Very short timeout for testing
        cleanup_interval: Duration::from_millis(50),
        ..Default::default()
    };

    let (session_manager, _event_receiver) = SessionManager::new(config);

    // Create a session
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let keypair = SigningKey::generate(&mut rand::thread_rng());
    let authenticator = RelayAuthenticator::with_key(keypair.clone());

    session_manager.add_trusted_key(client_addr, keypair.verifying_key());

    let auth_token = authenticator.create_token(1048576, 1)?; // 1 second timeout

    let session_id =
        session_manager.request_session(client_addr, b"cleanup_test_peer".to_vec(), auth_token)?;

    assert!(session_id > 0);

    // Wait for session to potentially timeout and be cleaned up
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Note: We can't easily test cleanup without access to internal state
    // This test mainly verifies that the setup works without panicking

    Ok(())
}

#[tokio::test]
async fn test_bandwidth_tracking_integration() -> RelayResult<()> {
    let config = RelayConnectionConfig {
        bandwidth_limit: 1000, // 1 KB/s
        ..Default::default()
    };

    let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let (event_sender, _event_receiver) = mpsc::unbounded_channel();
    let (_action_sender, action_receiver) = mpsc::unbounded_channel();

    let connection = RelayConnection::new(1, peer_addr, config, event_sender, action_receiver);

    // Send data within limits
    let small_data = vec![0u8; 500];
    assert!(connection.send_data(small_data).is_ok());

    // Try to send more data that would exceed frame size
    let large_data = vec![0u8; 70000];
    let result = connection.send_data(large_data);

    assert!(result.is_err());
    match result.unwrap_err() {
        RelayError::ProtocolError { frame_type, reason } => {
            assert_eq!(frame_type, 0x46); // RELAY_DATA frame type
            assert!(reason.contains("exceeds maximum"));
        }
        _ => panic!("Expected ProtocolError"),
    }

    Ok(())
}
