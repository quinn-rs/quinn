//! Comprehensive unit tests for the relay protocol implementation.

use ant_quic::relay::{
    RelayStatisticsCollector, SessionManager, SessionConfig,
    RelayConnection, RelayConnectionConfig, RelayAuthenticator,
    RelayError, RelayResult,
};
use ant_quic::relay::session_manager::SessionEvent;
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_session_manager_lifecycle() -> RelayResult<()> {
    let (session_manager, mut event_receiver) = SessionManager::new(SessionConfig::default());
    
    // Add a trusted key for testing
    let keypair = SigningKey::generate(&mut rand::thread_rng());
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    session_manager.add_trusted_key(client_addr, keypair.verifying_key());
    
    // Create a valid auth token using the same key pair
    let authenticator = RelayAuthenticator::with_key(keypair.clone());
    let auth_token = authenticator.create_token(1048576, 300)?;
    
    // Test session request
    let session_id = session_manager.request_session(
        client_addr,
        b"test_peer_connection_id".to_vec(),
        auth_token,
    )?;
    
    // Verify session request event was generated
    let event = event_receiver.recv().await.unwrap();
    match event {
        SessionEvent::SessionRequested { session_id: id, client_addr: addr, .. } => {
            assert_eq!(id, session_id);
            assert_eq!(addr, client_addr);
        }
        _ => panic!("Expected SessionRequested event"),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_session_manager_authentication() -> RelayResult<()> {
    let (session_manager, _event_receiver) = SessionManager::new(SessionConfig::default());
    
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let keypair = SigningKey::generate(&mut rand::thread_rng());
    
    // Test with no trusted key - should fail
    let authenticator = RelayAuthenticator::with_key(keypair.clone());
    let auth_token = authenticator.create_token(1048576, 300)?;
    
    let result = session_manager.request_session(
        client_addr,
        b"test_peer_connection_id".to_vec(),
        auth_token.clone(),
    );
    
    assert!(result.is_err());
    
    // Add trusted key and try again - should succeed
    session_manager.add_trusted_key(client_addr, keypair.verifying_key());
    
    // Create a new token after adding the trusted key
    let auth_token2 = authenticator.create_token(1048576, 300)?;
    
    let session_id = session_manager.request_session(
        client_addr,
        b"test_peer_connection_id".to_vec(),
        auth_token2,
    )?;
    
    assert!(session_id > 0);
    
    Ok(())
}

#[tokio::test]
async fn test_session_manager_resource_limits() -> RelayResult<()> {
    let config = SessionConfig {
        max_sessions: 2, // Limit to 2 sessions
        ..Default::default()
    };
    
    let (session_manager, _event_receiver) = SessionManager::new(config);
    
    let keypair = SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = keypair.verifying_key();
    let authenticator = RelayAuthenticator::with_key(keypair);
    
    // Add trusted keys for multiple clients
    for i in 0..3 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 12345 + i).parse().unwrap();
        session_manager.add_trusted_key(addr, verifying_key);
    }
    
    // Create sessions up to the limit
    for i in 0..2 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 12345 + i).parse().unwrap();
        let auth_token = authenticator.create_token(1048576, 300)?;
        
        let result = session_manager.request_session(
            addr,
            format!("peer_connection_id_{}", i).into_bytes(),
            auth_token,
        );
        
        assert!(result.is_ok());
    }
    
    // Next session should fail due to resource limit
    let addr: SocketAddr = "127.0.0.1:12347".parse().unwrap();
    let auth_token = authenticator.create_token(1048576, 300)?;
    
    let result = session_manager.request_session(
        addr,
        b"peer_connection_id_overflow".to_vec(),
        auth_token,
    );
    
    assert!(result.is_err());
    match result.unwrap_err() {
        RelayError::ResourceExhausted { resource_type, current_usage, limit } => {
            assert_eq!(resource_type, "sessions");
            assert_eq!(current_usage, 2);
            assert_eq!(limit, 2);
        }
        _ => panic!("Expected ResourceExhausted error"),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_relay_connection_bandwidth_limits() -> RelayResult<()> {
    let config = RelayConnectionConfig {
        bandwidth_limit: 1000, // 1KB/s limit
        ..Default::default()
    };
    
    let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let (event_sender, _event_receiver) = mpsc::unbounded_channel();
    let (_action_sender, action_receiver) = mpsc::unbounded_channel();
    
    let connection = RelayConnection::new(1, peer_addr, config, event_sender, action_receiver);
    
    // Test small data send - should succeed
    let small_data = vec![0u8; 500]; // 500 bytes
    let result = connection.send_data(small_data);
    assert!(result.is_ok());
    
    // Test large data send - should fail
    let large_data = vec![0u8; 70000]; // 70KB, exceeds max_frame_size
    let result = connection.send_data(large_data);
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_auth_token_creation_and_verification() -> RelayResult<()> {
    let authenticator = RelayAuthenticator::new();
    
    // Create a token
    let token = authenticator.create_token(1048576, 300)?;
    
    // Verify token with correct key
    let result = token.verify(authenticator.verifying_key());
    assert!(result.is_ok());
    
    // Verify token with wrong key
    let other_authenticator = RelayAuthenticator::new();
    let result = token.verify(other_authenticator.verifying_key());
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_auth_token_expiration() -> RelayResult<()> {
    let authenticator = RelayAuthenticator::new();
    let token = authenticator.create_token(1048576, 300)?;
    
    // Token should not be expired immediately (with sufficient max age)
    assert!(!token.is_expired(300)?);
    
    // Add sufficient delay to ensure timestamp difference (tokens use second precision)
    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
    
    // Token should be expired with very small max age  
    assert!(token.is_expired(1)?);
    
    Ok(())
}

#[tokio::test]
async fn test_relay_statistics_collection() -> RelayResult<()> {
    let collector = RelayStatisticsCollector::new();
    
    // Record mostly successful operations to maintain health
    for _ in 0..100 {
        collector.record_auth_attempt(true, None);
        collector.record_rate_limit(true); // allowed request
    }
    
    // Record a few failures (but keep success rate high)
    collector.record_auth_attempt(false, Some("test auth failure"));
    collector.record_rate_limit(false); // blocked request  
    collector.record_error("protocol_error");
    
    // Get comprehensive statistics
    let stats = collector.collect_statistics();
    
    // Verify statistics
    assert_eq!(stats.auth_stats.successful_auths, 100);
    assert_eq!(stats.auth_stats.failed_auths, 1);
    assert_eq!(stats.rate_limit_stats.requests_blocked, 1);
    assert_eq!(stats.error_stats.protocol_errors, 1);
    
    // Check health (should be healthy with high success rate)
    assert!(stats.is_healthy());
    
    Ok(())
}

#[tokio::test]
async fn test_relay_statistics_health_check() -> RelayResult<()> {
    let collector = RelayStatisticsCollector::new();
    
    // Initially healthy (no operations recorded)
    let stats = collector.collect_statistics();
    assert!(stats.is_healthy());
    
    // Record some successful operations first
    for _ in 0..10 {
        collector.record_auth_attempt(true, None);
        collector.record_rate_limit(true);
    }
    
    // Still should be healthy
    let stats = collector.collect_statistics();
    assert!(stats.is_healthy());
    
    // Now record many errors relative to successful operations
    for _ in 0..50 {
        collector.record_error("protocol_error");
        collector.record_auth_attempt(false, Some("auth failure"));
        collector.record_rate_limit(false);
    }
    
    // Should now be unhealthy due to poor success rate
    let stats = collector.collect_statistics();
    assert!(!stats.is_healthy());
    
    Ok(())
}

#[tokio::test]
async fn test_session_manager_key_management() {
    let (session_manager, _event_receiver) = SessionManager::new(SessionConfig::default());
    
    let addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:12346".parse().unwrap();
    
    let keypair1 = SigningKey::generate(&mut rand::thread_rng());
    let keypair2 = SigningKey::generate(&mut rand::thread_rng());
    
    // Add trusted keys
    session_manager.add_trusted_key(addr1, keypair1.verifying_key());
    session_manager.add_trusted_key(addr2, keypair2.verifying_key());
    
    // Remove a key
    session_manager.remove_trusted_key(&addr1);
    
    // Verify the key was removed by trying to create a session
    let authenticator = RelayAuthenticator::with_key(keypair1);
    let auth_token = authenticator.create_token(1048576, 300).unwrap();
    
    let result = session_manager.request_session(
        addr1,
        b"test_peer_connection_id".to_vec(),
        auth_token,
    );
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_relay_connection_state_management() -> RelayResult<()> {
    let config = RelayConnectionConfig::default();
    let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let (event_sender, _event_receiver) = mpsc::unbounded_channel();
    let (_action_sender, action_receiver) = mpsc::unbounded_channel();
    
    let connection = RelayConnection::new(1, peer_addr, config, event_sender, action_receiver);
    
    // Initially active
    assert!(connection.is_active());
    assert_eq!(connection.session_id(), 1);
    assert_eq!(connection.peer_addr(), peer_addr);
    
    Ok(())
}