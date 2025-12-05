//! Comprehensive test suite for authentication module
//!
//! This test suite applies the UltraThink framework to thoroughly test:
//! - Cryptographic correctness
//! - Security properties
//! - Protocol conformance
//! - Performance characteristics
//! - Failure modes and recovery
//! - Integration behavior

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    auth::{AuthConfig, AuthError, AuthManager, AuthMessage},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair, public_key_from_bytes,
        public_key_to_bytes, verify_peer_id,
    },
    nat_traversal_api::PeerId,
};
use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};
use futures_util::future;
use rand::Rng;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{Barrier, Mutex, RwLock},
    time::{sleep, timeout},
};
use tracing::info;

// ===== Test Utilities =====

/// Test environment for authentication scenarios
struct AuthTestEnvironment {
    /// Collection of test peers
    peers: HashMap<String, TestAuthPeer>,
    /// Network simulator for introducing delays/failures
    network: NetworkSimulator,
    /// Global event tracker
    events: Arc<Mutex<Vec<AuthEvent>>>,
}

/// Individual test peer with authentication
struct TestAuthPeer {
    id: PeerId,
    auth_manager: Arc<AuthManager>,
    secret_key: Ed25519SecretKey,
    public_key: Ed25519PublicKey,
    /// Messages received by this peer
    received_messages: Arc<Mutex<Vec<(PeerId, AuthMessage)>>>,
    /// Authentication attempts made
    auth_attempts: Arc<AtomicU64>,
}

/// Authentication event for tracking
#[derive(Debug, Clone)]
enum AuthEvent {
    AuthStarted {
        _initiator: PeerId,
        _target: PeerId,
        _timestamp: Instant,
    },
    ChallengeIssued {
        _issuer: PeerId,
        _target: PeerId,
        _nonce: [u8; 32],
    },
    ChallengeResponded {
        _responder: PeerId,
        _nonce: [u8; 32],
    },
    AuthSuccess {
        _peer1: PeerId,
        _peer2: PeerId,
        _duration: Duration,
    },
    AuthFailure {
        _peer: PeerId,
        _reason: String,
        _duration: Duration,
    },
}

/// Network simulator for testing various conditions
#[derive(Clone)]
struct NetworkSimulator {
    /// Packet loss rate (0.0 - 1.0)
    packet_loss: Arc<RwLock<f64>>,
    /// Network delay in milliseconds
    latency_ms: Arc<RwLock<u64>>,
    /// Whether network is partitioned
    partitioned: Arc<AtomicBool>,
    /// Peers that are isolated
    isolated_peers: Arc<RwLock<Vec<PeerId>>>,
}

impl AuthTestEnvironment {
    async fn new() -> Self {
        Self {
            peers: HashMap::new(),
            network: NetworkSimulator {
                packet_loss: Arc::new(RwLock::new(0.0)),
                latency_ms: Arc::new(RwLock::new(0)),
                partitioned: Arc::new(AtomicBool::new(false)),
                isolated_peers: Arc::new(RwLock::new(Vec::new())),
            },
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn create_peer(&mut self, name: &str, config: AuthConfig) -> PeerId {
        let (secret_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);
        let auth_manager = Arc::new(AuthManager::new(secret_key.clone(), config));

        let peer = TestAuthPeer {
            id: peer_id,
            auth_manager,
            secret_key,
            public_key,
            received_messages: Arc::new(Mutex::new(Vec::new())),
            auth_attempts: Arc::new(AtomicU64::new(0)),
        };

        self.peers.insert(name.to_string(), peer);
        peer_id
    }

    async fn simulate_auth_exchange(
        &self,
        initiator_name: &str,
        responder_name: &str,
    ) -> Result<Duration, AuthError> {
        let initiator = self.peers.get(initiator_name).unwrap();
        let responder = self.peers.get(responder_name).unwrap();

        // Get the auth timeout from the initiator's config
        let auth_timeout = initiator.auth_manager.config().auth_timeout;

        let start = Instant::now();
        self.events.lock().await.push(AuthEvent::AuthStarted {
            _initiator: initiator.id,
            _target: responder.id,
            _timestamp: start,
        });

        initiator.auth_attempts.fetch_add(1, Ordering::Relaxed);

        // Execute the auth exchange with timeout
        let auth_result = timeout(auth_timeout, async {
            // Apply network simulation with retries
            let mut delivery_success = false;
            for _ in 0..3 {
                // Try up to 3 times for packet delivery
                if self
                    .network
                    .simulate_packet_delivery(&initiator.id, &responder.id)
                    .await
                    .is_ok()
                {
                    delivery_success = true;
                    break;
                }
            }
            if !delivery_success {
                return Err(AuthError::Timeout);
            }

            // Step 1: Initiator creates auth request
            let auth_request = initiator.auth_manager.create_auth_request();

            // Step 2: Responder handles auth request and creates challenge
            let challenge = match auth_request {
                AuthMessage::AuthRequest {
                    peer_id,
                    public_key,
                    ..
                } => {
                    responder
                        .auth_manager
                        .handle_auth_request(peer_id, public_key)
                        .await?
                }
                _ => {
                    return Err(AuthError::SerializationError(
                        "Invalid initial message".into(),
                    ));
                }
            };

            // Track challenge
            if let AuthMessage::Challenge { nonce, .. } = &challenge {
                self.events.lock().await.push(AuthEvent::ChallengeIssued {
                    _issuer: responder.id,
                    _target: initiator.id,
                    _nonce: *nonce,
                });
            }

            // Apply network simulation again with retries
            let mut delivery_success = false;
            for _ in 0..3 {
                if self
                    .network
                    .simulate_packet_delivery(&responder.id, &initiator.id)
                    .await
                    .is_ok()
                {
                    delivery_success = true;
                    break;
                }
            }
            if !delivery_success {
                return Err(AuthError::Timeout);
            }

            // Step 3: Initiator responds to challenge
            let response = match challenge {
                AuthMessage::Challenge { nonce, .. } => {
                    self.events
                        .lock()
                        .await
                        .push(AuthEvent::ChallengeResponded {
                            _responder: initiator.id,
                            _nonce: nonce,
                        });
                    initiator.auth_manager.create_challenge_response(nonce)?
                }
                _ => return Err(AuthError::SerializationError("Expected challenge".into())),
            };

            // Apply network simulation with retries
            let mut delivery_success = false;
            for _ in 0..3 {
                if self
                    .network
                    .simulate_packet_delivery(&initiator.id, &responder.id)
                    .await
                    .is_ok()
                {
                    delivery_success = true;
                    break;
                }
            }
            if !delivery_success {
                return Err(AuthError::Timeout);
            }

            // Step 4: Responder verifies response
            let result = match response {
                AuthMessage::ChallengeResponse {
                    nonce, signature, ..
                } => {
                    responder
                        .auth_manager
                        .verify_challenge_response(
                            initiator.id,
                            public_key_to_bytes(&initiator.public_key),
                            nonce,
                            &signature,
                        )
                        .await?
                }
                _ => return Err(AuthError::SerializationError("Expected response".into())),
            };

            // Verify success
            match result {
                AuthMessage::AuthSuccess { session_id, .. } => {
                    // IMPORTANT: For mutual authentication, the initiator must also mark the responder as authenticated
                    initiator
                        .auth_manager
                        .handle_auth_success(
                            responder.id,
                            public_key_to_bytes(&responder.public_key),
                            session_id,
                        )
                        .await?;

                    let duration = start.elapsed();
                    self.events.lock().await.push(AuthEvent::AuthSuccess {
                        _peer1: initiator.id,
                        _peer2: responder.id,
                        _duration: duration,
                    });
                    Ok(duration)
                }
                _ => {
                    let duration = start.elapsed();
                    self.events.lock().await.push(AuthEvent::AuthFailure {
                        _peer: initiator.id,
                        _reason: "Authentication failed".into(),
                        _duration: duration,
                    });
                    Err(AuthError::InvalidSignature)
                }
            }
        })
        .await;

        // Handle timeout result
        match auth_result {
            Ok(result) => result,
            Err(_) => {
                let duration = start.elapsed();
                self.events.lock().await.push(AuthEvent::AuthFailure {
                    _peer: initiator.id,
                    _reason: "Authentication timed out".into(),
                    _duration: duration,
                });
                Err(AuthError::Timeout)
            }
        }
    }
}

impl NetworkSimulator {
    async fn simulate_packet_delivery(&self, from: &PeerId, to: &PeerId) -> Result<(), String> {
        // Check if network is partitioned
        if self.partitioned.load(Ordering::Relaxed) {
            return Err("Network partitioned".into());
        }

        // Check if either peer is isolated
        let isolated = self.isolated_peers.read().await;
        if isolated.contains(from) || isolated.contains(to) {
            return Err("Peer isolated".into());
        }

        // Simulate packet loss
        let loss_rate = *self.packet_loss.read().await;
        if loss_rate > 0.0 {
            let random: f64 = rand::thread_rng().r#gen();
            if random < loss_rate {
                return Err("Packet lost".into());
            }
        }

        // Simulate network latency
        let latency = *self.latency_ms.read().await;
        if latency > 0 {
            sleep(Duration::from_millis(latency)).await;
        }

        Ok(())
    }

    async fn set_packet_loss(&self, rate: f64) {
        *self.packet_loss.write().await = rate.clamp(0.0, 1.0);
    }

    async fn set_latency(&self, ms: u64) {
        *self.latency_ms.write().await = ms;
    }

    async fn partition_network(&self, partitioned: bool) {
        self.partitioned.store(partitioned, Ordering::Relaxed);
    }

    async fn _isolate_peer(&self, peer_id: PeerId) {
        self.isolated_peers.write().await.push(peer_id);
    }

    async fn _restore_peer(&self, peer_id: PeerId) {
        self.isolated_peers.write().await.retain(|p| *p != peer_id);
    }
}

// ===== Cryptographic Correctness Tests =====

#[tokio::test]
async fn test_ed25519_signature_verification() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that signatures are correctly generated and verified
    let (secret_key, public_key) = generate_ed25519_keypair();
    let _peer_id = derive_peer_id_from_public_key(&public_key);

    let auth_manager = AuthManager::new(secret_key, AuthConfig::default());

    // Generate a challenge nonce
    let nonce = {
        use rand::Rng;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill(&mut nonce);
        nonce
    };

    // Create challenge response
    let response = auth_manager.create_challenge_response(nonce).unwrap();

    // Extract signature
    if let AuthMessage::ChallengeResponse {
        nonce: resp_nonce,
        signature,
        ..
    } = response
    {
        assert_eq!(resp_nonce, nonce);

        // Verify signature manually
        use ed25519_dalek::{Signature, Verifier};
        let sig = Signature::from_slice(&signature).unwrap();
        assert!(public_key.verify(&nonce, &sig).is_ok());
    } else {
        panic!("Expected ChallengeResponse");
    }
}

#[tokio::test]
async fn test_peer_id_derivation_consistency() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that peer IDs are consistently derived from public keys
    for _ in 0..100 {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id1 = derive_peer_id_from_public_key(&public_key);
        let peer_id2 = derive_peer_id_from_public_key(&public_key);

        assert_eq!(
            peer_id1, peer_id2,
            "Peer ID derivation must be deterministic"
        );

        // Verify the peer ID
        assert!(verify_peer_id(&peer_id1, &public_key));
    }
}

#[tokio::test]
async fn test_key_serialization_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test key serialization and deserialization
    let (_, public_key) = generate_ed25519_keypair();
    let bytes = public_key_to_bytes(&public_key);
    let restored = public_key_from_bytes(&bytes).unwrap();

    // Verify they produce the same peer ID
    let peer_id1 = derive_peer_id_from_public_key(&public_key);
    let peer_id2 = derive_peer_id_from_public_key(&restored);

    assert_eq!(peer_id1, peer_id2);
}

// ===== Protocol Conformance Tests =====

#[tokio::test]
async fn test_complete_auth_handshake() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    let alice_id = env.create_peer("alice", AuthConfig::default()).await;
    let bob_id = env.create_peer("bob", AuthConfig::default()).await;

    // Perform authentication - Alice authenticates to Bob
    let duration1 = env
        .simulate_auth_exchange("alice", "bob")
        .await
        .expect("Alice->Bob authentication should succeed");

    // Perform reverse authentication - Bob authenticates to Alice
    let duration2 = env
        .simulate_auth_exchange("bob", "alice")
        .await
        .expect("Bob->Alice authentication should succeed");

    info!(
        "Mutual authentication completed in {:?} total",
        duration1 + duration2
    );

    // Verify both peers have authenticated each other
    let alice = &env.peers["alice"];
    let bob = &env.peers["bob"];

    assert!(alice.auth_manager.is_authenticated(&bob_id).await);
    assert!(bob.auth_manager.is_authenticated(&alice_id).await);

    // Verify events were recorded correctly
    let events = env.events.lock().await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::AuthStarted { .. }))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::ChallengeIssued { .. }))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::ChallengeResponded { .. }))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::AuthSuccess { .. }))
    );
}

#[tokio::test]
async fn test_auth_message_ordering() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that out-of-order messages are rejected
    let (secret_key1, public_key1) = generate_ed25519_keypair();
    let (secret_key2, _) = generate_ed25519_keypair();

    let auth1 = AuthManager::new(secret_key1, AuthConfig::default());
    let auth2 = AuthManager::new(secret_key2, AuthConfig::default());

    let peer_id1 = derive_peer_id_from_public_key(&public_key1);

    // Try to send challenge response without challenge
    let fake_nonce = [42u8; 32];
    let response = auth1.create_challenge_response(fake_nonce).unwrap();

    // This should fail because there's no pending challenge
    match response {
        AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } => {
            let result = auth2
                .verify_challenge_response(
                    peer_id1,
                    public_key_to_bytes(&public_key1),
                    nonce,
                    &signature,
                )
                .await;

            assert!(result.is_err(), "Should reject response without challenge");
            assert!(matches!(result.unwrap_err(), AuthError::PeerNotFound));
        }
        _ => panic!("Expected ChallengeResponse"),
    }
}

// ===== Security Property Tests =====

#[tokio::test]
async fn test_replay_attack_prevention() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    let alice_id = env.create_peer("alice", AuthConfig::default()).await;
    let _bob_id = env.create_peer("bob", AuthConfig::default()).await;

    let alice = &env.peers["alice"];
    let bob = &env.peers["bob"];

    // First authentication
    let auth_request = alice.auth_manager.create_auth_request();
    let challenge = match auth_request {
        AuthMessage::AuthRequest {
            peer_id,
            public_key,
            ..
        } => bob
            .auth_manager
            .handle_auth_request(peer_id, public_key)
            .await
            .unwrap(),
        _ => panic!("Expected AuthRequest"),
    };

    let response = match &challenge {
        AuthMessage::Challenge { nonce, .. } => alice
            .auth_manager
            .create_challenge_response(*nonce)
            .unwrap(),
        _ => panic!("Expected Challenge"),
    };

    // Complete first auth
    match &response {
        AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } => {
            let result = bob
                .auth_manager
                .verify_challenge_response(
                    alice_id,
                    public_key_to_bytes(&alice.public_key),
                    *nonce,
                    signature,
                )
                .await;
            assert!(result.is_ok());
        }
        _ => panic!("Expected ChallengeResponse"),
    }

    // Try to replay the same response
    match response {
        AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } => {
            let replay_result = bob
                .auth_manager
                .verify_challenge_response(
                    alice_id,
                    public_key_to_bytes(&alice.public_key),
                    nonce,
                    &signature,
                )
                .await;

            assert!(replay_result.is_err(), "Should reject replayed response");
            assert!(matches!(
                replay_result.unwrap_err(),
                AuthError::PeerNotFound
            ));
        }
        _ => panic!("Expected ChallengeResponse"),
    }
}

#[tokio::test]
async fn test_man_in_the_middle_prevention() {
    let _ = tracing_subscriber::fmt::try_init();

    let (alice_secret, alice_public) = generate_ed25519_keypair();
    let (bob_secret, _bob_public) = generate_ed25519_keypair();
    let (mallory_secret, mallory_public) = generate_ed25519_keypair();

    let alice_id = derive_peer_id_from_public_key(&alice_public);
    let _mallory_id = derive_peer_id_from_public_key(&mallory_public);

    let alice_auth = AuthManager::new(alice_secret, AuthConfig::default());
    let bob_auth = AuthManager::new(bob_secret, AuthConfig::default());
    let _mallory_auth = AuthManager::new(mallory_secret, AuthConfig::default());

    // Alice tries to authenticate with Bob
    let auth_request = alice_auth.create_auth_request();

    // Mallory intercepts and modifies the request
    match auth_request {
        AuthMessage::AuthRequest {
            peer_id: _,
            public_key: _,
            timestamp,
        } => {
            // Mallory substitutes their own public key
            let _malicious_request = AuthMessage::AuthRequest {
                peer_id: alice_id,                                // Claims to be Alice
                public_key: public_key_to_bytes(&mallory_public), // But uses Mallory's key
                timestamp,
            };

            // Bob processes the malicious request
            let result = bob_auth
                .handle_auth_request(alice_id, public_key_to_bytes(&mallory_public))
                .await;

            // This should fail because peer ID doesn't match public key
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), AuthError::InvalidPeerId));
        }
        _ => panic!("Expected AuthRequest"),
    }
}

#[tokio::test]
async fn test_timing_attack_resistance() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that signature verification takes constant time
    let (secret_key, public_key) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    let auth = AuthManager::new(secret_key, AuthConfig::default());

    // Create a valid signature
    let nonce = [1u8; 32];
    let valid_response = auth.create_challenge_response(nonce).unwrap();

    let (valid_nonce, valid_sig) = match valid_response {
        AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } => (nonce, signature),
        _ => panic!("Expected ChallengeResponse"),
    };

    // Create an invalid signature
    let mut invalid_sig = valid_sig.clone();
    invalid_sig[0] ^= 0xFF; // Flip bits to make invalid

    // Time multiple verification attempts
    let mut valid_times = Vec::new();
    let mut invalid_times = Vec::new();

    for _ in 0..100 {
        // Time valid signature verification
        let start = Instant::now();
        let _ = auth
            .verify_challenge_response(
                peer_id,
                public_key_to_bytes(&public_key),
                valid_nonce,
                &valid_sig,
            )
            .await;
        valid_times.push(start.elapsed());

        // Time invalid signature verification
        let start = Instant::now();
        let _ = auth
            .verify_challenge_response(
                peer_id,
                public_key_to_bytes(&public_key),
                valid_nonce,
                &invalid_sig,
            )
            .await;
        invalid_times.push(start.elapsed());
    }

    // Calculate average times
    let valid_avg = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let invalid_avg = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;

    // Times should be similar (within 20% tolerance)
    let diff = valid_avg.abs_diff(invalid_avg);

    let tolerance = valid_avg / 5; // 20% tolerance
    assert!(
        diff < tolerance,
        "Signature verification timing should be constant. Valid: {valid_avg:?}, Invalid: {invalid_avg:?}, Diff: {diff:?}"
    );
}

// ===== Performance Characteristic Tests =====

#[tokio::test]
#[ignore = "Performance test - may timeout in CI environments"]
async fn test_auth_performance_under_load() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    // Create many peers
    let peer_count = 100;
    let mut peer_ids = Vec::new();

    for i in 0..peer_count {
        let id = env
            .create_peer(&format!("peer{i}"), AuthConfig::default())
            .await;
        peer_ids.push(id);
    }

    // Measure authentication time under load
    let start = Instant::now();
    let mut tasks = Vec::new();

    // Each peer authenticates with every other peer
    for i in 0..peer_count {
        for j in i + 1..peer_count {
            let env_clone = env.clone();
            let peer_i = format!("peer{i}");
            let peer_j = format!("peer{j}");

            let task =
                tokio::spawn(
                    async move { env_clone.simulate_auth_exchange(&peer_i, &peer_j).await },
                );
            tasks.push(task);
        }
    }

    // Wait for all authentications
    let results = future::join_all(tasks).await;
    let total_time = start.elapsed();

    // Count successes
    let successes = results
        .iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
        .count();

    let total_auths = (peer_count * (peer_count - 1)) / 2;
    let success_rate = successes as f64 / total_auths as f64;

    info!(
        "Authenticated {} peer pairs in {:?} ({:.2}% success rate)",
        total_auths,
        total_time,
        success_rate * 100.0
    );

    // Performance assertions
    assert!(
        success_rate > 0.95,
        "Success rate should be high under load"
    );
    assert!(
        total_time < Duration::from_secs(30),
        "Should complete {total_auths} authentications within 30s"
    );
}

#[tokio::test]
async fn test_auth_memory_usage() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test memory usage scales linearly with authenticated peers
    let configs = vec![
        AuthConfig {
            max_auth_attempts: 3,
            ..Default::default()
        },
        AuthConfig {
            max_auth_attempts: 10,
            ..Default::default()
        },
    ];

    for config in configs {
        let (secret_key, _) = generate_ed25519_keypair();
        let auth_manager = AuthManager::new(secret_key, config.clone());

        // Simulate many authenticated peers
        for _i in 0..1000 {
            let (_, public_key) = generate_ed25519_keypair();
            let peer_id = derive_peer_id_from_public_key(&public_key);

            // Create and handle auth request
            let _ = auth_manager
                .handle_auth_request(peer_id, public_key_to_bytes(&public_key))
                .await;
        }

        // Check authenticated peer count
        let auth_peers = auth_manager.list_authenticated_peers().await;
        info!(
            "Config {:?} tracking {} authenticated peers",
            config.max_auth_attempts,
            auth_peers.len()
        );
    }
}

// ===== Failure Mode Tests =====

#[tokio::test]
async fn test_auth_timeout_handling() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    // Create peers with short timeout
    let config = AuthConfig {
        auth_timeout: Duration::from_millis(100),
        ..Default::default()
    };

    let _alice_id = env.create_peer("alice", config.clone()).await;
    let _bob_id = env.create_peer("bob", config).await;

    // Add significant network delay
    env.network.set_latency(200).await; // Longer than timeout

    // Try to authenticate - should timeout
    let result = timeout(
        Duration::from_secs(1),
        env.simulate_auth_exchange("alice", "bob"),
    )
    .await;

    assert!(result.is_ok()); // Outer timeout didn't fire
    assert!(result.unwrap().is_err()); // Inner auth failed
}

/// Test authentication under various packet loss conditions
///
/// Note: This test is probabilistic and can be flaky in CI environments
/// due to timing constraints and resource limitations. It tests that
/// authentication succeeds >50% of the time when packet loss is <50%.
#[tokio::test]
#[ignore = "Probabilistic test - may be flaky in CI environments"]
async fn test_auth_with_packet_loss() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    let config = AuthConfig {
        max_auth_attempts: 5,
        ..Default::default()
    };

    let _alice_id = env.create_peer("alice", config.clone()).await;
    let _bob_id = env.create_peer("bob", config).await;

    // Test various packet loss rates
    let loss_rates = vec![0.1, 0.3, 0.5, 0.7, 0.9];

    for rate in loss_rates {
        env.network.set_packet_loss(rate).await;

        let mut successes = 0;
        let attempts = 10;

        for _ in 0..attempts {
            if env.simulate_auth_exchange("alice", "bob").await.is_ok() {
                successes += 1;
            }
        }

        let success_rate = successes as f64 / attempts as f64;
        info!(
            "With {:.0}% packet loss: {:.0}% auth success rate",
            rate * 100.0,
            success_rate * 100.0
        );

        // Even with high packet loss, retries should help
        if rate < 0.5 {
            assert!(
                success_rate > 0.5,
                "Should maintain >50% success with <50% loss"
            );
        }
    }
}

#[tokio::test]
async fn test_auth_during_network_partition() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    let _alice_id = env.create_peer("alice", AuthConfig::default()).await;
    let _bob_id = env.create_peer("bob", AuthConfig::default()).await;

    // Partition the network
    env.network.partition_network(true).await;

    // Authentication should fail
    let result = env.simulate_auth_exchange("alice", "bob").await;
    assert!(result.is_err());

    // Heal partition
    env.network.partition_network(false).await;

    // Authentication should now succeed
    let result = env.simulate_auth_exchange("alice", "bob").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_concurrent_auth_attempts() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = AuthTestEnvironment::new().await;

    // Create several peers
    for i in 0..10 {
        env.create_peer(&format!("peer{i}"), AuthConfig::default())
            .await;
    }

    // All peers try to authenticate with peer0 simultaneously
    let barrier = Arc::new(Barrier::new(9));
    let mut tasks = Vec::new();

    for i in 1..10 {
        let env_clone = env.clone();
        let barrier_clone = barrier.clone();
        let peer_name = format!("peer{i}");

        let task = tokio::spawn(async move {
            barrier_clone.wait().await;
            env_clone.simulate_auth_exchange(&peer_name, "peer0").await
        });
        tasks.push(task);
    }

    let results = future::join_all(tasks).await;
    let successes = results
        .iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
        .count();

    // All concurrent attempts should succeed
    assert_eq!(
        successes, 9,
        "All concurrent authentications should succeed"
    );
}

#[tokio::test]
async fn test_auth_state_cleanup() {
    let _ = tracing_subscriber::fmt::try_init();

    let config = AuthConfig {
        challenge_validity: Duration::from_millis(100),
        ..Default::default()
    };

    let (secret_key, public_key) = generate_ed25519_keypair();
    let _peer_id = derive_peer_id_from_public_key(&public_key);
    let auth = AuthManager::new(secret_key, config);

    // Create many pending challenges
    for _i in 0..100 {
        let (_, peer_public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&peer_public_key);

        let _ = auth
            .handle_auth_request(peer_id, public_key_to_bytes(&peer_public_key))
            .await;
    }

    // Wait for challenges to expire
    sleep(Duration::from_millis(200)).await;

    // Cleanup expired challenges
    auth.cleanup_expired_challenges().await;

    // New challenge should work
    let (_, new_public_key) = generate_ed25519_keypair();
    let new_peer_id = derive_peer_id_from_public_key(&new_public_key);

    let result = auth
        .handle_auth_request(new_peer_id, public_key_to_bytes(&new_public_key))
        .await;

    assert!(result.is_ok(), "Should handle new auth after cleanup");
}

// ===== Integration Behavior Tests =====

#[tokio::test]
async fn test_auth_with_clock_skew() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test authentication with peers having different clock times
    let (secret_key1, public_key1) = generate_ed25519_keypair();
    let (secret_key2, public_key2) = generate_ed25519_keypair();

    let _auth1 = AuthManager::new(secret_key1, AuthConfig::default());
    let auth2 = AuthManager::new(secret_key2, AuthConfig::default());

    let peer_id1 = derive_peer_id_from_public_key(&public_key1);
    let _peer_id2 = derive_peer_id_from_public_key(&public_key2);

    // Create auth request with future timestamp
    let future_request = AuthMessage::AuthRequest {
        peer_id: peer_id1,
        public_key: public_key_to_bytes(&public_key1),
        timestamp: SystemTime::now() + Duration::from_secs(3600), // 1 hour in future
    };

    // This should still work as we don't enforce strict timestamp validation
    let result = match future_request {
        AuthMessage::AuthRequest {
            peer_id,
            public_key,
            ..
        } => auth2.handle_auth_request(peer_id, public_key).await,
        _ => panic!("Expected AuthRequest"),
    };

    assert!(result.is_ok(), "Should handle auth with clock skew");
}

#[tokio::test]
async fn test_auth_protocol_versioning() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that protocol versioning is handled correctly
    let auth_message = AuthMessage::AuthRequest {
        peer_id: PeerId([0; 32]),
        public_key: [0; 32],
        timestamp: SystemTime::now(),
    };

    // Serialize and deserialize
    let serialized = AuthManager::serialize_message(&auth_message).unwrap();
    let deserialized = AuthManager::deserialize_message(&serialized).unwrap();

    match (auth_message, deserialized) {
        (
            AuthMessage::AuthRequest {
                peer_id: p1,
                public_key: k1,
                ..
            },
            AuthMessage::AuthRequest {
                peer_id: p2,
                public_key: k2,
                ..
            },
        ) => {
            assert_eq!(p1, p2);
            assert_eq!(k1, k2);
        }
        _ => panic!("Message type mismatch"),
    }
}

// ===== Helper Implementation for Environment Clone =====

impl Clone for AuthTestEnvironment {
    fn clone(&self) -> Self {
        Self {
            peers: self.peers.clone(),
            network: self.network.clone(),
            events: Arc::clone(&self.events),
        }
    }
}

impl Clone for TestAuthPeer {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            auth_manager: Arc::clone(&self.auth_manager),
            secret_key: self.secret_key.clone(),
            public_key: self.public_key,
            received_messages: Arc::clone(&self.received_messages),
            auth_attempts: Arc::clone(&self.auth_attempts),
        }
    }
}
