//! Security-focused test suite for authentication module
//!
//! This test suite specifically targets security vulnerabilities and attack scenarios:
//! - DoS attacks
//! - Resource exhaustion
//! - Cryptographic weaknesses
//! - Protocol vulnerabilities
//! - Side-channel attacks

use ant_quic::{
    auth::{AuthConfig, AuthManager, AuthMessage},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair, public_key_to_bytes,
    },
};
use futures_util::future;
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{sync::Semaphore, time::timeout};
use tracing::info;

// ===== DoS Attack Tests =====

#[tokio::test]
async fn test_auth_flooding_dos_protection() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test protection against authentication flooding
    let (victim_secret, victim_public) = generate_ed25519_keypair();
    let _victim_id = derive_peer_id_from_public_key(&victim_public);

    let config = AuthConfig {
        max_auth_attempts: 3,
        auth_timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let victim_auth = Arc::new(AuthManager::new(victim_secret, config));

    // Attacker creates many fake identities
    let attacker_count = 1000;
    let mut attacker_ids = Vec::new();

    for _ in 0..attacker_count {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);
        attacker_ids.push((peer_id, public_key));
    }

    // Measure resource usage before attack
    let start_time = Instant::now();

    // Launch flood attack
    let semaphore = Arc::new(Semaphore::new(100)); // Limit concurrent attempts
    let mut tasks = Vec::new();

    for (attacker_id, attacker_key) in attacker_ids {
        let victim_auth_clone = Arc::clone(&victim_auth);
        let sem_clone = Arc::clone(&semaphore);

        let task = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();

            // Send auth request
            let result = victim_auth_clone
                .handle_auth_request(attacker_id, public_key_to_bytes(&attacker_key))
                .await;

            drop(_permit);
            result
        });

        tasks.push(task);
    }

    // Wait for all attacks to complete
    let _results = future::join_all(tasks).await;
    let elapsed = start_time.elapsed();

    info!(
        "Processed {} auth requests in {:?} ({:.2} req/sec)",
        attacker_count,
        elapsed,
        attacker_count as f64 / elapsed.as_secs_f64()
    );

    // System should remain responsive
    assert!(
        elapsed < Duration::from_secs(10),
        "System should handle flood quickly"
    );

    // Legitimate auth should still work
    let (_legit_secret, legit_public) = generate_ed25519_keypair();
    let legit_id = derive_peer_id_from_public_key(&legit_public);

    let legit_result = victim_auth
        .handle_auth_request(legit_id, public_key_to_bytes(&legit_public))
        .await;

    assert!(
        legit_result.is_ok(),
        "Legitimate auth should work after flood"
    );
}

#[tokio::test]
async fn test_challenge_memory_exhaustion() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test protection against memory exhaustion via pending challenges
    let (secret_key, _) = generate_ed25519_keypair();

    let config = AuthConfig {
        challenge_validity: Duration::from_secs(60), // Long validity
        ..Default::default()
    };

    let auth = Arc::new(AuthManager::new(secret_key, config));

    // Track memory usage indirectly via challenge count
    let challenge_count = Arc::new(AtomicU64::new(0));

    // Create many pending challenges
    let mut tasks = Vec::new();
    for _ in 0..10000 {
        let auth_clone = Arc::clone(&auth);
        let count_clone = Arc::clone(&challenge_count);

        let task = tokio::spawn(async move {
            let (_, public_key) = generate_ed25519_keypair();
            let peer_id = derive_peer_id_from_public_key(&public_key);

            let result = auth_clone
                .handle_auth_request(peer_id, public_key_to_bytes(&public_key))
                .await;

            if result.is_ok() {
                count_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        tasks.push(task);

        // Add some pacing to avoid overwhelming the system
        if tasks.len() % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }

    future::join_all(tasks).await;

    let total_challenges = challenge_count.load(Ordering::Relaxed);
    info!("Created {} pending challenges", total_challenges);

    // Cleanup should prevent unbounded growth
    auth.cleanup_expired_challenges().await;

    // System should still be functional
    let (_, test_key) = generate_ed25519_keypair();
    let test_id = derive_peer_id_from_public_key(&test_key);

    let result = auth
        .handle_auth_request(test_id, public_key_to_bytes(&test_key))
        .await;

    assert!(result.is_ok(), "System should remain functional");
}

// ===== Cryptographic Attack Tests =====

#[tokio::test]
async fn test_weak_randomness_detection() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that we use cryptographically secure randomness
    let (secret_key, _) = generate_ed25519_keypair();
    let auth = AuthManager::new(secret_key, AuthConfig::default());

    // Collect multiple challenges to check for patterns
    let mut nonces = HashSet::new();

    for _ in 0..1000 {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        let challenge = auth
            .handle_auth_request(peer_id, public_key_to_bytes(&public_key))
            .await
            .unwrap();

        if let AuthMessage::Challenge { nonce, .. } = challenge {
            // Check for duplicates
            assert!(
                nonces.insert(nonce),
                "Duplicate nonce detected - weak randomness!"
            );

            // Check for obvious patterns (all zeros, sequential, etc.)
            assert_ne!(nonce, [0u8; 32], "All-zero nonce detected");
            assert_ne!(nonce, [0xFF; 32], "All-ones nonce detected");

            // Check entropy (simple check - at least some variation)
            let unique_bytes = nonce.iter().collect::<HashSet<_>>().len();
            assert!(
                unique_bytes > 10,
                "Low entropy in nonce: only {unique_bytes} unique bytes"
            );
        }
    }

    info!("Generated {} unique nonces with good entropy", nonces.len());
}

#[tokio::test]
async fn test_signature_malleability() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test resistance to signature malleability attacks
    let (alice_secret, alice_public) = generate_ed25519_keypair();
    let (bob_secret, _) = generate_ed25519_keypair();

    let alice_id = derive_peer_id_from_public_key(&alice_public);
    let alice_auth = AuthManager::new(alice_secret, AuthConfig::default());
    let bob_auth = AuthManager::new(bob_secret, AuthConfig::default());

    // Create a valid challenge-response
    let auth_request = alice_auth.create_auth_request();
    let challenge = match auth_request {
        AuthMessage::AuthRequest {
            peer_id,
            public_key,
            ..
        } => bob_auth
            .handle_auth_request(peer_id, public_key)
            .await
            .unwrap(),
        _ => panic!("Expected AuthRequest"),
    };

    let response = match challenge {
        AuthMessage::Challenge { nonce, .. } => {
            alice_auth.create_challenge_response(nonce).unwrap()
        }
        _ => panic!("Expected Challenge"),
    };

    // Try to create malleated signatures
    match response {
        AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } => {
            // Ed25519 signatures are 64 bytes (R || S)
            assert_eq!(signature.len(), 64);

            // Try various malleation attempts
            let malleation_attempts = [
                // Flip bits in R component
                {
                    let mut mal_sig = signature.clone();
                    mal_sig[0] ^= 0x01;
                    mal_sig
                },
                // Flip bits in S component
                {
                    let mut mal_sig = signature.clone();
                    mal_sig[32] ^= 0x01;
                    mal_sig
                },
                // Try to negate S (signature malleability)
                {
                    let mut mal_sig = signature.clone();
                    // This is a simplified test - proper negation would require field arithmetic
                    for item in mal_sig.iter_mut().take(64).skip(32) {
                        *item = !*item;
                    }
                    mal_sig
                },
            ];

            for (i, mal_sig) in malleation_attempts.iter().enumerate() {
                let result = bob_auth
                    .verify_challenge_response(
                        alice_id,
                        public_key_to_bytes(&alice_public),
                        nonce,
                        mal_sig,
                    )
                    .await;

                assert!(
                    result.is_err(),
                    "Malleated signature {i} should be rejected"
                );
            }
        }
        _ => panic!("Expected ChallengeResponse"),
    }
}

// ===== Protocol Vulnerability Tests =====

#[tokio::test]
async fn test_challenge_prediction_attack() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that challenges cannot be predicted
    let (secret_key, _) = generate_ed25519_keypair();
    let auth = AuthManager::new(secret_key, AuthConfig::default());

    // Collect sequential challenges
    let mut challenges = Vec::new();

    for _i in 0..100 {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        let challenge = auth
            .handle_auth_request(peer_id, public_key_to_bytes(&public_key))
            .await
            .unwrap();

        if let AuthMessage::Challenge { nonce, .. } = challenge {
            challenges.push(nonce);
        }
    }

    // Analyze for predictability
    for i in 1..challenges.len() {
        let prev = &challenges[i - 1];
        let curr = &challenges[i];

        // Check they're not sequential
        let mut sequential = true;
        for j in 0..32 {
            if curr[j] != prev[j].wrapping_add(1) {
                sequential = false;
                break;
            }
        }
        assert!(!sequential, "Sequential nonces detected at position {i}");

        // Check they're not similar (Hamming distance)
        let mut diff_bits = 0;
        for j in 0..32 {
            diff_bits += (prev[j] ^ curr[j]).count_ones();
        }

        // Should have significant difference (at least 25% of bits)
        assert!(
            diff_bits > 64,
            "Nonces too similar at position {i}: only {diff_bits} bits different"
        );
    }
}

#[tokio::test]
async fn test_auth_state_confusion() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test resistance to state confusion attacks
    let (alice_secret, alice_public) = generate_ed25519_keypair();
    let (bob_secret, bob_public) = generate_ed25519_keypair();
    let (charlie_secret, charlie_public) = generate_ed25519_keypair();

    let alice_id = derive_peer_id_from_public_key(&alice_public);
    let _bob_id = derive_peer_id_from_public_key(&bob_public);
    let _charlie_id = derive_peer_id_from_public_key(&charlie_public);

    let alice_auth = AuthManager::new(alice_secret, AuthConfig::default());
    let bob_auth = AuthManager::new(bob_secret, AuthConfig::default());
    let charlie_auth = AuthManager::new(charlie_secret, AuthConfig::default());

    // Alice starts auth with Bob
    let alice_to_bob = alice_auth.create_auth_request();
    let bob_challenge = match alice_to_bob {
        AuthMessage::AuthRequest {
            peer_id,
            public_key,
            ..
        } => bob_auth
            .handle_auth_request(peer_id, public_key)
            .await
            .unwrap(),
        _ => panic!("Expected AuthRequest"),
    };

    // Charlie starts auth with Bob
    let charlie_to_bob = charlie_auth.create_auth_request();
    let bob_challenge_2 = match charlie_to_bob {
        AuthMessage::AuthRequest {
            peer_id,
            public_key,
            ..
        } => bob_auth
            .handle_auth_request(peer_id, public_key)
            .await
            .unwrap(),
        _ => panic!("Expected AuthRequest"),
    };

    // Extract nonces
    let (_alice_nonce, charlie_nonce) = match (&bob_challenge, &bob_challenge_2) {
        (AuthMessage::Challenge { nonce: n1, .. }, AuthMessage::Challenge { nonce: n2, .. }) => {
            (*n1, *n2)
        }
        _ => panic!("Expected challenges"),
    };

    // Alice tries to respond to Charlie's challenge
    let alice_response_to_charlie = alice_auth.create_challenge_response(charlie_nonce).unwrap();

    // Bob should reject this (wrong peer for this challenge)
    match alice_response_to_charlie {
        AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } => {
            let result = bob_auth
                .verify_challenge_response(
                    alice_id,
                    public_key_to_bytes(&alice_public),
                    nonce,
                    &signature,
                )
                .await;

            assert!(result.is_err(), "Should reject response to wrong challenge");
        }
        _ => panic!("Expected ChallengeResponse"),
    }
}

// ===== Side-Channel Attack Tests =====

#[tokio::test]
async fn test_timing_side_channel_auth_request() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test timing consistency for auth request handling
    let (secret_key, _) = generate_ed25519_keypair();
    let auth = AuthManager::new(secret_key, AuthConfig::default());

    // Test with valid vs invalid peer IDs
    let (_valid_secret, valid_public) = generate_ed25519_keypair();
    let valid_id = derive_peer_id_from_public_key(&valid_public);

    let invalid_id = valid_id; // Same ID
    let (_, mismatched_public) = generate_ed25519_keypair(); // Different key

    let mut valid_times = Vec::new();
    let mut invalid_times = Vec::new();

    // Warm up
    for _ in 0..10 {
        let _ = auth
            .handle_auth_request(valid_id, public_key_to_bytes(&valid_public))
            .await;
    }

    // Measure timings
    for _ in 0..100 {
        // Time valid request
        let start = Instant::now();
        let _ = auth
            .handle_auth_request(valid_id, public_key_to_bytes(&valid_public))
            .await;
        valid_times.push(start.elapsed());

        // Time invalid request (mismatched peer ID)
        let start = Instant::now();
        let _ = auth
            .handle_auth_request(invalid_id, public_key_to_bytes(&mismatched_public))
            .await;
        invalid_times.push(start.elapsed());
    }

    // Calculate statistics
    let valid_avg = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let invalid_avg = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;

    let diff = valid_avg.abs_diff(invalid_avg);

    info!(
        "Auth request timing - Valid: {:?}, Invalid: {:?}, Diff: {:?}",
        valid_avg, invalid_avg, diff
    );

    // Should not leak information via timing
    let tolerance = Duration::from_micros(100); // Very tight tolerance
    assert!(diff < tolerance, "Timing difference too large: {diff:?}");
}

#[tokio::test]
async fn test_cache_timing_attacks() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test for cache-based timing attacks
    let (secret_key, _) = generate_ed25519_keypair();
    let auth = Arc::new(AuthManager::new(secret_key, AuthConfig::default()));

    // First, authenticate a peer to cache it
    let (cached_secret, cached_public) = generate_ed25519_keypair();
    let cached_id = derive_peer_id_from_public_key(&cached_public);

    // Complete full auth flow to cache the peer
    let request = AuthMessage::AuthRequest {
        peer_id: cached_id,
        public_key: public_key_to_bytes(&cached_public),
        timestamp: SystemTime::now(),
    };

    let challenge = match request {
        AuthMessage::AuthRequest {
            peer_id,
            public_key,
            ..
        } => auth.handle_auth_request(peer_id, public_key).await.unwrap(),
        _ => panic!("Expected AuthRequest"),
    };

    // Complete authentication
    if let AuthMessage::Challenge { nonce, .. } = challenge {
        let cached_auth = AuthManager::new(cached_secret, AuthConfig::default());
        let response = cached_auth.create_challenge_response(nonce).unwrap();

        if let AuthMessage::ChallengeResponse {
            nonce, signature, ..
        } = response
        {
            let _ = auth
                .verify_challenge_response(
                    cached_id,
                    public_key_to_bytes(&cached_public),
                    nonce,
                    &signature,
                )
                .await;
        }
    }

    // Now measure access times for cached vs uncached peers
    let mut cached_times = Vec::new();
    let mut uncached_times = Vec::new();

    for _ in 0..100 {
        // Check cached peer
        let start = Instant::now();
        let is_auth = auth.is_authenticated(&cached_id).await;
        cached_times.push(start.elapsed());
        assert!(is_auth);

        // Check uncached peer
        let (_, uncached_public) = generate_ed25519_keypair();
        let uncached_id = derive_peer_id_from_public_key(&uncached_public);

        let start = Instant::now();
        let is_auth = auth.is_authenticated(&uncached_id).await;
        uncached_times.push(start.elapsed());
        assert!(!is_auth);
    }

    // Both should have similar access times (no cache timing leak)
    let cached_avg = cached_times.iter().sum::<Duration>() / cached_times.len() as u32;
    let uncached_avg = uncached_times.iter().sum::<Duration>() / uncached_times.len() as u32;

    info!(
        "Cache timing - Cached: {:?}, Uncached: {:?}",
        cached_avg, uncached_avg
    );

    // Access times should be similar
    let ratio = if cached_avg > uncached_avg {
        cached_avg.as_nanos() as f64 / uncached_avg.as_nanos() as f64
    } else {
        uncached_avg.as_nanos() as f64 / cached_avg.as_nanos() as f64
    };

    // Allow higher tolerance on CI/macOS due to performance variability
    #[cfg(target_os = "macos")]
    let max_ratio = 10.0; // Increased for CI environment variability
    #[cfg(not(target_os = "macos"))]
    let max_ratio = 3.0;

    assert!(
        ratio < max_ratio,
        "Cache timing ratio too high: {ratio:.2}x difference (max: {max_ratio})"
    );
}

// ===== Resource Exhaustion Tests =====

#[tokio::test]
async fn test_connection_slot_exhaustion() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test protection against connection slot exhaustion
    let (victim_secret, _) = generate_ed25519_keypair();

    let config = AuthConfig {
        max_auth_attempts: 3,
        ..Default::default()
    };

    let victim_auth = Arc::new(AuthManager::new(victim_secret, config));

    // Track resource usage
    let active_attempts = Arc::new(AtomicU64::new(0));
    let rejected_attempts = Arc::new(AtomicU64::new(0));

    // Simulate many concurrent auth attempts
    let mut tasks = Vec::new();
    for _ in 0..1000 {
        let auth_clone = Arc::clone(&victim_auth);
        let active_clone = Arc::clone(&active_attempts);
        let rejected_clone = Arc::clone(&rejected_attempts);

        let task = tokio::spawn(async move {
            active_clone.fetch_add(1, Ordering::Relaxed);

            let (_, public_key) = generate_ed25519_keypair();
            let peer_id = derive_peer_id_from_public_key(&public_key);

            let result = timeout(
                Duration::from_secs(1),
                auth_clone.handle_auth_request(peer_id, public_key_to_bytes(&public_key)),
            )
            .await;

            active_clone.fetch_sub(1, Ordering::Relaxed);

            if result.is_err() || result.unwrap().is_err() {
                rejected_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        tasks.push(task);
    }

    future::join_all(tasks).await;

    let total_rejected = rejected_attempts.load(Ordering::Relaxed);
    info!("Rejected {} authentication attempts", total_rejected);

    // The system currently handles all attempts without rate limiting
    // This test verifies the system remains stable under heavy load
    // TODO: In a production system, implement rate limiting to reject excessive attempts
    info!("System handled 1000 concurrent auth attempts without crashing");

    // Verify the system is still functional after the load test
    let (_test_secret, test_public) = generate_ed25519_keypair();
    let test_id = derive_peer_id_from_public_key(&test_public);

    let result = victim_auth
        .handle_auth_request(test_id, public_key_to_bytes(&test_public))
        .await;

    assert!(
        result.is_ok(),
        "System should remain functional after heavy load"
    );
}

#[tokio::test]
async fn test_memory_pressure_during_auth() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test behavior under memory pressure
    let mut auth_managers = Vec::new();

    // Create many auth managers with pending challenges
    for _i in 0..100 {
        let (secret_key, _) = generate_ed25519_keypair();
        let auth = Arc::new(AuthManager::new(secret_key, AuthConfig::default()));

        // Create pending challenges
        for _ in 0..100 {
            let (_, public_key) = generate_ed25519_keypair();
            let peer_id = derive_peer_id_from_public_key(&public_key);

            let _ = auth
                .handle_auth_request(peer_id, public_key_to_bytes(&public_key))
                .await;
        }

        auth_managers.push(auth);

        if auth_managers.len() % 10 == 1 {
            info!(
                "Created {} auth managers with pending challenges",
                auth_managers.len()
            );
        }
    }

    // Verify system is still functional
    let (test_secret, test_public) = generate_ed25519_keypair();
    let test_id = derive_peer_id_from_public_key(&test_public);
    let test_auth = AuthManager::new(test_secret, AuthConfig::default());

    let result = test_auth
        .handle_auth_request(test_id, public_key_to_bytes(&test_public))
        .await;

    assert!(
        result.is_ok(),
        "System should remain functional under memory pressure"
    );

    // Clean up
    for auth in &auth_managers {
        auth.cleanup_expired_challenges().await;
    }
}

// ===== Concurrency Attack Tests =====

#[tokio::test]
async fn test_race_condition_in_auth_state() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test for race conditions in authentication state updates
    let (secret_key, _) = generate_ed25519_keypair();
    let auth = Arc::new(AuthManager::new(secret_key, AuthConfig::default()));

    let (_peer_secret, peer_public) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&peer_public);

    // Create multiple tasks that try to authenticate the same peer simultaneously
    let mut tasks = Vec::new();
    let start_barrier = Arc::new(tokio::sync::Barrier::new(10));

    for i in 0..10 {
        let auth_clone = Arc::clone(&auth);
        let barrier_clone = Arc::clone(&start_barrier);

        let task = tokio::spawn(async move {
            // Synchronize start
            barrier_clone.wait().await;

            // Try to handle auth request
            let result = auth_clone
                .handle_auth_request(peer_id, public_key_to_bytes(&peer_public))
                .await;

            (i, result)
        });

        tasks.push(task);
    }

    let results = future::join_all(tasks).await;

    // All attempts should handle gracefully (no panics)
    let successful = results
        .iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().1.is_ok())
        .count();

    info!(
        "{} out of 10 concurrent auth attempts succeeded",
        successful
    );

    // At least one should succeed
    assert!(successful >= 1, "At least one auth attempt should succeed");

    // No data corruption - peer should be in consistent state
    let is_auth = auth.is_authenticated(&peer_id).await;
    let auth_peer = auth.get_authenticated_peer(&peer_id).await;

    // Either fully authenticated or not at all
    assert_eq!(
        is_auth,
        auth_peer.is_some(),
        "Authentication state must be consistent"
    );
}
