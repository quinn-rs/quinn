//! Performance benchmarks for authentication module
//!
//! Run with: cargo bench --bench auth_benchmarks

use ant_quic::{
    auth::{AuthConfig, AuthManager, AuthMessage},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair, public_key_to_bytes,
    },
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::{sync::Arc, time::Duration};
use tokio::runtime::Runtime;

/// Benchmark key generation and peer ID derivation
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    group.bench_function("generate_keypair", |b| {
        b.iter(|| {
            let (secret_key, public_key) = generate_ed25519_keypair();
            black_box((secret_key, public_key))
        });
    });

    group.bench_function("derive_peer_id", |b| {
        let (_, public_key) = generate_ed25519_keypair();
        b.iter(|| {
            let peer_id = derive_peer_id_from_public_key(&public_key);
            black_box(peer_id)
        });
    });

    group.bench_function("full_identity_generation", |b| {
        b.iter(|| {
            let (secret_key, public_key) = generate_ed25519_keypair();
            let peer_id = derive_peer_id_from_public_key(&public_key);
            black_box((secret_key, public_key, peer_id))
        });
    });

    group.finish();
}

/// Benchmark authentication manager creation
fn bench_auth_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_manager");

    group.bench_function("create_default", |b| {
        b.iter(|| {
            let (secret_key, _) = generate_ed25519_keypair();
            let auth_manager = AuthManager::new(secret_key, AuthConfig::default());
            black_box(auth_manager)
        });
    });

    group.bench_function("create_custom_config", |b| {
        let config = AuthConfig {
            auth_timeout: Duration::from_secs(30),
            challenge_validity: Duration::from_secs(120),
            require_authentication: true,
            max_auth_attempts: 5,
        };

        b.iter(|| {
            let (secret_key, _) = generate_ed25519_keypair();
            let auth_manager = AuthManager::new(secret_key, config.clone());
            black_box(auth_manager)
        });
    });

    group.finish();
}

/// Benchmark authentication protocol messages
fn bench_auth_messages(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("auth_messages");

    // Setup
    let (secret_key, public_key) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    let auth_manager = Arc::new(AuthManager::new(secret_key, AuthConfig::default()));

    group.bench_function("create_auth_request", |b| {
        b.iter(|| {
            let request = auth_manager.create_auth_request();
            black_box(request)
        });
    });

    group.bench_function("handle_auth_request", |b| {
        let (_peer_secret, peer_public) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&peer_public);
        let public_key_bytes = public_key_to_bytes(&peer_public);

        b.iter(|| {
            let auth_manager = auth_manager.clone();
            rt.block_on(async move {
                let result = auth_manager
                    .handle_auth_request(peer_id, public_key_bytes)
                    .await;
                black_box(result)
            })
        });
    });

    group.bench_function("create_challenge_response", |b| {
        let nonce = [42u8; 32];

        b.iter(|| {
            let response = auth_manager.create_challenge_response(nonce);
            black_box(response)
        });
    });

    group.bench_function("verify_challenge_response", |b| {
        // Create a valid challenge-response pair
        let nonce = [42u8; 32];
        let response = auth_manager.create_challenge_response(nonce).unwrap();

        let signature = match response {
            AuthMessage::ChallengeResponse { signature, .. } => signature,
            _ => panic!("Expected ChallengeResponse"),
        };

        b.iter(|| {
            let auth_manager = auth_manager.clone();
            let signature = signature.clone();
            rt.block_on(async move {
                let result = auth_manager
                    .verify_challenge_response(
                        peer_id,
                        public_key_to_bytes(&public_key),
                        nonce,
                        &signature,
                    )
                    .await;
                black_box(result)
            })
        });
    });

    group.finish();
}

/// Benchmark complete authentication flow
fn bench_auth_flow(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("auth_flow");

    group.bench_function("complete_handshake", |b| {
        b.iter(|| {
            rt.block_on(async {
            // Create two peers
            let (alice_secret, alice_public) = generate_ed25519_keypair();
            let (bob_secret, bob_public) = generate_ed25519_keypair();

            let alice_id = derive_peer_id_from_public_key(&alice_public);
            let _bob_id = derive_peer_id_from_public_key(&bob_public);

            let alice_auth = AuthManager::new(alice_secret, AuthConfig::default());
            let bob_auth = AuthManager::new(bob_secret, AuthConfig::default());

            // Step 1: Alice creates auth request
            let auth_request = alice_auth.create_auth_request();

            // Step 2: Bob handles request and creates challenge
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

            // Step 3: Alice responds to challenge
            let response = match challenge {
                AuthMessage::Challenge { nonce, .. } => {
                    alice_auth.create_challenge_response(nonce).unwrap()
                }
                _ => panic!("Expected Challenge"),
            };

            // Step 4: Bob verifies response
            let result = match response {
                AuthMessage::ChallengeResponse {
                    nonce, signature, ..
                } => {
                    bob_auth
                        .verify_challenge_response(
                            alice_id,
                            public_key_to_bytes(&alice_public),
                            nonce,
                            &signature,
                        )
                        .await
                }
                _ => panic!("Expected ChallengeResponse"),
            };

            black_box(result)
            })
        });
    });

    group.finish();
}

/// Benchmark concurrent authentication handling
fn bench_concurrent_auth(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_auth");

    for peer_count in [10, 50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*peer_count as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &peer_count| {
                b.iter(|| {
                    rt.block_on(async {
                    let (secret_key, _) = generate_ed25519_keypair();
                    let auth_manager =
                        Arc::new(AuthManager::new(secret_key, AuthConfig::default()));

                    // Create multiple peers trying to authenticate
                    let mut tasks = Vec::new();

                    for _ in 0..peer_count {
                        let auth_clone = auth_manager.clone();

                        let task = tokio::spawn(async move {
                            let (_peer_secret, peer_public) = generate_ed25519_keypair();
                            let peer_id = derive_peer_id_from_public_key(&peer_public);

                            auth_clone
                                .handle_auth_request(peer_id, public_key_to_bytes(&peer_public))
                                .await
                        });

                        tasks.push(task);
                    }

                    let mut results = Vec::new();
                    for task in tasks {
                        results.push(task.await.unwrap());
                    }
                    black_box(results)
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark message serialization
fn bench_message_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    let (_, public_key) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&public_key);

    let messages = vec![
        (
            "auth_request",
            AuthMessage::AuthRequest {
                peer_id,
                public_key: public_key_to_bytes(&public_key),
                timestamp: std::time::SystemTime::now(),
            },
        ),
        (
            "challenge",
            AuthMessage::Challenge {
                nonce: [42u8; 32],
                timestamp: std::time::SystemTime::now(),
            },
        ),
        (
            "challenge_response",
            AuthMessage::ChallengeResponse {
                nonce: [42u8; 32],
                signature: vec![0u8; 64],
                timestamp: std::time::SystemTime::now(),
            },
        ),
        (
            "auth_success",
            AuthMessage::AuthSuccess {
                session_id: [99u8; 32],
                timestamp: std::time::SystemTime::now(),
            },
        ),
        (
            "auth_failure",
            AuthMessage::AuthFailure {
                reason: "Test failure reason".to_string(),
            },
        ),
    ];

    for (name, message) in &messages {
        group.bench_with_input(
            BenchmarkId::new("serialize", name),
            message,
            |b, message| {
                b.iter(|| {
                    let serialized = AuthManager::serialize_message(message);
                    black_box(serialized)
                });
            },
        );
    }

    // Benchmark deserialization
    for (name, message) in &messages {
        let serialized = AuthManager::serialize_message(message).unwrap();

        group.bench_with_input(
            BenchmarkId::new("deserialize", name),
            &serialized,
            |b, serialized| {
                b.iter(|| {
                    let deserialized = AuthManager::deserialize_message(serialized);
                    black_box(deserialized)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark authenticated peer management
fn bench_peer_management(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("peer_management");

    // Setup auth manager with many authenticated peers
    let (secret_key, _) = generate_ed25519_keypair();
    let auth_manager = Arc::new(AuthManager::new(secret_key, AuthConfig::default()));

    // Pre-populate with authenticated peers
    rt.block_on(async {
        for _i in 0..1000 {
            let (_, peer_public) = generate_ed25519_keypair();
            let peer_id = derive_peer_id_from_public_key(&peer_public);

            // Simulate adding authenticated peer
            let _ = auth_manager
                .handle_auth_request(peer_id, public_key_to_bytes(&peer_public))
                .await;
        }
    });

    group.bench_function("is_authenticated_check", |b| {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        b.iter(|| {
            let auth_manager = auth_manager.clone();
            rt.block_on(async move {
                let result = auth_manager.is_authenticated(&peer_id).await;
                black_box(result)
            })
        });
    });

    group.bench_function("list_authenticated_peers", |b| {
        b.iter(|| {
            let auth_manager = auth_manager.clone();
            rt.block_on(async move {
                let peers = auth_manager.list_authenticated_peers().await;
                black_box(peers)
            })
        });
    });

    group.bench_function("cleanup_expired_challenges", |b| {
        b.iter(|| {
            let auth_manager = auth_manager.clone();
            rt.block_on(async move {
                auth_manager.cleanup_expired_challenges().await;
            })
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_auth_manager_creation,
    bench_auth_messages,
    bench_auth_flow,
    bench_concurrent_auth,
    bench_message_serialization,
    bench_peer_management
);

criterion_main!(benches);
