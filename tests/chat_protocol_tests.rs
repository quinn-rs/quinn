//! Integration tests for the chat protocol
//!
//! This module tests the chat messaging system over QUIC streams.

use ant_quic::{
    auth::AuthConfig,
    chat::{ChatError, ChatMessage, MAX_MESSAGE_SIZE, PeerInfo},
    nat_traversal_api::EndpointRole,
    nat_traversal_api::PeerId,
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use tracing::info;

/// Test helper to create a test QUIC node
async fn create_test_node(
    role: EndpointRole,
    bootstrap_nodes: Vec<SocketAddr>,
) -> Result<QuicP2PNode, Box<dyn std::error::Error + Send + Sync>> {
    let config = QuicNodeConfig {
        role,
        bootstrap_nodes,
        enable_coordinator: matches!(role, EndpointRole::Server { .. }),
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
        bind_addr: None,
    };

    QuicP2PNode::new(config).await
}

#[tokio::test]
async fn test_chat_message_exchange() {
    let _ = tracing_subscriber::fmt::try_init();

    // Ensure crypto provider is installed
    #[cfg(feature = "rustls-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(feature = "rustls-ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Create coordinator node with a bootstrap address (required for Server role)
    let bootstrap_addr = "127.0.0.1:9999".parse().unwrap();
    let _coordinator = create_test_node(
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![bootstrap_addr],
    )
    .await
    .unwrap();

    // Create two client nodes
    let _client1 = create_test_node(EndpointRole::Client, vec![bootstrap_addr])
        .await
        .unwrap();

    let _client2 = create_test_node(EndpointRole::Client, vec![bootstrap_addr])
        .await
        .unwrap();

    // Generate peer IDs
    let peer_id1 = PeerId([1u8; 32]);
    let _peer_id2 = PeerId([2u8; 32]);

    // Create chat messages
    let join_msg = ChatMessage::join("alice".to_string(), peer_id1);
    let text_msg = ChatMessage::text("alice".to_string(), peer_id1, "Hello, world!".to_string());
    let status_msg = ChatMessage::status("alice".to_string(), peer_id1, "Away".to_string());

    // Test serialization
    let join_data = join_msg.serialize().unwrap();
    let text_data = text_msg.serialize().unwrap();
    let status_data = status_msg.serialize().unwrap();

    // Test deserialization
    let join_deserialized = ChatMessage::deserialize(&join_data).unwrap();
    let text_deserialized = ChatMessage::deserialize(&text_data).unwrap();
    let _status_deserialized = ChatMessage::deserialize(&status_data).unwrap();

    // Verify message integrity
    match (&join_msg, &join_deserialized) {
        (
            ChatMessage::Join {
                nickname: n1,
                peer_id: p1,
                ..
            },
            ChatMessage::Join {
                nickname: n2,
                peer_id: p2,
                ..
            },
        ) => {
            assert_eq!(n1, n2);
            assert_eq!(p1, p2);
        }
        _ => panic!("Join message mismatch"),
    }

    match (&text_msg, &text_deserialized) {
        (
            ChatMessage::Text {
                nickname: n1,
                peer_id: p1,
                text: t1,
                ..
            },
            ChatMessage::Text {
                nickname: n2,
                peer_id: p2,
                text: t2,
                ..
            },
        ) => {
            assert_eq!(n1, n2);
            assert_eq!(p1, p2);
            assert_eq!(t1, t2);
        }
        _ => panic!("Text message mismatch"),
    }

    info!("Chat message serialization tests passed");
}

#[tokio::test]
async fn test_direct_messaging() {
    let _ = tracing_subscriber::fmt::try_init();

    let peer_id1 = PeerId([10u8; 32]);
    let peer_id2 = PeerId([20u8; 32]);

    // Create direct message
    let dm = ChatMessage::direct(
        "alice".to_string(),
        peer_id1,
        peer_id2,
        "Private message".to_string(),
    );

    // Serialize and deserialize
    let data = dm.serialize().unwrap();
    let deserialized = ChatMessage::deserialize(&data).unwrap();

    match deserialized {
        ChatMessage::Direct {
            from_nickname,
            from_peer_id,
            to_peer_id,
            text,
            ..
        } => {
            assert_eq!(from_nickname, "alice");
            assert_eq!(from_peer_id, peer_id1.0);
            assert_eq!(to_peer_id, peer_id2.0);
            assert_eq!(text, "Private message");
        }
        _ => panic!("Expected Direct message"),
    }
}

#[tokio::test]
async fn test_typing_indicators() {
    let _ = tracing_subscriber::fmt::try_init();

    let peer_id = PeerId([30u8; 32]);

    // Create typing indicators
    let typing_on = ChatMessage::typing("bob".to_string(), peer_id, true);
    let typing_off = ChatMessage::typing("bob".to_string(), peer_id, false);

    // Test serialization
    let on_data = typing_on.serialize().unwrap();
    let off_data = typing_off.serialize().unwrap();

    // Test deserialization
    match ChatMessage::deserialize(&on_data).unwrap() {
        ChatMessage::Typing {
            nickname,
            peer_id: p,
            is_typing,
        } => {
            assert_eq!(nickname, "bob");
            assert_eq!(p, peer_id.0);
            assert!(is_typing);
        }
        _ => panic!("Expected Typing message"),
    }

    match ChatMessage::deserialize(&off_data).unwrap() {
        ChatMessage::Typing {
            nickname,
            peer_id: p,
            is_typing,
        } => {
            assert_eq!(nickname, "bob");
            assert_eq!(p, peer_id.0);
            assert!(!is_typing);
        }
        _ => panic!("Expected Typing message"),
    }
}

#[tokio::test]
async fn test_peer_list_exchange() {
    let _ = tracing_subscriber::fmt::try_init();

    let peer_id = PeerId([40u8; 32]);

    // Create peer list request
    let request = ChatMessage::PeerListRequest { peer_id: peer_id.0 };

    // Create peer list response
    let peers = vec![
        PeerInfo {
            peer_id: [50u8; 32],
            nickname: "charlie".to_string(),
            status: "Online".to_string(),
            joined_at: SystemTime::now(),
        },
        PeerInfo {
            peer_id: [60u8; 32],
            nickname: "david".to_string(),
            status: "Away".to_string(),
            joined_at: SystemTime::now(),
        },
    ];

    let response = ChatMessage::PeerListResponse {
        peers: peers.clone(),
    };

    // Test serialization
    let req_data = request.serialize().unwrap();
    let resp_data = response.serialize().unwrap();

    // Test deserialization
    match ChatMessage::deserialize(&req_data).unwrap() {
        ChatMessage::PeerListRequest { peer_id: p } => {
            assert_eq!(p, peer_id.0);
        }
        _ => panic!("Expected PeerListRequest"),
    }

    match ChatMessage::deserialize(&resp_data).unwrap() {
        ChatMessage::PeerListResponse { peers: p } => {
            assert_eq!(p.len(), 2);
            assert_eq!(p[0].nickname, "charlie");
            assert_eq!(p[1].nickname, "david");
        }
        _ => panic!("Expected PeerListResponse"),
    }
}

#[tokio::test]
async fn test_message_size_limits() {
    let _ = tracing_subscriber::fmt::try_init();

    let peer_id = PeerId([70u8; 32]);

    // Create a message that's too large
    let large_text = "x".repeat(MAX_MESSAGE_SIZE);
    let large_msg = ChatMessage::text("eve".to_string(), peer_id, large_text);

    // Should fail to serialize
    match large_msg.serialize() {
        Err(ChatError::MessageTooLarge(size, max)) => {
            assert!(size > max);
            assert_eq!(max, MAX_MESSAGE_SIZE);
        }
        _ => panic!("Expected MessageTooLarge error"),
    }

    // Create a message just under the limit
    let ok_text = "x".repeat(1024 * 900); // Well under 1MB
    let ok_msg = ChatMessage::text("eve".to_string(), peer_id, ok_text.clone());

    // Should serialize successfully
    let data = ok_msg.serialize().unwrap();
    let deserialized = ChatMessage::deserialize(&data).unwrap();

    match deserialized {
        ChatMessage::Text { text, .. } => {
            assert_eq!(text.len(), ok_text.len());
        }
        _ => panic!("Expected Text message"),
    }
}

#[tokio::test]
async fn test_protocol_version_validation() {
    let _ = tracing_subscriber::fmt::try_init();

    let peer_id = PeerId([80u8; 32]);
    let msg = ChatMessage::text("frank".to_string(), peer_id, "test".to_string());

    // Create a message with wrong protocol version
    #[derive(serde::Serialize)]
    struct WrongVersionFormat {
        version: u16,
        message: ChatMessage,
    }

    let wrong_format = WrongVersionFormat {
        version: 999, // Wrong version
        message: msg,
    };

    let data = serde_json::to_vec(&wrong_format).unwrap();

    // Should fail to deserialize
    match ChatMessage::deserialize(&data) {
        Err(ChatError::InvalidProtocolVersion(999)) => {}
        _ => panic!("Expected InvalidProtocolVersion error"),
    }
}

#[tokio::test]
async fn test_message_metadata_extraction() {
    let _ = tracing_subscriber::fmt::try_init();

    let peer_id = PeerId([90u8; 32]);

    // Test peer_id extraction
    let messages = vec![
        ChatMessage::join("grace".to_string(), peer_id),
        ChatMessage::text("grace".to_string(), peer_id, "hello".to_string()),
        ChatMessage::typing("grace".to_string(), peer_id, true),
    ];

    for msg in &messages {
        assert_eq!(msg.peer_id(), Some(peer_id));
        assert_eq!(msg.nickname(), Some("grace"));
    }

    // Test messages without peer_id
    let peer_list = ChatMessage::PeerListResponse { peers: vec![] };
    assert_eq!(peer_list.peer_id(), None);
    assert_eq!(peer_list.nickname(), None);
}
