//! Simple chat example using the chat protocol
//!
//! This example demonstrates basic chat message serialization and handling.

use ant_quic::{
    chat::{ChatMessage, PeerInfo},
    nat_traversal_api::PeerId,
};
use std::time::SystemTime;

fn main() {
    println!("=== Chat Protocol Demo ===\n");

    // Create some peer IDs
    let alice_id = PeerId([1u8; 32]);
    let bob_id = PeerId([2u8; 32]);

    // Create different message types
    let messages = vec![
        ChatMessage::join("Alice".to_string(), alice_id),
        ChatMessage::join("Bob".to_string(), bob_id),
        ChatMessage::text("Alice".to_string(), alice_id, "Hello everyone!".to_string()),
        ChatMessage::text(
            "Bob".to_string(),
            bob_id,
            "Hi Alice! How are you?".to_string(),
        ),
        ChatMessage::status("Alice".to_string(), alice_id, "Away".to_string()),
        ChatMessage::direct(
            "Bob".to_string(),
            bob_id,
            alice_id,
            "Are you still there?".to_string(),
        ),
        ChatMessage::typing("Alice".to_string(), alice_id, true),
        ChatMessage::typing("Alice".to_string(), alice_id, false),
        ChatMessage::leave("Bob".to_string(), bob_id),
    ];

    // Demonstrate serialization and deserialization
    println!("Testing message serialization:\n");

    for (i, msg) in messages.iter().enumerate() {
        println!("Message {}: {:?}", i + 1, msg);

        // Serialize
        match msg.serialize() {
            Ok(data) => {
                println!("  Serialized size: {} bytes", data.len());

                // Deserialize
                match ChatMessage::deserialize(&data) {
                    Ok(deserialized) => {
                        println!("  Deserialized successfully");

                        // Verify fields match
                        match (&msg, &deserialized) {
                            (
                                ChatMessage::Text {
                                    nickname: n1,
                                    text: t1,
                                    ..
                                },
                                ChatMessage::Text {
                                    nickname: n2,
                                    text: t2,
                                    ..
                                },
                            ) => {
                                assert_eq!(n1, n2);
                                assert_eq!(t1, t2);
                                println!("  Verified: text message intact");
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("  Failed to deserialize: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("  Failed to serialize: {}", e);
            }
        }
        println!();
    }

    // Demonstrate peer list
    println!("\n=== Peer List Example ===\n");

    let peer_list = vec![
        PeerInfo {
            peer_id: alice_id.0,
            nickname: "Alice".to_string(),
            status: "Online".to_string(),
            joined_at: SystemTime::now(),
        },
        PeerInfo {
            peer_id: bob_id.0,
            nickname: "Bob".to_string(),
            status: "Away".to_string(),
            joined_at: SystemTime::now(),
        },
    ];

    let peer_list_msg = ChatMessage::PeerListResponse { peers: peer_list };

    match peer_list_msg.serialize() {
        Ok(data) => {
            println!("Peer list serialized: {} bytes", data.len());

            match ChatMessage::deserialize(&data) {
                Ok(ChatMessage::PeerListResponse { peers }) => {
                    println!("Peer list deserialized with {} peers:", peers.len());
                    for peer in peers {
                        println!(
                            "  - {} ({}): {}",
                            peer.nickname,
                            hex::encode(&peer.peer_id[..8]),
                            peer.status
                        );
                    }
                }
                _ => eprintln!("Unexpected message type"),
            }
        }
        Err(e) => eprintln!("Failed to serialize peer list: {}", e),
    }

    println!("\n=== Message Metadata ===\n");

    // Test metadata extraction
    for msg in &messages[0..3] {
        if let Some(peer_id) = msg.peer_id() {
            println!("Peer ID: {}", hex::encode(&peer_id.0[..8]));
        }
        if let Some(nickname) = msg.nickname() {
            println!("Nickname: {}", nickname);
        }
        println!();
    }
}
