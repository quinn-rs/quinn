//! Chat demo example showing P2P messaging over QUIC
//!
//! This example demonstrates the chat protocol implementation
//! with NAT traversal support.

use ant_quic::{
    auth::AuthConfig,
    chat::{ChatMessage, PeerInfo},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::{EndpointRole, PeerId},
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::{error, info};

#[derive(Clone)]
struct ChatNode {
    node: Arc<QuicP2PNode>,
    peer_id: PeerId,
    nickname: String,
    peers: Arc<Mutex<HashMap<PeerId, PeerInfo>>>,
}

impl ChatNode {
    async fn new(
        role: EndpointRole,
        bootstrap_nodes: Vec<SocketAddr>,
        nickname: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Generate identity
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // Create QUIC node
        let config = QuicNodeConfig {
            role,
            bootstrap_nodes,
            enable_coordinator: matches!(role, EndpointRole::Server { .. }),
            max_connections: 50,
            connection_timeout: Duration::from_secs(30),
            stats_interval: Duration::from_secs(60),
            auth_config: AuthConfig::default(),
        };

        let node = Arc::new(QuicP2PNode::new(config).await?);

        Ok(Self {
            node,
            peer_id,
            nickname,
            peers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        coordinator: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Connecting to peer {:?} via coordinator {}",
            peer_id, coordinator
        );

        let addr = self.node.connect_to_peer(peer_id, coordinator).await?;
        info!("Connected to peer at {}", addr);

        // Send join message
        let join_msg = ChatMessage::join(self.nickname.clone(), self.peer_id);
        let data = join_msg.serialize()?;
        self.node
            .send_to_peer(&peer_id, &data)
            .await
            .map_err(|e| format!("Failed to send join message: {}", e))?;

        Ok(())
    }

    async fn send_message(
        &self,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = ChatMessage::text(self.nickname.clone(), self.peer_id, text);
        let data = msg.serialize()?;

        // Send to all connected peers
        let peers = self.peers.lock().await;
        for (peer_id, _) in peers.iter() {
            if let Err(e) = self.node.send_to_peer(peer_id, &data).await {
                error!("Failed to send to peer {:?}: {}", peer_id, e);
            }
        }

        Ok(())
    }

    async fn handle_incoming_messages(&self) {
        loop {
            match self.node.receive().await {
                Ok((peer_id, data)) => match ChatMessage::deserialize(&data) {
                    Ok(msg) => {
                        self.handle_chat_message(peer_id, msg).await;
                    }
                    Err(e) => {
                        error!("Failed to deserialize message: {}", e);
                    }
                },
                Err(_) => {
                    // No messages available
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_chat_message(&self, peer_id: PeerId, msg: ChatMessage) {
        match msg {
            ChatMessage::Join {
                nickname,
                peer_id: sender_id,
                timestamp,
            } => {
                info!("[{}] joined the chat", nickname);
                let mut peers = self.peers.lock().await;
                peers.insert(
                    peer_id,
                    PeerInfo {
                        peer_id: sender_id,
                        nickname,
                        status: "Online".to_string(),
                        joined_at: timestamp,
                    },
                );
            }
            ChatMessage::Leave { nickname, .. } => {
                info!("[{}] left the chat", nickname);
                self.peers.lock().await.remove(&peer_id);
            }
            ChatMessage::Text { nickname, text, .. } => {
                println!("[{}]: {}", nickname, text);
            }
            ChatMessage::Status {
                nickname, status, ..
            } => {
                info!("[{}] status: {}", nickname, status);
                if let Some(peer_info) = self.peers.lock().await.get_mut(&peer_id) {
                    peer_info.status = status;
                }
            }
            ChatMessage::Direct {
                from_nickname,
                text,
                ..
            } => {
                println!("[DM from {}]: {}", from_nickname, text);
            }
            ChatMessage::Typing {
                nickname,
                is_typing,
                ..
            } => {
                if is_typing {
                    info!("[{}] is typing...", nickname);
                }
            }
            ChatMessage::PeerListRequest { .. } => {
                // Send peer list response
                let peers = self.peers.lock().await;
                let peer_list: Vec<PeerInfo> = peers.values().cloned().collect();
                let response = ChatMessage::PeerListResponse { peers: peer_list };
                if let Ok(data) = response.serialize() {
                    let _ = self.node.send_to_peer(&peer_id, &data).await;
                }
            }
            ChatMessage::PeerListResponse { peers } => {
                info!("Received peer list with {} peers", peers.len());
                for peer in peers {
                    info!("  - {}: {}", peer.nickname, peer.status);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info,chat_demo=info")
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <coordinator|client> [bootstrap_addr]", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    let bootstrap_addr = if args.len() > 2 {
        args[2].parse::<SocketAddr>().unwrap_or_else(|_| {
            eprintln!("Invalid bootstrap address: {}", args[2]);
            std::process::exit(1);
        })
    } else {
        "127.0.0.1:9000".parse().unwrap()
    };

    // Create chat node
    let (role, nickname) = match mode.as_str() {
        "coordinator" => (
            EndpointRole::Server {
                can_coordinate: true,
            },
            "Coordinator".to_string(),
        ),
        "client" => (
            EndpointRole::Client,
            format!("Client-{}", rand::random::<u16>()),
        ),
        _ => {
            eprintln!("Invalid mode: {}. Use 'coordinator' or 'client'", mode);
            std::process::exit(1);
        }
    };

    let chat_node = ChatNode::new(role, vec![bootstrap_addr], nickname.clone()).await?;
    info!("Started {} with peer ID: {:?}", nickname, chat_node.peer_id);

    // Start message handler
    let handler_node = chat_node.clone();
    tokio::spawn(async move {
        handler_node.handle_incoming_messages().await;
    });

    // Start stats reporting
    let _stats_handle = chat_node.node.start_stats_task();

    // Simple CLI interface
    println!("Chat node started. Commands:");
    println!("  /connect <peer_id> - Connect to a peer");
    println!("  /peers - List connected peers");
    println!("  /quit - Exit");
    println!("  <text> - Send message to all peers");

    let stdin = std::io::stdin();
    let mut line = String::new();

    loop {
        line.clear();
        if stdin.read_line(&mut line).is_err() {
            break;
        }

        let line = line.trim();

        if line.starts_with("/connect ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Parse peer ID (simplified - in real app would parse hex)
                let peer_id = PeerId([0u8; 32]); // Placeholder
                if let Err(e) = chat_node.connect_to_peer(peer_id, bootstrap_addr).await {
                    error!("Failed to connect: {}", e);
                }
            }
        } else if line == "/peers" {
            let peers = chat_node.peers.lock().await;
            println!("Connected peers: {}", peers.len());
            for (_, peer_info) in peers.iter() {
                println!(
                    "  - {} ({}): {}",
                    peer_info.nickname,
                    hex::encode(&peer_info.peer_id[..8]),
                    peer_info.status
                );
            }
        } else if line == "/quit" {
            break;
        } else if !line.is_empty() {
            if let Err(e) = chat_node.send_message(line.to_string()).await {
                error!("Failed to send message: {}", e);
            }
        }
    }

    info!("Chat node shutting down");
    Ok(())
}
