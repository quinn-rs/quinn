//! QUIC-based P2P demo application
//!
//! This is a migration of the UDP-based ant-quic binary to use real QUIC connections
//! with NAT traversal support.

use ant_quic::{
    nat_traversal_api::{EndpointRole, PeerId, NatTraversalEvent},
    quic_node::{QuicP2PNode, QuicNodeConfig},
    crypto::raw_public_keys::key_utils::{generate_ed25519_keypair, derive_peer_id_from_public_key},
};
use clap::{Parser, Subcommand};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "0.0.0.0:0")]
    listen: SocketAddr,

    /// Bootstrap nodes (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    bootstrap: Vec<SocketAddr>,

    /// Enable coordinator services
    #[arg(short = 'c', long)]
    coordinator: bool,

    /// Force coordinator mode (skip reachability detection)
    #[arg(short = 'f', long)]
    force_coordinator: bool,

    /// Use minimal output for automated testing
    #[arg(short = 'm', long)]
    minimal: bool,

    /// Enable debug logging
    #[arg(short = 'd', long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Connect to a specific peer
    Connect {
        /// Peer ID to connect to
        peer_id: String,
        /// Coordinator address to use
        #[arg(short, long)]
        coordinator: SocketAddr,
    },
    /// Run as a pure coordinator
    Coordinator,
    /// Run as a chat client
    Chat {
        /// Nickname to use
        #[arg(short, long)]
        nickname: Option<String>,
    },
}

/// Chat message types for QUIC streams
#[derive(Debug, Clone)]
enum ChatMessage {
    /// Join notification
    Join { nickname: String },
    /// Leave notification  
    Leave { nickname: String },
    /// Text message
    Text { nickname: String, text: String },
    /// Status update
    Status { nickname: String, status: String },
}

/// NAT traversal status information
#[derive(Debug, Clone)]
struct NatTraversalStatus {
    /// Current candidates discovered
    local_candidates: Vec<SocketAddr>,
    /// Server-reflexive addresses observed
    reflexive_addresses: Vec<SocketAddr>,
    /// Active coordination sessions
    coordination_sessions: Vec<(PeerId, String)>, // peer_id, status
    /// Last update time
    last_update: std::time::Instant,
}

/// Main P2P node implementation using QUIC
struct QuicDemoNode {
    /// The underlying QUIC P2P node
    quic_node: Arc<QuicP2PNode>,
    /// Our peer ID
    peer_id: PeerId,
    /// Our nickname for chat
    nickname: String,
    /// Connected peers and their nicknames
    connected_peers: Arc<Mutex<std::collections::HashMap<PeerId, String>>>,
    /// Message history
    message_history: Arc<Mutex<Vec<ChatMessage>>>,
    /// Whether we're running as coordinator
    is_coordinator: bool,
    /// NAT traversal status
    nat_status: Arc<Mutex<NatTraversalStatus>>,
}

impl QuicDemoNode {
    /// Create a new QUIC demo node
    async fn new(args: Args) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Generate Ed25519 keypair and derive peer ID
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);
        
        info!("Generated peer ID: {:?}", peer_id);

        // Determine role based on arguments
        let role = if args.coordinator || args.force_coordinator {
            EndpointRole::Server { can_coordinate: true }
        } else {
            EndpointRole::Client
        };

        // Create QUIC node configuration
        let config = QuicNodeConfig {
            role,
            bootstrap_nodes: args.bootstrap.clone(),
            enable_coordinator: args.coordinator,
            max_connections: 100,
            connection_timeout: Duration::from_secs(30),
            stats_interval: Duration::from_secs(30),
        };

        // Create the QUIC P2P node
        let quic_node = Arc::new(
            QuicP2PNode::new(config)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("Failed to create QUIC node: {}", e).into()
                })?
        );

        // Generate nickname
        let nickname = match &args.command {
            Some(Commands::Chat { nickname: Some(n) }) => n.clone(),
            _ => generate_random_nickname(),
        };

        info!("Using nickname: {}", nickname);

        Ok(Self {
            quic_node,
            peer_id,
            nickname,
            connected_peers: Arc::new(Mutex::new(std::collections::HashMap::new())),
            message_history: Arc::new(Mutex::new(Vec::new())),
            is_coordinator: args.coordinator || args.force_coordinator,
            nat_status: Arc::new(Mutex::new(NatTraversalStatus {
                local_candidates: Vec::new(),
                reflexive_addresses: Vec::new(),
                coordination_sessions: Vec::new(),
                last_update: std::time::Instant::now(),
            })),
        })
    }

    /// Run the main event loop
    async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting QUIC P2P node...");
        info!("Our peer ID: {}", hex::encode(self.peer_id.0));
        if self.is_coordinator {
            info!("Running as NAT traversal coordinator");
        }

        // Start statistics reporting
        let _stats_handle = self.quic_node.start_stats_task();
        
        // Start NAT traversal event monitoring
        let nat_status = Arc::clone(&self.nat_status);
        let _nat_handle = self.start_nat_event_monitor(nat_status);

        // Handle user input in a separate task
        let node = Arc::clone(&self.quic_node);
        let nickname = self.nickname.clone();
        let peers = Arc::clone(&self.connected_peers);
        let history = Arc::clone(&self.message_history);
        let nat_status_for_input = Arc::clone(&self.nat_status);
        
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut reader = tokio::io::BufReader::new(stdin);
            
            loop {
                use tokio::io::AsyncBufReadExt;
                let mut line = String::new();
                
                if reader.read_line(&mut line).await.is_ok() {
                    let line = line.trim();
                    
                    if line.starts_with("/connect ") {
                        // Handle connection command
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            if let Ok(peer_id) = parse_peer_id(parts[1]) {
                                if let Ok(coordinator) = parts[2].parse::<SocketAddr>() {
                                    match node.connect_to_peer(peer_id, coordinator).await {
                                        Ok(addr) => {
                                            info!("Connected to peer {:?} at {}", peer_id, addr);
                                            peers.lock().await.insert(peer_id, format!("peer-{}", addr));
                                        }
                                        Err(e) => {
                                            error!("Failed to connect: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    } else if line == "/status" {
                        // Show NAT traversal status
                        let status = nat_status_for_input.lock().await;
                        println!("\n=== NAT Traversal Status ===");
                        println!("Local candidates: {:?}", status.local_candidates);
                        println!("Reflexive addresses: {:?}", status.reflexive_addresses);
                        println!("Active coordination sessions: {}", status.coordination_sessions.len());
                        for (peer_id, status) in &status.coordination_sessions {
                            println!("  - Peer {}: {}", hex::encode(&peer_id.0[..8]), status);
                        }
                        println!("Last update: {:?} ago\n", status.last_update.elapsed());
                    } else if line == "/help" {
                        // Show help
                        println!("\n=== Commands ===");
                        println!("/connect <peer_id> <coordinator> - Connect to a peer via coordinator");
                        println!("/status - Show NAT traversal status");
                        println!("/help - Show this help message");
                        println!("<text> - Send chat message to all connected peers\n");
                    } else if !line.is_empty() {
                        // Send chat message to all connected peers
                        let message = ChatMessage::Text {
                            nickname: nickname.clone(),
                            text: line.to_string(),
                        };
                        
                        // Add to history
                        history.lock().await.push(message.clone());
                        
                        // Send to all peers
                        let peers_snapshot = peers.lock().await.clone();
                        for (peer_id, _) in peers_snapshot {
                            let data = serialize_chat_message(&message);
                            if let Err(e) = node.send_to_peer(&peer_id, &data).await {
                                warn!("Failed to send to peer {:?}: {}", peer_id, e);
                            }
                        }
                    }
                }
            }
        });

        // Main event loop
        loop {
            tokio::select! {
                // Accept incoming connections if we're a coordinator
                accept_result = self.quic_node.accept(), if self.is_coordinator => {
                    match accept_result {
                        Ok((addr, peer_id)) => {
                            info!("Accepted connection from peer {:?} at {}", peer_id, addr);
                            self.connected_peers.lock().await.insert(peer_id, format!("peer-{}", addr));
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                
                // Receive messages from connected peers
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    match self.quic_node.receive().await {
                        Ok((peer_id, data)) => {
                            if let Ok(message) = deserialize_chat_message(&data) {
                                self.handle_chat_message(peer_id, message).await;
                            }
                        }
                        Err(e) => {
                            debug!("No data available: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Handle incoming chat message
    async fn handle_chat_message(&self, peer_id: PeerId, message: ChatMessage) {
        // Add to history
        self.message_history.lock().await.push(message.clone());

        // Display the message
        match message {
            ChatMessage::Join { nickname } => {
                info!("[{}] joined the chat", nickname);
                self.connected_peers.lock().await.insert(peer_id, nickname);
            }
            ChatMessage::Leave { nickname } => {
                info!("[{}] left the chat", nickname);
                self.connected_peers.lock().await.remove(&peer_id);
            }
            ChatMessage::Text { nickname, text } => {
                println!("[{}]: {}", nickname, text);
            }
            ChatMessage::Status { nickname, status } => {
                info!("[{}] status: {}", nickname, status);
            }
        }
    }
    
    /// Start monitoring NAT traversal events
    fn start_nat_event_monitor(&self, nat_status: Arc<Mutex<NatTraversalStatus>>) -> tokio::task::JoinHandle<()> {
        let quic_node = Arc::clone(&self.quic_node);
        let peer_id = self.peer_id;
        
        tokio::spawn(async move {
            let mut last_poll = std::time::Instant::now();
            
            loop {
                // Poll for NAT traversal events
                if let Ok(endpoint) = quic_node.get_nat_endpoint() {
                    if let Ok(events) = endpoint.poll(std::time::Instant::now()) {
                        for event in events {
                            match event {
                                NatTraversalEvent::CandidateDiscovered { peer_id: evt_peer, candidate } => {
                                    info!("[NAT] Discovered candidate {} for peer {:?}", candidate.address, evt_peer);
                                    let mut status = nat_status.lock().await;
                                    // Track candidates we discover for peers
                                    if !status.local_candidates.contains(&candidate.address) {
                                        status.local_candidates.push(candidate.address);
                                    }
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::CandidateValidated { peer_id: evt_peer, candidate_address, .. } => {
                                    info!("[NAT] Validated candidate {} for peer {:?}", candidate_address, evt_peer);
                                    let mut status = nat_status.lock().await;
                                    if !status.reflexive_addresses.contains(&candidate_address) {
                                        status.reflexive_addresses.push(candidate_address);
                                    }
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::CoordinationRequested { peer_id: evt_peer, .. } => {
                                    if evt_peer != peer_id {
                                        info!("[NAT] Coordination requested by peer {:?}", evt_peer);
                                        let mut status = nat_status.lock().await;
                                        status.coordination_sessions.push((evt_peer, "Coordinating".to_string()));
                                        status.last_update = std::time::Instant::now();
                                    }
                                }
                                NatTraversalEvent::HolePunchingStarted { peer_id: evt_peer, .. } => {
                                    info!("[NAT] Hole punching started with peer {:?}", evt_peer);
                                    let mut status = nat_status.lock().await;
                                    if let Some(session) = status.coordination_sessions.iter_mut().find(|(p, _)| *p == evt_peer) {
                                        session.1 = "Hole punching".to_string();
                                    }
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::ConnectionEstablished { peer_id: evt_peer, remote_address } => {
                                    info!("[NAT] Connection established with peer {:?} at {}", evt_peer, remote_address);
                                    let mut status = nat_status.lock().await;
                                    status.coordination_sessions.retain(|(p, _)| *p != evt_peer);
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::TraversalFailed { peer_id: evt_peer, error, .. } => {
                                    warn!("[NAT] Traversal failed for peer {:?}: {}", evt_peer, error);
                                    let mut status = nat_status.lock().await;
                                    status.coordination_sessions.retain(|(p, _)| *p != evt_peer);
                                    status.last_update = std::time::Instant::now();
                                }
                                _ => {
                                    debug!("[NAT] Event: {:?}", event);
                                }
                            }
                        }
                    }
                    
                    // Get and display statistics periodically
                    if last_poll.elapsed() > Duration::from_secs(10) {
                        if let Ok(stats) = endpoint.get_statistics() {
                            debug!(
                                "[NAT Stats] Sessions: {}, Bootstrap nodes: {}, Successful coordinations: {}, Avg time: {:?}",
                                stats.active_sessions,
                                stats.total_bootstrap_nodes,
                                stats.successful_coordinations,
                                stats.average_coordination_time
                            );
                        }
                        last_poll = std::time::Instant::now();
                    }
                }
                
                // Brief sleep to avoid busy polling
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    }
}

/// Generate a random nickname
fn generate_random_nickname() -> String {
    use rand::Rng;
    
    let adjectives = [
        "swift", "brave", "clever", "mighty", "gentle",
        "bold", "wise", "keen", "noble", "bright",
    ];
    
    let nouns = [
        "falcon", "wolf", "eagle", "bear", "fox",
        "hawk", "lion", "tiger", "panther", "dragon",
    ];
    
    let mut rng = rand::thread_rng();
    let adj = adjectives[rng.gen_range(0..adjectives.len())];
    let noun = nouns[rng.gen_range(0..nouns.len())];
    let num = rng.gen_range(10..99);
    
    format!("{}-{}-{}", adj, noun, num)
}

/// Parse a peer ID from string
fn parse_peer_id(s: &str) -> Result<PeerId, Box<dyn std::error::Error + Send + Sync>> {
    // For demo purposes, accept hex-encoded 32-byte peer IDs
    if s.len() != 64 {
        return Err("Peer ID must be 64 hex characters".into());
    }
    
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err("Peer ID must be 32 bytes".into());
    }
    
    let mut peer_id_bytes = [0u8; 32];
    peer_id_bytes.copy_from_slice(&bytes);
    
    Ok(PeerId(peer_id_bytes))
}

/// Serialize a chat message
fn serialize_chat_message(msg: &ChatMessage) -> Vec<u8> {
    use std::io::Write;
    
    let mut data = Vec::new();
    
    match msg {
        ChatMessage::Join { nickname } => {
            data.write_all(&[0x01]).unwrap();
            data.write_all(nickname.as_bytes()).unwrap();
        }
        ChatMessage::Leave { nickname } => {
            data.write_all(&[0x02]).unwrap();
            data.write_all(nickname.as_bytes()).unwrap();
        }
        ChatMessage::Text { nickname, text } => {
            data.write_all(&[0x03]).unwrap();
            data.write_all(&(nickname.len() as u16).to_be_bytes()).unwrap();
            data.write_all(nickname.as_bytes()).unwrap();
            data.write_all(text.as_bytes()).unwrap();
        }
        ChatMessage::Status { nickname, status } => {
            data.write_all(&[0x04]).unwrap();
            data.write_all(&(nickname.len() as u16).to_be_bytes()).unwrap();
            data.write_all(nickname.as_bytes()).unwrap();
            data.write_all(status.as_bytes()).unwrap();
        }
    }
    
    data
}

/// Deserialize a chat message
fn deserialize_chat_message(data: &[u8]) -> Result<ChatMessage, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Read;
    
    if data.is_empty() {
        return Err("Empty message".into());
    }
    
    let msg_type = data[0];
    let mut cursor = std::io::Cursor::new(&data[1..]);
    
    match msg_type {
        0x01 => {
            let mut nickname = String::new();
            cursor.read_to_string(&mut nickname)?;
            Ok(ChatMessage::Join { nickname })
        }
        0x02 => {
            let mut nickname = String::new();
            cursor.read_to_string(&mut nickname)?;
            Ok(ChatMessage::Leave { nickname })
        }
        0x03 => {
            let mut len_bytes = [0u8; 2];
            cursor.read_exact(&mut len_bytes)?;
            let nickname_len = u16::from_be_bytes(len_bytes) as usize;
            
            let mut nickname_bytes = vec![0u8; nickname_len];
            cursor.read_exact(&mut nickname_bytes)?;
            let nickname = String::from_utf8(nickname_bytes)?;
            
            let mut text = String::new();
            cursor.read_to_string(&mut text)?;
            
            Ok(ChatMessage::Text { nickname, text })
        }
        0x04 => {
            let mut len_bytes = [0u8; 2];
            cursor.read_exact(&mut len_bytes)?;
            let nickname_len = u16::from_be_bytes(len_bytes) as usize;
            
            let mut nickname_bytes = vec![0u8; nickname_len];
            cursor.read_exact(&mut nickname_bytes)?;
            let nickname = String::from_utf8(nickname_bytes)?;
            
            let mut status = String::new();
            cursor.read_to_string(&mut status)?;
            
            Ok(ChatMessage::Status { nickname, status })
        }
        _ => Err(format!("Unknown message type: 0x{:02x}", msg_type).into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Set up logging
    let filter = if args.debug {
        EnvFilter::from_default_env()
            .add_directive("ant_quic=debug".parse()?)
            .add_directive("ant_quic_v2=debug".parse()?)
    } else if args.minimal {
        EnvFilter::from_default_env()
            .add_directive("ant_quic=warn".parse()?)
            .add_directive("ant_quic_v2=warn".parse()?)
    } else {
        EnvFilter::from_default_env()
            .add_directive("ant_quic=info".parse()?)
            .add_directive("ant_quic_v2=info".parse()?)
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    // Handle specific commands
    match &args.command {
        Some(Commands::Connect { peer_id, coordinator }) => {
            // Create node and connect to specific peer
            let peer_id_parsed = parse_peer_id(peer_id)?;
            let coordinator_addr = *coordinator;
            let node = QuicDemoNode::new(args).await?;
            
            match node.quic_node.connect_to_peer(peer_id_parsed, coordinator_addr).await {
                Ok(addr) => {
                    info!("Successfully connected to peer {:?} at {}", peer_id_parsed, addr);
                    
                    // Send join message
                    let join_msg = ChatMessage::Join {
                        nickname: node.nickname.clone(),
                    };
                    let data = serialize_chat_message(&join_msg);
                    if let Err(e) = node.quic_node.send_to_peer(&peer_id_parsed, &data).await {
                        return Err(format!("Failed to send join message: {}", e).into());
                    }
                    
                    // Run the node
                    node.run().await?;
                }
                Err(e) => {
                    error!("Failed to connect to peer: {}", e);
                    return Err(e.into());
                }
            }
        }
        Some(Commands::Coordinator) => {
            // Force coordinator mode
            let mut args = args;
            args.force_coordinator = true;
            let node = QuicDemoNode::new(args).await?;
            info!("Running as coordinator");
            node.run().await?;
        }
        Some(Commands::Chat { .. }) | None => {
            // Normal operation
            let node = QuicDemoNode::new(args).await?;
            node.run().await?;
        }
    }

    Ok(())
}