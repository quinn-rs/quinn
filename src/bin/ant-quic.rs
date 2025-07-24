//! QUIC-based P2P application with advanced NAT traversal
//!
//! This binary demonstrates the full capabilities of ant-quic including
//! peer discovery, NAT traversal, and secure P2P communication.

use ant_quic::{
    chat::ChatMessage,
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::{EndpointRole, NatTraversalEvent, PeerId},
    quic_node::{QuicNodeConfig, QuicP2PNode},
    stats_dashboard::{DashboardConfig, StatsDashboard},
};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, sync::Arc, time::Duration};
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

    /// Enable dashboard display
    #[arg(long)]
    dashboard: bool,

    /// Dashboard update interval in seconds
    #[arg(long, default_value = "2")]
    dashboard_interval: u64,

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
    /// Statistics dashboard
    dashboard: Option<Arc<StatsDashboard>>,
    /// Dashboard enabled flag
    dashboard_enabled: bool,
}

impl QuicDemoNode {
    /// Create a new QUIC demo node
    async fn new(args: Args) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Generate Ed25519 keypair and derive peer ID
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Generated peer ID: {:?}", peer_id);

        // Determine role based on arguments
        let role = if args.bootstrap.is_empty() && args.listen.port() != 0 {
            // If no bootstrap nodes and listening on a specific port, act as bootstrap
            EndpointRole::Bootstrap
        } else if args.coordinator || args.force_coordinator {
            EndpointRole::Server {
                can_coordinate: true,
            }
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
            auth_config: Default::default(),
            bind_addr: Some(args.listen),
        };

        // Create the QUIC P2P node
        let quic_node = Arc::new(QuicP2PNode::new(config).await.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Failed to create QUIC node: {}", e).into()
            },
        )?);

        // Generate nickname
        let nickname = match &args.command {
            Some(Commands::Chat { nickname: Some(n) }) => n.clone(),
            _ => generate_random_nickname(),
        };

        info!("Using nickname: {}", nickname);

        // Create dashboard if enabled
        let dashboard = if args.dashboard {
            let config = DashboardConfig {
                update_interval: Duration::from_secs(args.dashboard_interval),
                history_size: 120, // 2 minutes at 1 update per second
                detailed_tracking: true,
                show_graphs: true,
            };
            Some(Arc::new(StatsDashboard::new(config)))
        } else {
            None
        };

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
            dashboard,
            dashboard_enabled: args.dashboard,
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

        // Connect to bootstrap nodes if we're not a bootstrap node ourselves
        if !self.quic_node.get_config().bootstrap_nodes.is_empty()
            && !matches!(self.quic_node.get_config().role, EndpointRole::Bootstrap)
        {
            info!(
                "Connecting to {} bootstrap nodes",
                self.quic_node.get_config().bootstrap_nodes.len()
            );

            for bootstrap_addr in &self.quic_node.get_config().bootstrap_nodes {
                info!("Connecting to bootstrap node at {}", bootstrap_addr);
                match self.quic_node.connect_to_bootstrap(*bootstrap_addr).await {
                    Ok(peer_id) => {
                        info!(
                            "Successfully connected to bootstrap node {} (peer ID: {})",
                            bootstrap_addr,
                            hex::encode(&peer_id.0[..8])
                        );
                        self.connected_peers
                            .lock()
                            .await
                            .insert(peer_id, format!("bootstrap-{}", bootstrap_addr));
                    }
                    Err(e) => {
                        warn!(
                            "Failed to connect to bootstrap node {}: {}",
                            bootstrap_addr, e
                        );
                    }
                }
            }
        }

        // Wait a bit for address discovery to complete
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Print discovered external address
        if !self.quic_node.get_config().bootstrap_nodes.is_empty() {
            let nat_status = self.nat_status.lock().await;
            if !nat_status.reflexive_addresses.is_empty() {
                // Print the first discovered external address
                info!("🌐 Discovered external address: {}", nat_status.reflexive_addresses[0]);
                if !self.dashboard_enabled {
                    println!("🌐 Discovered external address: {}", nat_status.reflexive_addresses[0]);
                }
            } else {
                warn!("⚠️  CANNOT_FIND_EXTERNAL_ADDRESS - No external address discovered yet");
                if !self.dashboard_enabled {
                    println!("⚠️  CANNOT_FIND_EXTERNAL_ADDRESS - No external address discovered yet");
                }
            }
            drop(nat_status);
        }

        // Start dashboard update task if enabled
        if self.dashboard_enabled {
            if let Some(dashboard) = &self.dashboard {
                let dashboard_clone = Arc::clone(dashboard);
                let quic_node_clone = Arc::clone(&self.quic_node);
                let peers_clone = Arc::clone(&self.connected_peers);
                let interval = dashboard_clone.config().update_interval;

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(interval);

                    loop {
                        interval.tick().await;

                        // Get node stats
                        let node_stats = quic_node_clone.get_stats().await;
                        dashboard_clone.update_node_stats(node_stats).await;

                        // Get NAT stats
                        if let Ok(nat_stats) = quic_node_clone.get_nat_stats().await {
                            dashboard_clone.update_nat_stats(nat_stats).await;
                        }

                        // Update connection metrics for each peer
                        let peers = peers_clone.lock().await;
                        for (peer_id, _) in peers.iter() {
                            if let Ok(metrics) =
                                quic_node_clone.get_connection_metrics(peer_id).await
                            {
                                dashboard_clone
                                    .update_connection_metrics(
                                        *peer_id,
                                        metrics.bytes_sent,
                                        metrics.bytes_received,
                                        metrics.rtt,
                                    )
                                    .await;
                            }
                        }

                        // Render dashboard
                        let output = dashboard_clone.render().await;
                        print!("{}", output);
                    }
                });
            }
        }

        // Handle user input in a separate task
        let node = Arc::clone(&self.quic_node);
        let mut nickname = self.nickname.clone();
        let my_peer_id = self.peer_id;
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
                                            peers
                                                .lock()
                                                .await
                                                .insert(peer_id, format!("peer-{}", addr));
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
                        println!(
                            "Active coordination sessions: {}",
                            status.coordination_sessions.len()
                        );
                        for (peer_id, status) in &status.coordination_sessions {
                            println!("  - Peer {}: {}", hex::encode(&peer_id.0[..8]), status);
                        }
                        println!("Last update: {:?} ago\n", status.last_update.elapsed());
                    } else if line == "/peers" {
                        // Show connected peers
                        let peers_snapshot = peers.lock().await;
                        println!("\n=== Connected Peers ===");
                        if peers_snapshot.is_empty() {
                            println!("No peers connected");
                        } else {
                            for (peer_id, nickname) in peers_snapshot.iter() {
                                println!("  - {} ({})", nickname, hex::encode(&peer_id.0[..8]));
                            }
                        }
                        println!();
                    } else if line.starts_with("/dm ") {
                        // Send direct message
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let target_hex = parts[1];
                            let text = parts[2..].join(" ");

                            // Find peer by partial hex ID
                            let peers_snapshot = peers.lock().await;
                            let mut found_peer = None;
                            for (peer_id, nickname) in peers_snapshot.iter() {
                                let peer_hex = hex::encode(&peer_id.0[..8]);
                                if peer_hex.starts_with(target_hex) {
                                    found_peer = Some((*peer_id, nickname.clone()));
                                    break;
                                }
                            }

                            if let Some((target_peer_id, target_nickname)) = found_peer {
                                let message = ChatMessage::direct(
                                    nickname.clone(),
                                    my_peer_id,
                                    target_peer_id,
                                    text.clone(),
                                );
                                println!("[DM to {}]: {}", target_nickname, text);

                                match message.serialize() {
                                    Ok(data) => {
                                        if let Err(e) =
                                            node.send_to_peer(&target_peer_id, &data).await
                                        {
                                            warn!("Failed to send DM: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to serialize DM: {}", e);
                                    }
                                }
                            } else {
                                println!("No peer found matching '{}'", target_hex);
                            }
                        } else {
                            println!("Usage: /dm <peer_id_prefix> <message>");
                        }
                    } else if line.starts_with("/nick ") {
                        // Change nickname
                        let new_nick = line[6..].trim().to_string();
                        if !new_nick.is_empty() {
                            let old_nick = nickname.clone();
                            nickname = new_nick.clone();
                            println!("Nickname changed from '{}' to '{}'", old_nick, new_nick);

                            // Notify all peers
                            let status_msg = ChatMessage::status(
                                new_nick.clone(),
                                my_peer_id,
                                format!("changed nickname from {}", old_nick),
                            );
                            let peers_snapshot = peers.lock().await.clone();
                            for (peer_id, _) in peers_snapshot {
                                if let Ok(data) = status_msg.serialize() {
                                    let _ = node.send_to_peer(&peer_id, &data).await;
                                }
                            }
                        }
                    } else if line == "/dashboard" {
                        // Toggle dashboard - this would be handled differently in a real implementation
                        println!("Dashboard toggling not yet implemented in input handler");
                        println!("Use --dashboard flag when starting the application");
                    } else if line == "/help" {
                        // Show help
                        println!("\n=== Commands ===");
                        println!(
                            "/connect <peer_id> <coordinator> - Connect to a peer via coordinator"
                        );
                        println!("/status - Show NAT traversal status");
                        println!("/peers - List connected peers");
                        println!("/dm <peer_id_prefix> <message> - Send direct message");
                        println!("/nick <nickname> - Change your nickname");
                        println!("/dashboard - Toggle dashboard display");
                        println!("/help - Show this help message");
                        println!("<text> - Send chat message to all connected peers\n");
                    } else if !line.is_empty() {
                        // Send chat message to all connected peers
                        let message =
                            ChatMessage::text(nickname.clone(), my_peer_id, line.to_string());

                        // Add to history
                        history.lock().await.push(message.clone());

                        // Send to all peers
                        let peers_snapshot = peers.lock().await.clone();
                        for (peer_id, _) in peers_snapshot {
                            match message.serialize() {
                                Ok(data) => {
                                    if let Err(e) = node.send_to_peer(&peer_id, &data).await {
                                        warn!("Failed to send to peer {:?}: {}", peer_id, e);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to serialize message: {}", e);
                                }
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

                            // Update dashboard if enabled
                            if let Some(dashboard) = &self.dashboard {
                                dashboard.handle_nat_event(&NatTraversalEvent::ConnectionEstablished {
                                    peer_id,
                                    remote_address: addr,
                                }).await;
                            }
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
                            match ChatMessage::deserialize(&data) {
                                Ok(message) => {
                                    self.handle_chat_message(peer_id, message).await;
                                }
                                Err(e) => {
                                    debug!("Failed to deserialize message: {}", e);
                                }
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
        match &message {
            ChatMessage::Join { nickname, .. } => {
                info!("[{}] joined the chat", nickname);
                self.connected_peers
                    .lock()
                    .await
                    .insert(peer_id, nickname.clone());
            }
            ChatMessage::Leave { nickname, .. } => {
                info!("[{}] left the chat", nickname);
                self.connected_peers.lock().await.remove(&peer_id);
            }
            ChatMessage::Text { nickname, text, .. } => {
                println!("[{}]: {}", nickname, text);
            }
            ChatMessage::Status {
                nickname, status, ..
            } => {
                info!("[{}] status: {}", nickname, status);
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
                if *is_typing {
                    info!("[{}] is typing...", nickname);
                } else {
                    info!("[{}] stopped typing", nickname);
                }
            }
            ChatMessage::PeerListRequest { .. } => {
                // Handle peer list request
                debug!("Received peer list request from {:?}", peer_id);
            }
            ChatMessage::PeerListResponse { peers } => {
                info!("Connected peers: {}", peers.len());
                for peer_info in peers {
                    info!("  - {}: {}", peer_info.nickname, peer_info.status);
                }
            }
        }
    }

    /// Start monitoring NAT traversal events
    fn start_nat_event_monitor(
        &self,
        nat_status: Arc<Mutex<NatTraversalStatus>>,
    ) -> tokio::task::JoinHandle<()> {
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
                                NatTraversalEvent::CandidateDiscovered {
                                    peer_id: evt_peer,
                                    candidate,
                                } => {
                                    info!(
                                        "[NAT] Discovered candidate {} for peer {:?}",
                                        candidate.address, evt_peer
                                    );
                                    let mut status = nat_status.lock().await;
                                    // Track candidates we discover for peers
                                    if !status.local_candidates.contains(&candidate.address) {
                                        status.local_candidates.push(candidate.address);
                                    }
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::CandidateValidated {
                                    peer_id: evt_peer,
                                    candidate_address,
                                    ..
                                } => {
                                    info!(
                                        "[NAT] Validated candidate {} for peer {:?}",
                                        candidate_address, evt_peer
                                    );
                                    let mut status = nat_status.lock().await;
                                    let was_empty = status.reflexive_addresses.is_empty();
                                    if !status.reflexive_addresses.contains(&candidate_address) {
                                        status.reflexive_addresses.push(candidate_address);
                                        // Print the first discovered external address
                                        if was_empty {
                                            info!("🌐 Discovered external address: {}", candidate_address);
                                            println!("🌐 Discovered external address: {}", candidate_address);
                                        }
                                    }
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::CoordinationRequested {
                                    peer_id: evt_peer,
                                    ..
                                } => {
                                    if evt_peer != peer_id {
                                        info!(
                                            "[NAT] Coordination requested by peer {:?}",
                                            evt_peer
                                        );
                                        let mut status = nat_status.lock().await;
                                        status
                                            .coordination_sessions
                                            .push((evt_peer, "Coordinating".to_string()));
                                        status.last_update = std::time::Instant::now();
                                    }
                                }
                                NatTraversalEvent::HolePunchingStarted {
                                    peer_id: evt_peer,
                                    ..
                                } => {
                                    info!("[NAT] Hole punching started with peer {:?}", evt_peer);
                                    let mut status = nat_status.lock().await;
                                    if let Some(session) = status
                                        .coordination_sessions
                                        .iter_mut()
                                        .find(|(p, _)| *p == evt_peer)
                                    {
                                        session.1 = "Hole punching".to_string();
                                    }
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::ConnectionEstablished {
                                    peer_id: evt_peer,
                                    remote_address,
                                } => {
                                    info!(
                                        "[NAT] Connection established with peer {:?} at {}",
                                        evt_peer, remote_address
                                    );
                                    let mut status = nat_status.lock().await;
                                    status.coordination_sessions.retain(|(p, _)| *p != evt_peer);
                                    status.last_update = std::time::Instant::now();
                                }
                                NatTraversalEvent::TraversalFailed {
                                    peer_id: evt_peer,
                                    error,
                                    ..
                                } => {
                                    warn!(
                                        "[NAT] Traversal failed for peer {:?}: {}",
                                        evt_peer, error
                                    );
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
        "swift", "brave", "clever", "mighty", "gentle", "bold", "wise", "keen", "noble", "bright",
    ];

    let nouns = [
        "falcon", "wolf", "eagle", "bear", "fox", "hawk", "lion", "tiger", "panther", "dragon",
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
        Some(Commands::Connect {
            peer_id,
            coordinator,
        }) => {
            // Create node and connect to specific peer
            let peer_id_parsed = parse_peer_id(peer_id)?;
            let coordinator_addr = *coordinator;
            let node = QuicDemoNode::new(args).await?;

            match node
                .quic_node
                .connect_to_peer(peer_id_parsed, coordinator_addr)
                .await
            {
                Ok(addr) => {
                    info!(
                        "Successfully connected to peer {:?} at {}",
                        peer_id_parsed, addr
                    );

                    // Send join message
                    let join_msg = ChatMessage::join(node.nickname.clone(), node.peer_id);
                    match join_msg.serialize() {
                        Ok(data) => {
                            if let Err(e) =
                                node.quic_node.send_to_peer(&peer_id_parsed, &data).await
                            {
                                return Err(format!("Failed to send join message: {}", e).into());
                            }
                        }
                        Err(e) => {
                            return Err(format!("Failed to serialize join message: {}", e).into());
                        }
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
