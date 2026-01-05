//! ant-quic Test Network Binary
//!
//! "We will be legion!!"
//!
//! This binary provides both registry server and test node functionality
//! for the large-scale ant-quic network testing infrastructure.

use ant_quic_test_network::{
    TestNode,
    node::TestNodeConfig,
    registry::{RegistryConfig, start_registry_server},
    tui::{App, TuiEvent, run_tui},
};
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Command-line arguments for the test network binary.
#[derive(Debug)]
struct Args {
    /// Run as registry server
    registry: bool,
    /// HTTP server port (for registry mode)
    port: u16,
    /// QUIC port for address discovery (registry mode, 0 to disable)
    quic_port: u16,
    /// QUIC bind port (for client mode)
    bind_port: u16,
    /// Registry URL to connect to (for client mode)
    registry_url: String,
    /// Maximum peer connections
    max_peers: usize,
    /// Disable TUI (log mode only)
    quiet: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            registry: false,
            port: 8080,
            quic_port: 9001, // Registry QUIC port for address discovery (9001 to avoid conflict with P2P node on 9000)
            bind_port: 0,    // 0 = random available port
            registry_url: "https://saorsa-1.saorsalabs.com".to_string(),
            max_peers: 10,
            quiet: false,
        }
    }
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--registry" => args.registry = true,
            "--port" => {
                if let Some(port) = argv.next() {
                    if let Ok(p) = port.parse() {
                        args.port = p;
                    }
                }
            }
            "--registry-url" => {
                if let Some(url) = argv.next() {
                    args.registry_url = url;
                }
            }
            "--max-peers" => {
                if let Some(max) = argv.next() {
                    if let Ok(m) = max.parse() {
                        args.max_peers = m;
                    }
                }
            }
            "--bind-port" => {
                if let Some(port) = argv.next() {
                    if let Ok(p) = port.parse() {
                        args.bind_port = p;
                    }
                }
            }
            "--quic-port" => {
                if let Some(port) = argv.next() {
                    if let Ok(p) = port.parse() {
                        args.quic_port = p;
                    }
                }
            }
            "-q" | "--quiet" => args.quiet = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_help();
                std::process::exit(1);
            }
        }
    }

    args
}

fn print_help() {
    println!(
        r#"
ant-quic Test Network - "We will be legion!!"

Large-scale network testing for quantum-secure P2P connectivity.

USAGE:
    ant-quic-test [OPTIONS]

OPTIONS:
    --registry              Run as central registry server
    --port <PORT>           HTTP server port (registry mode) [default: 8080]
    --quic-port <PORT>      QUIC port for address discovery (registry mode, 0 to disable) [default: 9001]
    --bind-port <PORT>      QUIC UDP bind port (client mode) [default: 0 = random]
    --registry-url <URL>    Registry URL to connect to [default: https://saorsa-1.saorsalabs.com]
    --max-peers <N>         Maximum peer connections [default: 10]
    -q, --quiet             Disable TUI, log mode only
    -h, --help              Print this help message

EXAMPLES:
    # Run as registry server
    ant-quic-test --registry --port 8080

    # Run as test node (default mode, random port)
    ant-quic-test

    # Run multiple local instances (each on different random ports)
    ant-quic-test &
    ant-quic-test &

    # Run on specific port
    ant-quic-test --bind-port 9001

    # Connect to custom registry
    ant-quic-test --registry-url https://my-registry.example.com
"#
    );
}

// Use 8 worker threads to prevent thread starvation from blocking locks
// This is a mitigation until std::sync::RwLock is replaced with tokio::sync::RwLock
#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> anyhow::Result<()> {
    // CRITICAL: Install rustls crypto provider before any TLS/QUIC operations
    // This must happen early, before TestNode::new() which uses rustls internally.
    // Using aws-lc-rs as the default provider for FIPS-compliant cryptography.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = parse_args();

    // Only initialize logging for non-TUI modes (registry or quiet)
    // TUI mode handles its own display - tracing to stderr ruins the interface
    if args.registry || args.quiet {
        tracing_subscriber::fmt::init();
    }

    if args.registry {
        // Run as registry server
        println!("Starting registry server on port {}...", args.port);
        println!("\"We will be legion!!\"");

        let quic_addr = if args.quic_port > 0 {
            Some(
                format!("[::]:{}", args.quic_port)
                    .parse()
                    .expect("valid QUIC address"),
            )
        } else {
            None
        };

        let config = RegistryConfig {
            bind_addr: format!("[::]:{}", args.port)
                .parse()
                .expect("valid bind address"),
            // QUIC endpoint for native address discovery via OBSERVED_ADDRESS frames
            quic_addr,
            ttl_secs: 120,
            cleanup_interval_secs: 30,
            data_dir: std::path::PathBuf::from("./data"),
            persistence_enabled: true,
        };

        start_registry_server(config).await?;
    } else {
        // Run as test node with TUI
        println!("Starting ant-quic test node...");
        println!("Connecting to registry: {}", args.registry_url);
        println!("\"We will be legion!!\"");

        // Create event channel for TUI updates
        // Use large capacity (1000) to prevent event drops during high activity periods
        let (event_tx, event_rx) = mpsc::channel::<TuiEvent>(1000);

        // Create TUI application
        let app = App::new();

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.bind_port).parse()?;
        let node_config = TestNodeConfig {
            registry_url: args.registry_url.clone(),
            max_peers: args.max_peers,
            bind_addr,
            ..Default::default()
        };

        let test_node = TestNode::new(node_config, event_tx.clone()).await?;

        // Auto-detect TTY availability - fall back to quiet mode if not a terminal
        // This handles running from scripts, IDEs, CI, or piped environments
        let use_quiet_mode = args.quiet || !std::io::IsTerminal::is_terminal(&std::io::stdout());

        if use_quiet_mode && !args.quiet {
            eprintln!("INFO: No TTY detected, falling back to quiet mode");
        }

        if use_quiet_mode {
            // Quiet mode: run without TUI
            println!("Running in quiet mode (no TUI)...");
            println!("Press Ctrl+C to quit");

            // CRITICAL: Spawn a task to drain the event channel
            // Without this, the channel fills up (capacity 100) and send().await blocks,
            // causing heartbeat and other background tasks to hang!
            tokio::spawn(async move {
                let mut rx = event_rx;
                while rx.recv().await.is_some() {
                    // Just drain the events, don't process them
                }
            });

            // Run test node directly
            test_node.run().await?;
        } else {
            // Normal mode: run TUI with background tasks

            // Spawn the test node in the background
            let node_handle = tokio::spawn(async move {
                if let Err(e) = test_node.run().await {
                    tracing::error!("Test node error: {}", e);
                }
            });

            // Run TUI in foreground
            run_tui(app, event_rx).await?;

            // When TUI exits, abort the node
            node_handle.abort();
        }
    }

    Ok(())
}
