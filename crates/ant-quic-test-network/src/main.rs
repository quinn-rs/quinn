//! ant-quic Test Network Binary
//!
//! "We will be legion!!"
//!
//! This binary provides both registry server and test node functionality
//! for the large-scale ant-quic network testing infrastructure.

use ant_quic_test_network::{
    node::TestNodeConfig,
    registry::{start_registry_server, RegistryConfig},
    tui::{App, run_tui, TuiEvent},
    TestNode,
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
            registry_url: "https://quic.saorsalabs.com".to_string(),
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
    --registry-url <URL>    Registry URL to connect to [default: https://quic.saorsalabs.com]
    --max-peers <N>         Maximum peer connections [default: 10]
    -q, --quiet             Disable TUI, log mode only
    -h, --help              Print this help message

EXAMPLES:
    # Run as registry server
    ant-quic-test --registry --port 8080

    # Run as test node (default mode)
    ant-quic-test

    # Connect to custom registry
    ant-quic-test --registry-url https://my-registry.example.com:8080
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = parse_args();

    if args.registry {
        // Run as registry server
        println!("Starting registry server on port {}...", args.port);
        println!("\"We will be legion!!\"");

        let config = RegistryConfig {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], args.port)),
            ttl_secs: 120,
            cleanup_interval_secs: 30,
        };

        start_registry_server(config).await?;
    } else {
        // Run as test node with TUI
        println!("Starting ant-quic test node...");
        println!("Connecting to registry: {}", args.registry_url);
        println!("\"We will be legion!!\"");

        // Create event channel for TUI updates
        let (event_tx, event_rx) = mpsc::channel::<TuiEvent>(100);

        // Create TUI application
        let app = App::new();

        // Create test node configuration
        let node_config = TestNodeConfig {
            registry_url: args.registry_url.clone(),
            max_peers: args.max_peers,
            bind_addr: "0.0.0.0:9000".parse()?,
            ..Default::default()
        };

        // Create test node
        let test_node = TestNode::new(node_config, event_tx.clone());

        if args.quiet {
            // Quiet mode: run without TUI
            println!("Running in quiet mode (no TUI)...");
            println!("Press Ctrl+C to quit");

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
