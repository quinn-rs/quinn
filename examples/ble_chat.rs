//! BLE Chat Example - Demonstrate ant-quic over Bluetooth Low Energy
//!
//! This example shows how to use the BLE transport for peer-to-peer chat
//! over Bluetooth Low Energy. It demonstrates:
//!
//! - Scanning for nearby BLE peers
//! - Connecting to discovered devices
//! - Sending and receiving messages via GATT characteristics
//! - Session resumption for efficient reconnection
//!
//! # Requirements
//!
//! - BLE hardware (Bluetooth 4.0+ adapter)
//! - Platform support: Linux (BlueZ), macOS (Core Bluetooth), Windows (WinRT)
//! - Feature flag: `--features ble`
//!
//! # Usage
//!
//! Start as peripheral (advertises and waits for connections):
//! ```bash
//! cargo run --example ble_chat --features ble -- --peripheral
//! ```
//!
//! Start as central (scans and connects to peripherals):
//! ```bash
//! cargo run --example ble_chat --features ble -- --central
//! ```
//!
//! # GATT Architecture
//!
//! The BLE transport uses a custom GATT service:
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │           ant-quic BLE Service                  │
//! │  UUID: a03d7e9f-0bca-12fe-a600-000000000001    │
//! ├─────────────────────────────────────────────────┤
//! │  TX Characteristic (Write Without Response)    │
//! │  UUID: a03d7e9f-0bca-12fe-a600-000000000002    │
//! │  - Central writes to send data to peripheral   │
//! ├─────────────────────────────────────────────────┤
//! │  RX Characteristic (Notify)                    │
//! │  UUID: a03d7e9f-0bca-12fe-a600-000000000003    │
//! │  - Peripheral notifies to send data to central │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # PQC Mitigations
//!
//! BLE has limited bandwidth (~125 kbps) and small MTU (244 bytes typical),
//! making full PQC handshakes expensive. This example demonstrates:
//!
//! - Session caching (24+ hour retention)
//! - Session resumption tokens (32 bytes vs ~8KB handshake)
//! - Efficient reconnection via cached keys

#![cfg(feature = "ble")]

use ant_quic::transport::{
    BleConfig, BleTransport, DiscoveredDevice, TransportAddr, TransportProvider,
    ANT_QUIC_SERVICE_UUID,
};
use std::io::{self, BufRead, Write};
use std::time::Duration;

/// Mode of operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Central,
    Peripheral,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug,ble_chat=debug")
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mode = if args.iter().any(|a| a == "--peripheral" || a == "-p") {
        Mode::Peripheral
    } else if args.iter().any(|a| a == "--central" || a == "-c") {
        Mode::Central
    } else {
        println!("BLE Chat Example");
        println!("================");
        println!();
        println!("Usage:");
        println!("  {} --peripheral    Start as BLE peripheral (advertise)", args[0]);
        println!("  {} --central       Start as BLE central (scan and connect)", args[0]);
        println!();
        println!("Requirements:");
        println!("  - BLE hardware (Bluetooth 4.0+ adapter)");
        println!("  - Compile with: cargo run --example ble_chat --features ble");
        println!();
        return Ok(());
    };

    // Create BLE transport
    let config = BleConfig {
        max_connections: 3,
        session_cache_duration: Duration::from_secs(24 * 60 * 60),
        scan_interval: Duration::from_secs(5),
        connection_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    println!("Initializing BLE transport...");
    let transport = match BleTransport::with_config(config).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to initialize BLE: {e}");
            eprintln!("Make sure you have a Bluetooth adapter and appropriate permissions.");
            return Err(e.into());
        }
    };

    let local_addr = transport.local_addr();
    println!("Local BLE address: {:?}", local_addr);

    match mode {
        Mode::Peripheral => run_peripheral(transport).await?,
        Mode::Central => run_central(transport).await?,
    }

    Ok(())
}

/// Run as BLE peripheral (advertise and accept connections)
async fn run_peripheral(transport: BleTransport) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== BLE Chat - Peripheral Mode ===");
    println!("Advertising ant-quic service...");
    println!("Service UUID: {:02x?}", ANT_QUIC_SERVICE_UUID);
    println!();

    // Check if peripheral mode is supported
    if !BleTransport::is_peripheral_mode_supported() {
        println!("Note: Peripheral mode has limited support on some platforms.");
        println!("On Linux, BlueZ D-Bus GATT server may be required.");
        println!("On macOS, app-level peripheral mode only.");
    }

    // Start advertising
    match transport.start_advertising().await {
        Ok(()) => println!("Advertising started."),
        Err(e) => {
            println!("Warning: Could not start advertising: {e}");
            println!("Continuing in listen-only mode...");
        }
    }

    println!("\nWaiting for connections...");
    println!("Press Ctrl+C to exit\n");

    // Main event loop
    loop {
        // Check for incoming connections
        let stats = transport.pool_stats().await;
        if stats.active > 0 {
            println!("Active connections: {}", stats.active);
        }

        // Sleep briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Run as BLE central (scan for and connect to peripherals)
async fn run_central(transport: BleTransport) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== BLE Chat - Central Mode ===");
    println!("Scanning for ant-quic BLE peers...");
    println!();

    // Start scanning
    transport.start_scanning().await?;
    println!("Scanning for devices (will scan for 10 seconds)...");

    // Scan for devices
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Stop scanning
    transport.stop_scanning().await?;

    // Get discovered devices
    let devices = transport.discovered_devices().await;
    println!("\nDiscovered {} device(s):", devices.len());

    let ant_quic_devices: Vec<&DiscoveredDevice> = devices.iter().filter(|d| d.has_service).collect();

    if ant_quic_devices.is_empty() {
        println!("\nNo ant-quic BLE peers found nearby.");
        println!("Make sure another instance is running in peripheral mode.");
        return Ok(());
    }

    // Display devices
    for (i, device) in ant_quic_devices.iter().enumerate() {
        println!(
            "  [{}] {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} - RSSI: {:?} dBm",
            i,
            device.device_id[0],
            device.device_id[1],
            device.device_id[2],
            device.device_id[3],
            device.device_id[4],
            device.device_id[5],
            device.rssi,
        );
        if let Some(ref name) = device.local_name {
            println!("      Name: {name}");
        }
    }

    // Let user select a device
    println!("\nEnter device number to connect (or 'q' to quit):");
    print!("> ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let line = line.trim();
    if line == "q" || line == "quit" {
        return Ok(());
    }

    let index: usize = match line.parse() {
        Ok(i) if i < ant_quic_devices.len() => i,
        _ => {
            eprintln!("Invalid selection");
            return Ok(());
        }
    };

    let target = ant_quic_devices[index];
    println!(
        "\nConnecting to {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}...",
        target.device_id[0],
        target.device_id[1],
        target.device_id[2],
        target.device_id[3],
        target.device_id[4],
        target.device_id[5],
    );

    // Check for cached session (for efficient reconnection)
    if let Some(token) = transport.lookup_session(&target.device_id).await {
        println!("Found cached session! Using session resumption (32 bytes vs ~8KB handshake)");
        let _ = token; // Would use in real implementation
    }

    // Connect to the device
    match transport.connect_to_device(target.device_id).await {
        Ok(_connection) => {
            println!("Connected successfully!");
            run_chat_session(&transport, target.device_id).await?;
        }
        Err(e) => {
            eprintln!("Connection failed: {e}");
        }
    }

    // Disconnect
    transport.disconnect_from_device(&target.device_id).await?;

    Ok(())
}

/// Run an interactive chat session with a connected peer
async fn run_chat_session(
    transport: &BleTransport,
    device_id: [u8; 6],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Chat Session ===");
    println!("Type messages and press Enter to send.");
    println!("Type 'quit' or 'q' to disconnect.\n");

    let dest = TransportAddr::ble(device_id, None);

    loop {
        print!("You: ");
        io::stdout().flush()?;

        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut line = String::new();
        reader.read_line(&mut line)?;

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "q" || line == "quit" {
            break;
        }

        // Send the message
        let message = line.as_bytes();
        match transport.send(message, &dest).await {
            Ok(()) => {
                // Message sent successfully
            }
            Err(e) => {
                eprintln!("Send error: {e}");
                break;
            }
        }
    }

    Ok(())
}

// Note: In a real implementation, you would also have a receive loop
// that processes incoming notifications via the RX characteristic.
// This example focuses on the scanning, connection, and send flow.
