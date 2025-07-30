//! Dashboard demonstration example for ant-quic
//!
//! This example shows how to use the statistics dashboard to monitor
//! connection health and NAT traversal performance.

use ant_quic::{
    nat_traversal_api::NatTraversalStatistics,
    quic_node::NodeStats,
    stats_dashboard::{DashboardConfig, StatsDashboard},
};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create dashboard configuration
    let config = DashboardConfig {
        update_interval: Duration::from_secs(1),
        history_size: 60,
        detailed_tracking: true,
        show_graphs: true,
    };

    // Create the dashboard
    let dashboard = StatsDashboard::new(config);

    println!("Starting statistics dashboard demo...");
    println!("This will simulate connection statistics for 30 seconds.");
    println!("Press Ctrl+C to exit.\n");

    // Simulate some initial stats
    let mut active_connections = 0;
    let mut successful_connections = 0;
    let mut failed_connections = 0;
    let mut nat_attempts = 0;
    let mut nat_successes = 0;

    for i in 0..30 {
        // Simulate connection changes
        if i % 5 == 0 && active_connections < 10 {
            active_connections += 1;
            successful_connections += 1;
            nat_attempts += 1;
            nat_successes += 1;
        }

        if i % 7 == 0 && active_connections > 0 {
            active_connections -= 1;
        }

        if i % 8 == 0 {
            failed_connections += 1;
            nat_attempts += 1;
        }

        // Update node stats
        let node_stats = NodeStats {
            active_connections,
            successful_connections,
            failed_connections,
            nat_traversal_attempts: nat_attempts,
            nat_traversal_successes: nat_successes,
            start_time: Instant::now() - Duration::from_secs(i as u64),
        };
        dashboard.update_node_stats(node_stats).await;

        // Update NAT stats
        let nat_stats = NatTraversalStatistics {
            active_sessions: active_connections,
            total_bootstrap_nodes: 3,
            successful_coordinations: nat_successes as u32,
            average_coordination_time: Duration::from_millis(1500 + (i * 50) as u64),
            total_attempts: nat_attempts as u32,
            successful_connections: nat_successes as u32,
            direct_connections: (nat_successes * 7 / 10) as u32,
            relayed_connections: (nat_successes * 3 / 10) as u32,
        };
        dashboard.update_nat_stats(nat_stats).await;

        // Render the dashboard
        let output = dashboard.render().await;
        print!("{output}");

        // Wait before next update
        sleep(Duration::from_secs(1)).await;
    }

    println!("\n\nDemo completed!");
    Ok(())
}
