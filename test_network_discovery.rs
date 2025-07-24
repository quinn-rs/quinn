use ant_quic::candidate_discovery::{NetworkInterfaceDiscovery, create_platform_interface_discovery};

fn main() {
    let mut discovery = create_platform_interface_discovery();
    
    match discovery.start_scan() {
        Ok(()) => println\!("Scan started successfully"),
        Err(e) => println\!("Scan failed to start: {}", e),
    }
    
    // Give it a moment
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    match discovery.check_scan_complete() {
        Some(interfaces) => {
            println\!("Found {} interfaces:", interfaces.len());
            for interface in interfaces {
                println\!("  {} - {} addresses, up: {}, wireless: {}, mtu: {:?}",
                    interface.name,
                    interface.addresses.len(),
                    interface.is_up,
                    interface.is_wireless,
                    interface.mtu
                );
                for addr in &interface.addresses {
                    println\!("    {}", addr);
                }
            }
        }
        None => println\!("Scan not complete yet"),
    }
}
