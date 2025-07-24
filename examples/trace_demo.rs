//! Demonstration of the zero-cost tracing system

#[cfg(feature = "trace")]
use ant_quic::tracing::{Event, EventData, EventLog, TraceId};
#[cfg(not(feature = "trace"))]
use ant_quic::tracing::{Event, EventLog, TraceId};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    println!("ANT-QUIC Zero-Cost Tracing Demo");
    println!("================================\n");

    #[cfg(feature = "trace")]
    {
        println!("Tracing is ENABLED");

        // Create a global event log
        let log = Arc::new(EventLog::new());

        // Create a trace context
        let trace_id = TraceId::new();
        println!("Created trace ID: {:?}", trace_id);

        // Log some events
        println!("\nLogging events...");

        // Connection init event
        let event = Event::conn_init("127.0.0.1:8080".parse().unwrap(), trace_id);
        log.log(event);
        println!("  - Logged connection init");

        // Packet sent events
        for i in 0..5 {
            let event = Event::packet_sent(1200 + i * 100, i as u64, trace_id);
            log.log(event);
            println!("  - Logged packet sent: size={}, num={}", 1200 + i * 100, i);
        }

        // Packet received events
        for i in 0..5 {
            let event = Event::packet_received(1200 + i * 100, i as u64, trace_id);
            log.log(event);
            println!(
                "  - Logged packet received: size={}, num={}",
                1200 + i * 100,
                i
            );
        }

        // Connection established
        let event = Event {
            timestamp: ant_quic::tracing::timestamp_now(),
            trace_id,
            sequence: 0, // Will be set by log
            _padding: 0,
            node_id: [0u8; 32],
            event_data: EventData::ConnEstablished {
                rtt: 25,
                _padding: [0u8; 60],
            },
        };
        log.log(event);
        println!("  - Logged connection established with RTT=25ms");

        // Query events
        println!("\nQuerying events...");
        let events = log.get_events_by_trace(trace_id);
        println!("Found {} events for trace ID", events.len());

        for (i, event) in events.iter().enumerate() {
            print!("  Event {}: ", i);
            match &event.event_data {
                EventData::ConnInit { .. } => println!("Connection Init"),
                EventData::PacketSent {
                    size, packet_num, ..
                } => {
                    println!("Packet Sent (size={}, num={})", size, packet_num);
                }
                EventData::PacketReceived {
                    size, packet_num, ..
                } => {
                    println!("Packet Received (size={}, num={})", size, packet_num);
                }
                EventData::ConnEstablished { rtt, .. } => {
                    println!("Connection Established (RTT={}ms)", rtt);
                }
                _ => println!("Other event"),
            }
        }

        // Test concurrent logging
        println!("\nTesting concurrent logging...");
        let mut handles = vec![];

        for thread_id in 0..4 {
            let log_clone = log.clone();
            let handle = thread::spawn(move || {
                let trace_id = TraceId::new();
                for i in 0..10 {
                    let event = Event::packet_sent(
                        1000 + thread_id * 100 + i,
                        (thread_id * 10 + i) as u64,
                        trace_id,
                    );
                    log_clone.log(event);
                    thread::sleep(Duration::from_micros(10));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        println!("Concurrent logging completed!");

        // Get statistics
        println!("\nEvent Log Statistics:");
        println!("  Total events logged: {}", log.event_count());

        // Check memory usage
        let event_size = std::mem::size_of::<Event>();
        let buffer_size = 65536; // TraceConfig::BUFFER_SIZE
        let total_memory = event_size * buffer_size;
        println!("  Event size: {} bytes", event_size);
        println!("  Buffer capacity: {} events", buffer_size);
        println!("  Total memory usage: {} KB", total_memory / 1024);
    }

    #[cfg(not(feature = "trace"))]
    {
        println!("Tracing is DISABLED (zero-cost mode)");
        println!("To enable tracing, run with: cargo run --example trace_demo --features trace");

        // Demonstrate zero-cost - these compile to nothing
        let log = Arc::new(EventLog::new());
        let trace_id = TraceId::new();

        // These operations have zero runtime cost
        ant_quic::trace_packet_sent!(&log, trace_id, 1200, 0);
        ant_quic::trace_packet_received!(&log, trace_id, 1200, 0);

        println!("\nAll tracing macros compile to nothing in this mode.");
        println!("The types are zero-sized:");
        println!(
            "  size_of::<TraceId>() = {}",
            std::mem::size_of::<TraceId>()
        );
        println!("  size_of::<Event>() = {}", std::mem::size_of::<Event>());
        println!(
            "  size_of::<EventLog>() = {}",
            std::mem::size_of::<EventLog>()
        );
    }
}
