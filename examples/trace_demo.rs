//! Demonstration of the zero-cost tracing system

use ant_quic::tracing::{EventLog, TraceId};
use std::sync::Arc;

fn main() {
    println!("ANT-QUIC Zero-Cost Tracing Demo");
    println!("================================\n");

    #[cfg(feature = "trace")]
    {
        println!("Tracing is ENABLED");
        println!("Note: The tracing API is internal-only in this version.");
        println!("This demo shows the zero-cost nature when disabled.");

        // Create a global event log
        let log = Arc::new(EventLog::new());

        // Create a trace context
        let _trace_id = TraceId::new();
        println!("\nCreated trace ID (will be used internally)");

        // Since the Event creation methods are private, we can't directly
        // create events in this demo. In real usage, events are created
        // internally by the QUIC implementation.

        println!("\nIn production, events are logged automatically by:");
        println!("  - Connection establishment");
        println!("  - Packet transmission/reception");
        println!("  - NAT traversal operations");
        println!("  - Address discovery");

        // We can still demonstrate the query interface
        println!("\nEvent log provides these query methods:");
        println!("  - recent_events(count)");
        println!("  - get_events_by_trace(trace_id)");
        
        // Show that the log exists and is functional
        let recent = log.recent_events(5);
        println!("\nQueried {} recent events", recent.len());
    }

    #[cfg(not(feature = "trace"))]
    {
        println!("Tracing is DISABLED");
        println!("This demo shows the zero-cost nature of the tracing system.");
        println!("When the 'trace' feature is disabled:");
        println!("  - All tracing types are zero-sized");
        println!("  - All tracing operations compile to no-ops");
        println!("  - Zero runtime overhead!");
        
        // Even though we can create these, they're zero-sized
        let _log = EventLog::new();
        let _trace_id = TraceId::new();
        
        println!("\nSizes when tracing is disabled:");
        println!("  EventLog: {} bytes", std::mem::size_of::<EventLog>());
        println!("  TraceId: {} bytes", std::mem::size_of::<TraceId>());
    }

    println!("\nTo enable tracing, compile with: --features trace");
}