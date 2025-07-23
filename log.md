P2P Network Local Tracing System - Implementation Specification
Overview
Design and implement a local tracing system for our P2P network that provides comprehensive debugging capabilities while maintaining zero overhead in production builds. The system must support arbitrary application protocols and efficient local trace storage without any runtime cost when disabled.
Core Requirements
1. Compile-Time Zero-Cost Abstraction

All tracing code must compile to zero bytes in release builds
Use Rust feature flags: trace (core) and trace-app (application layer)
No runtime overhead, memory allocation, or network bytes when disabled
Same API surface whether tracing is enabled or disabled

2. Architecture Overview
rust// When trace feature is disabled, this entire system compiles to nothing
#[cfg(feature = "trace")]
mod tracing {
    // Full implementation
}

#[cfg(not(feature = "trace"))]
mod tracing {
    // Zero-cost stubs
}
Detailed Implementation Requirements
A. Core Data Structures
Event System
rust// Fixed-size event structure for zero-allocation logging
#[repr(C)]
struct Event {
    timestamp: u64,           // Unix timestamp micros
    node_id: [u8; 32],       // Local node address
    peer_id: Option<[u8; 32]>, // Remote peer if applicable
    trace_id: TraceId,       // 128-bit correlation ID
    sequence: u32,           // Event sequence number
    event_data: EventData,   // Fixed-size union of event types
}

// Event data must fit in fixed size (64 bytes) for ring buffer
#[repr(C)]
enum EventData {
    // QUIC events
    ConnInit { endpoint: SocketAddr },
    ConnEstablished { rtt: u32 },
    StreamOpened { stream_id: u64 },
    PacketSent { size: u32, packet_num: u64 },
    PacketReceived { size: u32, packet_num: u64 },
    PacketLost { packet_num: u64 },
    
    // Application events
    AppCommand {
        app_id: [u8; 4],
        cmd: u16,
        data: [u8; 42],
    },
    
    // Generic events
    Custom {
        category: u16,
        code: u16,
        data: [u8; 44],
    },
}

// Compile-time size assertion
const _: () = assert!(std::mem::size_of::<Event>() == 128);
Trace Context
rust#[derive(Copy, Clone)]
struct TraceId([u8; 16]);

struct TraceContext {
    trace_id: TraceId,
    start_time: u64,
    flags: TraceFlags,
}

#[repr(u8)]
struct TraceFlags {
    sampled: bool,
    debug: bool,
    app_initiated: bool,
}
B. Local Storage System
Ring Buffer Implementation
rustpub struct EventLog {
    // Fixed-size ring buffer (no allocations)
    events: Box<[Event; 65536]>,  // ~8MB when enabled
    write_index: AtomicU32,
    
    // Optional indices for fast queries (can be disabled)
    #[cfg(feature = "trace-index")]
    indices: EventIndices,
}

struct EventIndices {
    // Lock-free indices
    by_trace: DashMap<TraceId, Vec<u32>>,
    by_peer: DashMap<[u8; 32], RingBuffer<u32>>,
    by_time: SkipList<u64, u32>,
    
    // Bloom filter for quick existence checks
    trace_bloom: BloomFilter<TraceId, 16384>,
}

impl EventLog {
    // Lock-free event insertion
    pub fn log(&self, event: Event) {
        let idx = self.write_index.fetch_add(1, Ordering::Relaxed);
        let slot = (idx % 65536) as usize;
        
        // Atomic write to ring buffer
        unsafe {
            std::ptr::write_volatile(&mut self.events[slot], event);
        }
        
        #[cfg(feature = "trace-index")]
        self.update_indices(slot, &event);
    }
    
    // Query methods only available when tracing enabled
    #[cfg(feature = "trace")]
    pub fn query_trace(&self, trace_id: TraceId) -> Vec<Event> {
        // Implementation
    }
}
C. Zero-Cost Abstraction Layer
Conditional Types
rust// Message header changes size based on feature
#[cfg(feature = "trace")]
pub struct MessageHeader {
    pub trace_id: TraceId,
    pub flags: TraceFlags,
}

#[cfg(not(feature = "trace"))]
pub struct MessageHeader; // Zero-sized type

// Connection struct adapts to feature
pub struct Connection {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    peer_id: [u8; 32],
    
    #[cfg(feature = "trace")]
    trace_context: TraceContext,
    
    #[cfg(feature = "trace")]
    event_log: Arc<EventLog>,
}
Macro System
rust// Primary macro - compiles to nothing when disabled
#[cfg(feature = "trace")]
macro_rules! trace_event {
    ($log:expr, $event:expr) => {
        $log.log($event)
    };
}

#[cfg(not(feature = "trace"))]
macro_rules! trace_event {
    ($log:expr, $event:expr) => {};
}

// Convenience macros for common events
macro_rules! trace_packet_sent {
    ($log:expr, $trace_id:expr, $size:expr, $num:expr) => {
        trace_event!($log, Event {
            timestamp: timestamp_now(),
            trace_id: $trace_id,
            event_data: EventData::PacketSent {
                size: $size as u32,
                packet_num: $num,
            },
            ..Event::default()
        })
    };
}

// Conditional code blocks
macro_rules! if_trace {
    ($($body:tt)*) => {
        #[cfg(feature = "trace")]
        {
            $($body)*
        }
    };
}
D. Application Protocol Integration
App Integration Interface
rustpub trait AppProtocol: Send + Sync {
    const APP_ID: [u8; 4];
    
    // Convert app commands to trace data
    fn to_trace_data(&self, cmd: u16, payload: &[u8]) -> [u8; 42];
    
    // Describe command for debugging
    fn describe_command(&self, cmd: u16) -> &'static str;
    
    // Sampling decision
    fn should_trace(&self, cmd: u16) -> bool {
        true // Default: trace everything in debug
    }
}

// Registration system
pub struct AppRegistry {
    #[cfg(feature = "trace-app")]
    apps: DashMap<[u8; 4], Arc<dyn AppProtocol>>,
}

impl AppRegistry {
    pub fn register<A: AppProtocol + 'static>(&self, app: A) {
        #[cfg(feature = "trace-app")]
        self.apps.insert(A::APP_ID, Arc::new(app));
    }
}
Example App Implementation
ruststruct DataMapApp;

impl AppProtocol for DataMapApp {
    const APP_ID: [u8; 4] = *b"DMAP";
    
    fn to_trace_data(&self, cmd: u16, payload: &[u8]) -> [u8; 42] {
        let mut data = [0u8; 42];
        match cmd {
            0x01 => { // STORE
                data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                data[32..36].copy_from_slice(&payload[32..36]); // size
            }
            0x02 => { // GET
                data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
            }
            _ => {}
        }
        data
    }
    
    fn describe_command(&self, cmd: u16) -> &'static str {
        match cmd {
            0x01 => "STORE_CHUNK",
            0x02 => "GET_CHUNK",
            0x03 => "DELETE_CHUNK",
            _ => "UNKNOWN",
        }
    }
}
E. QUIC Integration
rustimpl QuicConnection {
    pub fn send_packet(&mut self, packet: &Packet) -> Result<()> {
        // Trace before sending
        if_trace! {
            trace_packet_sent!(
                self.event_log,
                self.trace_context.trace_id,
                packet.payload.len(),
                packet.packet_number
            );
        }
        
        // Actual send logic
        self.socket.send_to(&packet.payload, self.peer_addr)?;
        
        Ok(())
    }
    
    pub fn handle_stream_frame(&mut self, frame: &StreamFrame) {
        trace_event!(self.event_log, Event {
            timestamp: timestamp_now(),
            node_id: self.local_id,
            peer_id: Some(self.peer_id),
            trace_id: self.trace_context.trace_id,
            sequence: self.next_sequence(),
            event_data: EventData::StreamData {
                stream_id: frame.stream_id,
                offset: frame.offset,
                length: frame.data.len() as u32,
                fin: frame.fin,
            },
        });
        
        // Process frame
    }
}
F. Query Interface (Debug Builds Only)
rust#[cfg(feature = "trace")]
pub struct TraceQuery {
    log: Arc<EventLog>,
}

#[cfg(feature = "trace")]
impl TraceQuery {
    // Get all events for a trace
    pub fn get_trace(&self, trace_id: TraceId) -> Vec<Event> {
        self.log.query_trace(trace_id)
    }
    
    // Get recent events
    pub fn recent(&self, count: usize) -> Vec<Event> {
        self.log.recent_events(count)
    }
    
    // Time range query
    pub fn time_range(&self, start: u64, end: u64) -> Vec<Event> {
        self.log.query_time_range(start, end)
    }
    
    // Export for analysis
    pub fn export_json(&self, trace_id: TraceId) -> String {
        let events = self.get_trace(trace_id);
        serde_json::to_string_pretty(&events).unwrap()
    }
}
G. Performance Configuration
rust// Compile-time configuration
pub struct TraceConfig;

impl TraceConfig {
    // Ring buffer size (power of 2)
    #[cfg(feature = "trace")]
    pub const BUFFER_SIZE: usize = 65536; // ~8MB
    
    #[cfg(feature = "trace-minimal")]
    pub const BUFFER_SIZE: usize = 4096;  // ~512KB
    
    // Sampling rate (compile-time)
    pub const SAMPLE_RATE: bool = cfg!(feature = "trace-sample");
    
    // Index features
    pub const ENABLE_INDICES: bool = cfg!(feature = "trace-index");
}
H. Build Configuration
toml# Cargo.toml
[features]
default = []

# Core tracing - minimal overhead
trace = []

# Application-level tracing
trace-app = ["trace"]

# Additional features (more memory/CPU)
trace-index = ["trace"]  # Enable fast queries
trace-full = ["trace", "trace-app", "trace-index"]

# Debug profile - full tracing
debug = ["trace-full"]

[profile.release]
lto = true
codegen-units = 1
strip = true

[profile.dev]
features = ["trace-full"]
Usage Examples
Basic Integration
rust// In your main network code
pub struct Network {
    #[cfg(feature = "trace")]
    event_log: Arc<EventLog>,
    
    connections: HashMap<[u8; 32], Connection>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "trace")]
            event_log: Arc::new(EventLog::new()),
            
            connections: HashMap::new(),
        }
    }
    
    pub fn send_message(&mut self, peer: [u8; 32], msg: Message) {
        trace_event!(self.event_log, Event {
            event_data: EventData::Custom {
                category: 0x01, // Network messages
                code: msg.msg_type,
                data: msg.to_trace_data(),
            },
            peer_id: Some(peer),
            ..Event::with_trace_id(msg.trace_id)
        });
        
        // Send logic
    }
}
Application Integration
rustimpl MyApp {
    fn handle_request(&mut self, req: Request) -> Response {
        let trace_id = TraceId::new();
        
        // Start trace
        trace_event!(self.log, Event::app_start(
            Self::APP_ID,
            req.command,
            trace_id
        ));
        
        // Process request
        let result = match req.command {
            CMD_STORE => self.store_data(req.data),
            CMD_GET => self.get_data(req.key),
            _ => Err(Error::UnknownCommand),
        };
        
        // End trace
        trace_event!(self.log, Event::app_end(
            Self::APP_ID,
            req.command,
            trace_id,
            result.is_ok()
        ));
        
        result
    }
}
Debug Analysis
rust#[cfg(feature = "trace")]
fn analyze_connection_issues(log: &EventLog, peer: [u8; 32]) {
    let events = log.query_peer(peer);
    
    let packet_loss = events.iter()
        .filter(|e| matches!(e.event_data, EventData::PacketLost { .. }))
        .count();
    
    println!("Connection to {:?}: {} events, {} packet loss",
        peer, events.len(), packet_loss);
}
Testing Requirements

Zero-cost verification:

Compare binary size with/without trace feature
Benchmark performance with/without trace feature
Verify no allocations in release builds


Functionality tests:

Ring buffer overflow handling
Concurrent logging safety
Query accuracy


Integration tests:

QUIC event tracing
App protocol tracing
Trace correlation across components



Deliverables

Core tracing module with zero-cost abstraction
Lock-free ring buffer implementation
Macro system for easy integration
App protocol trait and registry
QUIC integration example
Query interface for debug builds
Comprehensive test suite
Performance benchmarks
Documentation and usage guide

Success Criteria

Zero overhead in production builds (verified by benchmarks)
Less than 100ns per trace event when enabled
Fixed memory footprint (configurable at compile time)
Thread-safe concurrent logging
Easy integration for app developers
Useful debugging output in development
