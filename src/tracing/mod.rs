//! Zero-cost tracing system for P2P network debugging
//!
//! This module provides comprehensive tracing capabilities with absolutely zero
//! overhead in release builds when the `trace` feature is disabled.

// Import modules at crate level
mod event;
mod ring_buffer;
mod macros;
mod context;
mod query;

#[cfg(feature = "trace-app")]
mod app_protocol;

#[cfg(feature = "trace")]
mod implementation {
    use std::sync::Arc;
    
    // Re-export types from parent modules
    pub use super::event::{Event, EventData, TraceId, timestamp_now, socket_addr_to_bytes};
    pub use super::ring_buffer::{EventLog, TraceConfig};
    pub use super::context::{TraceContext, TraceFlags};
    pub use super::query::{TraceQuery, ConnectionAnalysis};
    
    #[cfg(feature = "trace-app")]
    pub use super::app_protocol::{AppProtocol, AppProtocolRegistry, DataMapProtocol};
    
    /// Global event log instance
    static EVENT_LOG: once_cell::sync::Lazy<Arc<EventLog>> = 
        once_cell::sync::Lazy::new(|| Arc::new(EventLog::new()));
    
    /// Get the global event log
    pub fn global_log() -> Arc<EventLog> {
        EVENT_LOG.clone()
    }
    
    #[cfg(feature = "trace-app")]
    static APP_REGISTRY: once_cell::sync::Lazy<AppProtocolRegistry> = 
        once_cell::sync::Lazy::new(AppProtocolRegistry::new);
    
    #[cfg(feature = "trace-app")]
    pub fn global_app_registry() -> &'static AppProtocolRegistry {
        &APP_REGISTRY
    }
}

// When trace is disabled, export empty types and no-op functions
#[cfg(not(feature = "trace"))]
mod implementation {
    use std::sync::Arc;
    
    /// Zero-sized trace ID when tracing is disabled
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TraceId;
    
    impl TraceId {
        pub fn new() -> Self { TraceId }
    }
    
    /// Zero-sized event when tracing is disabled
    #[derive(Debug)]
    pub struct Event;
    
    /// Zero-sized event log when tracing is disabled
    #[derive(Debug)]
    pub struct EventLog;
    
    impl EventLog {
        pub fn new() -> Self { EventLog }
        pub fn log(&self, _event: Event) {}
    }
    
    /// Zero-sized trace context when tracing is disabled
    #[derive(Debug, Clone)]
    pub struct TraceContext;
    
    impl TraceContext {
        pub fn new(_trace_id: TraceId) -> Self { TraceContext }
        pub fn trace_id(&self) -> TraceId { TraceId }
    }
    
    /// Zero-sized trace flags when tracing is disabled
    #[derive(Debug, Clone, Copy)]
    pub struct TraceFlags;
    
    impl Default for TraceFlags {
        fn default() -> Self { TraceFlags }
    }
    
    /// No-op global log when tracing is disabled
    pub fn global_log() -> Arc<EventLog> {
        Arc::new(EventLog)
    }
}

// Re-export everything from implementation
pub use implementation::*;

// Helper function to get current timestamp in microseconds
#[cfg(feature = "trace")]
pub fn timestamp_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

#[cfg(not(feature = "trace"))]
pub fn timestamp_now() -> u64 { 0 }

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_sized_types() {
        // When trace is disabled, all types should be zero-sized
        #[cfg(not(feature = "trace"))]
        {
            assert_eq!(std::mem::size_of::<TraceId>(), 0);
            assert_eq!(std::mem::size_of::<Event>(), 0);
            assert_eq!(std::mem::size_of::<EventLog>(), 0);
            assert_eq!(std::mem::size_of::<TraceContext>(), 0);
            assert_eq!(std::mem::size_of::<TraceFlags>(), 0);
        }
    }
    
    #[test]
    fn test_no_op_operations() {
        let log = EventLog::new();
        log.log(Event); // Should compile to nothing
        
        let trace_id = TraceId::new();
        let _context = TraceContext::new(trace_id);
    }
}