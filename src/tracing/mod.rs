// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Zero-cost tracing system for P2P network debugging
//!
//! This module provides comprehensive tracing capabilities with absolutely zero
//! overhead in release builds when the `trace` feature is disabled.

// Import modules at crate level
mod context;
mod event;
mod macros;
mod query;
mod ring_buffer;

#[cfg(feature = "trace-app")]
mod app_protocol;

#[cfg(feature = "trace")]
mod implementation {
    use std::sync::Arc;

    // Re-export types from parent modules
    pub use super::context::TraceContext;
    pub use super::event::{Event, EventData, TraceId, socket_addr_to_bytes};
    pub use super::query::{ConnectionAnalysis, TraceQuery};
    pub use super::ring_buffer::{EventLog, TraceConfig};

    #[cfg(feature = "trace-app")]
    pub use super::app_protocol::{
        AppProtocol, AppRegistry as AppProtocolRegistry, DataMapProtocol,
    };

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
    /// Get the global application protocol registry
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

    impl Default for TraceId {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TraceId {
        pub fn new() -> Self {
            Self
        }
    }

    /// Zero-sized event when tracing is disabled
    #[derive(Debug)]
    pub struct Event;

    /// Zero-sized event log when tracing is disabled
    #[derive(Debug)]
    pub struct EventLog;

    impl Default for EventLog {
        fn default() -> Self {
            Self::new()
        }
    }

    impl EventLog {
        pub fn new() -> Self {
            Self
        }
        pub fn log(&self, _event: Event) {}
        pub fn recent_events(&self, _count: usize) -> Vec<Event> {
            Vec::new()
        }
        pub fn get_events_by_trace(&self, _trace_id: TraceId) -> Vec<Event> {
            Vec::new()
        }
    }

    /// Zero-sized trace context when tracing is disabled
    #[derive(Debug, Clone)]
    pub struct TraceContext;

    impl TraceContext {
        pub fn new(_trace_id: TraceId) -> Self {
            Self
        }
        pub fn trace_id(&self) -> TraceId {
            TraceId
        }
    }

    /// Zero-sized trace flags when tracing is disabled
    #[derive(Debug, Clone, Copy)]
    pub struct TraceFlags;

    impl Default for TraceFlags {
        fn default() -> Self {
            Self
        }
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
/// Monotonic timestamp in microseconds (platform-dependent)
pub fn timestamp_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

#[cfg(not(feature = "trace"))]
pub fn timestamp_now() -> u64 {
    0
}

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
        #[cfg(not(feature = "trace"))]
        log.log(Event); // Should compile to nothing when trace is disabled
        #[cfg(feature = "trace")]
        {
            // When trace is enabled, Event is a real struct
            let event = Event::default();
            log.log(event);
        }

        let trace_id = TraceId::new();
        let _context = TraceContext::new(trace_id);
    }
}
