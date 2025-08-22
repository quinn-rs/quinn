// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Trace context for propagating trace information

use super::event::TraceId;

/// Trace context for a connection or operation
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Unique trace identifier
    #[allow(dead_code)]
    pub trace_id: TraceId,
    /// Start time of the trace
    #[allow(dead_code)]
    pub start_time: u64,
    /// Trace flags
    pub flags: TraceFlags,
}

/// Flags controlling trace behavior
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceFlags {
    /// Whether this trace is being sampled
    pub sampled: bool,
    /// Debug mode for verbose tracing
    #[allow(dead_code)]
    pub debug: bool,
    /// Whether trace was initiated by application
    #[allow(dead_code)]
    pub app_initiated: bool,
}

impl TraceContext {
    /// Create a new trace context
    pub fn new(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            start_time: crate::tracing::timestamp_now(),
            flags: TraceFlags::default(),
        }
    }

    /// Create a new trace context with flags
    #[allow(dead_code)]
    pub fn with_flags(trace_id: TraceId, flags: TraceFlags) -> Self {
        Self {
            trace_id,
            start_time: crate::tracing::timestamp_now(),
            flags,
        }
    }

    /// Get the trace ID
    #[allow(dead_code)]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Check if trace is being sampled
    #[allow(dead_code)]
    pub(super) fn is_sampled(&self) -> bool {
        self.flags.sampled
    }

    /// Enable sampling for this trace
    #[allow(dead_code)]
    pub(super) fn enable_sampling(&mut self) {
        self.flags.sampled = true;
    }

    // Removed unused elapsed()
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new(TraceId::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context() {
        let trace_id = TraceId::new();
        let mut context = TraceContext::new(trace_id);

        assert_eq!(context.trace_id(), trace_id);
        assert!(!context.is_sampled());

        context.enable_sampling();
        assert!(context.is_sampled());
    }

    #[test]
    fn test_trace_flags() {
        let flags = TraceFlags {
            sampled: true,
            debug: false,
            app_initiated: true,
        };

        let trace_id = TraceId::new();
        let context = TraceContext::with_flags(trace_id, flags);

        assert!(context.is_sampled());
        assert!(context.flags.app_initiated);
        assert!(!context.flags.debug);
    }
}
