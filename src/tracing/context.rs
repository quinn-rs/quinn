//! Trace context for propagating trace information

use super::event::TraceId;

/// Trace context for a connection or operation
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Unique trace identifier
    pub trace_id: TraceId,
    /// Start time of the trace
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
    pub debug: bool,
    /// Whether trace was initiated by application
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
    pub fn with_flags(trace_id: TraceId, flags: TraceFlags) -> Self {
        Self {
            trace_id,
            start_time: crate::tracing::timestamp_now(),
            flags,
        }
    }

    /// Get the trace ID
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Check if trace is being sampled
    pub(super) fn is_sampled(&self) -> bool {
        self.flags.sampled
    }

    /// Enable sampling for this trace
    pub(super) fn enable_sampling(&mut self) {
        self.flags.sampled = true;
    }

    /// Get elapsed time since trace start
    pub(super) fn elapsed(&self) -> u64 {
        crate::tracing::timestamp_now() - self.start_time
    }
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
