//! Structured event logging for observability
//!
//! Provides consistent, structured event logging throughout ant-quic.
//! Events are categorized by component and severity for easy filtering
//! and analysis.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::nat_traversal_api::PeerId;

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventSeverity {
    /// Trace-level debugging information
    Trace,
    /// Debug information
    Debug,
    /// Informational messages
    Info,
    /// Warning conditions
    Warn,
    /// Error conditions
    Error,
}

impl fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace => write!(f, "TRACE"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// Component that generated the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventComponent {
    /// NAT traversal subsystem
    NatTraversal,
    /// Connection management
    Connection,
    /// Discovery subsystem
    Discovery,
    /// Transport layer
    Transport,
    /// Path selection
    PathSelection,
    /// Shutdown coordinator
    Shutdown,
    /// Relay subsystem
    Relay,
    /// Crypto operations
    Crypto,
    /// Endpoint operations
    Endpoint,
}

impl fmt::Display for EventComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NatTraversal => write!(f, "nat_traversal"),
            Self::Connection => write!(f, "connection"),
            Self::Discovery => write!(f, "discovery"),
            Self::Transport => write!(f, "transport"),
            Self::PathSelection => write!(f, "path_selection"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::Relay => write!(f, "relay"),
            Self::Crypto => write!(f, "crypto"),
            Self::Endpoint => write!(f, "endpoint"),
        }
    }
}

/// A structured event with typed fields
#[derive(Debug, Clone)]
pub struct StructuredEvent {
    /// Event severity
    pub severity: EventSeverity,
    /// Component that generated the event
    pub component: EventComponent,
    /// Event kind/type
    pub kind: EventKind,
    /// Event message
    pub message: String,
    /// Timestamp when event occurred
    pub timestamp: Instant,
    /// Optional peer ID associated with event
    pub peer_id: Option<PeerId>,
    /// Optional address associated with event
    pub addr: Option<SocketAddr>,
    /// Optional duration associated with event
    pub duration: Option<Duration>,
    /// Optional count/value associated with event
    pub count: Option<u64>,
}

/// Kinds of events that can be logged
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    // Connection events
    /// Connection established
    ConnectionEstablished,
    /// Connection closed
    ConnectionClosed,
    /// Connection failed
    ConnectionFailed,
    /// Connection migrated to new path
    ConnectionMigrated,

    // NAT traversal events
    /// Candidate discovered
    CandidateDiscovered,
    /// Candidate validated
    CandidateValidated,
    /// Candidate failed validation
    CandidateFailed,
    /// Hole punch initiated
    HolePunchStarted,
    /// Hole punch succeeded
    HolePunchSucceeded,
    /// Hole punch failed
    HolePunchFailed,

    // Path events
    /// Path selected
    PathSelected,
    /// Path changed
    PathChanged,
    /// Path closed
    PathClosed,
    /// Path RTT updated
    PathRttUpdated,

    // Transport events
    /// Packet sent
    PacketSent,
    /// Packet received
    PacketReceived,
    /// Transport error
    TransportError,

    // Discovery events
    /// Discovery started
    DiscoveryStarted,
    /// Address discovered
    AddressDiscovered,
    /// Discovery completed
    DiscoveryCompleted,

    // Lifecycle events
    /// Endpoint started
    EndpointStarted,
    /// Endpoint shutdown initiated
    ShutdownInitiated,
    /// Endpoint shutdown completed
    ShutdownCompleted,

    // Performance events
    /// Actor tick completed
    ActorTick,
    /// Cleanup performed
    CleanupPerformed,
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionEstablished => write!(f, "connection_established"),
            Self::ConnectionClosed => write!(f, "connection_closed"),
            Self::ConnectionFailed => write!(f, "connection_failed"),
            Self::ConnectionMigrated => write!(f, "connection_migrated"),
            Self::CandidateDiscovered => write!(f, "candidate_discovered"),
            Self::CandidateValidated => write!(f, "candidate_validated"),
            Self::CandidateFailed => write!(f, "candidate_failed"),
            Self::HolePunchStarted => write!(f, "hole_punch_started"),
            Self::HolePunchSucceeded => write!(f, "hole_punch_succeeded"),
            Self::HolePunchFailed => write!(f, "hole_punch_failed"),
            Self::PathSelected => write!(f, "path_selected"),
            Self::PathChanged => write!(f, "path_changed"),
            Self::PathClosed => write!(f, "path_closed"),
            Self::PathRttUpdated => write!(f, "path_rtt_updated"),
            Self::PacketSent => write!(f, "packet_sent"),
            Self::PacketReceived => write!(f, "packet_received"),
            Self::TransportError => write!(f, "transport_error"),
            Self::DiscoveryStarted => write!(f, "discovery_started"),
            Self::AddressDiscovered => write!(f, "address_discovered"),
            Self::DiscoveryCompleted => write!(f, "discovery_completed"),
            Self::EndpointStarted => write!(f, "endpoint_started"),
            Self::ShutdownInitiated => write!(f, "shutdown_initiated"),
            Self::ShutdownCompleted => write!(f, "shutdown_completed"),
            Self::ActorTick => write!(f, "actor_tick"),
            Self::CleanupPerformed => write!(f, "cleanup_performed"),
        }
    }
}

impl StructuredEvent {
    /// Create a new event builder
    pub fn builder(component: EventComponent, kind: EventKind) -> StructuredEventBuilder {
        StructuredEventBuilder::new(component, kind)
    }

    /// Log this event using tracing
    pub fn log(&self) {
        match self.severity {
            EventSeverity::Trace => {
                tracing::trace!(
                    component = %self.component,
                    kind = %self.kind,
                    peer_id = ?self.peer_id,
                    addr = ?self.addr,
                    duration_ms = ?self.duration.map(|d| d.as_millis()),
                    count = ?self.count,
                    "{}",
                    self.message
                );
            }
            EventSeverity::Debug => {
                tracing::debug!(
                    component = %self.component,
                    kind = %self.kind,
                    peer_id = ?self.peer_id,
                    addr = ?self.addr,
                    duration_ms = ?self.duration.map(|d| d.as_millis()),
                    count = ?self.count,
                    "{}",
                    self.message
                );
            }
            EventSeverity::Info => {
                tracing::info!(
                    component = %self.component,
                    kind = %self.kind,
                    peer_id = ?self.peer_id,
                    addr = ?self.addr,
                    duration_ms = ?self.duration.map(|d| d.as_millis()),
                    count = ?self.count,
                    "{}",
                    self.message
                );
            }
            EventSeverity::Warn => {
                tracing::warn!(
                    component = %self.component,
                    kind = %self.kind,
                    peer_id = ?self.peer_id,
                    addr = ?self.addr,
                    duration_ms = ?self.duration.map(|d| d.as_millis()),
                    count = ?self.count,
                    "{}",
                    self.message
                );
            }
            EventSeverity::Error => {
                tracing::error!(
                    component = %self.component,
                    kind = %self.kind,
                    peer_id = ?self.peer_id,
                    addr = ?self.addr,
                    duration_ms = ?self.duration.map(|d| d.as_millis()),
                    count = ?self.count,
                    "{}",
                    self.message
                );
            }
        }
    }
}

/// Builder for structured events
#[derive(Debug)]
pub struct StructuredEventBuilder {
    component: EventComponent,
    kind: EventKind,
    severity: EventSeverity,
    message: Option<String>,
    peer_id: Option<PeerId>,
    addr: Option<SocketAddr>,
    duration: Option<Duration>,
    count: Option<u64>,
}

impl StructuredEventBuilder {
    /// Create a new builder
    pub fn new(component: EventComponent, kind: EventKind) -> Self {
        Self {
            component,
            kind,
            severity: EventSeverity::Info,
            message: None,
            peer_id: None,
            addr: None,
            duration: None,
            count: None,
        }
    }

    /// Set event severity
    pub fn severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set event message
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set associated peer ID
    pub fn peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Set associated address
    pub fn addr(mut self, addr: SocketAddr) -> Self {
        self.addr = Some(addr);
        self
    }

    /// Set associated duration
    pub fn duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Set associated count
    pub fn count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    /// Build the event
    pub fn build(self) -> StructuredEvent {
        StructuredEvent {
            severity: self.severity,
            component: self.component,
            kind: self.kind,
            message: self.message.unwrap_or_else(|| format!("{}", self.kind)),
            timestamp: Instant::now(),
            peer_id: self.peer_id,
            addr: self.addr,
            duration: self.duration,
            count: self.count,
        }
    }

    /// Build and log the event
    pub fn log(self) {
        self.build().log();
    }
}

/// Actor tick metrics for monitoring loop fairness
#[derive(Debug)]
pub struct ActorTickMetrics {
    /// Name of the actor
    name: &'static str,
    /// Total number of ticks
    tick_count: AtomicU64,
    /// Total processing time in nanoseconds
    total_time_ns: AtomicU64,
    /// Maximum tick duration in nanoseconds
    max_tick_ns: AtomicU64,
}

impl ActorTickMetrics {
    /// Create new actor tick metrics
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            tick_count: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
            max_tick_ns: AtomicU64::new(0),
        }
    }

    /// Record a tick with the given duration
    pub fn record_tick(&self, duration: Duration) {
        let ns = duration.as_nanos() as u64;

        self.tick_count.fetch_add(1, Ordering::Relaxed);
        self.total_time_ns.fetch_add(ns, Ordering::Relaxed);

        // Update max (relaxed ordering is fine for metrics)
        let mut current_max = self.max_tick_ns.load(Ordering::Relaxed);
        while ns > current_max {
            match self.max_tick_ns.compare_exchange_weak(
                current_max,
                ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }
    }

    /// Start timing a tick, returns a guard that records duration on drop
    pub fn start_tick(&self) -> TickGuard<'_> {
        TickGuard {
            metrics: self,
            start: Instant::now(),
        }
    }

    /// Get the actor name
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Get total tick count
    pub fn tick_count(&self) -> u64 {
        self.tick_count.load(Ordering::Relaxed)
    }

    /// Get average tick duration
    pub fn average_tick_duration(&self) -> Duration {
        let count = self.tick_count.load(Ordering::Relaxed);
        if count == 0 {
            return Duration::ZERO;
        }
        let total_ns = self.total_time_ns.load(Ordering::Relaxed);
        Duration::from_nanos(total_ns / count)
    }

    /// Get maximum tick duration
    pub fn max_tick_duration(&self) -> Duration {
        Duration::from_nanos(self.max_tick_ns.load(Ordering::Relaxed))
    }

    /// Get a snapshot of all metrics
    pub fn snapshot(&self) -> ActorTickSnapshot {
        ActorTickSnapshot {
            name: self.name,
            tick_count: self.tick_count(),
            average_duration: self.average_tick_duration(),
            max_duration: self.max_tick_duration(),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.tick_count.store(0, Ordering::Relaxed);
        self.total_time_ns.store(0, Ordering::Relaxed);
        self.max_tick_ns.store(0, Ordering::Relaxed);
    }
}

/// Guard that records tick duration on drop
pub struct TickGuard<'a> {
    metrics: &'a ActorTickMetrics,
    start: Instant,
}

impl<'a> Drop for TickGuard<'a> {
    fn drop(&mut self) {
        self.metrics.record_tick(self.start.elapsed());
    }
}

/// Snapshot of actor tick metrics
#[derive(Debug, Clone)]
pub struct ActorTickSnapshot {
    /// Actor name
    pub name: &'static str,
    /// Total tick count
    pub tick_count: u64,
    /// Average tick duration
    pub average_duration: Duration,
    /// Maximum tick duration
    pub max_duration: Duration,
}

impl fmt::Display for ActorTickSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ticks, avg={:?}, max={:?}",
            self.name, self.tick_count, self.average_duration, self.max_duration
        )
    }
}

/// Convenience macros for logging structured events
#[macro_export]
macro_rules! log_event {
    ($component:expr, $kind:expr, $msg:expr) => {
        $crate::structured_events::StructuredEvent::builder($component, $kind)
            .message($msg)
            .log()
    };
    ($component:expr, $kind:expr, $msg:expr, severity = $sev:expr) => {
        $crate::structured_events::StructuredEvent::builder($component, $kind)
            .message($msg)
            .severity($sev)
            .log()
    };
    ($component:expr, $kind:expr, $msg:expr, addr = $addr:expr) => {
        $crate::structured_events::StructuredEvent::builder($component, $kind)
            .message($msg)
            .addr($addr)
            .log()
    };
    ($component:expr, $kind:expr, $msg:expr, peer = $peer:expr) => {
        $crate::structured_events::StructuredEvent::builder($component, $kind)
            .message($msg)
            .peer_id($peer)
            .log()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_severity_ordering() {
        assert!(EventSeverity::Trace < EventSeverity::Debug);
        assert!(EventSeverity::Debug < EventSeverity::Info);
        assert!(EventSeverity::Info < EventSeverity::Warn);
        assert!(EventSeverity::Warn < EventSeverity::Error);
    }

    #[test]
    fn test_event_builder() {
        let event = StructuredEvent::builder(EventComponent::Connection, EventKind::ConnectionEstablished)
            .severity(EventSeverity::Info)
            .message("Connection established")
            .addr("192.168.1.1:5000".parse().unwrap())
            .build();

        assert_eq!(event.component, EventComponent::Connection);
        assert_eq!(event.kind, EventKind::ConnectionEstablished);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.message, "Connection established");
        assert_eq!(event.addr, Some("192.168.1.1:5000".parse().unwrap()));
    }

    #[test]
    fn test_event_builder_defaults() {
        let event = StructuredEvent::builder(EventComponent::Discovery, EventKind::DiscoveryStarted)
            .build();

        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.message, "discovery_started");
        assert!(event.peer_id.is_none());
        assert!(event.addr.is_none());
    }

    #[test]
    fn test_actor_tick_metrics() {
        let metrics = ActorTickMetrics::new("test_actor");

        metrics.record_tick(Duration::from_millis(10));
        metrics.record_tick(Duration::from_millis(20));
        metrics.record_tick(Duration::from_millis(5));

        assert_eq!(metrics.tick_count(), 3);
        assert_eq!(metrics.max_tick_duration(), Duration::from_millis(20));

        let avg = metrics.average_tick_duration();
        // Average should be around 11.66ms
        assert!(avg.as_millis() >= 10 && avg.as_millis() <= 13);
    }

    #[test]
    fn test_actor_tick_guard() {
        let metrics = ActorTickMetrics::new("test_actor");

        {
            let _guard = metrics.start_tick();
            std::thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(metrics.tick_count(), 1);
        assert!(metrics.max_tick_duration() >= Duration::from_millis(4));
    }

    #[test]
    fn test_actor_tick_reset() {
        let metrics = ActorTickMetrics::new("test_actor");

        metrics.record_tick(Duration::from_millis(10));
        assert_eq!(metrics.tick_count(), 1);

        metrics.reset();
        assert_eq!(metrics.tick_count(), 0);
        assert_eq!(metrics.max_tick_duration(), Duration::ZERO);
    }

    #[test]
    fn test_actor_tick_snapshot() {
        let metrics = ActorTickMetrics::new("test_actor");
        metrics.record_tick(Duration::from_millis(10));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.name, "test_actor");
        assert_eq!(snapshot.tick_count, 1);
    }

    #[test]
    fn test_event_component_display() {
        assert_eq!(format!("{}", EventComponent::NatTraversal), "nat_traversal");
        assert_eq!(format!("{}", EventComponent::Connection), "connection");
        assert_eq!(format!("{}", EventComponent::PathSelection), "path_selection");
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(format!("{}", EventKind::ConnectionEstablished), "connection_established");
        assert_eq!(format!("{}", EventKind::HolePunchStarted), "hole_punch_started");
        assert_eq!(format!("{}", EventKind::PathSelected), "path_selected");
    }

    #[test]
    fn test_actor_tick_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let metrics = Arc::new(ActorTickMetrics::new("concurrent_actor"));
        let mut handles = vec![];

        for _ in 0..10 {
            let m = Arc::clone(&metrics);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m.record_tick(Duration::from_micros(1));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(metrics.tick_count(), 1000);
    }

    #[test]
    fn test_event_with_duration() {
        let event = StructuredEvent::builder(EventComponent::PathSelection, EventKind::PathRttUpdated)
            .duration(Duration::from_millis(42))
            .build();

        assert_eq!(event.duration, Some(Duration::from_millis(42)));
    }

    #[test]
    fn test_event_with_count() {
        let event = StructuredEvent::builder(EventComponent::NatTraversal, EventKind::CleanupPerformed)
            .count(5)
            .message("Cleaned up 5 expired candidates")
            .build();

        assert_eq!(event.count, Some(5));
    }
}
