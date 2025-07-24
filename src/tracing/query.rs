//! Query interface for trace analysis (debug builds only)

#[cfg(feature = "trace")]
mod implementation {
    use super::super::{EventLog, Event, TraceId};
    use super::super::event::EventData;
    use std::sync::Arc;
    use std::collections::HashMap;

    /// Query interface for analyzing traces
    pub struct TraceQuery {
        log: Arc<EventLog>,
    }

    impl TraceQuery {
        /// Create a new query interface
        pub fn new(log: Arc<EventLog>) -> Self {
            TraceQuery { log }
        }
        
        /// Get all events for a specific trace
        pub fn get_trace(&self, trace_id: TraceId) -> Vec<Event> {
            self.log.get_events_by_trace(trace_id)
        }
        
        /// Get the most recent events
        pub fn recent(&self, count: usize) -> Vec<Event> {
            self.log.get_recent_events(count)
        }
        
        /// Query events within a time range
        pub fn time_range(&self, start: u64, end: u64) -> Vec<Event> {
            self.log.get_events_in_range(start, end)
        }
        
        /// Get total event count
        pub fn event_count(&self) -> u64 {
            self.log.event_count()
        }
        
        /// Export trace as JSON (requires serde feature)
        #[cfg(feature = "serde")]
        pub fn export_json(&self, trace_id: TraceId) -> Result<String, serde_json::Error> {
            let events = self.get_trace(trace_id);
            serde_json::to_string_pretty(&events)
        }
        
        /// Analyze connection performance for a trace
        pub fn analyze_connection(&self, trace_id: TraceId) -> ConnectionAnalysis {
            let events = self.get_trace(trace_id);
            let mut analysis = ConnectionAnalysis::default();
            
            for event in events {
                match &event.event_data {
                    EventData::PacketSent { size, .. } => {
                        analysis.packets_sent += 1;
                        analysis.bytes_sent += *size as u64;
                    }
                    EventData::PacketReceived { size, .. } => {
                        analysis.packets_received += 1;
                        analysis.bytes_received += *size as u64;
                    }
                    EventData::PacketLost { .. } => {
                        analysis.packets_lost += 1;
                    }
                    EventData::ConnEstablished { rtt, .. } => {
                        analysis.initial_rtt = Some(*rtt);
                    }
                    _ => {}
                }
            }
            
            if analysis.packets_sent > 0 {
                analysis.loss_rate = analysis.packets_lost as f32 / analysis.packets_sent as f32;
            }
            
            analysis
        }
        
        /// Find traces with errors or issues
        pub fn find_problematic_traces(&self, recent_count: usize) -> Vec<TraceId> {
            let events = self.recent(recent_count);
            let mut problematic = Vec::new();
            let mut trace_issues = HashMap::new();
            
            for event in events {
                match &event.event_data {
                    EventData::PacketLost { .. } => {
                        *trace_issues.entry(event.trace_id).or_insert(0) += 1;
                    }
                    EventData::StreamClosed { error_code, .. } if *error_code != 0 => {
                        *trace_issues.entry(event.trace_id).or_insert(0) += 10;
                    }
                    _ => {}
                }
            }
            
            // Consider traces with issues as problematic
            for (trace_id, issue_count) in trace_issues {
                if issue_count > 5 {
                    problematic.push(trace_id);
                }
            }
            
            problematic
        }
    }

    /// Analysis results for a connection
    #[derive(Debug, Default)]
    pub struct ConnectionAnalysis {
        pub packets_sent: u64,
        pub packets_received: u64,
        pub packets_lost: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub loss_rate: f32,
        pub initial_rtt: Option<u32>,
    }
}

#[cfg(not(feature = "trace"))]
mod implementation {
    use super::super::{EventLog, Event, TraceId};
    use std::sync::Arc;

    /// Query interface for analyzing traces (no-op when trace is disabled)
    pub struct TraceQuery;

    impl TraceQuery {
        pub fn new(_log: Arc<EventLog>) -> Self {
            TraceQuery
        }
        
        pub fn get_trace(&self, _trace_id: TraceId) -> Vec<Event> {
            vec![]
        }
        
        pub fn recent(&self, _count: usize) -> Vec<Event> {
            vec![]
        }
        
        pub fn time_range(&self, _start: u64, _end: u64) -> Vec<Event> {
            vec![]
        }
        
        pub fn event_count(&self) -> u64 {
            0
        }
        
        pub fn analyze_connection(&self, _trace_id: TraceId) -> ConnectionAnalysis {
            ConnectionAnalysis::default()
        }
        
        pub fn find_problematic_traces(&self, _recent_count: usize) -> Vec<TraceId> {
            vec![]
        }
    }

    /// Analysis results for a connection
    #[derive(Debug, Default)]
    pub struct ConnectionAnalysis {
        pub packets_sent: u64,
        pub packets_received: u64,
        pub packets_lost: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub loss_rate: f32,
        pub initial_rtt: Option<u32>,
    }
}

// Re-export from implementation
#[cfg(feature = "trace")]
pub use implementation::*;

#[cfg(test)]
mod tests {
    #[cfg(feature = "trace")]
    use super::*;
    #[cfg(feature = "trace")]
    use crate::tracing::{EventLog, Event, TraceId};
    #[cfg(feature = "trace")]
    use std::sync::Arc;
    
    #[test]
    #[cfg(feature = "trace")]
    fn test_query_interface() {
        let log = Arc::new(EventLog::new());
        let query = TraceQuery::new(log.clone());
        
        let trace_id = TraceId::new();
        
        // Log some events
        log.log(Event::conn_init("127.0.0.1:8080".parse().unwrap(), trace_id));
        log.log(Event::packet_sent(1200, 1, trace_id));
        log.log(Event::packet_sent(1200, 2, trace_id));
        log.log(Event::packet_received(1200, 1, trace_id));
        
        // Query and analyze
        let analysis = query.analyze_connection(trace_id);
        assert_eq!(analysis.packets_sent, 2);
        assert_eq!(analysis.packets_received, 1);
        assert_eq!(analysis.bytes_sent, 2400);
        assert_eq!(analysis.bytes_received, 1200);
    }
    
    #[test]
    #[cfg(not(feature = "trace"))]
    fn test_zero_cost_query() {
        use crate::tracing::{EventLog, TraceId};
        use std::sync::Arc;
        
        let log = Arc::new(EventLog::new());
        let query = super::implementation::TraceQuery::new(log);
        
        // All operations should be no-ops
        assert_eq!(query.event_count(), 0);
        assert!(query.recent(10).is_empty());
        assert!(query.get_trace(TraceId::new()).is_empty());
    }
}