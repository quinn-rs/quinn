//! Application protocol integration for tracing

use dashmap::DashMap;
use std::sync::Arc;

/// Trait for application protocols to implement tracing
pub trait AppProtocol: Send + Sync {
    /// Unique 4-byte identifier for this protocol
    const APP_ID: [u8; 4];
    
    /// Convert application command and payload to trace data
    fn to_trace_data(&self, cmd: u16, payload: &[u8]) -> [u8; 42];
    
    /// Get human-readable description of a command
    fn describe_command(&self, cmd: u16) -> &'static str;
    
    /// Decide whether to trace this command (for sampling)
    fn should_trace(&self, cmd: u16) -> bool {
        true // Default: trace everything
    }
}

/// Registry for application protocols
pub struct AppRegistry {
    apps: DashMap<[u8; 4], Arc<dyn AppProtocol>>,
}

impl AppRegistry {
    /// Create a new app registry
    pub fn new() -> Self {
        AppRegistry {
            apps: DashMap::new(),
        }
    }
    
    /// Register an application protocol
    pub fn register<A: AppProtocol + 'static>(&self, app: A) {
        self.apps.insert(A::APP_ID, Arc::new(app));
    }
    
    /// Get an application protocol by ID
    pub fn get(&self, app_id: &[u8; 4]) -> Option<Arc<dyn AppProtocol>> {
        self.apps.get(app_id).map(|entry| entry.clone())
    }
    
    /// Check if an app should trace a command
    pub fn should_trace(&self, app_id: &[u8; 4], cmd: u16) -> bool {
        if let Some(app) = self.get(app_id) {
            app.should_trace(cmd)
        } else {
            true // Default to tracing if app not registered
        }
    }
    
    /// Get command description
    pub fn describe_command(&self, app_id: &[u8; 4], cmd: u16) -> String {
        if let Some(app) = self.get(app_id) {
            app.describe_command(cmd).to_string()
        } else {
            format!("Unknown app {:?} cmd {}", app_id, cmd)
        }
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Example implementation for a data storage protocol
pub struct DataMapProtocol;

impl AppProtocol for DataMapProtocol {
    const APP_ID: [u8; 4] = *b"DMAP";
    
    fn to_trace_data(&self, cmd: u16, payload: &[u8]) -> [u8; 42] {
        let mut data = [0u8; 42];
        
        match cmd {
            0x01 => { // STORE
                if payload.len() >= 36 {
                    data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                    data[32..36].copy_from_slice(&payload[32..36]); // size
                }
            }
            0x02 => { // GET
                if payload.len() >= 32 {
                    data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                }
            }
            0x03 => { // DELETE
                if payload.len() >= 32 {
                    data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                }
            }
            _ => {
                // Copy what we can
                let len = payload.len().min(42);
                data[..len].copy_from_slice(&payload[..len]);
            }
        }
        
        data
    }
    
    fn describe_command(&self, cmd: u16) -> &'static str {
        match cmd {
            0x01 => "STORE_CHUNK",
            0x02 => "GET_CHUNK",
            0x03 => "DELETE_CHUNK",
            0x04 => "CHUNK_EXISTS",
            _ => "UNKNOWN",
        }
    }
    
    fn should_trace(&self, cmd: u16) -> bool {
        match cmd {
            0x04 => false, // Don't trace existence checks (too frequent)
            _ => true,
        }
    }
}

/// Create an app command event
#[macro_export]
macro_rules! trace_app_command {
    ($log:expr, $trace_id:expr, $app_id:expr, $cmd:expr, $data:expr) => {
        $crate::if_trace! {
            if $crate::tracing::global_app_registry().should_trace(&$app_id, $cmd) {
                $crate::trace_event!($log, $crate::tracing::Event {
                    timestamp: $crate::tracing::timestamp_now(),
                    trace_id: $trace_id,
                    event_data: $crate::tracing::EventData::AppCommand {
                        app_id: $app_id,
                        cmd: $cmd,
                        data: $data,
                        _padding: [0u8; 16],
                    },
                    ..Default::default()
                })
            }
        }
    };
}

// Global app registry
static APP_REGISTRY: once_cell::sync::Lazy<AppRegistry> = 
    once_cell::sync::Lazy::new(AppRegistry::new);

/// Get the global app registry
pub fn global_app_registry() -> &'static AppRegistry {
    &APP_REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_app_protocol() {
        let protocol = DataMapProtocol;
        
        assert_eq!(protocol.describe_command(0x01), "STORE_CHUNK");
        assert_eq!(protocol.describe_command(0x02), "GET_CHUNK");
        assert_eq!(protocol.describe_command(0xFF), "UNKNOWN");
        
        assert!(protocol.should_trace(0x01));
        assert!(!protocol.should_trace(0x04));
    }
    
    #[test]
    fn test_app_registry() {
        let registry = AppRegistry::new();
        registry.register(DataMapProtocol);
        
        assert!(registry.get(&DataMapProtocol::APP_ID).is_some());
        assert!(registry.should_trace(&DataMapProtocol::APP_ID, 0x01));
        assert!(!registry.should_trace(&DataMapProtocol::APP_ID, 0x04));
        
        let desc = registry.describe_command(&DataMapProtocol::APP_ID, 0x01);
        assert_eq!(desc, "STORE_CHUNK");
    }
}