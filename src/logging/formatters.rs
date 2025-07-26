/// Log formatting utilities
/// 
/// Provides various utility functions for formatting log data

use crate::{ConnectionId, Duration};

/// Format bytes in a human-readable way
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Format duration in a human-readable way
pub fn format_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros < 1000 {
        format!("{micros}μs")
    } else if micros < 1_000_000 {
        format!("{:.2}ms", micros as f64 / 1000.0)
    } else if micros < 60_000_000 {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    } else {
        let seconds = micros / 1_000_000;
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        format!("{minutes}m{seconds}s")
    }
}

/// Format a connection ID for display
pub fn format_conn_id(conn_id: &ConnectionId) -> String {
    let bytes = conn_id.as_ref();
    if bytes.len() <= 8 {
        hex::encode(bytes)
    } else {
        format!("{}..{}", 
            hex::encode(&bytes[..4]),
            hex::encode(&bytes[bytes.len()-4..])
        )
    }
}

/// Format a structured log event as JSON  
pub(super) fn format_as_json(event: &super::LogEvent) -> String {
    use serde_json::json;
    
    let json = json!({
        "timestamp": event.timestamp.elapsed().as_secs(),
        "level": match event.level {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARN",
            tracing::Level::INFO => "INFO",
            tracing::Level::DEBUG => "DEBUG",
            tracing::Level::TRACE => "TRACE",
        },
        "target": event.target,
        "message": event.message,
        "fields": event.fields,
        "span_id": event.span_id,
    });
    
    json.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
    
    #[test]
    fn test_format_duration() {
        use crate::Duration;
        
        assert_eq!(format_duration(Duration::from_micros(500)), "500μs");
        assert_eq!(format_duration(Duration::from_micros(1500)), "1.50ms");
        assert_eq!(format_duration(Duration::from_millis(50)), "50.00ms");
        assert_eq!(format_duration(Duration::from_secs(5)), "5.00s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m5s");
    }
}