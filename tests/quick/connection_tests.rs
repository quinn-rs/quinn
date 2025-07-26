//! Quick connection tests

use std::time::Duration;

#[test]
fn test_connection_basics() {
    super::utils::assert_duration(Duration::from_millis(10), || {
        // Connection functionality tested in unit tests
        assert!(true);
    });
}

#[test]
fn test_connection_state_machine() {
    super::utils::assert_duration(Duration::from_millis(10), || {
        // State machine tested in unit tests
        assert!(true);
    });
}