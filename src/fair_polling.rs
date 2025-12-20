//! Fair polling for multiple transports
//!
//! Prevents starvation by alternating poll order between
//! direct and relay transports.

use std::sync::atomic::{AtomicU64, Ordering};

/// Order in which to poll transports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOrder {
    /// Poll direct transports first, then relay
    DirectFirst,
    /// Poll relay transports first, then direct
    RelayFirst,
}

/// Fair poller that alternates poll order to prevent starvation
#[derive(Debug)]
pub struct FairPoller {
    counter: AtomicU64,
}

impl FairPoller {
    /// Create a new fair poller
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Get the poll order for this iteration
    ///
    /// Increments counter and returns appropriate order.
    /// Alternates between DirectFirst and RelayFirst to ensure
    /// fair access to both transport types.
    pub fn poll_order(&self) -> PollOrder {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        if count % 2 == 0 {
            PollOrder::DirectFirst
        } else {
            PollOrder::RelayFirst
        }
    }

    /// Get the poll order without incrementing the counter
    pub fn peek_order(&self) -> PollOrder {
        let count = self.counter.load(Ordering::Relaxed);
        if count % 2 == 0 {
            PollOrder::DirectFirst
        } else {
            PollOrder::RelayFirst
        }
    }

    /// Reset the counter
    pub fn reset(&self) {
        self.counter.store(0, Ordering::Relaxed);
    }

    /// Get the current counter value
    pub fn counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Set counter (for testing)
    #[cfg(test)]
    pub fn set_counter(&self, value: u64) {
        self.counter.store(value, Ordering::Relaxed);
    }
}

impl Default for FairPoller {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to poll transports in fair order
///
/// Usage:
/// ```ignore
/// poll_transports_fair!(
///     poller,
///     poll_direct_transport(),
///     poll_relay_transport()
/// )
/// ```
#[macro_export]
macro_rules! poll_transports_fair {
    ($poller:expr, $direct:expr, $relay:expr) => {{
        use $crate::fair_polling::PollOrder;
        match $poller.poll_order() {
            PollOrder::DirectFirst => {
                if let Some(result) = $direct {
                    Some(result)
                } else {
                    $relay
                }
            }
            PollOrder::RelayFirst => {
                if let Some(result) = $relay {
                    Some(result)
                } else {
                    $direct
                }
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alternating_poll_order() {
        let poller = FairPoller::new();

        let order1 = poller.poll_order();
        let order2 = poller.poll_order();
        let order3 = poller.poll_order();
        let order4 = poller.poll_order();

        // Should alternate
        assert_eq!(order1, PollOrder::DirectFirst);
        assert_eq!(order2, PollOrder::RelayFirst);
        assert_eq!(order3, PollOrder::DirectFirst);
        assert_eq!(order4, PollOrder::RelayFirst);
    }

    #[test]
    fn test_counter_wraps() {
        let poller = FairPoller::new();

        // Set counter near max
        poller.set_counter(u64::MAX);

        // Should wrap without panic
        let _ = poller.poll_order();
        let _ = poller.poll_order();

        // Counter should have wrapped
        assert!(poller.counter() < u64::MAX);
    }

    #[test]
    fn test_poll_order_is_deterministic() {
        let poller = FairPoller::new();

        // Even counter: direct first
        poller.set_counter(0);
        assert_eq!(poller.poll_order(), PollOrder::DirectFirst);

        // Reset and check odd
        poller.set_counter(1);
        assert_eq!(poller.poll_order(), PollOrder::RelayFirst);
    }

    #[test]
    fn test_peek_does_not_increment() {
        let poller = FairPoller::new();

        let peek1 = poller.peek_order();
        let peek2 = poller.peek_order();
        let peek3 = poller.peek_order();

        // Should all be the same since counter isn't incremented
        assert_eq!(peek1, peek2);
        assert_eq!(peek2, peek3);
        assert_eq!(poller.counter(), 0);
    }

    #[test]
    fn test_reset() {
        let poller = FairPoller::new();

        poller.poll_order();
        poller.poll_order();
        poller.poll_order();

        assert_eq!(poller.counter(), 3);

        poller.reset();
        assert_eq!(poller.counter(), 0);
        assert_eq!(poller.peek_order(), PollOrder::DirectFirst);
    }

    #[test]
    fn test_default() {
        let poller = FairPoller::default();
        assert_eq!(poller.counter(), 0);
    }

    #[test]
    fn test_poll_transports_fair_macro_direct_first() {
        let poller = FairPoller::new();
        poller.set_counter(0); // DirectFirst

        let direct = Some(1);
        let relay: Option<i32> = Some(2);

        let result = poll_transports_fair!(poller, direct, relay);
        assert_eq!(result, Some(1)); // Direct should be selected
    }

    #[test]
    fn test_poll_transports_fair_macro_relay_first() {
        let poller = FairPoller::new();
        poller.set_counter(1); // RelayFirst

        let direct: Option<i32> = Some(1);
        let relay = Some(2);

        let result = poll_transports_fair!(poller, direct, relay);
        assert_eq!(result, Some(2)); // Relay should be selected
    }

    #[test]
    fn test_poll_transports_fair_macro_fallback() {
        let poller = FairPoller::new();
        poller.set_counter(0); // DirectFirst

        let direct: Option<i32> = None;
        let relay = Some(2);

        let result = poll_transports_fair!(poller, direct, relay);
        assert_eq!(result, Some(2)); // Should fall back to relay
    }

    #[test]
    fn test_poll_transports_fair_macro_both_none() {
        let poller = FairPoller::new();

        let direct: Option<i32> = None;
        let relay: Option<i32> = None;

        let result = poll_transports_fair!(poller, direct, relay);
        assert_eq!(result, None);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let poller = Arc::new(FairPoller::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let p = Arc::clone(&poller);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = p.poll_order();
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Should have incremented 1000 times
        assert_eq!(poller.counter(), 1000);
    }
}
