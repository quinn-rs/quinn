//! Watchable state pattern
//!
//! Provides reactive state observation without polling or lock contention.
//! Based on tokio::sync::watch for efficient notification of state changes.

use std::ops::Deref;
use tokio::sync::watch;

/// A value that can be watched for changes
#[derive(Debug)]
pub struct Watchable<T> {
    sender: watch::Sender<T>,
}

impl<T: Clone + Send + Sync + 'static> Watchable<T> {
    /// Create a new watchable with initial value
    pub fn new(value: T) -> Self {
        let (sender, _) = watch::channel(value);
        Self { sender }
    }

    /// Get the current value
    pub fn get(&self) -> T {
        self.sender.borrow().clone()
    }

    /// Set a new value, notifying all watchers
    pub fn set(&self, value: T) {
        // Use send_modify to ensure the value is always updated,
        // even when there are no active receivers
        self.sender.send_modify(|v| *v = value);
    }

    /// Modify the value in place
    pub fn modify<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        self.sender.send_modify(f);
    }

    /// Create a watcher for this value
    pub fn watch(&self) -> Watcher<T> {
        Watcher {
            receiver: self.sender.subscribe(),
        }
    }

    /// Get a reference to the sender (for advanced use cases)
    pub fn sender(&self) -> &watch::Sender<T> {
        &self.sender
    }

    /// Check if there are any active watchers
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl<T: Clone + Default + Send + Sync + 'static> Default for Watchable<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// A watcher that receives updates from a Watchable
#[derive(Debug)]
pub struct Watcher<T> {
    receiver: watch::Receiver<T>,
}

impl<T: Clone> Watcher<T> {
    /// Wait for the value to change
    ///
    /// Returns `Ok(())` when the value has changed, or `Err` if the
    /// sender was dropped.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }

    /// Get the current value (cloned)
    pub fn borrow(&self) -> T {
        self.receiver.borrow().clone()
    }

    /// Get a reference to the current value
    pub fn borrow_ref(&self) -> impl Deref<Target = T> + '_ {
        self.receiver.borrow()
    }

    /// Check if the value has changed since last check
    pub fn has_changed(&self) -> bool {
        self.receiver.has_changed().unwrap_or(false)
    }

    /// Mark the current value as seen
    pub fn mark_unchanged(&mut self) {
        self.receiver.mark_unchanged();
    }
}

impl<T: Clone> Clone for Watcher<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
        }
    }
}

/// Extension to combine multiple watchers
pub struct CombinedWatcher<T1, T2> {
    watcher1: Watcher<T1>,
    watcher2: Watcher<T2>,
}

impl<T1: Clone, T2: Clone> CombinedWatcher<T1, T2> {
    /// Create a new combined watcher
    pub fn new(watcher1: Watcher<T1>, watcher2: Watcher<T2>) -> Self {
        Self { watcher1, watcher2 }
    }

    /// Wait for either value to change
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        tokio::select! {
            result = self.watcher1.changed() => result,
            result = self.watcher2.changed() => result,
        }
    }

    /// Get both current values
    pub fn borrow(&self) -> (T1, T2) {
        (self.watcher1.borrow(), self.watcher2.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_get_returns_current_value() {
        let watchable = Watchable::new(42);
        assert_eq!(watchable.get(), 42);
    }

    #[test]
    fn test_set_updates_value() {
        let watchable = Watchable::new(0);
        watchable.set(100);
        assert_eq!(watchable.get(), 100);
    }

    #[tokio::test]
    async fn test_watch_notified_on_change() {
        let watchable = Arc::new(Watchable::new(0));
        let mut watcher = watchable.watch();

        // Spawn task to update value
        let w = watchable.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            w.set(42);
        });

        // Wait for change
        let result = timeout(Duration::from_millis(100), watcher.changed()).await;
        assert!(result.is_ok());
        assert_eq!(watcher.borrow(), 42);
    }

    #[tokio::test]
    async fn test_multiple_watchers() {
        let watchable = Arc::new(Watchable::new(0));
        let mut watcher1 = watchable.watch();
        let mut watcher2 = watchable.watch();

        watchable.set(99);

        // Both watchers should see the change
        let r1 = timeout(Duration::from_millis(50), watcher1.changed()).await;
        let r2 = timeout(Duration::from_millis(50), watcher2.changed()).await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(watcher1.borrow(), 99);
        assert_eq!(watcher2.borrow(), 99);
    }

    #[test]
    fn test_watch_borrow_returns_current() {
        let watchable = Watchable::new("hello".to_string());
        let watcher = watchable.watch();
        assert_eq!(watcher.borrow(), "hello");

        watchable.set("world".to_string());
        // borrow() returns current even without calling changed()
        assert_eq!(watcher.borrow(), "world");
    }

    #[test]
    fn test_modify_in_place() {
        let watchable = Watchable::new(vec![1, 2, 3]);
        watchable.modify(|v| v.push(4));
        assert_eq!(watchable.get(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_watchable_with_option() {
        let watchable: Watchable<Option<String>> = Watchable::new(None);
        assert_eq!(watchable.get(), None);

        watchable.set(Some("test".to_string()));
        assert_eq!(watchable.get(), Some("test".to_string()));
    }

    #[test]
    fn test_default_watchable() {
        let watchable: Watchable<i32> = Watchable::default();
        assert_eq!(watchable.get(), 0);
    }

    #[test]
    fn test_receiver_count() {
        let watchable = Watchable::new(0);
        assert_eq!(watchable.receiver_count(), 0);

        let _w1 = watchable.watch();
        assert_eq!(watchable.receiver_count(), 1);

        let _w2 = watchable.watch();
        assert_eq!(watchable.receiver_count(), 2);
    }

    #[test]
    fn test_watcher_has_changed() {
        let watchable = Watchable::new(0);
        let watcher = watchable.watch();

        // Initially no change
        assert!(!watcher.has_changed());

        // After set, has_changed returns true
        watchable.set(1);
        assert!(watcher.has_changed());
    }

    #[tokio::test]
    async fn test_combined_watcher() {
        let w1 = Watchable::new(1);
        let w2 = Watchable::new("a".to_string());

        let watcher1 = w1.watch();
        let watcher2 = w2.watch();

        let mut combined = CombinedWatcher::new(watcher1, watcher2);

        // Get current values
        let (v1, v2) = combined.borrow();
        assert_eq!(v1, 1);
        assert_eq!(v2, "a");

        // Update one value
        w1.set(2);

        // Combined should detect change
        let result = timeout(Duration::from_millis(50), combined.changed()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_watcher_clone() {
        let watchable = Watchable::new(42);
        let watcher1 = watchable.watch();
        let watcher2 = watcher1.clone();

        assert_eq!(watcher1.borrow(), watcher2.borrow());
    }

    #[tokio::test]
    async fn test_mark_unchanged() {
        let watchable = Watchable::new(0);
        let mut watcher = watchable.watch();

        watchable.set(1);
        assert!(watcher.has_changed());

        watcher.mark_unchanged();
        assert!(!watcher.has_changed());
    }
}
