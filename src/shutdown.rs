//! Coordinated shutdown for ant-quic endpoints
//!
//! Implements staged shutdown:
//! 1. Stop accepting new work
//! 2. Drain existing work with timeout
//! 3. Cancel remaining tasks
//! 4. Clean up resources

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default timeout for graceful shutdown
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// Timeout for waiting on individual tasks
pub const TASK_ABORT_TIMEOUT: Duration = Duration::from_millis(100);

/// Coordinates shutdown across all endpoint components
pub struct ShutdownCoordinator {
    /// Token cancelled when shutdown starts (stop accepting new work)
    close_start: CancellationToken,

    /// Token cancelled after connections drained
    close_complete: CancellationToken,

    /// Whether shutdown has been initiated
    shutdown_initiated: AtomicBool,

    /// Count of active background tasks
    active_tasks: Arc<AtomicUsize>,

    /// Notified when all tasks complete
    tasks_complete: Arc<Notify>,

    /// Tracked task handles
    task_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for ShutdownCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownCoordinator")
            .field("shutdown_initiated", &self.shutdown_initiated)
            .field("active_tasks", &self.active_tasks)
            .finish_non_exhaustive()
    }
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            close_start: CancellationToken::new(),
            close_complete: CancellationToken::new(),
            shutdown_initiated: AtomicBool::new(false),
            active_tasks: Arc::new(AtomicUsize::new(0)),
            tasks_complete: Arc::new(Notify::new()),
            task_handles: Mutex::new(Vec::new()),
        })
    }

    /// Get a token that is cancelled when shutdown starts
    pub fn close_start_token(&self) -> CancellationToken {
        self.close_start.clone()
    }

    /// Get a token that is cancelled when shutdown completes
    pub fn close_complete_token(&self) -> CancellationToken {
        self.close_complete.clone()
    }

    /// Check if shutdown has been initiated
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_initiated.load(Ordering::SeqCst)
    }

    /// Register a background task for tracking
    pub fn register_task(&self, handle: JoinHandle<()>) {
        self.active_tasks.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut handles) = self.task_handles.lock() {
            handles.push(handle);
        }
    }

    /// Spawn a tracked task that respects the shutdown token
    pub fn spawn_tracked<F>(self: &Arc<Self>, future: F) -> JoinHandle<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let tasks_complete = Arc::clone(&self.tasks_complete);
        let task_counter = Arc::clone(&self.active_tasks);

        // Increment task count before spawning
        self.active_tasks.fetch_add(1, Ordering::SeqCst);

        tokio::spawn(async move {
            future.await;
            // Decrement and notify if last task
            if task_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
                tasks_complete.notify_waiters();
            }
        })
    }

    /// Get count of active tasks
    pub fn active_task_count(&self) -> usize {
        self.active_tasks.load(Ordering::SeqCst)
    }

    /// Execute coordinated shutdown
    pub async fn shutdown(&self) {
        // Prevent multiple shutdown attempts
        if self.shutdown_initiated.swap(true, Ordering::SeqCst) {
            debug!("Shutdown already in progress");
            return;
        }

        info!("Starting coordinated shutdown");

        // Stage 1: Signal close start (stop accepting new work)
        debug!("Stage 1: Signaling close start");
        self.close_start.cancel();

        // Stage 2: Wait for tasks with timeout
        debug!("Stage 2: Waiting for tasks to complete");
        let wait_result = timeout(DEFAULT_SHUTDOWN_TIMEOUT, self.wait_for_tasks()).await;

        if wait_result.is_err() {
            warn!("Shutdown timeout - aborting remaining tasks");
        }

        // Stage 3: Abort any remaining tasks
        debug!("Stage 3: Aborting remaining tasks");
        self.abort_remaining_tasks().await;

        // Stage 4: Signal close complete
        debug!("Stage 4: Signaling close complete");
        self.close_complete.cancel();

        info!("Shutdown complete");
    }

    /// Wait for all tasks to complete
    async fn wait_for_tasks(&self) {
        while self.active_tasks.load(Ordering::SeqCst) > 0 {
            self.tasks_complete.notified().await;
        }
    }

    /// Abort any tasks that didn't complete gracefully
    async fn abort_remaining_tasks(&self) {
        let handles: Vec<_> = if let Ok(mut guard) = self.task_handles.lock() {
            guard.drain(..).collect()
        } else {
            Vec::new()
        };

        for handle in handles {
            if !handle.is_finished() {
                handle.abort();
                // Give a moment for abort to take effect
                let _ = timeout(TASK_ABORT_TIMEOUT, async {
                    // Wait for task to actually finish
                    let _ = handle.await;
                })
                .await;
            }
        }

        self.active_tasks.store(0, Ordering::SeqCst);
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self {
            close_start: CancellationToken::new(),
            close_complete: CancellationToken::new(),
            shutdown_initiated: AtomicBool::new(false),
            active_tasks: Arc::new(AtomicUsize::new(0)),
            tasks_complete: Arc::new(Notify::new()),
            task_handles: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_shutdown_completes_within_timeout() {
        let coordinator = ShutdownCoordinator::new();

        let start = Instant::now();
        coordinator.shutdown().await;

        assert!(start.elapsed() < DEFAULT_SHUTDOWN_TIMEOUT + Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_shutdown_is_idempotent() {
        let coordinator = ShutdownCoordinator::new();

        // Multiple shutdowns should not panic
        coordinator.shutdown().await;
        coordinator.shutdown().await;
        coordinator.shutdown().await;
    }

    #[tokio::test]
    async fn test_is_shutting_down_flag() {
        let coordinator = ShutdownCoordinator::new();

        assert!(!coordinator.is_shutting_down());
        coordinator.shutdown().await;
        assert!(coordinator.is_shutting_down());
    }

    #[tokio::test]
    async fn test_close_start_token_cancelled() {
        let coordinator = ShutdownCoordinator::new();
        let token = coordinator.close_start_token();

        assert!(!token.is_cancelled());
        coordinator.shutdown().await;
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_close_complete_token_cancelled() {
        let coordinator = ShutdownCoordinator::new();
        let token = coordinator.close_complete_token();

        assert!(!token.is_cancelled());
        coordinator.shutdown().await;
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_spawn_tracked_increments_count() {
        let coordinator = ShutdownCoordinator::new();

        assert_eq!(coordinator.active_task_count(), 0);

        let _handle = coordinator.spawn_tracked(async {
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        // Task count should be incremented
        assert!(coordinator.active_task_count() >= 1);

        coordinator.shutdown().await;
    }

    #[tokio::test]
    async fn test_shutdown_with_long_running_tasks() {
        let coordinator = ShutdownCoordinator::new();

        // Spawn a task that would run forever
        let token = coordinator.close_start_token();
        let _handle = coordinator.spawn_tracked(async move {
            // Respect shutdown token
            token.cancelled().await;
        });

        // Shutdown should complete despite long-running task
        let start = Instant::now();
        coordinator.shutdown().await;

        // Should complete within timeout + buffer
        assert!(start.elapsed() < DEFAULT_SHUTDOWN_TIMEOUT + Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_task_completes_before_shutdown() {
        let coordinator = ShutdownCoordinator::new();

        // Spawn a short task
        let handle = coordinator.spawn_tracked(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        });

        // Wait for task to complete
        let _ = handle.await;

        // Shutdown should be quick
        let start = Instant::now();
        coordinator.shutdown().await;
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_multiple_tracked_tasks() {
        let coordinator = ShutdownCoordinator::new();
        let token = coordinator.close_start_token();

        // Spawn multiple tasks that respect shutdown
        for _ in 0..5 {
            let t = token.clone();
            coordinator.spawn_tracked(async move {
                t.cancelled().await;
            });
        }

        // All should be tracked
        assert!(coordinator.active_task_count() >= 5);

        // Shutdown should complete all
        coordinator.shutdown().await;
    }

    #[tokio::test]
    async fn test_task_decrements_on_completion() {
        let coordinator = ShutdownCoordinator::new();

        // Spawn a task that completes quickly
        let handle = coordinator.spawn_tracked(async {
            // Quick task
        });

        // Wait for task to complete
        let _ = handle.await;

        // Give a moment for counter to update
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Count should have decremented
        assert_eq!(coordinator.active_task_count(), 0);
    }
}
