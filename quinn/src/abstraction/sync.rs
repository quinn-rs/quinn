#[cfg(feature = "runtime-tokio")]
pub(crate) use tokio::sync::{Notify, futures::Notified};

#[cfg(all(feature = "runtime-smol", not(feature = "runtime-tokio")))]
pub(crate) use smol_impl::{Notified, Notify};

#[cfg(all(feature = "runtime-smol", not(feature = "runtime-tokio")))]
mod smol_impl {
    use event_listener::{Event, EventListener};
    use std::fmt;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    /// A notification primitive for waking tasks.
    pub(crate) struct Notify {
        /// The underlying event for broadcasting notifications.
        event: Event,
        /// Counter to track stored notifications for `notify_one` semantics.
        /// When a `notify_one` is called without any waiters, this is incremented.
        /// When a `Notified` future starts waiting, it checks this first.
        stored_notifications: AtomicUsize,
        /// Version counter incremented on each `notify_waiters()` call.
        /// Used to detect notifications that happened between `notified()`
        /// creation and the first poll.
        waiters_version: AtomicUsize,
    }

    impl Notify {
        /// Create a new `Notify` instance.
        #[inline]
        pub(crate) fn new() -> Self {
            Self {
                event: Event::new(),
                stored_notifications: AtomicUsize::new(0),
                waiters_version: AtomicUsize::new(0),
            }
        }

        /// Wait for a notification.
        #[inline]
        pub(crate) fn notified(&self) -> Notified<'_> {
            // Capture the current waiters_version to detect notify_waiters()
            // calls that happen between now and when we first poll.
            let version_at_creation = self.waiters_version.load(Ordering::SeqCst);

            Notified {
                notify: self,
                listener: None,
                state: NotifiedState::Init,
                version_at_creation,
            }
        }

        /// Notify all waiting tasks.
        #[inline]
        pub(crate) fn notify_waiters(&self) {
            // Increment version BEFORE notifying, so that any Notified
            // created before this point will see the new version on first poll.
            self.waiters_version.fetch_add(1, Ordering::SeqCst);
            self.event.notify(usize::MAX);
        }

        /// Notify a single waiting task.
        ///
        /// If there is a task waiting via [`notified`](Self::notified), it
        /// will be woken. If no task is waiting, the notification is stored
        /// and the next call to `notified` will complete immediately.
        #[inline]
        #[allow(dead_code)]
        pub(crate) fn notify_one(&self) {
            // First try to notify a waiter
            if self.event.notify(1) == 0 {
                // No waiters, store the notification
                self.stored_notifications.fetch_add(1, Ordering::SeqCst);
            }
        }

        /// Try to consume a stored notification.
        fn try_consume_stored(&self) -> bool {
            loop {
                let current = self.stored_notifications.load(Ordering::SeqCst);
                if current == 0 {
                    return false;
                }

                if self
                    .stored_notifications
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return true;
                }
            }
        }
    }

    impl Default for Notify {
        #[inline]
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Debug for Notify {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Notify")
                .field(
                    "stored_notifications",
                    &self.stored_notifications.load(Ordering::Relaxed),
                )
                .field(
                    "waiters_version",
                    &self.waiters_version.load(Ordering::Relaxed),
                )
                .finish_non_exhaustive()
        }
    }

    /// State machine for the Notified future
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NotifiedState {
        /// Initial state, haven't checked for stored notifications yet
        Init,
        /// Listener has been created and is waiting
        Waiting,
        /// Notification has been received
        Done,
    }

    /// A future that completes when the associated [`Notify`] is signaled.
    #[must_use = "futures do nothing unless polled"]
    pub(crate) struct Notified<'a> {
        notify: &'a Notify,
        listener: Option<Pin<Box<EventListener>>>,
        state: NotifiedState,
        version_at_creation: usize,
    }

    impl Future for Notified<'_> {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            // Safety: We're only modifying fields, not moving the pinned data
            let this = unsafe { self.get_unchecked_mut() };

            loop {
                match this.state {
                    NotifiedState::Init => {
                        let current_version = this.notify.waiters_version.load(Ordering::SeqCst);
                        if current_version != this.version_at_creation {
                            this.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }

                        // Check for a stored notification
                        if this.notify.try_consume_stored() {
                            this.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }

                        // No notification yet, create and register the listener.
                        this.listener = Some(Box::pin(this.notify.event.listen()));
                        this.state = NotifiedState::Waiting;

                        // Check version again after registering, in case notify_waiters()
                        // was called between our check above and registering the listener.
                        let current_version = this.notify.waiters_version.load(Ordering::SeqCst);
                        if current_version != this.version_at_creation {
                            this.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }
                    }

                    NotifiedState::Waiting => {
                        // Check again for stored notifications (might've been added)
                        if this.notify.try_consume_stored() {
                            this.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }

                        // Also check version in case notify_waiters() was called
                        let current_version = this.notify.waiters_version.load(Ordering::SeqCst);
                        if current_version != this.version_at_creation {
                            this.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }

                        // Poll the listener
                        let listener = this
                            .listener
                            .as_mut()
                            .expect("listener must exist in Waiting state");

                        match listener.as_mut().poll(cx) {
                            Poll::Ready(()) => {
                                this.state = NotifiedState::Done;
                                return Poll::Ready(());
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    NotifiedState::Done => {
                        // Already notified, return immediately
                        return Poll::Ready(());
                    }
                }
            }
        }
    }

    impl fmt::Debug for Notified<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Notified")
                .field("state", &self.state)
                .field("version_at_creation", &self.version_at_creation)
                .finish_non_exhaustive()
        }
    }

    // Safety: Event and EventListener are Send + Sync
    unsafe impl Send for Notify {}
    unsafe impl Sync for Notify {}
    unsafe impl Send for Notified<'_> {}
    unsafe impl Sync for Notified<'_> {}
}
