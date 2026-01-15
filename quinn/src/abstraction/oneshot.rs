#[cfg(feature = "runtime-tokio")]
pub(crate) use tokio::sync::oneshot::{Receiver, Sender, channel};

#[cfg(all(feature = "runtime-smol", not(feature = "runtime-tokio")))]
pub(crate) use smol_impl::*;

#[cfg(all(feature = "runtime-smol", not(feature = "runtime-tokio")))]
mod smol_impl {
    use event_listener::{Event, EventListener};
    use std::fmt;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    /// Internal state of the oneshot channel.
    struct Inner<T> {
        /// The value, if it has been sent.
        value: Option<T>,
        /// Whether the channel is closed.
        closed: bool,
        /// Event for notifying the receiver when a value is sent.
        recv_event: Event,
        /// Event for notifying the sender when the receiver is closed.
        close_event: Event,
    }

    /// Create a new oneshot channel.
    ///
    /// Returns a sender and receiver pair. The sender can send exactly one value,
    /// and the receiver will receive it.
    pub(crate) fn channel<T>() -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(Mutex::new(Inner {
            value: None,
            closed: false,
            recv_event: Event::new(),
            close_event: Event::new(),
        }));
        (
            Sender {
                inner: inner.clone(),
            },
            Receiver {
                inner,
                listener: None,
            },
        )
    }

    /// The sending half of a oneshot channel.
    ///
    /// A `Sender` can be used to send a single value to the corresponding [`Receiver`].
    pub(crate) struct Sender<T> {
        inner: Arc<Mutex<Inner<T>>>,
    }

    impl<T> Sender<T> {
        /// Send a value on the channel.
        ///
        /// This consumes the sender. Returns an error containing the value if the
        /// receiver has been dropped.
        pub(crate) fn send(self, value: T) -> Result<(), T> {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                return Err(value);
            }
            inner.value = Some(value);
            inner.recv_event.notify(usize::MAX);
            Ok(())
        }
    }

    impl<T> Drop for Sender<T> {
        fn drop(&mut self) {
            let inner = self.inner.lock().unwrap();
            // Wake up the receiver to let it know the sender is gone
            inner.recv_event.notify(usize::MAX);
        }
    }

    impl<T> fmt::Debug for Sender<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Sender").finish_non_exhaustive()
        }
    }

    /// The receiving half of a oneshot channel.
    ///
    /// A `Receiver` can be awaited to receive the value sent by the corresponding [`Sender`].
    pub(crate) struct Receiver<T> {
        inner: Arc<Mutex<Inner<T>>>,
        listener: Option<Pin<Box<EventListener>>>,
    }

    impl<T> Receiver<T> {
        /// Try to receive the value without blocking.
        ///
        /// Returns `Ok(value)` if the value has been sent,
        /// `Err(TryRecvError::Empty)` if no value has been sent yet,
        /// or `Err(TryRecvError::Closed)` if the sender has been dropped.
        #[allow(dead_code)]
        pub(crate) fn try_recv(&mut self) -> Result<T, TryRecvError> {
            let mut inner = self.inner.lock().unwrap();
            if let Some(value) = inner.value.take() {
                Ok(value)
            } else if Arc::strong_count(&self.inner) == 1 {
                // Only this Receiver holds a reference, sender must be dropped
                Err(TryRecvError::Closed)
            } else {
                Err(TryRecvError::Empty)
            }
        }

        /// Close the channel.
        ///
        /// This signals to the sender that the receiver is no longer interested.
        fn close(&mut self) {
            let mut inner = self.inner.lock().unwrap();
            inner.closed = true;
            inner.close_event.notify(usize::MAX);
        }
    }

    impl<T> Future for Receiver<T> {
        type Output = Result<T, RecvError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = unsafe { self.get_unchecked_mut() };

            loop {
                // First, always check for the value
                {
                    let mut inner = this.inner.lock().unwrap();
                    if let Some(value) = inner.value.take() {
                        return Poll::Ready(Ok(value));
                    }
                    // Check if sender is dropped (we're the only Arc holder)
                    if Arc::strong_count(&this.inner) == 1 {
                        return Poll::Ready(Err(RecvError));
                    }
                }

                // Create listener if we don't have one
                if this.listener.is_none() {
                    let inner = this.inner.lock().unwrap();
                    this.listener = Some(Box::pin(inner.recv_event.listen()));
                }

                // Check again after registering - the value might have arrived
                // between our check and listener registration
                {
                    let mut inner = this.inner.lock().unwrap();
                    if let Some(value) = inner.value.take() {
                        return Poll::Ready(Ok(value));
                    }
                    if Arc::strong_count(&this.inner) == 1 {
                        return Poll::Ready(Err(RecvError));
                    }
                }

                // Poll the listener
                let listener = this.listener.as_mut().unwrap();
                match listener.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        // Event was triggered, clear listener and loop to check value
                        this.listener = None;
                        // Continue the loop to check for value
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    impl<T> Drop for Receiver<T> {
        fn drop(&mut self) {
            // Mark as closed and notify the sender
            self.close();
        }
    }

    impl<T> fmt::Debug for Receiver<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Receiver").finish_non_exhaustive()
        }
    }

    /// Error returned when receiving from a closed channel.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct RecvError;

    impl fmt::Display for RecvError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "channel closed")
        }
    }

    impl std::error::Error for RecvError {}

    /// Error returned from [`Receiver::try_recv`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(dead_code)]
    pub(crate) enum TryRecvError {
        /// The channel is empty but not closed.
        Empty,
        /// The channel is closed.
        Closed,
    }

    impl fmt::Display for TryRecvError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Empty => write!(f, "channel empty"),
                Self::Closed => write!(f, "channel closed"),
            }
        }
    }

    impl std::error::Error for TryRecvError {}
}
