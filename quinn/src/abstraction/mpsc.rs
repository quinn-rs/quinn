#[cfg(feature = "runtime-tokio")]
pub(crate) use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

#[cfg(all(feature = "runtime-smol", not(feature = "runtime-tokio")))]
pub(crate) use smol_impl::*;

#[cfg(all(feature = "runtime-smol", not(feature = "runtime-tokio")))]
mod smol_impl {
    use std::fmt;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Creates an unbounded multi-producer, single-consumer channel.
    #[inline]
    pub(crate) fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
        let (tx, rx) = async_channel::unbounded();
        (
            UnboundedSender { inner: tx },
            UnboundedReceiver {
                inner: rx,
                recv_future: None,
            },
        )
    }

    /// The sending half of an unbounded channel.
    pub(crate) struct UnboundedSender<T> {
        inner: async_channel::Sender<T>,
    }

    impl<T> UnboundedSender<T> {
        /// Send a value into the channel.
        #[inline]
        pub(crate) fn send(&self, value: T) -> Result<(), SendError<T>> {
            // For unbounded channels, try_send never fails due to capacity
            self.inner.try_send(value).map_err(|e| match e {
                async_channel::TrySendError::Full(_) => {
                    unreachable!("unbounded channel cannot be full")
                }
                async_channel::TrySendError::Closed(v) => SendError(v),
            })
        }
    }

    impl<T> Clone for UnboundedSender<T> {
        #[inline]
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T> fmt::Debug for UnboundedSender<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("UnboundedSender").finish_non_exhaustive()
        }
    }

    // Type alias for the boxed receive future
    type RecvFuture<T> = Pin<Box<dyn Future<Output = Result<T, async_channel::RecvError>> + Send>>;

    /// The receiving half of an unbounded channel.
    pub(crate) struct UnboundedReceiver<T> {
        inner: async_channel::Receiver<T>,
        recv_future: Option<RecvFuture<T>>,
    }

    impl<T: Send + 'static> UnboundedReceiver<T> {
        /// Receive a value from the channel.
        #[inline]
        #[allow(dead_code)]
        pub(crate) async fn recv(&mut self) -> Option<T> {
            // Clear any pending poll_recv future since we're using async recv
            self.recv_future = None;
            self.inner.recv().await.ok()
        }

        /// Poll for a value from the channel.
        pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
            loop {
                // First, always try to receive without blocking
                // This handles the case where data arrived between polls
                match self.inner.try_recv() {
                    Ok(value) => {
                        // Got a value, clear any pending future
                        self.recv_future = None;
                        return Poll::Ready(Some(value));
                    }
                    Err(async_channel::TryRecvError::Closed) => {
                        self.recv_future = None;
                        return Poll::Ready(None);
                    }
                    Err(async_channel::TryRecvError::Empty) => {
                        // Channel is empty, need to wait
                    }
                }

                // Create the receive future if we don't have one
                if self.recv_future.is_none() {
                    let rx = self.inner.clone();
                    self.recv_future = Some(Box::pin(async move { rx.recv().await }));
                }

                // Poll the receive future
                let future = self.recv_future.as_mut().unwrap();
                match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(value)) => {
                        self.recv_future = None;
                        return Poll::Ready(Some(value));
                    }
                    Poll::Ready(Err(_)) => {
                        // Channel closed
                        self.recv_future = None;
                        return Poll::Ready(None);
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        }

        /// Try to receive a value from the channel without blocking.
        #[inline]
        #[allow(dead_code)]
        pub(crate) fn try_recv(&mut self) -> Result<T, TryRecvError> {
            self.inner.try_recv().map_err(|e| match e {
                async_channel::TryRecvError::Empty => TryRecvError::Empty,
                async_channel::TryRecvError::Closed => TryRecvError::Disconnected,
            })
        }
    }

    impl<T> fmt::Debug for UnboundedReceiver<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("UnboundedReceiver")
                .field("has_pending_recv", &self.recv_future.is_some())
                .finish_non_exhaustive()
        }
    }

    /// Error returned from [`UnboundedSender::send`] when the receiver
    /// has been dropped.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct SendError<T>(pub T);

    impl<T> fmt::Display for SendError<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "channel closed")
        }
    }

    impl<T: fmt::Debug> std::error::Error for SendError<T> {}

    /// Error returned from [`UnboundedReceiver::try_recv`].
    #[allow(dead_code)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum TryRecvError {
        /// The channel is empty but not closed.
        Empty,
        /// The channel is closed and empty.
        Disconnected,
    }

    impl fmt::Display for TryRecvError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Empty => write!(f, "channel empty"),
                Self::Disconnected => write!(f, "channel disconnected"),
            }
        }
    }

    impl std::error::Error for TryRecvError {}
}
