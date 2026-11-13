//! Ownership accounting for events waiting between endpoint and connection drivers.
use crate::ConnectionEvent;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::mpsc;

#[derive(Debug)]
struct Credit {
    bytes: u64,
    queued: Arc<AtomicU64>,
}
impl Drop for Credit {
    fn drop(&mut self) {
        self.queued.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}
#[derive(Debug)]
struct Queued {
    event: ConnectionEvent,
    _credit: Credit,
}
#[derive(Debug, Clone)]
pub(crate) struct Sender {
    inner: mpsc::UnboundedSender<Queued>,
    queued: Arc<AtomicU64>,
}
#[derive(Debug)]
pub(crate) struct Receiver {
    inner: mpsc::UnboundedReceiver<Queued>,
    queued: Arc<AtomicU64>,
}
pub(crate) fn channel() -> (Sender, Receiver) {
    let (inner, receiver) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicU64::new(0));
    (
        Sender {
            inner,
            queued: queued.clone(),
        },
        Receiver {
            inner: receiver,
            queued,
        },
    )
}
impl Sender {
    pub(crate) fn send(&self, event: ConnectionEvent) -> Result<(), ()> {
        let heap = match &event {
            ConnectionEvent::Proto(event) => event.estimated_heap_bytes(),
            ConnectionEvent::Close { reason, .. } => reason.len() as u64,
            ConnectionEvent::Rebind(_) => 0,
        };
        let bytes = heap.saturating_add(size_of::<Queued>() as u64);
        self.queued.fetch_add(bytes, Ordering::Relaxed);
        self.inner
            .send(Queued {
                event,
                _credit: Credit {
                    bytes,
                    queued: self.queued.clone(),
                },
            })
            .map_err(|_| ())
    }
}
impl Receiver {
    pub(crate) fn queued_bytes(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<ConnectionEvent>> {
        self.inner
            .poll_recv(cx)
            .map(|event| event.map(|Queued { event, _credit }| event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Queue accounting releases credit on dequeue, failed send and receiver destruction.
    #[test]
    fn releases_event_memory_on_all_ownership_paths() {
        let (sender, mut receiver) = channel();
        let event = || ConnectionEvent::Close {
            error_code: 0_u32.into(),
            reason: bytes::Bytes::from_static(b"test"),
        };
        sender.send(event()).unwrap();
        let expected = size_of::<Queued>() as u64 + 4;
        assert_eq!(receiver.queued_bytes(), expected);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(receiver.poll_recv(&mut cx), Poll::Ready(Some(_))));
        assert_eq!(receiver.queued_bytes(), 0);
        sender.send(event()).unwrap();
        drop(receiver);
        assert_eq!(sender.queued.load(Ordering::Relaxed), 0);
        assert!(sender.send(event()).is_err());
        assert_eq!(sender.queued.load(Ordering::Relaxed), 0);
    }
}
