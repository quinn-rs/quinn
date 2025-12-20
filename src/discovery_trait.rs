//! Discovery trait for stream composition
//!
//! Provides a trait-based abstraction for address discovery that allows
//! composing multiple discovery sources into a unified stream.
//!
//! This is inspired by iroh's `Discovery` trait and `ConcurrentDiscovery`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{Stream, StreamExt};
use tokio::sync::mpsc;

use crate::nat_traversal_api::PeerId;

/// Information about a discovered address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAddress {
    /// The discovered socket address
    pub addr: SocketAddr,
    /// Source of the discovery
    pub source: DiscoverySource,
    /// Priority of this address (higher = better)
    pub priority: u32,
    /// Time-to-live for this discovery
    pub ttl: Option<Duration>,
}

/// Source of address discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    /// Discovered from local network interfaces
    LocalInterface,
    /// Discovered via peer exchange
    PeerExchange,
    /// Observed by a remote peer
    Observed,
    /// From configuration or known peers
    Config,
    /// Manual/explicit discovery
    Manual,
    /// From DNS resolution
    Dns,
}

impl DiscoverySource {
    /// Get base priority for this source
    pub fn base_priority(&self) -> u32 {
        match self {
            Self::Observed => 100, // Highest - verified by peer
            Self::LocalInterface => 90,
            Self::PeerExchange => 80,
            Self::Config => 70,
            Self::Dns => 60,
            Self::Manual => 50,
        }
    }
}

/// Result of a discovery operation
pub type DiscoveryResult = Result<DiscoveredAddress, DiscoveryError>;

/// Error from discovery operations
#[derive(Debug, Clone)]
pub struct DiscoveryError {
    /// Error message
    pub message: String,
    /// Source that failed
    pub source: Option<DiscoverySource>,
    /// Whether this error is retryable
    pub retryable: bool,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Discovery error: {}", self.message)
    }
}

impl std::error::Error for DiscoveryError {}

/// Trait for address discovery sources
///
/// Implementations provide a stream of discovered addresses
/// that can be composed with other discovery sources.
pub trait Discovery: Send + Sync + 'static {
    /// Discover addresses for a given peer
    ///
    /// Returns a stream of discovered addresses. The stream may
    /// continue indefinitely or terminate when discovery is complete.
    fn discover(
        &self,
        peer_id: &PeerId,
    ) -> Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>>;

    /// Get the name of this discovery source (for logging)
    fn name(&self) -> &'static str;
}

/// Combines multiple discovery sources into a concurrent stream
#[derive(Default)]
pub struct ConcurrentDiscovery {
    sources: Vec<Arc<dyn Discovery>>,
}

impl ConcurrentDiscovery {
    /// Create a new concurrent discovery with no sources
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a discovery source
    pub fn add_source<D: Discovery>(&mut self, source: D) {
        self.sources.push(Arc::new(source));
    }

    /// Add a boxed discovery source
    pub fn add_boxed_source(&mut self, source: Arc<dyn Discovery>) {
        self.sources.push(source);
    }

    /// Create a builder for fluent construction
    pub fn builder() -> ConcurrentDiscoveryBuilder {
        ConcurrentDiscoveryBuilder::new()
    }

    /// Discover addresses from all sources concurrently
    pub fn discover(&self, peer_id: &PeerId) -> ConcurrentDiscoveryStream {
        let mut streams = Vec::new();

        for source in &self.sources {
            streams.push(source.discover(peer_id));
        }

        ConcurrentDiscoveryStream::new(streams)
    }

    /// Number of discovery sources
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

/// Builder for ConcurrentDiscovery
#[derive(Default)]
pub struct ConcurrentDiscoveryBuilder {
    sources: Vec<Arc<dyn Discovery>>,
}

impl ConcurrentDiscoveryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a discovery source
    pub fn with_source<D: Discovery>(mut self, source: D) -> Self {
        self.sources.push(Arc::new(source));
        self
    }

    /// Build the concurrent discovery
    pub fn build(self) -> ConcurrentDiscovery {
        ConcurrentDiscovery {
            sources: self.sources,
        }
    }
}

/// Stream that polls multiple discovery sources concurrently
pub struct ConcurrentDiscoveryStream {
    streams: Vec<Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>>>,
    completed: Vec<bool>,
}

impl ConcurrentDiscoveryStream {
    fn new(streams: Vec<Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>>>) -> Self {
        let completed = vec![false; streams.len()];
        Self { streams, completed }
    }
}

impl Stream for ConcurrentDiscoveryStream {
    type Item = DiscoveryResult;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        // Check if all streams are done
        if this.completed.iter().all(|&c| c) {
            return Poll::Ready(None);
        }

        // Poll each stream, returning the first ready result
        for i in 0..this.streams.len() {
            if this.completed[i] {
                continue;
            }

            match this.streams[i].as_mut().poll_next(cx) {
                Poll::Ready(Some(result)) => {
                    return Poll::Ready(Some(result));
                }
                Poll::Ready(None) => {
                    this.completed[i] = true;
                }
                Poll::Pending => {}
            }
        }

        // Check again if all completed during this poll
        if this.completed.iter().all(|&c| c) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

/// A simple discovery source that yields addresses from a channel
pub struct ChannelDiscovery {
    name: &'static str,
    sender: mpsc::Sender<DiscoveredAddress>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<DiscoveredAddress>>>,
}

impl ChannelDiscovery {
    /// Create a new channel-based discovery
    pub fn new(name: &'static str, buffer_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(buffer_size);
        Self {
            name,
            sender,
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }

    /// Get a sender to push discovered addresses
    pub fn sender(&self) -> mpsc::Sender<DiscoveredAddress> {
        self.sender.clone()
    }

    /// Push a discovered address
    pub async fn push(
        &self,
        addr: DiscoveredAddress,
    ) -> Result<(), mpsc::error::SendError<DiscoveredAddress>> {
        self.sender.send(addr).await
    }
}

impl Discovery for ChannelDiscovery {
    fn discover(
        &self,
        _peer_id: &PeerId,
    ) -> Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>> {
        let receiver = self.receiver.clone();

        Box::pin(futures_util::stream::unfold(
            receiver,
            |receiver| async move {
                let mut guard = receiver.lock().await;
                guard.recv().await.map(|addr| (Ok(addr), receiver.clone()))
            },
        ))
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Discovery source from static/configured addresses
pub struct StaticDiscovery {
    addresses: Vec<DiscoveredAddress>,
}

impl StaticDiscovery {
    /// Create a new static discovery with the given addresses
    pub fn new(addresses: Vec<DiscoveredAddress>) -> Self {
        Self { addresses }
    }

    /// Create from socket addresses with default settings
    pub fn from_addrs(addrs: Vec<SocketAddr>) -> Self {
        let addresses = addrs
            .into_iter()
            .map(|addr| DiscoveredAddress {
                addr,
                source: DiscoverySource::Config,
                priority: DiscoverySource::Config.base_priority(),
                ttl: None,
            })
            .collect();
        Self { addresses }
    }
}

impl Discovery for StaticDiscovery {
    fn discover(
        &self,
        _peer_id: &PeerId,
    ) -> Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>> {
        let addresses = self.addresses.clone();
        Box::pin(futures_util::stream::iter(addresses.into_iter().map(Ok)))
    }

    fn name(&self) -> &'static str {
        "static"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    fn test_addr(port: u16) -> SocketAddr {
        format!("192.168.1.1:{}", port).parse().unwrap()
    }

    fn test_peer_id() -> PeerId {
        PeerId([0u8; 32])
    }

    #[test]
    fn test_discovery_source_priority() {
        assert!(
            DiscoverySource::Observed.base_priority()
                > DiscoverySource::LocalInterface.base_priority()
        );
        assert!(
            DiscoverySource::LocalInterface.base_priority()
                > DiscoverySource::PeerExchange.base_priority()
        );
        assert!(DiscoverySource::Config.base_priority() > DiscoverySource::Manual.base_priority());
    }

    #[tokio::test]
    async fn test_static_discovery() {
        let addrs = vec![test_addr(5000), test_addr(5001)];
        let discovery = StaticDiscovery::from_addrs(addrs.clone());

        let mut stream = discovery.discover(&test_peer_id());

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.addr, addrs[0]);

        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.addr, addrs[1]);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_concurrent_discovery() {
        let addrs1 = vec![test_addr(5000)];
        let addrs2 = vec![test_addr(6000)];

        let discovery = ConcurrentDiscovery::builder()
            .with_source(StaticDiscovery::from_addrs(addrs1))
            .with_source(StaticDiscovery::from_addrs(addrs2))
            .build();

        assert_eq!(discovery.source_count(), 2);

        let mut stream = discovery.discover(&test_peer_id());
        let mut found_ports = vec![];

        while let Some(result) = stream.next().await {
            found_ports.push(result.unwrap().addr.port());
        }

        assert!(found_ports.contains(&5000));
        assert!(found_ports.contains(&6000));
    }

    #[tokio::test]
    async fn test_channel_discovery() {
        let discovery = ChannelDiscovery::new("test", 10);
        let sender = discovery.sender();

        // Send addresses in background
        tokio::spawn(async move {
            sender
                .send(DiscoveredAddress {
                    addr: test_addr(7000),
                    source: DiscoverySource::Observed,
                    priority: 100,
                    ttl: None,
                })
                .await
                .unwrap();
        });

        let mut stream = discovery.discover(&test_peer_id());

        // Wait for address
        let result = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;

        assert!(result.is_ok());
        let addr = result.unwrap().unwrap().unwrap();
        assert_eq!(addr.addr.port(), 7000);
    }

    #[test]
    fn test_discovery_error_display() {
        let err = DiscoveryError {
            message: "test error".to_string(),
            source: Some(DiscoverySource::Dns),
            retryable: true,
        };
        assert!(err.to_string().contains("test error"));
    }

    #[tokio::test]
    async fn test_empty_concurrent_discovery() {
        let discovery = ConcurrentDiscovery::new();
        assert_eq!(discovery.source_count(), 0);

        let mut stream = discovery.discover(&test_peer_id());
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn test_discovered_address_equality() {
        let addr1 = DiscoveredAddress {
            addr: test_addr(5000),
            source: DiscoverySource::Config,
            priority: 70,
            ttl: None,
        };
        let addr2 = DiscoveredAddress {
            addr: test_addr(5000),
            source: DiscoverySource::Config,
            priority: 70,
            ttl: None,
        };
        let addr3 = DiscoveredAddress {
            addr: test_addr(5001),
            source: DiscoverySource::Config,
            priority: 70,
            ttl: None,
        };

        assert_eq!(addr1, addr2);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn test_builder_pattern() {
        let discovery = ConcurrentDiscoveryBuilder::new()
            .with_source(StaticDiscovery::from_addrs(vec![test_addr(5000)]))
            .with_source(StaticDiscovery::from_addrs(vec![test_addr(6000)]))
            .build();

        assert_eq!(discovery.source_count(), 2);
    }
}
