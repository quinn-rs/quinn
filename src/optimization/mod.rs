//! Performance optimization modules for ant-quic

pub mod memory;
pub mod network;

pub use memory::{
    CandidateCache, CandidateCacheConfig, CandidateCacheStats, ConnectionPool,
    ConnectionPoolConfig, ConnectionPoolStats, FrameBatchingConfig, FrameBatchingCoordinator,
    FrameBatchingStats, MemoryOptimizationManager, MemoryOptimizationStats, SessionCleanupConfig,
    SessionCleanupCoordinator, SessionCleanupStats,
};

pub use network::{
    AdaptiveTimeoutManager, AdaptiveTimeoutStats, BandwidthAwareValidator,
    BandwidthValidationConfig, BandwidthValidationStats, CongestionControlIntegrator,
    CongestionIntegrationConfig, CongestionIntegrationStats, InterfaceType,
    NetworkEfficiencyManager, NetworkEfficiencyStats, OperationType, ParallelDiscoveryConfig,
    ParallelDiscoveryCoordinator, ParallelDiscoveryStats,
};
