//! Performance optimization modules for ant-quic

pub mod memory;
pub mod network;

pub use memory::{
    MemoryOptimizationManager,
    ConnectionPool, ConnectionPoolConfig, ConnectionPoolStats,
    CandidateCache, CandidateCacheConfig, CandidateCacheStats,
    SessionCleanupCoordinator, SessionCleanupConfig, SessionCleanupStats,
    FrameBatchingCoordinator, FrameBatchingConfig, FrameBatchingStats,
    MemoryOptimizationStats,
};

pub use network::{
    NetworkEfficiencyManager,
    ParallelDiscoveryCoordinator, ParallelDiscoveryConfig, ParallelDiscoveryStats,
    AdaptiveTimeoutManager, AdaptiveTimeoutStats, OperationType,
    BandwidthAwareValidator, BandwidthValidationConfig, BandwidthValidationStats,
    CongestionControlIntegrator, CongestionIntegrationConfig, CongestionIntegrationStats,
    NetworkEfficiencyStats, InterfaceType,
};