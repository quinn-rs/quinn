// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


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
