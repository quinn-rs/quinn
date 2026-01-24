//! Property-based tests for transport selection logic
//!
//! This test suite uses proptest to verify transport selection invariants
//! across randomly generated capability profiles and online/offline states.
//!
//! Properties verified:
//! 1. Transport selection is deterministic given same capabilities
//! 2. online_providers() never returns offline providers
//! 3. Registry lookup consistency across different query methods

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::TransportCapabilities;
use ant_quic::transport::{
    InboundDatagram, ProviderError, TransportAddr, TransportProvider, TransportRegistry,
    TransportStats, TransportType,
};
use async_trait::async_trait;
use proptest::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Mock transport provider with controllable capabilities and online state
#[derive(Clone, Debug)]
struct MockTransportProvider {
    name: String,
    transport_type: TransportType,
    capabilities: TransportCapabilities,
    is_online: Arc<AtomicBool>,
    stats: Arc<Mutex<TransportStats>>,
}

impl MockTransportProvider {
    fn new(
        name: String,
        transport_type: TransportType,
        capabilities: TransportCapabilities,
        is_online: bool,
    ) -> Self {
        Self {
            name,
            transport_type,
            capabilities,
            is_online: Arc::new(AtomicBool::new(is_online)),
            stats: Arc::new(Mutex::new(TransportStats::default())),
        }
    }

    fn set_online(&self, online: bool) {
        self.is_online.store(online, Ordering::SeqCst);
    }
}

#[async_trait]
impl TransportProvider for MockTransportProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn is_online(&self) -> bool {
        self.is_online.load(Ordering::SeqCst)
    }

    fn stats(&self) -> TransportStats {
        self.stats.lock().unwrap().clone()
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        Some(TransportAddr::Udp("127.0.0.1:0".parse().unwrap()))
    }

    fn protocol_engine(&self) -> ant_quic::transport::ProtocolEngine {
        if self.capabilities.supports_full_quic() {
            ant_quic::transport::ProtocolEngine::Quic
        } else {
            ant_quic::transport::ProtocolEngine::Constrained
        }
    }

    async fn send(&self, _data: &[u8], _dest: &TransportAddr) -> Result<(), ProviderError> {
        Ok(())
    }

    fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// Strategy for generating transport capabilities with various profiles
fn arb_transport_capabilities() -> impl Strategy<Value = TransportCapabilities> {
    prop_oneof![
        // High-bandwidth capable
        Just(TransportCapabilities::broadband()),
        // Low-bandwidth constrained
        Just(TransportCapabilities::lora_long_range()),
        Just(TransportCapabilities::lora_fast()),
        // Medium bandwidth
        Just(TransportCapabilities::ble()),
        Just(TransportCapabilities::serial_115200()),
        // Custom random capabilities
        (
            10u64..=1_000_000_000u64, // bandwidth_bps
            200usize..=65535usize,    // mtu
            1u64..=5000u64,           // typical_rtt millis
            1000u64..=60000u64,       // max_rtt millis
            any::<bool>(),            // half_duplex
            any::<bool>(),            // broadcast
            any::<bool>(),            // metered
            0.0f32..=0.5f32,          // loss_rate
            any::<bool>(),            // power_constrained
            any::<bool>(),            // link_layer_acks
            0.5f32..=1.0f32,          // availability
        )
            .prop_map(
                |(
                    bandwidth_bps,
                    mtu,
                    typical_rtt_ms,
                    max_rtt_ms,
                    half_duplex,
                    broadcast,
                    metered,
                    loss_rate,
                    power_constrained,
                    link_layer_acks,
                    availability,
                )| {
                    TransportCapabilities {
                        bandwidth_bps,
                        mtu,
                        typical_rtt: Duration::from_millis(typical_rtt_ms),
                        max_rtt: Duration::from_millis(max_rtt_ms),
                        half_duplex,
                        broadcast,
                        metered,
                        loss_rate,
                        power_constrained,
                        link_layer_acks,
                        availability,
                    }
                }
            ),
    ]
}

/// Strategy for generating a mock transport provider
fn arb_mock_transport() -> impl Strategy<Value = MockTransportProvider> {
    (
        "[a-z]{3,10}",                // name
        any::<bool>(),                // is_online
        arb_transport_capabilities(), // capabilities
    )
        .prop_map(|(name, is_online, capabilities)| {
            MockTransportProvider::new(name, TransportType::Udp, capabilities, is_online)
        })
}

/// Strategy for generating a list of mock transports
fn arb_transport_list() -> impl Strategy<Value = Vec<MockTransportProvider>> {
    prop::collection::vec(arb_mock_transport(), 1..=10)
}

proptest! {
    /// Property: Transport selection is deterministic
    ///
    /// Given the same set of capabilities and online states, querying
    /// the registry multiple times should always return the same result.
    #[test]
    fn prop_transport_selection_deterministic(transports in arb_transport_list()) {
        let mut registry = TransportRegistry::new();

        // Register all transports
        for transport in &transports {
            registry.register(Arc::new(transport.clone()));
        }

        // Query online providers multiple times
        let first_query: Vec<_> = registry.online_providers().collect();
        let second_query: Vec<_> = registry.online_providers().collect();
        let third_query: Vec<_> = registry.online_providers().collect();

        // All queries should return same count
        prop_assert_eq!(first_query.len(), second_query.len());
        prop_assert_eq!(second_query.len(), third_query.len());

        // All queries should return same providers (by name)
        let first_names: Vec<_> = first_query.iter().map(|p| p.name()).collect();
        let second_names: Vec<_> = second_query.iter().map(|p| p.name()).collect();
        let third_names: Vec<_> = third_query.iter().map(|p| p.name()).collect();

        prop_assert_eq!(&first_names, &second_names);
        prop_assert_eq!(&second_names, &third_names);
    }

    /// Property: online_providers() never returns offline providers
    ///
    /// The online_providers() iterator must filter out all providers
    /// where is_online() returns false. This is a critical safety property.
    #[test]
    fn prop_online_filter_correct(transports in arb_transport_list()) {
        let mut registry = TransportRegistry::new();

        // Register all transports
        for transport in &transports {
            registry.register(Arc::new(transport.clone()));
        }

        // Get online providers
        let online: Vec<_> = registry.online_providers().collect();

        // Every provider in online list MUST report is_online() == true
        for provider in &online {
            prop_assert!(provider.is_online(), "Found offline provider in online_providers()");
        }

        // Count online transports manually
        let expected_online_count = transports.iter().filter(|t| t.is_online()).count();
        prop_assert_eq!(online.len(), expected_online_count);
    }

    /// Property: Registry lookup consistency
    ///
    /// Different methods of querying the registry should return consistent
    /// results. If a provider is in online_providers(), it should also be
    /// returned by providers() and be marked as online.
    #[test]
    fn prop_registry_lookup_consistent(transports in arb_transport_list()) {
        let mut registry = TransportRegistry::new();

        // Register all transports
        for transport in &transports {
            registry.register(Arc::new(transport.clone()));
        }

        // Get all providers
        let all_providers = registry.providers();
        let online_providers: Vec<_> = registry.online_providers().collect();

        // All online providers must be in the full provider list
        for online_provider in &online_providers {
            let found = all_providers.iter().any(|p| {
                p.name() == online_provider.name()
            });
            prop_assert!(found, "Online provider '{}' not in providers()", online_provider.name());
        }

        // All online providers must actually report is_online() == true
        for online_provider in &online_providers {
            prop_assert!(online_provider.is_online());
        }

        // Registry length matches registered count
        prop_assert_eq!(registry.len(), transports.len());
        prop_assert_eq!(all_providers.len(), transports.len());
    }

    /// Property: QUIC capability detection is consistent
    ///
    /// has_quic_capable_transport() should return true if and only if
    /// there exists at least one online provider that supports full QUIC.
    #[test]
    fn prop_quic_capability_detection_consistent(transports in arb_transport_list()) {
        let mut registry = TransportRegistry::new();

        // Register all transports
        for transport in &transports {
            registry.register(Arc::new(transport.clone()));
        }

        // Check registry's QUIC capability detection
        let has_quic = registry.has_quic_capable_transport();

        // Manually check if any online transport supports full QUIC
        let expected_has_quic = transports.iter().any(|t| {
            t.is_online() && t.capabilities().supports_full_quic()
        });

        prop_assert_eq!(has_quic, expected_has_quic);
    }

    /// Property: Transport type filtering is correct
    ///
    /// providers_by_type() should only return providers of the requested type.
    #[test]
    fn prop_transport_type_filtering_correct(transports in arb_transport_list()) {
        let mut registry = TransportRegistry::new();

        // Register all transports (all are UDP in our mock)
        for transport in &transports {
            registry.register(Arc::new(transport.clone()));
        }

        // Query by UDP type
        let udp_providers = registry.providers_by_type(TransportType::Udp);

        // All returned providers must be UDP
        for provider in &udp_providers {
            prop_assert_eq!(provider.transport_type(), TransportType::Udp);
        }

        // Should return all providers since all are UDP
        prop_assert_eq!(udp_providers.len(), transports.len());
    }

    /// Property: Online state transitions maintain invariants
    ///
    /// If we toggle provider online states, the registry's view should
    /// immediately reflect the changes without needing re-registration.
    #[test]
    fn prop_online_state_transitions_consistent(transports in arb_transport_list()) {
        let mut registry = TransportRegistry::new();
        let transport_refs: Vec<_> = transports.iter()
            .map(|t| Arc::new(t.clone()))
            .collect();

        // Register all transports
        for transport_ref in &transport_refs {
            registry.register(transport_ref.clone());
        }

        // Get initial online count
        let initial_online_count = registry.online_providers().count();

        // Set all to offline
        for transport in &transports {
            transport.set_online(false);
        }

        // Should have zero online providers
        let offline_count = registry.online_providers().count();
        prop_assert_eq!(offline_count, 0);

        // Set all to online
        for transport in &transports {
            transport.set_online(true);
        }

        // Should have all providers online
        let all_online_count = registry.online_providers().count();
        prop_assert_eq!(all_online_count, transports.len());

        // Restore original states (for cleanup)
        for (i, transport) in transports.iter().enumerate() {
            transport.set_online(i < initial_online_count);
        }
    }

    /// Property: Empty registry behaves correctly
    ///
    /// An empty registry should have consistent behavior across all queries.
    #[test]
    fn prop_empty_registry_consistent(_seed in any::<u64>()) {
        let registry = TransportRegistry::new();

        prop_assert!(registry.is_empty());
        prop_assert_eq!(registry.len(), 0);
        prop_assert_eq!(registry.providers().len(), 0);
        prop_assert_eq!(registry.online_providers().count(), 0);
        prop_assert!(!registry.has_quic_capable_transport());
        prop_assert_eq!(registry.diagnostics().len(), 0);
    }

    /// Property: Bandwidth classification is consistent
    ///
    /// All providers should report a bandwidth class that matches
    /// their actual bandwidth_bps value.
    #[test]
    fn prop_bandwidth_classification_consistent(transports in arb_transport_list()) {
        for transport in &transports {
            let caps = transport.capabilities();
            let bandwidth_class = caps.bandwidth_class();
            let bps = caps.bandwidth_bps;

            // Verify classification matches bandwidth ranges
            // Boundaries from BandwidthClass::from_bps():
            // VeryLow: 0..=999
            // Low: 1000..=99_999
            // Medium: 100_000..=9_999_999
            // High: >= 10_000_000
            use ant_quic::transport::BandwidthClass;
            match bandwidth_class {
                BandwidthClass::VeryLow => prop_assert!(bps <= 999),
                BandwidthClass::Low => prop_assert!((1_000..=99_999).contains(&bps)),
                BandwidthClass::Medium => prop_assert!((100_000..=9_999_999).contains(&bps)),
                BandwidthClass::High => prop_assert!(bps >= 10_000_000),
            }
        }
    }

    /// Property: Protocol engine selection matches QUIC capability
    ///
    /// Protocol engine should be FullQuic if and only if the transport
    /// supports full QUIC according to its capabilities.
    #[test]
    fn prop_protocol_engine_matches_quic_capability(transports in arb_transport_list()) {
        for transport in &transports {
            let supports_quic = transport.capabilities().supports_full_quic();
            let engine = transport.protocol_engine();

            use ant_quic::transport::ProtocolEngine;
            if supports_quic {
                prop_assert_eq!(engine, ProtocolEngine::Quic);
            } else {
                prop_assert_eq!(engine, ProtocolEngine::Constrained);
            }
        }
    }
}
