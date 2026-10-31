use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::hmac;
use rand::{CryptoRng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
#[cfg(feature = "ring")]
use ring::hmac;

use super::util::*;
use crate::{
    Endpoint, EndpointConfig, RngFactory, TransportConfig,
    congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig},
};

#[derive(Default)]
struct CountingFactory {
    endpoint_rngs: AtomicUsize,
    seeded_rngs: AtomicUsize,
    bytes: Arc<AtomicUsize>,
}

impl CountingFactory {
    fn endpoint_rngs(&self) -> usize {
        self.endpoint_rngs.load(Ordering::Relaxed)
    }

    fn seeded_rngs(&self) -> usize {
        self.seeded_rngs.load(Ordering::Relaxed)
    }

    fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    fn rng(&self, inner: StdRng) -> Box<dyn CryptoRng + Send + Sync> {
        Box::new(CountingRng {
            inner,
            bytes: self.bytes.clone(),
        })
    }
}

impl RngFactory for CountingFactory {
    fn endpoint_rng(&self) -> Box<dyn CryptoRng + Send + Sync> {
        let index = self.endpoint_rngs.fetch_add(1, Ordering::Relaxed);
        self.rng(StdRng::seed_from_u64(index as u64))
    }

    fn rng_from_seed(&self, seed: [u8; 32]) -> Box<dyn CryptoRng + Send + Sync> {
        self.seeded_rngs.fetch_add(1, Ordering::Relaxed);
        self.rng(StdRng::from_seed(seed))
    }
}

struct CountingRng {
    inner: StdRng,
    bytes: Arc<AtomicUsize>,
}

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.bytes.fetch_add(4, Ordering::Relaxed);
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.bytes.fetch_add(8, Ordering::Relaxed);
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.bytes.fetch_add(dst.len(), Ordering::Relaxed);
        self.inner.try_fill_bytes(dst)
    }
}

impl TryCryptoRng for CountingRng {}

fn endpoint_config(factory: &Arc<CountingFactory>) -> EndpointConfig {
    let reset_key = hmac::Key::new(hmac::HMAC_SHA256, &[0xab; 64]);
    EndpointConfig::with_rng_factory(Arc::new(reset_key), factory.clone())
}

#[test]
fn rng_factory_builds_every_endpoint_and_connection_generator() {
    let _guard = subscribe();
    let factory = Arc::new(CountingFactory::default());
    let mut pair = Pair::new(Arc::new(endpoint_config(&factory)), server_config());
    // Each endpoint builds its own generator, then seeds its default connection ID generator.
    assert_eq!(factory.endpoint_rngs(), 2);
    assert_eq!(factory.seeded_rngs(), 2);

    pair.connect();
    // Each connection's generator is seeded from its endpoint's.
    assert_eq!(factory.endpoint_rngs(), 2);
    assert_eq!(factory.seeded_rngs(), 4);
}

#[test]
fn rng_seed_seeds_the_endpoint_generator_through_the_factory() {
    let factory = Arc::new(CountingFactory::default());
    let mut config = endpoint_config(&factory);
    config.rng_seed(Some([7; 32]));
    let _endpoint = Endpoint::new(Arc::new(config), None, true);
    assert_eq!(factory.endpoint_rngs(), 0);
    assert_eq!(factory.seeded_rngs(), 2);
}

fn bytes_drawn_by_connect(controller: Arc<dyn ControllerFactory + Send + Sync>) -> usize {
    let factory = Arc::new(CountingFactory::default());
    let mut pair = Pair::new(Arc::new(endpoint_config(&factory)), server_config());
    let mut transport = TransportConfig::default();
    transport.congestion_controller_factory(controller);
    let mut client = client_config();
    client.transport_config(Arc::new(transport));
    let before = factory.bytes();
    let server = pair.server.addr;
    pair.client
        .connect(pair.time, client, server, "localhost")
        .unwrap();
    factory.bytes() - before
}

#[test]
fn bbr_seeds_its_gain_cycle_from_the_connection_generator() {
    let cubic = bytes_drawn_by_connect(Arc::new(CubicConfig::default()));
    let new_reno = bytes_drawn_by_connect(Arc::new(NewRenoConfig::default()));
    let bbr = bytes_drawn_by_connect(Arc::new(BbrConfig::default()));
    assert_eq!(cubic, new_reno);
    // BBR seeds its 128-bit Pcg32 state from the connection generator.
    assert_eq!(bbr, cubic + 16);
}
