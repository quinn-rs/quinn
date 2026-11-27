//! This example demonstrates how to rate limit inbound connection attempts with [`InitialFilter`].
//!
//! Checkout the `README.md` for guidance.

use std::{
    error::Error,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use quinn::{
    Endpoint, InitialDecision, InitialFilter, InitialMetadata, ServerConfig, TokenCheck,
    crypto::rustls::QuicServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

mod common;
use common::make_client_endpoint;

/// Admits at most `limit` attempts per one-second window, without per-source state
///
/// A burst across a window boundary can get up to twice the limit.
#[derive(Debug)]
struct Budget {
    epoch: Instant,
    limit: u32,
    /// Current window and attempts admitted in it
    state: Mutex<(u64, u32)>,
}

impl Budget {
    fn new(limit: u32) -> Self {
        Self {
            epoch: Instant::now(),
            limit,
            state: Mutex::new((0, 0)),
        }
    }

    fn admit_at(&self, now: Instant) -> bool {
        let (window, used) = &mut *self.state.lock().unwrap();
        // A late timestamp counts against the current window
        let current = now.saturating_duration_since(self.epoch).as_secs();
        if current > *window {
            *window = current;
            *used = 0;
        }
        if *used >= self.limit {
            return false;
        }
        *used += 1;
        true
    }
}

#[derive(Debug)]
struct AdmissionPolicy {
    /// Every new Initial
    initials: Budget,
    /// Retries sent to peers without a valid token
    strangers: Budget,
    /// Handshakes started for peers with a valid token
    handshakes: Budget,
    retried: AtomicU64,
    ignored: AtomicU64,
    admitted: AtomicU64,
}

impl AdmissionPolicy {
    fn new(initials: u32, strangers: u32, handshakes: u32) -> Self {
        Self {
            initials: Budget::new(initials),
            strangers: Budget::new(strangers),
            handshakes: Budget::new(handshakes),
            retried: AtomicU64::new(0),
            ignored: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
        }
    }

    fn report(&self) {
        println!(
            "[server] admitted={} retried={} ignored={}",
            self.admitted.load(Ordering::Relaxed),
            self.retried.load(Ordering::Relaxed),
            self.ignored.load(Ordering::Relaxed),
        );
    }
}

impl InitialFilter for AdmissionPolicy {
    // A global budget here bounds all work for new Initials, including those that skip
    // `after_token_check()`. Only broken clients send malformed Initials, so drop them.
    fn before_token_check(&self, initial: &InitialMetadata) -> bool {
        if !initial.is_malformed() && self.initials.admit_at(initial.received_at()) {
            return true;
        }
        self.ignored.fetch_add(1, Ordering::Relaxed);
        false
    }

    fn after_token_check(&self, initial: &InitialMetadata, token: &TokenCheck) -> InitialDecision {
        // Validated peers still need a budget: proceeding starts a full handshake, and a Retry
        // token can be reused within its lifetime. It's separate from the strangers' one, so a
        // retried client's return doesn't compete with new strangers.
        let (budget, verdict, counter) = if token.remote_address_validated() {
            (&self.handshakes, InitialDecision::Proceed, &self.admitted)
        } else {
            (&self.strangers, InitialDecision::Retry, &self.retried)
        };
        if budget.admit_at(initial.received_at()) {
            counter.fetch_add(1, Ordering::Relaxed);
            verdict
        } else {
            self.ignored.fetch_add(1, Ordering::Relaxed);
            InitialDecision::Ignore
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // A very low stranger rate, to show the rejection path
    let admission_policy = Arc::new(AdmissionPolicy::new(1000, 1, 100));
    let (addr, cert) = spawn_server(admission_policy.clone())?;

    println!("New client connecting to a server retrying 1 new client/s");
    let client = make_client_endpoint("0.0.0.0:0".parse()?, &[&cert])?;
    let connection = client.connect(addr, "localhost")?.await?;
    println!("[client] connected: {}", connection.remote_address());
    drop(connection);
    client.wait_idle().await;
    admission_policy.report();

    println!("Familiar client connecting again - no problem");
    let connection = client.connect(addr, "localhost")?.await?;
    println!("[client] connected: {}", connection.remote_address());
    drop(connection);
    client.wait_idle().await;
    admission_policy.report();

    println!("Unfamiliar client connecting");
    // A second endpoint, as the first one is no longer a stranger
    let second_client = make_client_endpoint("0.0.0.0:0".parse()?, &[&cert])?;
    let connecting = second_client.connect(addr, "localhost")?;
    // Usually the strangers' budget is still used up. On a slow run its window may have rolled
    // over, and the client is retried and connects.
    match tokio::time::timeout(Duration::from_millis(500), connecting).await {
        Err(_) => println!("[client] no response within 500ms: the strangers' budget is used up"),
        Ok(Ok(connection)) => println!(
            "[client] connected: {} (the strangers' budget had refilled)",
            connection.remote_address()
        ),
        Ok(Err(error)) => return Err(error.into()),
    }
    admission_policy.report();
    Ok(())
}

/// Bind a server endpoint on an ephemeral loopback port and accept connections until dropped
fn spawn_server(
    filter: Arc<AdmissionPolicy>,
) -> Result<(SocketAddr, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key.into())?;
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    server_config.initial_filter(filter);

    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        println!("[server] accepted {}", connection.remote_address())
                    }
                    Err(error) => println!("[server] handshake failed: {error}"),
                }
            });
        }
    });

    Ok((addr, cert_der))
}

#[test]
fn budget_rejects_and_refills_deterministically() {
    let budget = Budget::new(2);
    let start = budget.epoch;
    assert!(budget.admit_at(start));
    assert!(budget.admit_at(start));
    assert!(
        !budget.admit_at(start),
        "a third attempt in the same window"
    );
    let next = start + Duration::from_secs(1);
    assert!(budget.admit_at(next), "the next window refills");
    assert!(
        budget.admit_at(start),
        "a late timestamp counts against the current window"
    );
    assert!(!budget.admit_at(next));
    assert!(
        !Budget::new(0).admit_at(start),
        "a zero budget admits nothing"
    );
}
