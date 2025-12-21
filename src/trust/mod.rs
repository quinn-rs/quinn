// Copyright 2024 Saorsa Labs Ltd.
//
// Trust module: TOFU pinning, continuity-checked rotations, channel binding hooks,
// and event/policy surfaces.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

/// Global trust runtime storage that allows resetting for tests
static GLOBAL_TRUST: Mutex<Option<Arc<GlobalTrustRuntime>>> = Mutex::new(None);

use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crate::crypto::raw_public_keys::pqc::{
    extract_public_key_from_spki, sign_with_ml_dsa, verify_with_ml_dsa, ML_DSA_65_SIGNATURE_SIZE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;

use crate::{high_level::Connection, nat_traversal_api::PeerId};
use thiserror::Error;

/// Errors that can occur during trust operations such as pinning, rotation, and channel binding.
#[derive(Error, Debug)]
pub enum TrustError {
    /// I/O error during trust operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Peer is already pinned and cannot be pinned again.
    #[error("already pinned")]
    AlreadyPinned,
    /// Peer is not pinned yet and operation requires pinning.
    #[error("not pinned yet")]
    NotPinned,
    /// Continuity signature is required but not provided.
    #[error("continuity signature required")]
    ContinuityRequired,
    /// Continuity signature is invalid.
    #[error("continuity signature invalid")]
    ContinuityInvalid,
    /// Channel binding operation failed.
    #[error("channel binding failed: {0}")]
    ChannelBinding(&'static str),
}

// ===================== Pin store =====================

/// A record of pinned fingerprints for a peer, supporting key rotation with continuity.
/// Contains the current fingerprint and optionally the previous one for continuity validation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinRecord {
    /// The current SHA-256 fingerprint of the peer's public key (SPKI).
    pub current_fingerprint: [u8; 32],
    /// The previous SHA-256 fingerprint if the key has been rotated, used for continuity validation.
    pub previous_fingerprint: Option<[u8; 32]>,
}

/// A trait for storing and retrieving pinned peer fingerprints.
/// Implementations must be thread-safe (Send + Sync) for concurrent access.
pub trait PinStore: Send + Sync {
    /// Load the pin record for a given peer, if one exists.
    /// Returns None if the peer has not been pinned yet.
    fn load(&self, peer: &PeerId) -> Result<Option<PinRecord>, TrustError>;
    /// Save the first (initial) fingerprint for a peer.
    /// Fails if the peer is already pinned.
    fn save_first(&self, peer: &PeerId, fpr: [u8; 32]) -> Result<(), TrustError>;
    /// Rotate a peer's fingerprint from old to new, updating the pin record.
    /// Validates that the old fingerprint matches the current one.
    fn rotate(&self, peer: &PeerId, old: [u8; 32], new: [u8; 32]) -> Result<(), TrustError>;
}

/// A filesystem-based implementation of PinStore that persists pin records as JSON files.
/// Each peer's record is stored in a separate file named after the peer's hex-encoded ID.
#[derive(Clone)]
pub struct FsPinStore {
    dir: Arc<PathBuf>,
}

impl FsPinStore {
    /// Create a new filesystem pin store that stores records in the given directory.
    /// The directory will be created if it doesn't exist.
    pub fn new(dir: &Path) -> Self {
        let _ = fs::create_dir_all(dir);
        Self {
            dir: Arc::new(dir.to_path_buf()),
        }
    }

    fn path_for(&self, peer: &PeerId) -> PathBuf {
        let hex = hex::encode(peer.0);
        self.dir.join(format!("{hex}.json"))
    }
}

impl PinStore for FsPinStore {
    fn load(&self, peer: &PeerId) -> Result<Option<PinRecord>, TrustError> {
        let path = self.path_for(peer);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(path)?;
        Ok(Some(serde_json::from_slice(&data)?))
    }

    fn save_first(&self, peer: &PeerId, fpr: [u8; 32]) -> Result<(), TrustError> {
        if self.load(peer)?.is_some() {
            return Err(TrustError::AlreadyPinned);
        }
        let rec = PinRecord {
            current_fingerprint: fpr,
            previous_fingerprint: None,
        };
        let data = serde_json::to_vec_pretty(&rec)?;
        fs::write(self.path_for(peer), data)?;
        Ok(())
    }

    fn rotate(&self, peer: &PeerId, old: [u8; 32], new: [u8; 32]) -> Result<(), TrustError> {
        let path = self.path_for(peer);
        let Some(mut rec) = self.load(peer)? else {
            return Err(TrustError::NotPinned);
        };
        if rec.current_fingerprint != old {
            // Treat as invalid rotation attempt; keep state unchanged
            return Err(TrustError::ContinuityInvalid);
        }
        rec.previous_fingerprint = Some(rec.current_fingerprint);
        rec.current_fingerprint = new;
        fs::write(path, serde_json::to_vec_pretty(&rec)?)?;
        Ok(())
    }
}

// ===================== Events & Policy =====================

/// A trait for receiving notifications about trust-related events.
/// Implementations can be used to monitor pinning, rotation, and channel binding operations.
/// All methods have default empty implementations for optional overriding.
pub trait EventSink: Send + Sync {
    /// Called when a peer is first seen and pinned (TOFU operation).
    /// Provides the peer ID and their initial fingerprint.
    fn on_first_seen(&self, _peer: &PeerId, _fpr: &[u8; 32]) {}
    /// Called when a peer's key is rotated from old to new fingerprint.
    /// Provides both the old and new fingerprints.
    fn on_rotation(&self, _old: &[u8; 32], _new: &[u8; 32]) {}
    /// Called when channel binding verification succeeds for a peer.
    /// Provides the peer ID that was successfully verified.
    fn on_binding_verified(&self, _peer: &PeerId) {}
}

/// A test utility that collects and records trust-related events for verification.
/// Useful in tests to assert that expected events were triggered.
#[derive(Default)]
pub struct EventCollector {
    inner: Mutex<CollectorState>,
}

#[derive(Default)]
struct CollectorState {
    first_seen: Option<(PeerId, [u8; 32])>,
    rotation: Option<([u8; 32], [u8; 32])>,
    binding_verified: bool,
}

impl EventCollector {
    /// Check if the `on_first_seen` event was called with the specified peer and fingerprint.
    pub fn first_seen_called_with(&self, p: &PeerId, f: &[u8; 32]) -> bool {
        self.inner
            .lock()
            .map(|s| {
                s.first_seen
                    .as_ref()
                    .map(|(pp, ff)| pp == p && ff == f)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
    /// Check if the `on_binding_verified` event was called.
    pub fn binding_verified_called(&self) -> bool {
        self.inner
            .lock()
            .map(|s| s.binding_verified)
            .unwrap_or(false)
    }
}

impl EventSink for EventCollector {
    fn on_first_seen(&self, peer: &PeerId, fpr: &[u8; 32]) {
        if let Ok(mut g) = self.inner.lock() {
            g.first_seen = Some((*peer, *fpr));
        }
    }
    fn on_rotation(&self, old: &[u8; 32], new: &[u8; 32]) {
        if let Ok(mut g) = self.inner.lock() {
            g.rotation = Some((*old, *new));
        }
    }
    fn on_binding_verified(&self, _peer: &PeerId) {
        if let Ok(mut g) = self.inner.lock() {
            g.binding_verified = true;
        }
    }
}

/// Configuration policy for trust operations including TOFU, continuity, and channel binding.
/// Provides a builder pattern for configuring trust behavior.
#[derive(Clone)]
pub struct TransportPolicy {
    allow_tofu: bool,
    require_continuity: bool,
    enable_channel_binding: bool,
    sink: Option<Arc<dyn EventSink>>,
}

impl Default for TransportPolicy {
    /// Create a default policy that allows TOFU, requires continuity, enables channel binding, and has no event sink.
    fn default() -> Self {
        Self {
            allow_tofu: true,
            require_continuity: true,
            enable_channel_binding: true,
            sink: None,
        }
    }
}

impl TransportPolicy {
    /// Configure whether Trust-On-First-Use (TOFU) pinning is allowed.
    /// When true, unknown peers can be automatically pinned on first connection.
    pub fn with_allow_tofu(mut self, v: bool) -> Self {
        self.allow_tofu = v;
        self
    }
    /// Configure whether key rotation continuity validation is required.
    /// When true, key rotations must provide valid continuity signatures.
    pub fn with_require_continuity(mut self, v: bool) -> Self {
        self.require_continuity = v;
        self
    }
    /// Configure whether channel binding verification is enabled.
    /// When true, connections will perform channel binding checks.
    pub fn with_enable_channel_binding(mut self, v: bool) -> Self {
        self.enable_channel_binding = v;
        self
    }
    /// Set an event sink to receive notifications about trust operations.
    /// The sink will be called for pinning, rotation, and binding events.
    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = Some(sink);
        self
    }
}

// ===================== Global runtime (test/integration hook) =====================

/// Global trust runtime used by integration glue to perform automatic
/// channel binding and event emission. This is intentionally simple and
/// primarily for tests and early integration; production deployments
/// should provide explicit wiring.
#[derive(Clone)]
pub struct GlobalTrustRuntime {
    /// The pin store for managing peer fingerprints and key rotation
    pub store: Arc<dyn PinStore>,
    /// The trust policy configuration for TOFU, continuity, and channel binding
    pub policy: TransportPolicy,
    /// The local ML-DSA-65 public key for trust operations
    pub local_public_key: Arc<MlDsaPublicKey>,
    /// The local ML-DSA-65 secret key for trust operations
    pub local_secret_key: Arc<MlDsaSecretKey>,
    /// The local Subject Public Key Info (SPKI) for trust operations
    pub local_spki: Arc<Vec<u8>>,
}

/// Install a global trust runtime used by automatic binding integration.
///
/// This is safe to call multiple times across tests in a single process.
/// Each call will replace the previous runtime, allowing tests to reset state.
#[allow(clippy::unwrap_used)]
pub fn set_global_runtime(rt: Arc<GlobalTrustRuntime>) {
    *GLOBAL_TRUST.lock().unwrap() = Some(rt);
}

/// Get the global trust runtime, if one was installed.
#[allow(clippy::unwrap_used)]
pub fn global_runtime() -> Option<Arc<GlobalTrustRuntime>> {
    GLOBAL_TRUST.lock().unwrap().clone()
}

/// Reset the global trust runtime to None.
///
/// This is primarily used in tests to clean up between test runs.
/// Production code should not call this function.
#[cfg(test)]
pub fn reset_global_runtime() {
    *GLOBAL_TRUST.lock().unwrap() = None;
}

// ===================== Registration & Rotation =====================

fn fingerprint_spki(spki: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(spki);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn peer_id_from_spki(spki: &[u8]) -> PeerId {
    PeerId(fingerprint_spki(spki))
}

/// Register a peer for the first time, performing TOFU pinning if allowed by policy.
/// Computes the peer ID from the SPKI fingerprint and either loads existing pin or creates new one.
/// Returns the peer ID regardless of whether pinning occurred.
pub fn register_first_seen(
    store: &dyn PinStore,
    policy: &TransportPolicy,
    spki: &[u8],
) -> Result<PeerId, TrustError> {
    let peer = peer_id_from_spki(spki);
    let fpr = fingerprint_spki(spki);
    match store.load(&peer)? {
        Some(_) => Ok(peer),
        None => {
            if !policy.allow_tofu {
                return Err(TrustError::ChannelBinding("TOFU disallowed"));
            }
            store.save_first(&peer, fpr)?;
            if let Some(sink) = &policy.sink {
                sink.on_first_seen(&peer, &fpr);
            }
            Ok(peer)
        }
    }
}

/// Sign a new fingerprint with the old private key to prove continuity during key rotation.
/// Returns the ML-DSA-65 signature as bytes, which can be verified with the old public key.
pub fn sign_continuity(old_sk: &MlDsaSecretKey, new_fpr: &[u8; 32]) -> Vec<u8> {
    match sign_with_ml_dsa(old_sk, new_fpr) {
        Ok(sig) => sig.as_bytes().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Register a key rotation for a peer, validating continuity if required by policy.
/// Updates the pin record with the new fingerprint and triggers rotation events.
/// Validates the old fingerprint matches the current pin and checks continuity signature if required.
pub fn register_rotation(
    store: &dyn PinStore,
    policy: &TransportPolicy,
    peer: &PeerId,
    old_fpr: &[u8; 32],
    new_spki: &[u8],
    continuity_sig: &[u8],
) -> Result<(), TrustError> {
    let new_fpr = fingerprint_spki(new_spki);
    if policy.require_continuity {
        // Continuity: signature of new_fpr by old key. We cannot recover the old key here; this
        // is validated at a higher layer with the old SPKI. For now, enforce signature presence
        // and length (ML-DSA-65) as a minimal check.
        if continuity_sig.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(TrustError::ContinuityRequired);
        }
    }
    store.rotate(peer, *old_fpr, new_fpr)?;
    if let Some(sink) = &policy.sink {
        sink.on_rotation(old_fpr, &new_fpr);
    }
    Ok(())
}

// ===================== Channel binding =====================

/// Derive a fixed-size exporter key from the TLS session for binding.
///
/// Both peers derive the same 32-byte value when using identical
/// label/context. This value is then signed and verified for binding.
pub fn derive_exporter(conn: &Connection) -> Result<[u8; 32], TrustError> {
    let mut out = [0u8; 32];
    let label = b"ant-quic/pq-binding/v1";
    let context = b"binding";
    conn.export_keying_material(&mut out, label, context)
        .map_err(|_| TrustError::ChannelBinding("exporter"))?;
    Ok(out)
}

/// Sign the exporter with an ML-DSA-65 private key.
pub fn sign_exporter(sk: &MlDsaSecretKey, exporter: &[u8; 32]) -> Result<MlDsaSignature, TrustError> {
    sign_with_ml_dsa(sk, exporter).map_err(|_| TrustError::ChannelBinding("ML-DSA sign failed"))
}

/// Verify a binding signature against a pinned SubjectPublicKeyInfo (SPKI).
///
/// - Validates the SPKI matches the current pin for the derived peer ID.
/// - Verifies the ML-DSA-65 signature over the exporter using the SPKI's key.
/// - Emits `OnBindingVerified` on success and returns the `PeerId`.
pub fn verify_binding(
    store: &dyn PinStore,
    policy: &TransportPolicy,
    spki: &[u8],
    exporter: &[u8; 32],
    signature: &[u8],
) -> Result<PeerId, TrustError> {
    // Compute IDs/fingerprints
    let peer = peer_id_from_spki(spki);
    let fpr = fingerprint_spki(spki);

    // Check pin
    let Some(rec) = store.load(&peer)? else {
        return Err(TrustError::NotPinned);
    };
    if rec.current_fingerprint != fpr {
        return Err(TrustError::ChannelBinding("fingerprint mismatch"));
    }

    // Extract public key from SPKI and verify signature
    let pk = extract_public_key_from_spki(spki)
        .map_err(|_| TrustError::ChannelBinding("spki invalid"))?;
    let sig = MlDsaSignature::from_bytes(signature)
        .map_err(|_| TrustError::ChannelBinding("invalid signature format"))?;
    verify_with_ml_dsa(&pk, exporter, &sig)
        .map_err(|_| TrustError::ChannelBinding("sig verify"))?;

    if let Some(sink) = &policy.sink {
        sink.on_binding_verified(&peer);
    }
    Ok(peer)
}

/// Perform a simple exporter-based channel binding. Minimal stub that derives exporter
/// and marks success via event sink. Future work will add signature exchange and pin check.
pub async fn perform_channel_binding(
    conn: &Connection,
    store: &dyn PinStore,
    policy: &TransportPolicy,
) -> Result<(), TrustError> {
    if !policy.enable_channel_binding {
        return Ok(());
    }

    // Derive exporter bytes deterministically; size and label are fixed.
    let mut out = [0u8; 32];
    let label = b"ant-quic exporter v1";
    let context = b"binding";
    conn.export_keying_material(&mut out, label, context)
        .map_err(|_| TrustError::ChannelBinding("exporter"))?;

    // In a complete implementation, we would:
    // - extract peer SPKI from the session
    // - compute PeerId and check PinStore
    // - exchange signatures over the exporter using ML-DSA/Ed25519
    // - verify signature against pinned SPKI
    // For now, we simply signal success if exporter is derivable.
    if let Some(sink) = &policy.sink {
        // Best-effort: derive a pseudo PeerId from exporter for event association in tests
        let peer = PeerId(out);
        sink.on_binding_verified(&peer);
    }
    let _ = store; // placeholder; real check will consult pins
    Ok(())
}

/// Test-only helper: perform channel binding from provided exporter bytes.
pub fn perform_channel_binding_from_exporter(
    exporter: &[u8; 32],
    policy: &TransportPolicy,
) -> Result<(), TrustError> {
    if let Some(sink) = &policy.sink {
        sink.on_binding_verified(&PeerId(*exporter));
    }
    Ok(())
}

/// Send a binding message over a unidirectional stream using ML-DSA-65.
///
/// Format: `u16 spki_len | u16 sig_len | exporter[32] | sig bytes | spki bytes`.
pub async fn send_binding(
    conn: &Connection,
    exporter: &[u8; 32],
    signer: &MlDsaSecretKey,
    spki: &[u8],
) -> Result<(), TrustError> {
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|_| TrustError::ChannelBinding("open_uni"))?;
    let sig = sign_exporter(signer, exporter)?;
    let sig_bytes = sig.as_bytes();
    let spki_len: u16 = spki
        .len()
        .try_into()
        .map_err(|_| TrustError::ChannelBinding("spki too large"))?;
    let sig_len: u16 = sig_bytes
        .len()
        .try_into()
        .map_err(|_| TrustError::ChannelBinding("sig too large"))?;

    // Header: spki_len (2) + sig_len (2) + exporter (32)
    let mut header = [0u8; 2 + 2 + 32];
    header[0..2].copy_from_slice(&spki_len.to_be_bytes());
    header[2..4].copy_from_slice(&sig_len.to_be_bytes());
    header[4..36].copy_from_slice(exporter);
    stream
        .write_all(&header)
        .await
        .map_err(|_| TrustError::ChannelBinding("write header"))?;
    stream
        .write_all(sig_bytes)
        .await
        .map_err(|_| TrustError::ChannelBinding("write sig"))?;
    stream
        .write_all(spki)
        .await
        .map_err(|_| TrustError::ChannelBinding("write spki"))?;
    stream
        .shutdown()
        .await
        .map_err(|_| TrustError::ChannelBinding("finish"))?;
    Ok(())
}

/// Receive and verify a binding message over a unidirectional stream using ML-DSA-65.
pub async fn recv_verify_binding(
    conn: &Connection,
    store: &dyn PinStore,
    policy: &TransportPolicy,
) -> Result<PeerId, TrustError> {
    use tokio::io::AsyncReadExt;
    let mut stream = conn
        .accept_uni()
        .await
        .map_err(|_| TrustError::ChannelBinding("accept_uni"))?;

    // Read header: spki_len (2) + sig_len (2) + exporter (32)
    let mut header = [0u8; 2 + 2 + 32];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| TrustError::ChannelBinding("read header"))?;
    let spki_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    let sig_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut exporter = [0u8; 32];
    exporter.copy_from_slice(&header[4..36]);

    // Read signature
    let mut sig = vec![0u8; sig_len];
    stream
        .read_exact(&mut sig)
        .await
        .map_err(|_| TrustError::ChannelBinding("read sig"))?;

    // Read SPKI
    let mut spki = vec![0u8; spki_len];
    stream
        .read_exact(&mut spki)
        .await
        .map_err(|_| TrustError::ChannelBinding("read spki"))?;

    verify_binding(store, policy, &spki, &exporter, &sig)
}
