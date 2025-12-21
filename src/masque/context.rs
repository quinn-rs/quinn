// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Context ID management for MASQUE CONNECT-UDP Bind
//!
//! Per draft-ietf-masque-connect-udp-listen-10:
//! - Clients allocate even Context IDs
//! - Servers allocate odd Context IDs
//! - Context ID 0 is reserved for unextended UDP proxying
//! - Only one uncompressed context allowed at a time
//!
//! This module provides the [`ContextManager`] for managing context lifecycles
//! and enforcing the allocation rules required by the specification.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Instant;

use crate::VarInt;

/// Context allocation and state management
///
/// Manages both locally allocated contexts (sent via COMPRESSION_ASSIGN)
/// and remotely allocated contexts (received via COMPRESSION_ASSIGN).
#[derive(Debug)]
pub struct ContextManager {
    /// Locally allocated contexts
    local_contexts: HashMap<VarInt, ContextInfo>,
    /// Remotely allocated contexts
    remote_contexts: HashMap<VarInt, ContextInfo>,
    /// Current uncompressed context (only one allowed)
    uncompressed_context: Option<VarInt>,
    /// Next local context ID to allocate
    next_local_id: u64,
    /// Whether we allocate even (client) or odd (server) IDs
    is_client: bool,
}

/// Information about a registered context
#[derive(Debug, Clone)]
pub struct ContextInfo {
    /// Target address (None for uncompressed)
    pub target: Option<SocketAddr>,
    /// Current state
    pub state: ContextState,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
}

/// Context lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextState {
    /// COMPRESSION_ASSIGN sent, awaiting ACK
    Pending,
    /// COMPRESSION_ACK received, context active
    Active,
    /// COMPRESSION_CLOSE sent or received
    Closing,
    /// Fully closed
    Closed,
}

impl fmt::Display for ContextState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextState::Pending => write!(f, "pending"),
            ContextState::Active => write!(f, "active"),
            ContextState::Closing => write!(f, "closing"),
            ContextState::Closed => write!(f, "closed"),
        }
    }
}

impl ContextManager {
    /// Create a new context manager
    ///
    /// # Arguments
    ///
    /// * `is_client` - true if we're the initiating endpoint (allocates even IDs)
    ///
    /// # Example
    ///
    /// ```
    /// use ant_quic::masque::ContextManager;
    ///
    /// // Client creates a manager that allocates even IDs
    /// let client_mgr = ContextManager::new(true);
    ///
    /// // Server creates a manager that allocates odd IDs
    /// let server_mgr = ContextManager::new(false);
    /// ```
    pub fn new(is_client: bool) -> Self {
        Self {
            local_contexts: HashMap::new(),
            remote_contexts: HashMap::new(),
            uncompressed_context: None,
            // Start at 2 for client (0 reserved), 1 for server
            next_local_id: if is_client { 2 } else { 1 },
            is_client,
        }
    }

    /// Returns whether this manager is for a client endpoint
    pub fn is_client(&self) -> bool {
        self.is_client
    }

    /// Allocate a new local context ID
    ///
    /// Clients allocate even IDs starting from 2.
    /// Servers allocate odd IDs starting from 1.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::IdSpaceExhausted`] if no more IDs are available.
    pub fn allocate_local(&mut self) -> Result<VarInt, ContextError> {
        let id = self.next_local_id;

        // Ensure we stay within VarInt bounds
        if id > VarInt::MAX.into_inner() {
            return Err(ContextError::IdSpaceExhausted);
        }

        // Increment by 2 to stay in our allocation space (even/odd)
        self.next_local_id = self
            .next_local_id
            .checked_add(2)
            .ok_or(ContextError::IdSpaceExhausted)?;

        VarInt::from_u64(id).map_err(|_| ContextError::IdSpaceExhausted)
    }

    /// Register a new uncompressed context
    ///
    /// An uncompressed context allows sending datagrams with inline target
    /// information. Per the specification, only one uncompressed context
    /// is allowed at a time.
    ///
    /// # Errors
    ///
    /// - [`ContextError::DuplicateUncompressed`] if an uncompressed context already exists
    /// - [`ContextError::ReservedId`] if context_id is 0
    pub fn register_uncompressed(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        if self.uncompressed_context.is_some() {
            return Err(ContextError::DuplicateUncompressed);
        }

        if context_id.into_inner() == 0 {
            return Err(ContextError::ReservedId);
        }

        let info = ContextInfo {
            target: None,
            state: ContextState::Pending,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };

        self.local_contexts.insert(context_id, info);
        self.uncompressed_context = Some(context_id);

        Ok(())
    }

    /// Register a new compressed context for a specific target
    ///
    /// A compressed context eliminates the need to include target address
    /// information in each datagram, reducing overhead.
    ///
    /// # Errors
    ///
    /// - [`ContextError::DuplicateTarget`] if a context for this target already exists
    pub fn register_compressed(
        &mut self,
        context_id: VarInt,
        target: SocketAddr,
    ) -> Result<(), ContextError> {
        // Check for duplicate target
        for info in self
            .local_contexts
            .values()
            .chain(self.remote_contexts.values())
        {
            if info.target == Some(target) && info.state != ContextState::Closed {
                return Err(ContextError::DuplicateTarget(target));
            }
        }

        let info = ContextInfo {
            target: Some(target),
            state: ContextState::Pending,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };

        self.local_contexts.insert(context_id, info);

        Ok(())
    }

    /// Register a remote context (received via COMPRESSION_ASSIGN)
    ///
    /// This is called when we receive a COMPRESSION_ASSIGN from the peer.
    /// The context starts in Active state since we'll send COMPRESSION_ACK.
    ///
    /// # Errors
    ///
    /// - [`ContextError::DuplicateTarget`] if a context for this target already exists
    /// - [`ContextError::DuplicateUncompressed`] if registering uncompressed and one exists
    pub fn register_remote(
        &mut self,
        context_id: VarInt,
        target: Option<SocketAddr>,
    ) -> Result<(), ContextError> {
        // Check for duplicate uncompressed
        if target.is_none() && self.uncompressed_context.is_some() {
            return Err(ContextError::DuplicateUncompressed);
        }

        // Check for duplicate target
        if let Some(t) = target {
            for info in self
                .local_contexts
                .values()
                .chain(self.remote_contexts.values())
            {
                if info.target == Some(t) && info.state != ContextState::Closed {
                    return Err(ContextError::DuplicateTarget(t));
                }
            }
        }

        let info = ContextInfo {
            target,
            state: ContextState::Active, // Remote contexts are active once we ACK
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };

        self.remote_contexts.insert(context_id, info);

        if target.is_none() {
            self.uncompressed_context = Some(context_id);
        }

        Ok(())
    }

    /// Handle received COMPRESSION_ACK
    ///
    /// Transitions a pending local context to active state.
    ///
    /// # Errors
    ///
    /// - [`ContextError::UnknownContext`] if the context ID is not found
    /// - [`ContextError::InvalidState`] if the context is not in Pending state
    pub fn handle_ack(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        let info = self
            .local_contexts
            .get_mut(&context_id)
            .ok_or(ContextError::UnknownContext)?;

        if info.state != ContextState::Pending {
            return Err(ContextError::InvalidState);
        }

        info.state = ContextState::Active;
        info.last_activity = Instant::now();

        Ok(())
    }

    /// Close a context (local or remote)
    ///
    /// Transitions the context to Closed state and clears the uncompressed
    /// context tracking if applicable.
    ///
    /// # Errors
    ///
    /// - [`ContextError::UnknownContext`] if the context ID is not found
    pub fn close(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        if let Some(info) = self.local_contexts.get_mut(&context_id) {
            info.state = ContextState::Closed;
            info.last_activity = Instant::now();
        } else if let Some(info) = self.remote_contexts.get_mut(&context_id) {
            info.state = ContextState::Closed;
            info.last_activity = Instant::now();
        } else {
            return Err(ContextError::UnknownContext);
        }

        if self.uncompressed_context == Some(context_id) {
            self.uncompressed_context = None;
        }

        Ok(())
    }

    /// Look up context by target address
    ///
    /// Returns the Context ID for an active compressed context targeting
    /// the specified address, if one exists.
    pub fn get_by_target(&self, target: SocketAddr) -> Option<VarInt> {
        for (id, info) in self
            .local_contexts
            .iter()
            .chain(self.remote_contexts.iter())
        {
            if info.target == Some(target) && info.state == ContextState::Active {
                return Some(*id);
            }
        }
        None
    }

    /// Get the active uncompressed context ID if available
    pub fn uncompressed(&self) -> Option<VarInt> {
        self.uncompressed_context.filter(|id| {
            self.local_contexts
                .get(id)
                .or_else(|| self.remote_contexts.get(id))
                .map(|i| i.state == ContextState::Active)
                .unwrap_or(false)
        })
    }

    /// Get information about a context
    pub fn get_context(&self, context_id: VarInt) -> Option<&ContextInfo> {
        self.local_contexts
            .get(&context_id)
            .or_else(|| self.remote_contexts.get(&context_id))
    }

    /// Get target address for a context
    pub fn get_target(&self, context_id: VarInt) -> Option<SocketAddr> {
        self.get_context(context_id).and_then(|info| info.target)
    }

    /// Update last activity time for a context
    pub fn touch(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        if let Some(info) = self.local_contexts.get_mut(&context_id) {
            info.last_activity = Instant::now();
            Ok(())
        } else if let Some(info) = self.remote_contexts.get_mut(&context_id) {
            info.last_activity = Instant::now();
            Ok(())
        } else {
            Err(ContextError::UnknownContext)
        }
    }

    /// Get count of active contexts
    pub fn active_count(&self) -> usize {
        self.local_contexts
            .values()
            .chain(self.remote_contexts.values())
            .filter(|info| info.state == ContextState::Active)
            .count()
    }

    /// Clean up closed contexts older than the specified age
    pub fn cleanup_closed(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        self.local_contexts.retain(|_, info| {
            info.state != ContextState::Closed || now.duration_since(info.last_activity) < max_age
        });
        self.remote_contexts.retain(|_, info| {
            info.state != ContextState::Closed || now.duration_since(info.last_activity) < max_age
        });
    }

    /// Get iterator over all local context IDs
    pub fn local_context_ids(&self) -> impl Iterator<Item = VarInt> + '_ {
        self.local_contexts.keys().copied()
    }

    /// Get iterator over all remote context IDs
    pub fn remote_context_ids(&self) -> impl Iterator<Item = VarInt> + '_ {
        self.remote_contexts.keys().copied()
    }
}

/// Context management errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// Context ID space exhausted (no more IDs available)
    IdSpaceExhausted,
    /// Only one uncompressed context allowed
    DuplicateUncompressed,
    /// Context ID 0 is reserved
    ReservedId,
    /// Duplicate target address
    DuplicateTarget(SocketAddr),
    /// Unknown context ID
    UnknownContext,
    /// Invalid context state for operation
    InvalidState,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::IdSpaceExhausted => write!(f, "context ID space exhausted"),
            ContextError::DuplicateUncompressed => {
                write!(f, "only one uncompressed context allowed")
            }
            ContextError::ReservedId => write!(f, "context ID 0 is reserved"),
            ContextError::DuplicateTarget(addr) => {
                write!(f, "duplicate target address: {}", addr)
            }
            ContextError::UnknownContext => write!(f, "unknown context ID"),
            ContextError::InvalidState => write!(f, "invalid context state for operation"),
        }
    }
}

impl std::error::Error for ContextError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_context_allocation_client() {
        let mut mgr = ContextManager::new(true);
        assert!(mgr.is_client());

        let id1 = mgr.allocate_local().unwrap();
        assert_eq!(id1.into_inner(), 2); // Client starts at 2 (even)

        let id2 = mgr.allocate_local().unwrap();
        assert_eq!(id2.into_inner(), 4);

        let id3 = mgr.allocate_local().unwrap();
        assert_eq!(id3.into_inner(), 6);
    }

    #[test]
    fn test_context_allocation_server() {
        let mut mgr = ContextManager::new(false);
        assert!(!mgr.is_client());

        let id1 = mgr.allocate_local().unwrap();
        assert_eq!(id1.into_inner(), 1); // Server starts at 1 (odd)

        let id2 = mgr.allocate_local().unwrap();
        assert_eq!(id2.into_inner(), 3);
    }

    #[test]
    fn test_uncompressed_context_limit() {
        let mut mgr = ContextManager::new(true);
        let id = mgr.allocate_local().unwrap();
        mgr.register_uncompressed(id).unwrap();

        let id2 = mgr.allocate_local().unwrap();
        let result = mgr.register_uncompressed(id2);
        assert_eq!(result, Err(ContextError::DuplicateUncompressed));
    }

    #[test]
    fn test_reserved_id_zero() {
        let mut mgr = ContextManager::new(true);
        let result = mgr.register_uncompressed(VarInt::from_u32(0));
        assert_eq!(result, Err(ContextError::ReservedId));
    }

    #[test]
    fn test_compressed_context_lifecycle() {
        let mut mgr = ContextManager::new(true);
        let id = mgr.allocate_local().unwrap();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);

        mgr.register_compressed(id, target).unwrap();
        assert_eq!(mgr.get_context(id).unwrap().state, ContextState::Pending);

        mgr.handle_ack(id).unwrap();
        assert_eq!(mgr.get_context(id).unwrap().state, ContextState::Active);

        assert_eq!(mgr.get_by_target(target), Some(id));
        assert_eq!(mgr.get_target(id), Some(target));

        mgr.close(id).unwrap();
        assert_eq!(mgr.get_context(id).unwrap().state, ContextState::Closed);
        assert_eq!(mgr.get_by_target(target), None);
    }

    #[test]
    fn test_duplicate_target() {
        let mut mgr = ContextManager::new(true);
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

        let id1 = mgr.allocate_local().unwrap();
        mgr.register_compressed(id1, target).unwrap();
        mgr.handle_ack(id1).unwrap();

        let id2 = mgr.allocate_local().unwrap();
        let result = mgr.register_compressed(id2, target);
        assert_eq!(result, Err(ContextError::DuplicateTarget(target)));
    }

    #[test]
    fn test_remote_context_registration() {
        let mut mgr = ContextManager::new(true);
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);

        // Remote context from server (odd ID)
        mgr.register_remote(VarInt::from_u32(1), Some(target))
            .unwrap();

        // Remote contexts start as Active
        assert_eq!(
            mgr.get_context(VarInt::from_u32(1)).unwrap().state,
            ContextState::Active
        );

        // Should be findable by target
        assert_eq!(mgr.get_by_target(target), Some(VarInt::from_u32(1)));
    }

    #[test]
    fn test_active_count() {
        let mut mgr = ContextManager::new(true);

        assert_eq!(mgr.active_count(), 0);

        let id1 = mgr.allocate_local().unwrap();
        let target1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000);
        mgr.register_compressed(id1, target1).unwrap();
        mgr.handle_ack(id1).unwrap();

        assert_eq!(mgr.active_count(), 1);

        let id2 = mgr.allocate_local().unwrap();
        let target2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000);
        mgr.register_compressed(id2, target2).unwrap();
        mgr.handle_ack(id2).unwrap();

        assert_eq!(mgr.active_count(), 2);

        mgr.close(id1).unwrap();
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_unknown_context_errors() {
        let mut mgr = ContextManager::new(true);
        let unknown_id = VarInt::from_u32(999);

        assert_eq!(
            mgr.handle_ack(unknown_id),
            Err(ContextError::UnknownContext)
        );
        assert_eq!(mgr.close(unknown_id), Err(ContextError::UnknownContext));
        assert_eq!(mgr.touch(unknown_id), Err(ContextError::UnknownContext));
    }

    #[test]
    fn test_invalid_state_ack() {
        let mut mgr = ContextManager::new(true);
        let id = mgr.allocate_local().unwrap();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);

        mgr.register_compressed(id, target).unwrap();
        mgr.handle_ack(id).unwrap();

        // Double ack should fail
        assert_eq!(mgr.handle_ack(id), Err(ContextError::InvalidState));
    }

    #[test]
    fn test_context_iterators() {
        let mut mgr = ContextManager::new(true);

        let id1 = mgr.allocate_local().unwrap();
        let id2 = mgr.allocate_local().unwrap();
        let target1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000);
        let target2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000);

        mgr.register_compressed(id1, target1).unwrap();
        mgr.register_compressed(id2, target2).unwrap();

        let local_ids: Vec<_> = mgr.local_context_ids().collect();
        assert_eq!(local_ids.len(), 2);
        assert!(local_ids.contains(&id1));
        assert!(local_ids.contains(&id2));

        // Register a remote context
        let remote_id = VarInt::from_u32(1);
        let remote_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        mgr.register_remote(remote_id, Some(remote_target)).unwrap();

        let remote_ids: Vec<_> = mgr.remote_context_ids().collect();
        assert_eq!(remote_ids.len(), 1);
        assert!(remote_ids.contains(&remote_id));
    }
}
