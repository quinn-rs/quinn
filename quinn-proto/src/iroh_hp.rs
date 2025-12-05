//! iroh NAT Traversal

use std::{
    collections::hash_map::Entry,
    net::{IpAddr, SocketAddr},
};

use identity_hash::IntMap;
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::trace;

use crate::{
    PathId, Side, VarInt,
    frame::{AddAddress, ReachOut, RemoveAddress},
};

type IpPort = (IpAddr, u16);

/// Errors that the nat traversal state might encounter.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An endpoint (local or remote) tried to add too many addresses to their advertised set
    #[error("Tried to add too many addresses to their advertised set")]
    TooManyAddresses,
    /// The operation is not allowed for this endpoint's connection side
    #[error("Not allowed for this endpoint's connection side")]
    WrongConnectionSide,
    /// The extension was not negotiated
    #[error("Iroh's nat traversal was not negotiated")]
    ExtensionNotNegotiated,
    /// Not enough addresses to complete the operation
    #[error("Not enough addresses")]
    NotEnoughAddresses,
    /// Nat traversal attempt failed due to a multipath error
    #[error("Failed to establish paths {0}")]
    Multipath(super::PathError),
}

pub(crate) struct NatTraversalRound {
    /// Sequence number to use for the new reach out frames
    pub(crate) new_round: VarInt,
    /// Addresses to use to send reach out frames
    pub(crate) reach_out_at: Vec<(IpAddr, u16)>,
    /// Remotes to probe by attempting to open new paths
    pub(crate) addresses_to_probe: Vec<(IpAddr, u16)>,
    /// [`PathId`]s of the cancelled round
    pub(crate) prev_round_path_ids: Vec<PathId>,
}

/// Event emitted when the client receives ADD_ADDRESS or REMOVE_ADDRESS frames.
#[derive(Debug, Clone)]
pub enum Event {
    /// An ADD_ADDRESS frame was received.
    AddressAdded(SocketAddr),
    /// A REMOVE_ADDRESS frame was received.
    AddressRemoved(SocketAddr),
}

/// State kept for Iroh's nat traversal
#[derive(Debug, Default)]
pub(crate) enum State {
    #[default]
    NotNegotiated,
    ClientSide(ClientState),
    ServerSide(ServerState),
}

#[derive(Debug)]
pub(crate) struct ClientState {
    /// Max number of remote addresses we allow
    ///
    /// This is set by the local endpoint.
    max_remote_addresses: usize,
    /// Max number of local addresses allowed
    ///
    /// This is set by the remote endpoint.
    max_local_addresses: usize,
    /// Candidate addresses the remote server reports as potentially reachable, to use for nat
    /// traversal attempts.
    remote_addresses: FxHashMap<VarInt, (IpAddr, u16)>,
    /// Candidate addresses the local client reports as potentially reachable, to use for nat
    /// traversal attempts. Always canonical.
    local_addresses: FxHashSet<(IpAddr, u16)>,
    /// Current nat holepunching round.
    round: VarInt,
    /// [`PathId`]s used to probe remotes assigned to this round.
    round_path_ids: Vec<PathId>,
}

impl ClientState {
    fn new(max_remote_addresses: usize, max_local_addresses: usize) -> Self {
        Self {
            max_remote_addresses,
            max_local_addresses,
            remote_addresses: Default::default(),
            local_addresses: Default::default(),
            round: Default::default(),
            round_path_ids: Default::default(),
        }
    }

    fn add_local_address(&mut self, address: IpPort) -> Result<(), Error> {
        if self.local_addresses.len() < self.max_local_addresses {
            self.local_addresses.insert(address);
            Ok(())
        } else if self.local_addresses.contains(&address) {
            // at capacity, but the address is known, no issues here
            Ok(())
        } else {
            // at capacity and the address is new
            Err(Error::TooManyAddresses)
        }
    }

    fn remove_local_address(&mut self, address: &IpPort) {
        self.local_addresses.remove(address);
    }

    /// Initiates a new nat traversal round.
    ///
    /// A nat traversal round involves advertising the client's local addresses in `REACH_OUT`
    /// frames, and initiating probing of the known remote addresses. When a new round is
    /// initiated, the previous one is cancelled, and paths that have not been opened should be
    /// closed.
    pub(crate) fn initiate_nat_traversal_round(&mut self) -> Result<NatTraversalRound, Error> {
        if self.local_addresses.is_empty() {
            return Err(Error::NotEnoughAddresses);
        }

        let prev_round_path_ids = std::mem::take(&mut self.round_path_ids);
        self.round = self.round.saturating_add(1u8);

        Ok(NatTraversalRound {
            new_round: self.round,
            reach_out_at: self.local_addresses.iter().copied().collect(),
            addresses_to_probe: self.remote_addresses.values().copied().collect(),
            prev_round_path_ids,
        })
    }

    /// Add a [`PathId`] as part of the current attempts to create paths based on the server's
    /// advertised addresses.
    pub(crate) fn set_round_path_ids(&mut self, path_ids: Vec<PathId>) {
        self.round_path_ids = path_ids;
    }

    /// Adds an address to the remote set
    ///
    /// On success returns the address if it was new to the set. It will error when the set has no
    /// capacity for the address.
    pub(crate) fn add_remote_address(
        &mut self,
        add_addr: AddAddress,
    ) -> Result<Option<SocketAddr>, Error> {
        let AddAddress { seq_no, ip, port } = add_addr;
        let address = (ip, port);
        let allow_new = self.remote_addresses.len() < self.max_remote_addresses;
        match self.remote_addresses.entry(seq_no) {
            Entry::Occupied(mut occupied_entry) => {
                let old_value = occupied_entry.insert(address);
                // The value might be different. This should not happen, but we assume that the new
                // address is more recent than the previous, and thus worth updating
                Ok((address != old_value).then_some(address.into()))
            }
            Entry::Vacant(vacant_entry) if allow_new => {
                vacant_entry.insert(address);
                Ok(Some(address.into()))
            }
            _ => Err(Error::TooManyAddresses),
        }
    }

    /// Removes an address from the remote set
    ///
    /// Returns whether the address was present.
    pub(crate) fn remove_remote_address(
        &mut self,
        remove_addr: RemoveAddress,
    ) -> Option<SocketAddr> {
        self.remote_addresses
            .remove(&remove_addr.seq_no)
            .map(Into::into)
    }

    /// Checks that a received remote address is valid
    ///
    /// An address is valid as long as it does not change the value of a known address id.
    pub(crate) fn check_remote_address(&self, add_addr: &AddAddress) -> bool {
        let existing = self.remote_addresses.get(&add_addr.seq_no);
        existing.is_none() || existing == Some(&add_addr.ip_port())
    }

    pub(crate) fn get_remote_nat_traversal_addresses(&self) -> Vec<SocketAddr> {
        self.remote_addresses
            .values()
            .copied()
            .map(Into::into)
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct ServerState {
    /// Max number of remote addresses we allow.
    ///
    /// This is set by the local endpoint.
    max_remote_addresses: usize,
    /// Max number of local addresses allowed.
    ///
    /// This is set by the remote endpoint.
    max_local_addresses: usize,
    /// Candidate addresses the server reports as potentially reachable, to use for nat
    /// traversal attempts.
    local_addresses: FxHashMap<IpPort, VarInt>,
    /// The next id to use for local addresses sent to the client.
    next_local_addr_id: VarInt,
    /// Current nat holepunching round
    ///
    /// Servers keep track of the client's most recent round and cancel probing related to previous
    /// rounds.
    round: VarInt,
    /// Addresses to which PATH_CHALLENGES need to be sent.
    pending_probes: FxHashSet<IpPort>,
    /// Sent PATH_CHALLENGES for this round.
    ///
    /// This is used to validate the remotes assigned to each token.
    active_probes: IntMap<u64, IpPort>,
}

impl ServerState {
    fn new(max_remote_addresses: usize, max_local_addresses: usize) -> Self {
        Self {
            max_remote_addresses,
            max_local_addresses,
            local_addresses: Default::default(),
            next_local_addr_id: Default::default(),
            round: Default::default(),
            pending_probes: Default::default(),
            active_probes: Default::default(),
        }
    }

    fn add_local_address(&mut self, address: IpPort) -> Result<Option<AddAddress>, Error> {
        let allow_new = self.local_addresses.len() < self.max_local_addresses;
        match self.local_addresses.entry(address) {
            Entry::Occupied(_) => Ok(None),
            Entry::Vacant(vacant_entry) if allow_new => {
                let id = self.next_local_addr_id;
                self.next_local_addr_id = self.next_local_addr_id.saturating_add(1u8);
                vacant_entry.insert(id);
                Ok(Some(AddAddress::new(address, id)))
            }
            _ => Err(Error::TooManyAddresses),
        }
    }

    fn remove_local_address(&mut self, address: &IpPort) -> Option<RemoveAddress> {
        self.local_addresses.remove(address).map(RemoveAddress::new)
    }

    /// Handles a received [`ReachOut`].
    ///
    /// It returns the token that should be sent in response to this frame as a challenge, and
    /// whether this starts a new nat traversal round.
    ///
    /// If this frame was ignored, it returns `None`.
    pub(crate) fn handle_reach_out(&mut self, reach_out: ReachOut) -> Result<(), Error> {
        let ReachOut { round, ip, port } = reach_out;

        if round < self.round {
            trace!(current_round=%self.round, "ignoring REACH_OUT for previous round");
            return Ok(());
        }

        if round > self.round {
            self.pending_probes.clear();
            // TODO(@divma): This log is here because I'm not sure if dropping the challenges
            // without further interaction with the connection is going to cause issues.
            for (token, remote) in self.active_probes.drain() {
                let remote: SocketAddr = remote.into();
                trace!(token=format!("{:08x}", token), %remote, "dropping nat traversal challenge pending response");
            }
        } else if self.pending_probes.len() >= self.max_remote_addresses {
            return Err(Error::TooManyAddresses);
        }
        self.pending_probes.insert((ip, port));
        Ok(())
    }

    pub(crate) fn next_probe(&mut self) -> Option<ServerProbing<'_>> {
        self.pending_probes
            .iter()
            .next()
            .copied()
            .map(|remote| ServerProbing {
                remote,
                pending_probes: &mut self.pending_probes,
                active_probes: &mut self.active_probes,
            })
    }
}

pub(crate) struct ServerProbing<'a> {
    remote: IpPort,
    pending_probes: &'a mut FxHashSet<IpPort>,
    active_probes: &'a mut IntMap<u64, IpPort>,
}

impl<'a> ServerProbing<'a> {
    pub(crate) fn finish(self, token: u64) {
        self.pending_probes.remove(&self.remote);
        self.active_probes.insert(token, self.remote);
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.remote.into()
    }
}

impl State {
    pub(crate) fn new(max_remote_addresses: u8, max_local_addresses: u8, side: Side) -> Self {
        match side {
            Side::Client => Self::ClientSide(ClientState::new(
                max_remote_addresses.into(),
                max_local_addresses.into(),
            )),
            Side::Server => Self::ServerSide(ServerState::new(
                max_remote_addresses.into(),
                max_local_addresses.into(),
            )),
        }
    }

    pub(crate) fn client_side(&self) -> Result<&ClientState, Error> {
        match self {
            Self::NotNegotiated => Err(Error::ExtensionNotNegotiated),
            Self::ClientSide(client_side) => Ok(client_side),
            Self::ServerSide(_) => Err(Error::WrongConnectionSide),
        }
    }

    pub(crate) fn client_side_mut(&mut self) -> Result<&mut ClientState, Error> {
        match self {
            Self::NotNegotiated => Err(Error::ExtensionNotNegotiated),
            Self::ClientSide(client_side) => Ok(client_side),
            Self::ServerSide(_) => Err(Error::WrongConnectionSide),
        }
    }

    pub(crate) fn server_side_mut(&mut self) -> Result<&mut ServerState, Error> {
        match self {
            Self::NotNegotiated => Err(Error::ExtensionNotNegotiated),
            Self::ClientSide(_) => Err(Error::WrongConnectionSide),
            Self::ServerSide(server_side) => Ok(server_side),
        }
    }

    /// Adds a local address to use for nat traversal.
    ///
    /// When this endpoint is the server within the connection, these addresses will be sent to the
    /// client in add address frames. For clients, these addresses will be sent in reach out frames
    /// when nat traversal attempts are initiated.
    ///
    /// If a frame should be sent, it is returned.
    pub(crate) fn add_local_address(
        &mut self,
        address: SocketAddr,
    ) -> Result<Option<AddAddress>, Error> {
        match self {
            Self::NotNegotiated => Err(Error::ExtensionNotNegotiated),
            Self::ClientSide(client_state) => {
                client_state.add_local_address((address.ip(), address.port()))?;
                Ok(None)
            }
            Self::ServerSide(server_state) => {
                server_state.add_local_address((address.ip(), address.port()))
            }
        }
    }

    /// Removes a local address from the advertised set for nat traversal.
    ///
    /// When this endpoint is the server, removed addresses must be reported with remove address
    /// frames. Clients will simply stop reporting these addresses in reach out frames.
    ///
    /// If a frame should be sent, it is returned.
    pub(crate) fn remove_local_address(
        &mut self,
        address: SocketAddr,
    ) -> Result<Option<RemoveAddress>, Error> {
        let address = &(address.ip(), address.port());
        match self {
            Self::NotNegotiated => Err(Error::ExtensionNotNegotiated),
            Self::ClientSide(client_state) => {
                client_state.remove_local_address(address);
                Ok(None)
            }
            Self::ServerSide(server_state) => Ok(server_state.remove_local_address(address)),
        }
    }

    pub(crate) fn get_local_nat_traversal_addresses(&self) -> Result<Vec<SocketAddr>, Error> {
        match self {
            Self::NotNegotiated => Err(Error::ExtensionNotNegotiated),
            Self::ClientSide(client_state) => Ok(client_state
                .local_addresses
                .iter()
                .copied()
                .map(Into::into)
                .collect()),
            Self::ServerSide(server_state) => Ok(server_state
                .local_addresses
                .keys()
                .copied()
                .map(Into::into)
                .collect()),
        }
    }
}
