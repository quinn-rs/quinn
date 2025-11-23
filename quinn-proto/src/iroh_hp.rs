use std::{
    collections::hash_map::Entry,
    net::{IpAddr, SocketAddr},
};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    PathId, Side, VarInt,
    frame::{AddAddress, ReachOut, RemoveAddress},
};

/// Maximum number of addresses to handle, applied both to local and remote addresses, regardless
/// of configuration parameters
const MAX_ADDRESSES: u8 = 20;

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

pub(crate) struct RandDataNeeded {
    /// Destination address of the hole punching random data
    pub(crate) ip: IpAddr,
    /// Destination port of the hole punching random data
    pub(crate) port: u16,
    /// Round to which this hole punching random data belongs to
    pub(crate) round: VarInt,
    /// Whether this starts a new round
    pub(crate) is_new_round: bool,
}

// TODO(@divma): unclear to me what these events are useful for\
#[derive(Debug, Clone)]
pub enum Event {
    AddressAdded(SocketAddr),
    AddressRemoved(SocketAddr),
}

/// State kept for Iroh's nat traversal
#[derive(Debug)]
pub(crate) struct State {
    /// Max number of remote addresses we allow
    ///
    /// This is set by the local endpoint.
    max_remote_addresses: usize,
    /// Max number of local addresses allowed
    ///
    /// This is set by the remote endpoint.
    max_local_addresses: usize,
    /// Candidate addresses the remote server reports as potentially reachable, to use for nat
    /// traversal attempts. Always canonical.
    remote_addresses: FxHashMap<VarInt, (IpAddr, u16)>,
    /// Candidate addresses the local client reports as potentially reachable, to use for nat
    /// traversal attempts. Always canonical.
    local_addresses: FxHashMap<(IpAddr, u16), VarInt>,
    /// The next id to use for local addresses sent to the client
    next_local_addr_id: VarInt,
    /// Local connection side
    side: Side,
    /// Current nat holepunching round
    ///
    /// Clients initiate hole punching rounds and are thus responsible for incrementing the count.
    /// Servers keep track of the client's most recent round and cancel probing related to previous
    /// rounds.
    round: VarInt,
    /// [`PathId`]s used to probe remotes assigned to this round
    round_path_ids: Vec<PathId>,
    /// Addresses to which random data sent by servers to attempt to hole punch to clients
    server_sent_rand_data: FxHashSet<(IpAddr, u16)>,
}

/// Nat traversal api exclusive to clients
pub(crate) struct ClientSide<'a> {
    state: &'a mut State,
}

impl State {
    /// Adds a local address to use for nat traversal
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
        let address = (address.ip().to_canonical(), address.port());
        let allow_new = self.local_addresses.len() < self.max_local_addresses;
        let is_server = self.side.is_server();
        match self.local_addresses.entry(address) {
            Entry::Occupied(_) => Ok(None),
            Entry::Vacant(vacant_entry) if allow_new => {
                let id = self.next_local_addr_id;
                self.next_local_addr_id = self.next_local_addr_id.saturating_add(1u8);
                vacant_entry.insert(id);
                if is_server {
                    Ok(Some(AddAddress::new(address, id)))
                } else {
                    Ok(None)
                }
            }
            _ => Err(Error::TooManyAddresses),
        }
    }

    /// Removes a local address from the advertised set for nat traversal
    ///
    /// When this endpoint is the server, removed addresses must be reported with remove address
    /// frames. Clients will simply stop reporting these addresses in reach out frames.
    ///
    /// If a frame should be sent, it is returned.
    pub(crate) fn remove_local_address(&mut self, address: SocketAddr) -> Option<RemoveAddress> {
        let id = self
            .local_addresses
            .remove(&(address.ip(), address.port()))?;
        if self.side.is_server() {
            Some(RemoveAddress::new(id))
        } else {
            None
        }
    }

    pub(crate) fn client_side(&mut self) -> Result<ClientSide<'_>, Error> {
        if self.side.is_client() {
            Ok(ClientSide { state: self })
        } else {
            Err(Error::WrongConnectionSide)
        }
    }

    pub(crate) fn new(max_remote_addresses: u8, max_local_addresses: u8, side: Side) -> Self {
        Self {
            remote_addresses: Default::default(),
            local_addresses: Default::default(),
            next_local_addr_id: Default::default(),
            side,
            round: Default::default(),
            round_path_ids: Default::default(),
            server_sent_rand_data: Default::default(),
            max_remote_addresses: max_remote_addresses.min(MAX_ADDRESSES).into(),
            max_local_addresses: max_local_addresses.min(MAX_ADDRESSES).into(),
        }
    }

    pub(crate) fn get_local_nat_traversal_addresses(&self) -> Vec<SocketAddr> {
        self.local_addresses
            .keys()
            .copied()
            .map(Into::into)
            .collect()
    }

    pub(crate) fn get_remote_nat_traversal_addresses(&self) -> Result<Vec<SocketAddr>, Error> {
        if !self.side.is_client() {
            return Err(Error::WrongConnectionSide);
        }

        Ok(self
            .remote_addresses
            .values()
            .copied()
            .map(Into::into)
            .collect())
    }

    /// Initiates a new nat traversal round
    ///
    /// A nat traversal round involves advertising the client's local addresses in `REACH_OUT`
    /// frames, and initiating probing of the known remote addresses. When a new round is
    /// initiated, the previous one is cancelled, and paths that have not been opened should be
    /// closed.
    pub(crate) fn initiate_nat_traversal_round(&mut self) -> Result<NatTraversalRound, Error> {
        if self.side.is_server() {
            return Err(Error::WrongConnectionSide);
        }

        if self.local_addresses.is_empty() {
            return Err(Error::NotEnoughAddresses);
        }

        let prev_round_path_ids = std::mem::replace(&mut self.round_path_ids, Default::default());
        self.round = self.round.saturating_add(1u8);

        Ok(NatTraversalRound {
            new_round: self.round,
            reach_out_at: self.local_addresses.keys().copied().collect(),
            addresses_to_probe: self.remote_addresses.values().copied().collect(),
            prev_round_path_ids,
        })
    }

    /// Add a [`PathId`] as part of the current attempts to create paths based on the server's
    /// advertised addresses.
    pub(crate) fn set_round_path_ids(&mut self, path_ids: Vec<PathId>) -> Result<(), Error> {
        if self.side.is_server() {
            return Err(Error::WrongConnectionSide);
        }
        self.round_path_ids = path_ids;
        Ok(())
    }

    /// Handles a received [`ReachOut`]
    ///
    /// It returns the token that should be sent in response to this frame as a challenge, and
    /// whether this starts a new nat traversal round.
    ///
    /// If this frame was ignored, it returns `None`.
    pub(crate) fn handle_reach_out(
        &mut self,
        reach_out: ReachOut,
    ) -> Result<Option<RandDataNeeded>, Error> {
        let ReachOut { round, ip, port } = reach_out;
        if self.side.is_client() {
            return Err(Error::WrongConnectionSide);
        }

        if round >= self.round {
            let is_new_round = round > self.round;
            if is_new_round {
                self.server_sent_rand_data.clear();
            }
            if self.server_sent_rand_data.len() >= self.max_remote_addresses {
                return Err(Error::TooManyAddresses);
            }
            self.server_sent_rand_data.insert((ip, port));
            let info = RandDataNeeded {
                ip,
                port,
                round,
                is_new_round,
            };
            return Ok(Some(info));
        }

        Ok(None)
    }
}

impl<'a> ClientSide<'a> {
    /// Adds an address to the remote set
    ///
    /// On success returns the address if it was new to the set. It will error when the set has no
    /// capacity for the address.
    pub(crate) fn add_remote_address(
        &mut self,
        add_addr: AddAddress,
    ) -> Result<Option<SocketAddr>, Error> {
        let AddAddress { seq_no, ip, port } = add_addr;
        let address = (ip.to_canonical(), port);
        let allow_new = self.state.remote_addresses.len() < self.state.max_remote_addresses;
        match self.state.remote_addresses.entry(seq_no) {
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
        self.state
            .remote_addresses
            .remove(&remove_addr.seq_no)
            .map(Into::into)
    }

    /// Checks that a received remote address is valid
    ///
    /// An address is valid as long as it does not change the value of a known address id.
    pub(crate) fn check_remote_address(&self, add_addr: &AddAddress) -> bool {
        let existing = self.state.remote_addresses.get(&add_addr.seq_no);
        existing.is_none() || existing == Some(&add_addr.ip_port())
    }
}
