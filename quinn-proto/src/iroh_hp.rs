use std::{
    collections::hash_map::Entry,
    net::{IpAddr, SocketAddr},
};

use rustc_hash::FxHashMap;

use crate::{
    Side, VarInt,
    frame::{AddAddress, RemoveAddress},
};

/// Maximum number of addresses to handle, applied both to local and remote addresses.
// TODO(@divma): consider making this a config option
const MAX_ADDRESSES: usize = 20;

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
}

// TODO(@divma): unclear to me what these events are useful for\
#[derive(Debug)]
pub enum Event {
    AddressAdded(SocketAddr),
    AddressRemoved(SocketAddr),
}

/// State kept for Iroh's nat traversal
#[derive(Debug)]
pub(crate) struct State {
    /// Candidate addresses the remote server reports as potentially reachable, to use for nat
    /// traversal attempts.
    remote_addresses: FxHashMap<VarInt, (IpAddr, u16)>,
    /// Candidate addresses the local client reports as potentially reachable, to use for nat
    /// traversal attempts.
    local_addresses: FxHashMap<(IpAddr, u16), VarInt>,
    /// The next id to use for local addresses sent to the client
    next_local_addr_id: VarInt,
    /// Max concurrent address validations to perform
    max_concurrent_path_validations: u64,
    /// Local connection side
    side: Side,
}

/// Nat traversal api exclusive to clients
pub(crate) struct ClientSide<'a> {
    state: &'a mut State,
}

impl State {
    /// Add a local address to use for nat traversal
    ///
    /// When this endpoint is the server within the connection, these addresses will be sent to the
    /// client in add address frames. For clients, these addresses will be sent in reach out frames
    pub(crate) fn add_local_address(&mut self, address: SocketAddr) -> Result<SocketAddr, Error> {
        let address = (address.ip(), address.port());
        let allow_new = self.local_addresses.len() < MAX_ADDRESSES;
        match self.local_addresses.entry(address) {
            Entry::Occupied(occupied_entry) => Ok(*occupied_entry.get()),
            Entry::Vacant(vacant_entry) if allow_new => {
                let id = self.next_local_addr_id;
                self.next_local_addr_id = self.next_local_addr_id.saturating_add(1u8);
                vacant_entry.insert(id);
                // NOTE for ipv6 addresses this cleans up fields not relevant to the protocol
                Ok(address.into())
            }
            _ => Err(Error::TooManyAddresses),
        }
    }

    /// Removes a local address from the advertised set for nat traversal
    ///
    /// When this endpoint is the server, removed addresses must be reported with remove address
    /// frames. Clients will simply stop reporting these addresses in reach out frames.
    pub(crate) fn remove_local_address(&mut self, address: SocketAddr) -> Option<VarInt> {
        self.local_addresses.remove(&(address.ip(), address.port()))
    }

    pub(crate) fn client_side(&mut self) -> Result<ClientSide<'_>, Error> {
        if self.side.is_client() {
            Ok(ClientSide { state: self })
        } else {
            Err(Error::WrongConnectionSide)
        }
    }

    pub(crate) fn new(VarInt(max_concurrent_path_validations): VarInt, side: Side) -> Self {
        Self {
            remote_addresses: Default::default(),
            local_addresses: Default::default(),
            next_local_addr_id: Default::default(),
            max_concurrent_path_validations,
            side,
        }
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
        let address = (ip, port);
        let allow_new = self.state.remote_addresses.len() < MAX_ADDRESSES;
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
