use std::{
    collections::hash_map::Entry,
    net::{IpAddr, SocketAddr},
};

use rustc_hash::FxHashMap;

use crate::{VarInt, frame::RemoveAddress};

use super::frame::AddAddress;

/// Maximum number of addresses to handle, applied both to local and remote addresses.
// TODO(@divma): consider making this a config option
const MAX_ADDRESSES: usize = 20;

/// Errors that the nat traversal state might encounter.
pub(crate) enum Error {
    // An endpoint (local or remote) tried to add too many addresses to their advertised set
    TooManyAddresses,
}

/// State kept for Iroh's nat traversal
#[derive(Debug, Default)]
pub(crate) struct State {
    /// Candidate addresses the remote server reports as potentially reachable, to use for nat
    /// traversal attempts.
    remote_addresses: FxHashMap<VarInt, (IpAddr, u16)>,

    /// Candidate addresses the local client reports as potentially reachable, to use for nat
    /// traversal attempts.
    local_addresses: FxHashMap<(IpAddr, u16), VarInt>,
    // The next id to use for local addresses sent to the client
    next_local_addr_id: VarInt,
}

impl State {
    /// Add a local address to use for nat traversal
    ///
    /// When this endpoint is the server within the connection, these addresses will be sent to the
    /// client in add address frames. For clients, these addresses will be sent in reach out frames
    pub(crate) fn add_local_address(&mut self, address: SocketAddr) -> Result<VarInt, Error> {
        let address = (address.ip(), address.port());
        let allow_new = self.local_addresses.len() < MAX_ADDRESSES;
        match self.local_addresses.entry(address) {
            Entry::Occupied(occupied_entry) => Ok(*occupied_entry.get()),
            Entry::Vacant(vacant_entry) if allow_new => {
                let id = self.next_local_addr_id;
                self.next_local_addr_id = self.next_local_addr_id.saturating_add(1u8);
                vacant_entry.insert(id);
                Ok(id)
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

    /// Adds an address to the remote set
    ///
    /// On success returns whether the address was new to the set. It will error when the set has
    /// no capacity for the address.
    pub(crate) fn add_remote_address(&mut self, add_addr: AddAddress) -> Result<bool, Error> {
        let AddAddress { seq_no, ip, port } = add_addr;
        let address = (ip, port);
        let allow_new = self.remote_addresses.len() < MAX_ADDRESSES;
        match self.remote_addresses.entry(seq_no) {
            Entry::Occupied(mut occupied_entry) => {
                let old_value = occupied_entry.insert(address);
                // The value might be different. This should not happen, but we assume that the new
                // address is more recent than the previous, and thus worth updating
                Ok(address != old_value)
            }
            Entry::Vacant(vacant_entry) if allow_new => {
                vacant_entry.insert(address);
                Ok(true)
            }
            _ => Err(Error::TooManyAddresses),
        }
    }

    /// Removes an address from the remote set
    ///
    /// Returns whether the address was present.
    pub(crate) fn remove_remote_address(&mut self, remove_addr: RemoveAddress) -> bool {
        self.remote_addresses.remove(&remove_addr.seq_no).is_some()
    }

    /// Checks that a received remote address is valid
    ///
    /// An address is valid as long as it does not change the value of a known address id
    pub(crate) fn check_remote_address(&self, add_addr: AddAddress) -> bool {
        let existing = self.remote_addresses.get(&add_addr.seq_no);
        existing.is_none() || existing == Some(&add_addr.ip_port())
    }
}
