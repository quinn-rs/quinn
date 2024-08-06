//! Storing tokens sent from servers in NEW_TOKEN frames and using them in subsequent connections

use bytes::Bytes;
use slab::Slab;
use std::{
    collections::{hash_map, HashMap},
    mem::take,
    rc::Rc,
    sync::Mutex,
};

/// Responsible for storing tokens sent from servers in NEW_TOKEN frames and retreiving them for
/// use in subsequent connections
pub trait NewTokenStore: Send + Sync {
    /// Called when a NEW_TOKEN frame is received from the server
    fn store(&self, server_name: &str, token: Bytes);

    /// Called when trying to connect to a server
    ///
    /// The same token should never be returned from `take` twice.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}

/// `NewTokenStore` implementation that stores up to `N` tokens per server name for up to a limited
/// number of server names, in-memory
pub struct InMemNewTokenStore<const N: usize>(Mutex<InMemNewTokenStoreState<N>>);

impl<const N: usize> InMemNewTokenStore<N> {
    /// Construct empty
    pub fn new(size_limit: usize) -> Self {
        Self(Mutex::new(InMemNewTokenStoreState::new(size_limit)))
    }
}

impl<const N: usize> NewTokenStore for InMemNewTokenStore<N> {
    fn store(&self, server_name: &str, token: Bytes) {
        self.0.lock().unwrap().store(server_name, token)
    }

    fn take(&self, server_name: &str) -> Option<Bytes> {
        self.0.lock().unwrap().take(server_name)
    }
}

/// Defaults to a size limit of 256
impl<const N: usize> Default for InMemNewTokenStore<N> {
    fn default() -> Self {
        Self::new(256)
    }
}

// safety: InMemNewTokenStoreState is !Send and !Sync because it uses Rc. so long as
//         InMemNewTokenStore doesn't keep Rc handles after the mutex is unlocked, it's safe.
unsafe impl<const N: usize> Send for InMemNewTokenStore<N> {}
unsafe impl<const N: usize> Sync for InMemNewTokenStore<N> {}

#[derive(Debug)]
struct InMemNewTokenStoreState<const N: usize> {
    size_limit: usize,
    // linked hash table structure
    lookup: HashMap<Rc<str>, usize>,
    entries: Slab<InMemNewTokenStoreEntry<N>>,
    oldest_newest: Option<(usize, usize)>,
}

#[derive(Debug)]
struct InMemNewTokenStoreEntry<const N: usize> {
    server_name: Rc<str>,
    older: Option<usize>,
    newer: Option<usize>,
    // tokens are pushed to and popped from the top of the token stack. exceeding capacity is
    // handled by dropping the bottom of the stack.
    token_stack: [Bytes; N],
    token_stack_start: usize,
    token_stack_len: usize,
}

impl<const N: usize> InMemNewTokenStoreState<N> {
    fn new(size_limit: usize) -> Self {
        assert!(size_limit > 0, "size limit cannot be 0");
        InMemNewTokenStoreState {
            size_limit,
            lookup: HashMap::new(),
            entries: Slab::new(),
            oldest_newest: None,
        }
    }

    /// Unlink an entry's neighbors from it
    fn unlink(
        idx: usize,
        entries: &mut Slab<InMemNewTokenStoreEntry<N>>,
        oldest_newest: &mut Option<(usize, usize)>,
    ) {
        if let Some(older) = entries[idx].older {
            entries[older].newer = entries[idx].newer;
        } else {
            // unwrap safety: entries[idx] exists, therefore oldest_newest is some
            *oldest_newest = entries[idx]
                .newer
                .map(|newer| (oldest_newest.unwrap().0, newer));
        }
        if let Some(newer) = entries[idx].newer {
            entries[newer].older = entries[idx].older;
        } else {
            // unwrap safety: oldest_newest is none iff entries[idx] was the only entry.
            //                if entries[idx].older is some, entries[idx] was not the only entry
            //                therefore oldest_newest is some.
            *oldest_newest = entries[idx]
                .older
                .map(|older| (older, oldest_newest.unwrap().1));
        }
    }

    /// Link an entry as the most recently used entry
    ///
    /// Assumes any pre-existing neighbors are already unlinked.
    fn link(
        idx: usize,
        entries: &mut Slab<InMemNewTokenStoreEntry<N>>,
        oldest_newest: &mut Option<(usize, usize)>,
    ) {
        entries[idx].newer = None;
        entries[idx].older = oldest_newest.map(|(_, newest)| newest);
        if let &mut Some((_, ref mut newest)) = oldest_newest {
            *newest = idx;
        } else {
            *oldest_newest = Some((idx, idx));
        }
    }

    fn store(&mut self, server_name: &str, token: Bytes) {
        let server_name = Rc::<str>::from(server_name);
        let idx = match self.lookup.entry(server_name.clone()) {
            hash_map::Entry::Occupied(hmap_entry) => {
                // key already exists, add the new token to its token stack
                let entry = &mut self.entries[*hmap_entry.get()];
                entry.token_stack[(entry.token_stack_start + entry.token_stack_len) % N] = token;
                if entry.token_stack_len < N {
                    entry.token_stack_len += 1;
                } else {
                    entry.token_stack_start += 1;
                }

                // unlink the entry and set it up to be linked as the most recently used
                Self::unlink(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
                *hmap_entry.get()
            }
            hash_map::Entry::Vacant(hmap_entry) => {
                // key does not yet exist, create a new one, evicting the oldest if necessary
                let removed_key = if self.entries.len() >= self.size_limit {
                    // unwrap safety: size_limit is > 0, so there's at least one entry, so
                    //                oldest_newest is some
                    let oldest = self.oldest_newest.unwrap().0;
                    Self::unlink(oldest, &mut self.entries, &mut self.oldest_newest);
                    Some(self.entries.remove(oldest).server_name)
                } else {
                    None
                };

                const EMPTY_BYTES: Bytes = Bytes::new();
                let mut token_stack = [EMPTY_BYTES; N];
                token_stack[0] = token;
                let idx = self.entries.insert(InMemNewTokenStoreEntry {
                    server_name,
                    // we'll link these after the fact
                    older: None,
                    newer: None,
                    token_stack,
                    token_stack_start: 0,
                    token_stack_len: 1,
                });
                hmap_entry.insert(idx);

                // for borrowing reasons, we must defer removing the evicted hmap entry
                if let Some(removed_key) = removed_key {
                    let removed = self.lookup.remove(&removed_key);
                    debug_assert!(removed.is_some());
                }

                idx
            }
        };

        // link it as the newest entry
        Self::link(idx, &mut self.entries, &mut self.oldest_newest);
    }

    fn take(&mut self, server_name: &str) -> Option<Bytes> {
        if let hash_map::Entry::Occupied(hmap_entry) = self.lookup.entry(server_name.into()) {
            let entry = &mut self.entries[*hmap_entry.get()];
            debug_assert_ne!(entry.token_stack_len, 0);
            let token = take(
                &mut entry.token_stack[(entry.token_stack_start + entry.token_stack_len - 1) % N],
            );
            if entry.token_stack_len > 1 {
                // pop from entry's token stack, re-link entry as most recently used
                entry.token_stack_len -= 1;
                Self::unlink(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
                Self::link(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
            } else {
                // token stack emptied, remove entry
                Self::unlink(
                    *hmap_entry.get(),
                    &mut self.entries,
                    &mut self.oldest_newest,
                );
                self.entries.remove(*hmap_entry.get());
                hmap_entry.remove();
            }
            Some(token)
        } else {
            None
        }
    }
}
