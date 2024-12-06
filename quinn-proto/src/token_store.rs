//! Storing tokens sent from servers in NEW_TOKEN frames and using them in subsequent connections

use bytes::Bytes;
use slab::Slab;
use std::{
    collections::{hash_map, HashMap},
    mem::take,
    sync::{Arc, Mutex},
};
use tracing::trace;

/// Responsible for storing address validation tokens received from servers and retrieving them for
/// use in subsequent connections
pub trait TokenStore: Send + Sync {
    /// Potentially store a token for later one-time use
    ///
    /// Called when a NEW_TOKEN frame is received from the server.
    fn insert(&self, server_name: &str, token: Bytes);

    /// Try to find and take a token that was stored with the given server name
    ///
    /// The same token must never be returned from `take` twice, as doing so can be used to
    /// de-anonymize a client's traffic.
    ///
    /// Called when trying to connect to a server. It is always ok for this to return `None`.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}

/// `TokenStore` implementation that stores up to `N` tokens per server name for up to a
/// limited number of server names, in-memory
#[derive(Debug)]
pub struct TokenMemoryCache<const N: usize>(Mutex<State<N>>);

impl<const N: usize> TokenMemoryCache<N> {
    /// Construct empty
    pub fn new(max_server_names: usize) -> Self {
        Self(Mutex::new(State::new(max_server_names)))
    }
}

impl<const N: usize> TokenStore for TokenMemoryCache<N> {
    fn insert(&self, server_name: &str, token: Bytes) {
        trace!(%server_name, "storing token");
        self.0.lock().unwrap().store(server_name, token)
    }

    fn take(&self, server_name: &str) -> Option<Bytes> {
        let token = self.0.lock().unwrap().take(server_name);
        trace!(%server_name, found=%token.is_some(), "taking token");
        token
    }
}

/// Defaults to a maximum of 256 servers
impl<const N: usize> Default for TokenMemoryCache<N> {
    fn default() -> Self {
        Self::new(256)
    }
}

/// Lockable inner state of `TokenMemoryCache`
#[derive(Debug)]
struct State<const N: usize> {
    max_server_names: usize,
    // map from server name to slab index in linked
    lookup: HashMap<Arc<str>, usize>,
    linked: LinkedCache<N>,
}

impl<const N: usize> State<N> {
    fn new(max_server_names: usize) -> Self {
        assert!(max_server_names > 0, "size limit cannot be 0");
        Self {
            max_server_names,
            lookup: HashMap::new(),
            linked: LinkedCache::default(),
        }
    }

    fn store(&mut self, server_name: &str, token: Bytes) {
        let server_name = Arc::<str>::from(server_name);
        let idx = match self.lookup.entry(server_name.clone()) {
            hash_map::Entry::Occupied(hmap_entry) => {
                // key already exists, add the new token to its token stack
                let entry = &mut self.linked.entries[*hmap_entry.get()];
                entry.tokens.push(token);

                // unlink the entry and set it up to be linked as the most recently used
                self.linked.unlink(*hmap_entry.get());
                *hmap_entry.get()
            }
            hash_map::Entry::Vacant(hmap_entry) => {
                // key does not yet exist, create a new one, evicting the oldest if necessary
                let removed_key = if self.linked.entries.len() >= self.max_server_names {
                    // unwrap safety: max_server_names is > 0, so there's at least one entry, so
                    //                oldest_newest is some
                    let oldest = self.linked.oldest_newest.unwrap().0;
                    self.linked.unlink(oldest);
                    Some(self.linked.entries.remove(oldest).server_name)
                } else {
                    None
                };

                let cache_entry = CacheEntry::new(server_name, token);
                let idx = self.linked.entries.insert(cache_entry);
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
        self.linked.link(idx);
    }

    fn take(&mut self, server_name: &str) -> Option<Bytes> {
        if let hash_map::Entry::Occupied(hmap_entry) = self.lookup.entry(server_name.into()) {
            let entry = &mut self.linked.entries[*hmap_entry.get()];
            // pop from entry's token stack
            let token = entry.tokens.pop();
            if entry.tokens.len > 0 {
                // re-link entry as most recently used
                self.linked.unlink(*hmap_entry.get());
                self.linked.link(*hmap_entry.get());
            } else {
                // token stack emptied, remove entry
                self.linked.unlink(*hmap_entry.get());
                self.linked.entries.remove(*hmap_entry.get());
                hmap_entry.remove();
            }
            Some(token)
        } else {
            None
        }
    }
}

/// Slab-based linked LRU cache of `CacheEntry`
#[derive(Debug, Default)]
struct LinkedCache<const N: usize> {
    entries: Slab<CacheEntry<N>>,
    oldest_newest: Option<(usize, usize)>,
}

impl<const N: usize> LinkedCache<N> {
    /// Re-link an entry's neighbors around it
    fn unlink(&mut self, idx: usize) {
        // unwrap safety: we assume entries[idx] is linked, therefore oldest_newest is some
        let &mut (ref mut oldest, ref mut newest) = self.oldest_newest.as_mut().unwrap();
        if *oldest == idx && *newest == idx {
            // edge case where the list becomes empty
            self.oldest_newest = None;
        } else {
            let older = self.entries[idx].older;
            let newer = self.entries[idx].newer;
            // re-link older's newer
            if let Some(older) = older {
                self.entries[older].newer = newer;
            } else {
                // unwrap safety: if both older and newer were None, we would've entered the branch
                // where the list becomes empty instead
                *oldest = newer.unwrap();
            }
            // re-link newer's older
            if let Some(newer) = newer {
                self.entries[newer].older = older;
            } else {
                // unwrap safety: if both older and newer were None, we would've entered the branch
                // where the list becomes empty instead
                *newest = older.unwrap();
            }
        }
    }

    /// Link an unlinked entry as the most recently used entry
    fn link(&mut self, idx: usize) {
        self.entries[idx].newer = None;
        self.entries[idx].older = self.oldest_newest.map(|(_, newest)| newest);
        if let Some((_, ref mut newest)) = self.oldest_newest.as_mut() {
            self.entries[*newest].newer = Some(idx);
            *newest = idx;
        } else {
            self.oldest_newest = Some((idx, idx));
        }
    }
}

/// Cache entry within `LinkedCache`
#[derive(Debug)]
struct CacheEntry<const N: usize> {
    older: Option<usize>,
    newer: Option<usize>,
    server_name: Arc<str>,
    tokens: Queue<N>,
}

impl<const N: usize> CacheEntry<N> {
    /// Construct with a single token, not linked
    fn new(server_name: Arc<str>, token: Bytes) -> Self {
        let mut tokens = Queue::new();
        tokens.push(token);
        Self {
            server_name,
            older: None,
            newer: None,
            tokens,
        }
    }
}

/// In-place vector queue of up to `N` `Bytes`
#[derive(Debug)]
struct Queue<const N: usize> {
    elems: [Bytes; N],
    // if len > 0, front is elems[start]
    // invariant: start < N
    start: usize,
    // if len > 0, back is elems[(start + len - 1) % N]
    len: usize,
}

impl<const N: usize> Queue<N> {
    /// Construct empty
    fn new() -> Self {
        const EMPTY_BYTES: Bytes = Bytes::new();
        Self {
            elems: [EMPTY_BYTES; N],
            start: 0,
            len: 0,
        }
    }

    /// Push to back, popping from front first if already at capacity
    fn push(&mut self, elem: Bytes) {
        self.elems[(self.start + self.len) % N] = elem;
        if self.len < N {
            self.len += 1;
        } else {
            self.start += 1;
            self.start %= N;
        }
    }

    /// Pop from front, panicking if empty
    fn pop(&mut self) -> Bytes {
        const PANIC_MSG: &str = "TokenMemoryCache popped from empty Queue, this is a bug!";
        self.len = self.len.checked_sub(1).expect(PANIC_MSG);
        let elem = take(&mut self.elems[self.start]);
        self.start += 1;
        self.start %= N;
        elem
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use rand::prelude::*;
    use rand_pcg::Pcg32;

    fn new_rng() -> impl Rng {
        Pcg32::from_seed(0xdeadbeefdeadbeefdeadbeefdeadbeefu128.to_le_bytes())
    }

    #[test]
    fn queue_test() {
        let mut rng = new_rng();
        const N: usize = 2;

        for _ in 0..100 {
            let mut queue_1 = VecDeque::new();
            let mut queue_2 = Queue::<N>::new();

            for i in 0..10 {
                if rng.gen::<bool>() {
                    // push
                    let token = Bytes::from(vec![i]);
                    println!("PUSH {:?}", token);
                    queue_1.push_back(token.clone());
                    if queue_1.len() > N {
                        queue_1.pop_front();
                    }
                    queue_2.push(token);
                } else {
                    // pop
                    if let Some(token) = queue_1.pop_front() {
                        println!("POP {:?}", token);
                        assert_eq!(queue_2.pop(), token);
                    } else {
                        println!("POP nothing");
                        assert_eq!(queue_2.len, 0);
                    }
                }
                // assert equivalent
                println!("queue_1 = {:?}", queue_1);
                println!("queue_2 = {:?}", queue_2);
                assert_eq!(queue_1.len(), queue_2.len);
                for (j, token) in queue_1.iter().enumerate() {
                    let k = (queue_2.start + j) % N;
                    assert_eq!(queue_2.elems[k], token);
                }
            }
        }
    }

    #[test]
    fn linked_test() {
        let mut rng = new_rng();
        const N: usize = 2;

        for _ in 0..10 {
            let mut cache_1: Vec<i32> = Vec::new(); // keep it sorted oldest to newest
            let mut cache_2: LinkedCache<N> = LinkedCache::default();
            for i in 0..100 {
                match rng.gen::<u32>() % 4 {
                    0 | 1 => {
                        // insert
                        println!("INSERT {}", i);
                        let entry_2 = CacheEntry::new(i.to_string().into(), Bytes::new());
                        cache_1.push(i);
                        let slab_idx = cache_2.entries.insert(entry_2);
                        cache_2.link(slab_idx);
                    }
                    2 => {
                        if cache_1.is_empty() {
                            println!("SKIP BECAUSE EMPTY");
                            continue;
                        }
                        // hit
                        let idx = rng.gen::<usize>() % cache_1.len();
                        let entry_1 = cache_1.remove(idx);
                        println!("HIT {}", entry_1);
                        let (slab_idx, _) = cache_2
                            .entries
                            .iter()
                            .find(|(_, entry_2)| {
                                entry_2.server_name.as_ref() == entry_1.to_string().as_str()
                            })
                            .unwrap();
                        cache_1.push(entry_1);
                        cache_2.unlink(slab_idx);
                        cache_2.link(slab_idx);
                    }
                    3 => {
                        if cache_1.is_empty() {
                            println!("SKIP BECAUSE EMPTY");
                            continue;
                        }
                        // remove
                        let idx = rng.gen::<usize>() % cache_1.len();
                        let entry_1 = cache_1.remove(idx);
                        println!("REMOVE {}", entry_1);
                        let (slab_idx, _) = cache_2
                            .entries
                            .iter()
                            .find(|(_, entry_2)| {
                                entry_2.server_name.as_ref() == entry_1.to_string().as_str()
                            })
                            .unwrap();
                        cache_2.unlink(slab_idx);
                        cache_2.entries.remove(slab_idx);
                    }
                    _ => unreachable!(),
                }
                // assert equivalent
                println!("cache_1 = {:#?}", cache_1);
                println!("cache_2 = {:#?}", cache_2);
                assert_eq!(cache_1.len(), cache_2.entries.len());
                let mut prev_slab_idx = None;
                let mut slab_idx = cache_2.oldest_newest.map(|(oldest, _)| oldest);
                for (i, entry_1) in cache_1.iter().enumerate() {
                    let entry_2 = &cache_2.entries
                        [slab_idx.unwrap_or_else(|| panic!("next link missing at index {}", i))];
                    assert_eq!(
                        entry_2.server_name.as_ref(),
                        entry_1.to_string().as_str(),
                        "discrepancy at idx {}",
                        i
                    );
                    assert_eq!(
                        entry_2.older, prev_slab_idx,
                        "backlink discrepancy at idx {}",
                        i
                    );
                    prev_slab_idx = slab_idx;
                    slab_idx = entry_2.newer;
                }
                assert_eq!(slab_idx, None, "newest item has newer link");
            }
        }
    }

    #[test]
    fn cache_test() {
        let mut rng = new_rng();
        const N: usize = 2;

        for _ in 0..10 {
            let mut cache_1: Vec<(u32, VecDeque<Bytes>)> = Vec::new(); // keep it sorted oldest to newest
            let cache_2: TokenMemoryCache<N> = TokenMemoryCache::new(20);

            for i in 0..200 {
                let server_name = rng.gen::<u32>() % 10;
                if rng.gen_bool(0.666) {
                    // store
                    let token = Bytes::from(vec![i]);
                    println!("STORE {} {:?}", server_name, token);
                    if let Some((j, _)) = cache_1
                        .iter()
                        .enumerate()
                        .find(|&(_, &(server_name_2, _))| server_name_2 == server_name)
                    {
                        let (_, mut queue) = cache_1.remove(j);
                        queue.push_back(token.clone());
                        if queue.len() > N {
                            queue.pop_front();
                        }
                        cache_1.push((server_name, queue));
                    } else {
                        let mut queue = VecDeque::new();
                        queue.push_back(token.clone());
                        cache_1.push((server_name, queue));
                        if cache_1.len() > 20 {
                            cache_1.remove(0);
                        }
                    }
                    cache_2.insert(&server_name.to_string(), token);
                } else {
                    // take
                    println!("TAKE {}", server_name);
                    let expecting = cache_1
                        .iter()
                        .enumerate()
                        .find(|&(_, &(server_name_2, _))| server_name_2 == server_name)
                        .map(|(j, _)| j)
                        .map(|j| {
                            let (_, mut queue) = cache_1.remove(j);
                            let token = queue.pop_front().unwrap();
                            if !queue.is_empty() {
                                cache_1.push((server_name, queue));
                            }
                            token
                        });
                    println!("EXPECTING {:?}", expecting);
                    assert_eq!(cache_2.take(&server_name.to_string()), expecting);
                }
                // assert equivalent
                println!("cache_1 = {:#?}", cache_1);
                println!("cache_2 = {:#?}", cache_2);
                let cache_2 = cache_2.0.lock().unwrap();
                assert_eq!(cache_1.len(), cache_2.lookup.len(), "cache len discrepancy");
                assert_eq!(
                    cache_2.lookup.len(),
                    cache_2.linked.entries.len(),
                    "cache lookup hmap wrong len"
                );
                let mut prev_slab_idx = None;
                let mut slab_idx = cache_2.linked.oldest_newest.map(|(oldest, _)| oldest);
                for (i, (server_name_1, queue_1)) in cache_1.iter().enumerate() {
                    let entry_2 = &cache_2.linked.entries
                        [slab_idx.unwrap_or_else(|| panic!("next link missing at index {}", i))];
                    assert_eq!(
                        server_name_1.to_string().as_str(),
                        entry_2.server_name.as_ref(),
                        "server name discrepancy at idx {}",
                        i
                    );
                    assert_eq!(
                        entry_2.older, prev_slab_idx,
                        "backlink discrepancy at idx {}",
                        i
                    );
                    assert_eq!(
                        queue_1.len(),
                        entry_2.tokens.len,
                        "queue len discrepancy at idx {}",
                        i
                    );
                    for (j, token) in queue_1.iter().enumerate() {
                        let k = (entry_2.tokens.start + j) % N;
                        assert_eq!(
                            entry_2.tokens.elems[k], token,
                            "queue item discrepancy at idx {} queue idx {}",
                            i, j
                        );
                    }
                    assert_eq!(
                        *cache_2
                            .lookup
                            .get(&Arc::<str>::from(server_name_1.to_string()))
                            .unwrap_or_else(|| panic!(
                                "server name missing from hmap at idx {}",
                                i
                            )),
                        slab_idx.unwrap(),
                        "server name in hmap pointing to wrong slab entry at idx {}",
                        i
                    );
                    prev_slab_idx = slab_idx;
                    slab_idx = entry_2.newer;
                }
                assert_eq!(slab_idx, None, "newest item has newer link");
            }
        }
    }
}
