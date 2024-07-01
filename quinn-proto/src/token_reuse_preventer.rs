//! Limiting clients' ability to reuse tokens from NEW_TOKEN frames

use std::{
    hash::{Hash as _, Hasher as _},
    mem::{size_of, swap},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustc_hash::{FxHashSet, FxHasher};
use tracing::warn;

/// Error for when a token may have been reused
pub struct TokenReuseError;

/// Responsible for limiting clients' ability to reuse tokens from NEW_TOKEN frames
///
/// [_RFC 9000 § 8.1.4:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4)
///
/// > Attackers could replay tokens to use servers as amplifiers in DDoS attacks. To protect
/// > against such attacks, servers MUST ensure that replay of tokens is prevented or limited.
/// > Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time,
/// > as they are returned immediately by clients. Tokens that are provided in NEW_TOKEN frames
/// > (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.
/// > Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include
/// > additional information about clients to further narrow applicability or reuse.
pub trait TokenReusePreventer: Send + Sync {
    /// Called when a client uses a token from a NEW_TOKEN frame
    ///
    /// False negatives and false positives are both permissible.
    fn using(
        &mut self,
        token_rand: u128,
        issued: SystemTime,
        new_token_lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// Bloom filter-based `TokenReusePreventer`
///
/// Parameterizable over an approximate maximum number of bytes to allocate. Starts out by storing
/// used tokens in a hash set. Once the hash set becomes too large, converts it to a bloom filter.
///
/// Divides time into periods based on `new_token_lifetime` and stores two filters at any given
/// moment, for each of the two periods currently non-expired tokens could expire in. As such,
/// turns over filters as time goes on to avoid bloom filter false positive rate increasing
/// infinitely over time.
pub struct BloomTokenReusePreventer {
    bloom_params: BloomParams,

    // filter_1 covers tokens that expire in the period starting at
    // UNIX_EPOCH + period_idx_1 * new_token_lifetime and extending new_token_lifetime after.
    // filter_2 covers tokens for the next new_token_lifetime after that.
    period_idx_1: u128,
    filter_1: Filter,
    filter_2: Filter,
}

#[derive(Clone)]
struct BloomParams {
    size_bytes: usize,
    hashers: [FxHasher; 2],
    k_num: u32,
}

enum Filter {
    Set(FxHashSet<u128>),
    Bloom(Vec<u8>),
}

impl BloomTokenReusePreventer {
    /// Construct with an approximate maximum memory usage and a bloom filter k number
    ///
    /// If choosing a custom k number, note that `BloomTokenReusePreventer` always maintains two
    /// filters between them and divides the allocation budget of `max_bytes` evenly between them.
    /// As such, each bloom filter will contain `max_bytes * 4` bits.
    pub fn new(max_bytes: usize, k_num: u32) -> Self {
        assert!(max_bytes >= 2, "BloomTokenReusePreventer max_bytes too low");
        assert!(
            k_num >= 1,
            "BloomTokenReusePreventer k_num must be at least 1"
        );

        BloomTokenReusePreventer {
            bloom_params: BloomParams {
                size_bytes: max_bytes / 2,
                hashers: [FxHasher::default(), FxHasher::default()],
                k_num,
            },
            period_idx_1: 0,
            filter_1: Filter::Set(FxHashSet::default()),
            filter_2: Filter::Set(FxHashSet::default()),
        }
    }
}

impl TokenReusePreventer for BloomTokenReusePreventer {
    fn using(
        &mut self,
        token_rand: u128,
        issued: SystemTime,
        new_token_lifetime: Duration,
    ) -> Result<(), TokenReuseError> {
        // calculate period index for token
        let period_idx = (issued + new_token_lifetime)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            / new_token_lifetime.as_nanos();

        // get relevant filter
        let filter = if period_idx < self.period_idx_1 {
            // shouldn't happen unless time travels backwards or new_token_lifetime changes
            warn!("BloomTokenReusePreventer presented with token too far in past");
            return Err(TokenReuseError);
        } else if period_idx == self.period_idx_1 {
            &mut self.filter_1
        } else if period_idx == self.period_idx_1 + 1 {
            &mut self.filter_2
        } else {
            // turn over filters
            if period_idx == self.period_idx_1 + 2 {
                swap(&mut self.filter_1, &mut self.filter_2);
            } else {
                self.filter_1 = Filter::Set(FxHashSet::default());
            }
            self.filter_2 = Filter::Set(FxHashSet::default());
            self.period_idx_1 = period_idx - 1;

            &mut self.filter_2
        };

        // query and insert
        match filter {
            &mut Filter::Set(ref mut hset) => {
                if !hset.insert(token_rand) {
                    return Err(TokenReuseError);
                }

                if hset.capacity() * size_of::<u128>() > self.bloom_params.size_bytes {
                    // convert to bloom
                    let mut bits = vec![0; self.bloom_params.size_bytes];
                    for &item in hset.iter() {
                        for i in self.bloom_params.iter(item) {
                            bits[(i / 8) as usize] |= 1 << (i % 8);
                        }
                    }
                    *filter = Filter::Bloom(bits);
                }
            }
            &mut Filter::Bloom(ref mut bits) => {
                let mut refuted = false;
                for i in self.bloom_params.iter(token_rand) {
                    let byte = &mut bits[(i / 8) as usize];
                    let mask = 1 << (i % 8);
                    refuted |= (*byte & mask) == 0;
                    *byte |= mask;
                }
                if !refuted {
                    return Err(TokenReuseError);
                }
            }
        }

        Ok(())
    }
}

impl Default for BloomTokenReusePreventer {
    fn default() -> Self {
        // 10 MiB per bloom filter, totalling 20 MiB
        // k=55 is optimal for a 10 MiB bloom filter and one million hits
        // sanity check: a 10 MiB hash set can store upper bound 64 kibi tokens
        Self::new(10 << 20, 55)
    }
}

impl BloomParams {
    /// Iterator over bit array indexes corresponding to item
    fn iter(&self, item: u128) -> BloomIter {
        BloomIter {
            params: self.clone(),
            item,
            hashes: [0; 2],
            next_ki: 0,
        }
    }
}

struct BloomIter {
    params: BloomParams,
    item: u128,
    hashes: [u64; 2],
    next_ki: u32,
}

impl Iterator for BloomIter {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.next_ki >= self.params.k_num {
            return None;
        }

        let ki = self.next_ki;
        self.next_ki += 1;
        Some(
            if ki < 2 {
                let mut hasher = self.params.hashers[ki as usize].clone();
                self.item.hash(&mut hasher);
                self.hashes[ki as usize] = hasher.finish();
                self.hashes[ki as usize]
            } else {
                self.hashes[0].wrapping_add((ki as u64).wrapping_mul(self.hashes[1]))
                    % 0xFFFF_FFFF_FFFF_FFC5
            } % (self.params.size_bytes as u64 * 8),
        )
    }
}
