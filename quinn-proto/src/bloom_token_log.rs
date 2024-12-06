use std::{
    collections::HashSet,
    f64::consts::LN_2,
    hash::{BuildHasher, Hasher},
    mem::{size_of, swap},
    sync::Mutex,
};

use fastbloom::BloomFilter;
use rustc_hash::FxBuildHasher;
use tracing::{trace, warn};

use crate::{Duration, SystemTime, TokenLog, TokenReuseError, UNIX_EPOCH};

/// Bloom filter-based `TokenLog`
///
/// Parameterizable over an approximate maximum number of bytes to allocate. Starts out by storing
/// used tokens in a hash set. Once the hash set becomes too large, converts it to a bloom filter.
/// This achieves a memory profile of linear growth with an upper bound.
///
/// Divides time into periods based on `lifetime` and stores two filters at any given moment, for
/// each of the two periods currently non-expired tokens could expire in. As such, turns over
/// filters as time goes on to avoid bloom filter false positive rate increasing infinitely over
/// time.
pub struct BloomTokenLog(Mutex<State>);

impl BloomTokenLog {
    /// Construct with an approximate maximum memory usage and expected number of validation token
    /// usages per expiration period
    ///
    /// Calculates the optimal bloom filter k number automatically.
    ///
    /// Panics if:
    /// - `max_bytes` < 2
    pub fn new_expected_items(max_bytes: usize, expected_hits: u64) -> Self {
        Self::new(max_bytes, optimal_k_num(max_bytes, expected_hits))
    }

    /// Construct with an approximate maximum memory usage and a bloom filter k number
    ///
    /// If choosing a custom k number, note that `BloomTokenLog` always maintains two filters
    /// between them and divides the allocation budget of `max_bytes` evenly between them. As such,
    /// each bloom filter will contain `max_bytes * 4` bits.
    ///
    /// Panics if:
    /// - `max_bytes` < 2
    /// - `k_num` < 1
    pub fn new(max_bytes: usize, k_num: u32) -> Self {
        assert!(max_bytes >= 2, "BloomTokenLog max_bytes too low");
        assert!(k_num >= 1, "BloomTokenLog k_num must be at least 1");

        Self(Mutex::new(State {
            config: FilterConfig {
                filter_max_bytes: max_bytes / 2,
                k_num,
            },
            period_idx_1: 0,
            filter_1: Filter::new(),
            filter_2: Filter::new(),
        }))
    }
}

fn optimal_k_num(num_bytes: usize, expected_hits: u64) -> u32 {
    // be more forgiving rather than panickey here. excessively high num_bits may occur if the user
    // wishes it to be unbounded, so just saturate. expected_hits of 0 would cause divide-by-zero,
    // so just fudge it up to 1 in that case.
    let num_bits = (num_bytes as u64).saturating_mul(8);
    let expected_hits = expected_hits.max(1);
    (((num_bits as f64 / expected_hits as f64) * LN_2).round() as u32).max(1)
}

/// Lockable state of [`BloomTokenLog`]
struct State {
    config: FilterConfig,
    // filter_1 covers tokens that expire in the period starting at
    // UNIX_EPOCH + period_idx_1 * lifetime and extending lifetime after.
    // filter_2 covers tokens for the next lifetime after that.
    period_idx_1: u128,
    filter_1: Filter,
    filter_2: Filter,
}

impl TokenLog for BloomTokenLog {
    fn check_and_insert(
        &self,
        rand: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError> {
        trace!(%rand, "check_and_insert");
        let mut guard = self.0.lock().unwrap();
        let state = &mut *guard;
        let fingerprint = rand_to_fingerprint(rand);

        // calculate period index for token
        let period_idx = (issued + lifetime)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            / lifetime.as_nanos();

        // get relevant filter
        let filter = if period_idx < state.period_idx_1 {
            // shouldn't happen unless time travels backwards or new_token_lifetime changes
            warn!("BloomTokenLog presented with token too far in past");
            return Err(TokenReuseError);
        } else if period_idx == state.period_idx_1 {
            &mut state.filter_1
        } else if period_idx == state.period_idx_1 + 1 {
            &mut state.filter_2
        } else {
            // turn over filters
            if period_idx == state.period_idx_1 + 2 {
                swap(&mut state.filter_1, &mut state.filter_2);
            } else {
                state.filter_1 = Filter::new();
            }
            state.filter_2 = Filter::new();
            state.period_idx_1 = period_idx - 1;

            &mut state.filter_2
        };

        filter.check_and_insert(fingerprint, &state.config)
    }
}

/// The token's rand needs to guarantee uniqueness because of the role it plays in the encryption
/// of the tokens, so it is 128 bits. But since the token log can tolerate both false positives and
/// false negatives, we trim it down to 64 bits, which would still only have a small collision rate
/// even at significant amounts of usage, while allowing us to store twice as many in the hash set
/// variant.
///
/// Token rand values are uniformly randomly generated server-side and cryptographically integrity-
/// checked, so we don't need to employ secure hashing for this, we can simply truncate.
fn rand_to_fingerprint(rand: u128) -> u64 {
    (rand & 0xffffffff) as u64
}

const DEFAULT_MAX_BYTES: usize = 10 << 20;
const DEFAULT_EXPECTED_HITS: u64 = 1_000_000;

/// Default to 20 MiB max memory consumption and expected one million hits
impl Default for BloomTokenLog {
    fn default() -> Self {
        Self::new_expected_items(DEFAULT_MAX_BYTES, DEFAULT_EXPECTED_HITS)
    }
}

/// Unchanging parameters governing [`Filter`] behavior
struct FilterConfig {
    filter_max_bytes: usize,
    k_num: u32,
}

/// Period filter within [`State`]
enum Filter {
    Set(IdentityHashSet),
    Bloom(FxBloomFilter),
}

impl Filter {
    fn new() -> Self {
        Self::Set(HashSet::default())
    }

    fn check_and_insert(
        &mut self,
        fingerprint: u64,
        config: &FilterConfig,
    ) -> Result<(), TokenReuseError> {
        match *self {
            Self::Set(ref mut hset) => {
                if !hset.insert(fingerprint) {
                    return Err(TokenReuseError);
                }

                if hset.capacity() * size_of::<u64>() > config.filter_max_bytes {
                    // convert to bloom
                    let mut bloom = BloomFilter::with_num_bits(config.filter_max_bytes * 8)
                        .hasher(FxBuildHasher)
                        .hashes(config.k_num);
                    for item in hset.iter() {
                        bloom.insert(item);
                    }
                    *self = Self::Bloom(bloom);
                }
            }
            Self::Bloom(ref mut bloom) => {
                if bloom.insert(&fingerprint) {
                    return Err(TokenReuseError);
                }
            }
        }
        Ok(())
    }
}

/// Bloom filter that uses `FxHasher`s
type FxBloomFilter = BloomFilter<512, FxBuildHasher>;

/// `BuildHasher` of `IdentityHasher`
#[derive(Default)]
struct IdentityBuildHasher;

impl BuildHasher for IdentityBuildHasher {
    type Hasher = IdentityHasher;

    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher::default()
    }
}

/// Hasher that is the identity operation--it assumes that exactly 8 bytes will be hashed, and the
/// resultant hash is those bytes as a `u64`
#[derive(Default)]
struct IdentityHasher {
    data: [u8; 8],
    #[cfg(debug_assertions)]
    wrote_8_byte_slice: bool,
}

impl Hasher for IdentityHasher {
    fn write(&mut self, bytes: &[u8]) {
        #[cfg(debug_assertions)]
        {
            assert!(!self.wrote_8_byte_slice);
            assert_eq!(bytes.len(), 8);
            self.wrote_8_byte_slice = true;
        }
        self.data.copy_from_slice(bytes);
    }

    fn finish(&self) -> u64 {
        #[cfg(debug_assertions)]
        assert!(self.wrote_8_byte_slice);
        u64::from_ne_bytes(self.data)
    }
}

/// Hash set of `u64` which are assumed to already be uniformly randomly distributed, and thus
/// effectively pre-hashed
type IdentityHashSet = HashSet<u64, IdentityBuildHasher>;

#[cfg(test)]
mod test {
    use super::*;
    use rand::prelude::*;
    use rand_pcg::Pcg32;

    fn new_rng() -> impl Rng {
        Pcg32::from_seed(0xdeadbeefdeadbeefdeadbeefdeadbeefu128.to_le_bytes())
    }

    #[test]
    fn identity_hash_test() {
        let mut rng = new_rng();
        let builder = IdentityBuildHasher;
        for _ in 0..100 {
            let n = rng.gen::<u64>();
            let hash = builder.hash_one(n);
            assert_eq!(hash, n);
        }
    }

    #[test]
    fn optimal_k_num_test() {
        assert_eq!(optimal_k_num(10 << 20, 1_000_000), 58);
        assert_eq!(optimal_k_num(10 << 20, 1_000_000_000_000_000), 1);
        // assert that these don't panic:
        optimal_k_num(10 << 20, 0);
        optimal_k_num(usize::MAX, 1_000_000);
    }

    #[test]
    fn bloom_token_log_conversion() {
        let mut rng = new_rng();
        let log = BloomTokenLog::new_expected_items(800, 200);

        let issued = SystemTime::now();
        let lifetime = Duration::from_secs(1_000_000);

        for i in 0..200 {
            let token = rng.gen::<u128>();
            let result = log.check_and_insert(token, issued, lifetime);
            {
                let filter = &log.0.lock().unwrap().filter_2;
                if let Filter::Set(ref hset) = *filter {
                    assert!(hset.capacity() * size_of::<u64>() <= 800);
                    assert_eq!(hset.len(), i + 1);
                    assert!(result.is_ok());
                } else {
                    assert!(i > 10, "definitely bloomed too early");
                }
            }
            assert!(log.check_and_insert(token, issued, lifetime).is_err());
        }
    }

    #[test]
    fn turn_over() {
        let mut rng = new_rng();
        let log = BloomTokenLog::new_expected_items(800, 200);
        let lifetime = Duration::from_secs(1_000);
        let mut old = Vec::default();
        let mut accepted = 0;

        for i in 0..200 {
            let token = rng.gen::<u128>();
            let now = UNIX_EPOCH + lifetime * 10 + lifetime * i / 10;
            let issued = now - lifetime.mul_f32(rng.gen_range(0.0..3.0));
            let result = log.check_and_insert(token, issued, lifetime);
            if result.is_ok() {
                accepted += 1;
            }
            old.push((token, issued));
            let old_idx = rng.gen::<usize>() % old.len();
            let (old_token, old_issued) = old[old_idx];
            assert!(log
                .check_and_insert(old_token, old_issued, lifetime)
                .is_err());
        }
        assert!(accepted > 0);
    }
}
