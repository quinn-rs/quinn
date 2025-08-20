// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Token bucket rate limiting implementation for relay operations.

use crate::relay::{RelayError, RelayResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limiter interface for controlling request rates
pub trait RateLimiter: Send + Sync {
    /// Check if a request from the given address should be allowed
    fn check_rate_limit(&self, addr: &SocketAddr) -> RelayResult<()>;

    /// Reset rate limiting state for an address
    fn reset(&self, addr: &SocketAddr);

    /// Clean up expired entries
    fn cleanup_expired(&self);
}

/// Token bucket rate limiter with per-address tracking
#[derive(Debug)]
pub struct TokenBucket {
    /// Tokens added per second
    tokens_per_second: u32,
    /// Maximum number of tokens that can be stored
    max_tokens: u32,
    /// Per-address token buckets
    buckets: Arc<Mutex<HashMap<SocketAddr, BucketState>>>,
}

/// Individual bucket state for an address
#[derive(Debug, Clone)]
struct BucketState {
    /// Current number of tokens
    tokens: f64,
    /// Last time tokens were updated
    last_update: Instant,
}

impl TokenBucket {
    /// Create a new token bucket rate limiter
    pub fn new(tokens_per_second: u32, max_tokens: u32) -> RelayResult<Self> {
        if tokens_per_second == 0 {
            return Err(RelayError::ConfigurationError {
                parameter: "tokens_per_second".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if max_tokens == 0 {
            return Err(RelayError::ConfigurationError {
                parameter: "max_tokens".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        Ok(Self {
            tokens_per_second,
            max_tokens,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Get or create bucket state for an address
    fn get_or_create_bucket(&self, addr: &SocketAddr) -> BucketState {
        let mut buckets = self.buckets.lock().unwrap();

        match buckets.get(addr) {
            Some(state) => state.clone(),
            None => {
                let state = BucketState {
                    tokens: self.max_tokens as f64,
                    last_update: Instant::now(),
                };
                buckets.insert(*addr, state.clone());
                state
            }
        }
    }

    /// Update bucket tokens based on elapsed time
    fn update_tokens(&self, mut state: BucketState) -> BucketState {
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update);
        let elapsed_seconds = elapsed.as_secs_f64();

        // Add tokens based on elapsed time
        let tokens_to_add = elapsed_seconds * self.tokens_per_second as f64;
        state.tokens = (state.tokens + tokens_to_add).min(self.max_tokens as f64);
        state.last_update = now;

        state
    }

    /// Try to consume one token from the bucket
    fn try_consume_token(&self, addr: &SocketAddr) -> RelayResult<()> {
        let mut buckets = self.buckets.lock().unwrap();

        let current_state = self.get_or_create_bucket(addr);
        let updated_state = self.update_tokens(current_state);

        if updated_state.tokens >= 1.0 {
            // Consume one token
            let new_state = BucketState {
                tokens: updated_state.tokens - 1.0,
                last_update: updated_state.last_update,
            };
            buckets.insert(*addr, new_state);
            Ok(())
        } else {
            // Calculate retry delay
            let tokens_needed = 1.0 - updated_state.tokens;
            let retry_after_seconds = tokens_needed / self.tokens_per_second as f64;
            let retry_after_ms = (retry_after_seconds * 1000.0) as u64;

            Err(RelayError::RateLimitExceeded { retry_after_ms })
        }
    }
}

impl RateLimiter for TokenBucket {
    fn check_rate_limit(&self, addr: &SocketAddr) -> RelayResult<()> {
        self.try_consume_token(addr)
    }

    fn reset(&self, addr: &SocketAddr) {
        let mut buckets = self.buckets.lock().unwrap();
        buckets.remove(addr);
    }

    fn cleanup_expired(&self) {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(300); // 5 minutes

        buckets.retain(|_, state| now.duration_since(state.last_update) < cleanup_threshold);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use std::time::Duration;

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::new(10, 100).unwrap();
        assert_eq!(bucket.tokens_per_second, 10);
        assert_eq!(bucket.max_tokens, 100);
    }

    #[test]
    fn test_token_bucket_invalid_config() {
        assert!(TokenBucket::new(0, 100).is_err());
        assert!(TokenBucket::new(10, 0).is_err());
    }

    #[test]
    fn test_rate_limiting_allows_initial_requests() {
        let bucket = TokenBucket::new(10, 100).unwrap();
        let addr = test_addr();

        // Should allow initial requests up to max_tokens
        for _ in 0..100 {
            assert!(bucket.check_rate_limit(&addr).is_ok());
        }

        // Should deny the next request
        assert!(bucket.check_rate_limit(&addr).is_err());
    }

    #[test]
    fn test_token_replenishment() {
        let bucket = TokenBucket::new(10, 10).unwrap();
        let addr = test_addr();

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.check_rate_limit(&addr).is_ok());
        }

        // Should be rate limited
        assert!(bucket.check_rate_limit(&addr).is_err());

        // Wait for token replenishment (100ms = 1 token at 10/second)
        thread::sleep(Duration::from_millis(100));

        // Should allow one more request
        assert!(bucket.check_rate_limit(&addr).is_ok());
    }

    #[test]
    fn test_per_address_isolation() {
        let bucket = TokenBucket::new(1, 1).unwrap();
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8080);

        // Consume token for addr1
        assert!(bucket.check_rate_limit(&addr1).is_ok());
        assert!(bucket.check_rate_limit(&addr1).is_err());

        // addr2 should still have tokens
        assert!(bucket.check_rate_limit(&addr2).is_ok());
    }

    #[test]
    fn test_reset_functionality() {
        let bucket = TokenBucket::new(1, 1).unwrap();
        let addr = test_addr();

        // Consume token
        assert!(bucket.check_rate_limit(&addr).is_ok());
        assert!(bucket.check_rate_limit(&addr).is_err());

        // Reset should restore tokens
        bucket.reset(&addr);
        assert!(bucket.check_rate_limit(&addr).is_ok());
    }

    #[test]
    fn test_cleanup_expired() {
        let bucket = TokenBucket::new(10, 10).unwrap();
        let addr = test_addr();

        // Create entry
        assert!(bucket.check_rate_limit(&addr).is_ok());

        // Verify entry exists
        {
            let buckets = bucket.buckets.lock().unwrap();
            assert!(buckets.contains_key(&addr));
        }

        // Cleanup should not remove recent entries
        bucket.cleanup_expired();
        {
            let buckets = bucket.buckets.lock().unwrap();
            assert!(buckets.contains_key(&addr));
        }
    }

    #[test]
    fn test_rate_limit_error_retry_calculation() {
        let bucket = TokenBucket::new(2, 1).unwrap(); // 2 tokens/second, max 1
        let addr = test_addr();

        // Consume the token
        assert!(bucket.check_rate_limit(&addr).is_ok());

        // Next request should fail with retry time
        match bucket.check_rate_limit(&addr) {
            Err(RelayError::RateLimitExceeded { retry_after_ms }) => {
                // Should be approximately 500ms (1 token / 2 tokens per second)
                assert!((400..=600).contains(&retry_after_ms));
            }
            _ => panic!("Expected RateLimitExceeded error"),
        }
    }
}
