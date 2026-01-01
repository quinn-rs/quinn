// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Port Prediction for Symmetric NAT Traversal
//!
//! Implements the "Birthday Paradox" / Linear Prediction technique for traversing
//! symmetric NATs. When a symmetric NAT assigns different external ports for different
//! destinations, it often does so in a predictable way (e.g. +1 incremental or +delta).
//!
//! By observing the pattern of ports assigned by a peer's NAT for other connections,
//! we can predict the port it will assign for a connection to *us*.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Configuration for the port predictor
#[derive(Debug, Clone)]
pub struct PortPredictorConfig {
    /// Maximum number of samples to keep per peer IP
    pub max_samples: usize,
    /// Maximum age of samples to consider relevant
    pub sample_ttl: Duration,
    /// Minimum samples required to make a prediction
    pub min_samples_for_prediction: usize,
    /// Maximum usage count for a single prediction (to prevent spam)
    pub max_prediction_attempts: usize,
}

impl Default for PortPredictorConfig {
    fn default() -> Self {
        Self {
            max_samples: 10,
            sample_ttl: Duration::from_secs(60), // NAT mappings change quickly
            min_samples_for_prediction: 2,
            max_prediction_attempts: 3,
        }
    }
}

/// A recorded observation of a peer's external address
#[derive(Debug, Clone)]
struct PortObservation {
    port: u16,
    observed_at: Instant,
}

/// Helper to track observations and generate predictions
#[derive(Debug)]
pub struct PortPredictor {
    config: PortPredictorConfig,
    /// History of observations per IP address
    history: HashMap<IpAddr, VecDeque<PortObservation>>,
}

impl PortPredictor {
    /// Create a new port predictor
    pub fn new(config: PortPredictorConfig) -> Self {
        Self {
            config,
            history: HashMap::new(),
        }
    }

    /// Record a new observation of a peer's external address
    ///
    /// This should be called whenever we learn about an external address for this peer,
    /// e.g. via Peer Exchange (PEX) or explicit signaling.
    pub fn record_observation(&mut self, addr: SocketAddr, now: Instant) {
        let entry = self.history.entry(addr.ip()).or_default();

        // Prune old observations
        while let Some(obs) = entry.front() {
            if now.duration_since(obs.observed_at) > self.config.sample_ttl {
                entry.pop_front();
            } else {
                break;
            }
        }

        // Avoid exact duplicates (same port) that don't add info
        // (unless it's been a while, but for now simplistic dedup)
        if entry.iter().any(|obs| obs.port == addr.port()) {
            return;
        }

        entry.push_back(PortObservation {
            port: addr.port(),
            observed_at: now,
        });

        // Limit history size
        if entry.len() > self.config.max_samples {
            entry.pop_front();
        }
    }

    /// Try to predict the next likely port for this IP
    ///
    /// Returns a list of predicted ports, ordered by likelihood.
    pub fn predict_ports(&self, ip: IpAddr) -> Vec<u16> {
        let Some(samples) = self.history.get(&ip) else {
            return Vec::new();
        };

        if samples.len() < self.config.min_samples_for_prediction {
            return Vec::new();
        }

        let mut predictions = Vec::new();

        // Strategy 1: Linear Delta Prediction
        // If we see ports p1, p2, p3... check if the delta is constant.
        // Even with just 2 samples (p1, p2), we can guess p3 = p2 + (p2 - p1).
        
        // We look at the most recent samples. 
        // Note: the samples are not necessarily in temporal order of allocation, 
        // but they are in order of *our observation*. We assume observation order 
        // roughly correlates to allocation order.
        let mut sorted_observations: Vec<_> = samples.iter().collect();
        // Sort by time to ensure we are calculating deltas correctly
        sorted_observations.sort_by_key(|o| o.observed_at);
        
        // Take the last few samples
        let count = sorted_observations.len();
        if count >= 2 {
            let last = sorted_observations[count - 1];
            let prev = sorted_observations[count - 2];
            
            // Calculate delta with wrapping arithmetic
            let delta = last.port.wrapping_sub(prev.port);
            
            // If delta is small (e.g. +1, +2, +10), it's a strong signal.
            // Some NATs jump purely randomly, others increment.
            // We'll predict the next few steps.
            
            // Predict: next = last + delta
            let next_1 = last.port.wrapping_add(delta);
            predictions.push(next_1);
            
            // Predict: next = last + 2*delta (in case we raced)
            let next_2 = next_1.wrapping_add(delta);
            predictions.push(next_2);
        }

        // Strategy 2: "Birthday Paradox" / Dense Search
        // If the NAT allocates ports randomly but within a range, or if the 
        // linear prediction is noisy, we might want to just guess ports "near" 
        // the last observed one.
        // For now, let's stick to linear prediction as it's the most high-value "smart trick".

        predictions
    }
    
    /// Clear history for an IP (e.g. if we confirm they moved networks)
    pub fn clear(&mut self, ip: IpAddr) {
        self.history.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn test_linear_prediction_increment() {
        let mut predictor = PortPredictor::new(PortPredictorConfig::default());
        let ip = test_ip();
        let now = Instant::now();

        // Observed port 1000
        predictor.record_observation(SocketAddr::new(ip, 1000), now);
        // Observed port 1002 (delta = 2)
        predictor.record_observation(SocketAddr::new(ip, 1002), now + Duration::from_secs(1));

        let predicted = predictor.predict_ports(ip);
        
        // Expect 1004 (1002 + 2) and 1006 (1004 + 2)
        assert!(predicted.contains(&1004));
        assert!(predicted.contains(&1006));
    }

    #[test]
    fn test_linear_prediction_decrement() {
        let mut predictor = PortPredictor::new(PortPredictorConfig::default());
        let ip = test_ip();
        let now = Instant::now();

        // Observed port 2000
        predictor.record_observation(SocketAddr::new(ip, 2000), now);
        // Observed port 1990 (delta = -10)
        predictor.record_observation(SocketAddr::new(ip, 1990), now + Duration::from_secs(1));

        let predicted = predictor.predict_ports(ip);
        
        // Expect 1980 and 1970
        assert!(predicted.contains(&1980));
        assert!(predicted.contains(&1970));
    }

    #[test]
    fn test_insufficient_samples() {
        let mut predictor = PortPredictor::new(PortPredictorConfig::default());
        let ip = test_ip();
        let now = Instant::now();

        predictor.record_observation(SocketAddr::new(ip, 1000), now);
        let predicted = predictor.predict_ports(ip);
        assert!(predicted.is_empty());
    }

    #[test]
    fn test_ttl_expiry() {
        let mut config = PortPredictorConfig::default();
        config.sample_ttl = Duration::from_millis(100);
        let mut predictor = PortPredictor::new(config);
        let ip = test_ip();
        let now = Instant::now();

        predictor.record_observation(SocketAddr::new(ip, 1000), now);
        
        // Fast forward past TTL
        let future = now + Duration::from_millis(200);
        predictor.record_observation(SocketAddr::new(ip, 1002), future);
        
        // The first sample (1000) should be expired when we check or add new ones
        // Actually record_observation prunes *before* adding. 
        // So at this point '1000' is pruned. '1002' is added.
        // We only have 1 sample (1002).
        
        let predicted = predictor.predict_ports(ip);
        assert!(predicted.is_empty(), "Should not predict with only 1 valid sample");
    }
}
