//! Epsilon-greedy peer selection.

use super::entry::CachedPeer;
use rand::Rng;
use std::collections::HashSet;

/// Peer selection strategy
#[derive(Debug, Clone, Copy)]
pub enum SelectionStrategy {
    /// Always select highest quality peers
    BestFirst,
    /// Epsilon-greedy: explore with probability epsilon
    EpsilonGreedy {
        /// Exploration rate (0.0 = pure exploitation, 1.0 = pure exploration)
        epsilon: f64,
    },
    /// Purely random selection
    Random,
}

impl Default for SelectionStrategy {
    fn default() -> Self {
        Self::EpsilonGreedy { epsilon: 0.1 }
    }
}

/// Select peers using epsilon-greedy strategy
///
/// This balances exploitation (selecting known-good peers) with
/// exploration (trying unknown peers to discover potentially better ones).
///
/// # Arguments
/// * `peers` - Slice of cached peers to select from
/// * `count` - Number of peers to select
/// * `epsilon` - Exploration rate (0.0 = pure exploitation, 1.0 = pure exploration)
///
/// # Returns
/// References to selected peers, up to `count` items
pub fn select_epsilon_greedy(
    peers: &[CachedPeer],
    count: usize,
    epsilon: f64,
) -> Vec<&CachedPeer> {
    if peers.is_empty() || count == 0 {
        return Vec::new();
    }

    let mut rng = rand::thread_rng();
    let mut selected = Vec::with_capacity(count.min(peers.len()));
    let mut used_indices = HashSet::new();

    // Sort indices by quality for exploitation
    let mut sorted_indices: Vec<usize> = (0..peers.len()).collect();
    sorted_indices.sort_by(|&a, &b| {
        peers[b]
            .quality_score
            .partial_cmp(&peers[a].quality_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Calculate how many to explore vs exploit
    let target_count = count.min(peers.len());
    let explore_count = ((target_count as f64) * epsilon).ceil() as usize;
    let exploit_count = target_count.saturating_sub(explore_count);

    // Exploit: select top quality peers
    for &idx in sorted_indices.iter().take(exploit_count) {
        if used_indices.insert(idx) && selected.len() < target_count {
            selected.push(&peers[idx]);
        }
    }

    // Explore: randomly select from remaining peers
    // Preferentially select untested peers (those with neutral quality)
    let remaining: Vec<usize> = (0..peers.len())
        .filter(|idx| !used_indices.contains(idx))
        .collect();

    if !remaining.is_empty() && selected.len() < target_count {
        // Separate untested and tested peers
        let (untested, tested): (Vec<_>, Vec<_>) = remaining.iter().partition(|&&idx| {
            peers[idx].stats.success_count + peers[idx].stats.failure_count == 0
        });

        // Prefer untested peers for exploration
        let explore_pool = if !untested.is_empty() {
            untested
        } else {
            tested
        };

        // Randomly select from exploration pool
        let mut explore_indices: Vec<usize> = explore_pool.into_iter().copied().collect();
        // Shuffle for randomness
        for i in (1..explore_indices.len()).rev() {
            let j = rng.gen_range(0..=i);
            explore_indices.swap(i, j);
        }

        for &idx in explore_indices.iter() {
            if selected.len() >= target_count {
                break;
            }
            if used_indices.insert(idx) {
                selected.push(&peers[idx]);
            }
        }
    }

    // Fill any remaining slots with best available
    for &idx in &sorted_indices {
        if selected.len() >= target_count {
            break;
        }
        if used_indices.insert(idx) {
            selected.push(&peers[idx]);
        }
    }

    selected
}

/// Select peers with specific capability requirements
///
/// Filters peers by capability flags and returns sorted by quality.
#[allow(dead_code)]
pub fn select_with_capabilities(
    peers: &[CachedPeer],
    count: usize,
    require_relay: bool,
    require_coordination: bool,
) -> Vec<&CachedPeer> {
    let mut filtered: Vec<&CachedPeer> = peers
        .iter()
        .filter(|p| {
            (!require_relay || p.capabilities.supports_relay)
                && (!require_coordination || p.capabilities.supports_coordination)
        })
        .collect();

    if filtered.is_empty() {
        return Vec::new();
    }

    // Sort by quality score descending
    filtered.sort_by(|a, b| {
        b.quality_score
            .partial_cmp(&a.quality_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    filtered.into_iter().take(count).collect()
}

/// Select peers by strategy
#[allow(dead_code)]
pub fn select_by_strategy(
    peers: &[CachedPeer],
    count: usize,
    strategy: SelectionStrategy,
) -> Vec<&CachedPeer> {
    match strategy {
        SelectionStrategy::BestFirst => {
            let mut sorted: Vec<&CachedPeer> = peers.iter().collect();
            sorted.sort_by(|a, b| {
                b.quality_score
                    .partial_cmp(&a.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            sorted.into_iter().take(count).collect()
        }
        SelectionStrategy::EpsilonGreedy { epsilon } => {
            select_epsilon_greedy(peers, count, epsilon)
        }
        SelectionStrategy::Random => {
            let mut rng = rand::thread_rng();
            let mut indices: Vec<usize> = (0..peers.len()).collect();
            // Fisher-Yates shuffle
            for i in (1..indices.len()).rev() {
                let j = rng.gen_range(0..=i);
                indices.swap(i, j);
            }
            indices
                .into_iter()
                .take(count)
                .map(|i| &peers[i])
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_cache::entry::PeerSource;
    use crate::nat_traversal_api::PeerId;

    fn create_test_peers(count: usize) -> Vec<CachedPeer> {
        (0..count)
            .map(|i| {
                let mut peer = CachedPeer::new(
                    PeerId([i as u8; 32]),
                    vec![format!("127.0.0.1:{}", 9000 + i).parse().unwrap()],
                    PeerSource::Seed,
                );
                // Higher index = higher quality
                peer.quality_score = i as f64 / count as f64;
                peer
            })
            .collect()
    }

    #[test]
    fn test_select_empty() {
        let peers: Vec<CachedPeer> = vec![];
        let selected = select_epsilon_greedy(&peers, 5, 0.1);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_select_pure_exploitation() {
        let peers = create_test_peers(10);
        // epsilon=0 means pure exploitation (best first)
        let selected = select_epsilon_greedy(&peers, 5, 0.0);

        assert_eq!(selected.len(), 5);
        // Should be sorted by quality descending
        for i in 0..4 {
            assert!(selected[i].quality_score >= selected[i + 1].quality_score);
        }
        // First selected should be highest quality
        assert!((selected[0].quality_score - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_select_with_exploration() {
        let peers = create_test_peers(20);
        // epsilon=0.5 means 50% exploration
        // Run multiple times to verify randomness
        let mut has_variation = false;
        let first_selection = select_epsilon_greedy(&peers, 10, 0.5);

        for _ in 0..10 {
            let selection = select_epsilon_greedy(&peers, 10, 0.5);
            if selection
                .iter()
                .map(|p| p.peer_id)
                .collect::<Vec<_>>()
                != first_selection
                    .iter()
                    .map(|p| p.peer_id)
                    .collect::<Vec<_>>()
            {
                has_variation = true;
                break;
            }
        }
        // With 50% exploration, we should see some variation
        assert!(has_variation, "Expected variation with epsilon=0.5");
    }

    #[test]
    fn test_select_more_than_available() {
        let peers = create_test_peers(3);
        let selected = select_epsilon_greedy(&peers, 10, 0.1);
        assert_eq!(selected.len(), 3); // Can't select more than available
    }

    #[test]
    fn test_select_with_capabilities() {
        let mut peers = create_test_peers(10);

        // Mark some as relays
        peers[0].capabilities.supports_relay = true;
        peers[5].capabilities.supports_relay = true;
        peers[9].capabilities.supports_relay = true;

        let relays = select_with_capabilities(&peers, 10, true, false);
        assert_eq!(relays.len(), 3);

        // All selected should support relay
        for peer in &relays {
            assert!(peer.capabilities.supports_relay);
        }
    }

    #[test]
    fn test_best_first_strategy() {
        let peers = create_test_peers(10);
        let selected = select_by_strategy(&peers, 5, SelectionStrategy::BestFirst);

        assert_eq!(selected.len(), 5);
        // Should be strictly sorted by quality
        for i in 0..4 {
            assert!(selected[i].quality_score >= selected[i + 1].quality_score);
        }
    }

    #[test]
    fn test_random_strategy() {
        let peers = create_test_peers(20);
        // Run multiple times to verify randomness
        let mut has_variation = false;
        let first_selection = select_by_strategy(&peers, 10, SelectionStrategy::Random);

        for _ in 0..10 {
            let selection = select_by_strategy(&peers, 10, SelectionStrategy::Random);
            if selection
                .iter()
                .map(|p| p.peer_id)
                .collect::<Vec<_>>()
                != first_selection
                    .iter()
                    .map(|p| p.peer_id)
                    .collect::<Vec<_>>()
            {
                has_variation = true;
                break;
            }
        }
        assert!(has_variation, "Random selection should vary");
    }
}
