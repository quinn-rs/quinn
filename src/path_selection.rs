//! RTT-based path selection with hysteresis
//!
//! Path selection algorithm:
//! - Lower RTT paths preferred
//! - 5ms hysteresis to prevent flapping
//! - 3ms advantage for IPv6
//! - Direct paths strongly preferred over relay

use std::net::SocketAddr;
use std::time::Duration;

/// Maximum number of candidates per peer
pub const MAX_CANDIDATES_PER_PEER: usize = 30;

/// Maximum number of inactive candidates to keep
pub const MAX_INACTIVE_CANDIDATES: usize = 10;

/// Minimum RTT improvement required to switch paths (prevents flapping)
pub const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// RTT advantage given to IPv6 paths
pub const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// Type of path connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    /// Direct UDP connection
    Direct,
    /// Via relay server
    Relay,
}

/// A candidate path with measured RTT
#[derive(Debug, Clone)]
pub struct PathCandidate {
    /// Socket address of the path
    pub addr: SocketAddr,
    /// Measured round-trip time
    pub rtt: Duration,
    /// Type of path (direct or relay)
    pub path_type: PathType,
}

impl PathCandidate {
    /// Create a new direct path candidate
    pub fn new(addr: SocketAddr, rtt: Duration) -> Self {
        Self {
            addr,
            rtt,
            path_type: PathType::Direct,
        }
    }

    /// Create a direct path candidate
    pub fn direct(addr: SocketAddr, rtt: Duration) -> Self {
        Self {
            addr,
            rtt,
            path_type: PathType::Direct,
        }
    }

    /// Create a relay path candidate
    pub fn relay(addr: SocketAddr, rtt: Duration) -> Self {
        Self {
            addr,
            rtt,
            path_type: PathType::Relay,
        }
    }

    /// Check if this is a direct path
    pub fn is_direct(&self) -> bool {
        self.path_type == PathType::Direct
    }

    /// Check if this is a relay path
    pub fn is_relay(&self) -> bool {
        self.path_type == PathType::Relay
    }

    /// Calculate effective RTT (with IPv6 advantage applied)
    pub fn effective_rtt(&self) -> Duration {
        if self.addr.is_ipv6() {
            self.rtt.saturating_sub(IPV6_RTT_ADVANTAGE)
        } else {
            self.rtt
        }
    }
}

/// Select the best path from candidates
///
/// Algorithm:
/// 1. Prefer direct paths over relay paths
/// 2. Among same type, prefer lower RTT
/// 3. Apply IPv6 advantage (3ms)
/// 4. Apply hysteresis (5ms) when switching from current path
pub fn select_best_path(
    paths: &[PathCandidate],
    current: Option<&PathCandidate>,
) -> Option<PathCandidate> {
    if paths.is_empty() {
        return None;
    }

    // Separate direct and relay paths
    let direct_paths: Vec<_> = paths.iter().filter(|p| p.is_direct()).collect();
    let relay_paths: Vec<_> = paths.iter().filter(|p| p.is_relay()).collect();

    // Find best direct path
    let best_direct = find_best_by_rtt(&direct_paths);

    // Find best relay path
    let best_relay = find_best_by_rtt(&relay_paths);

    // Determine the best new path (prefer direct)
    let best_new = match (best_direct, best_relay) {
        (Some(direct), _) => Some(direct),
        (None, Some(relay)) => Some(relay),
        (None, None) => None,
    };

    // Apply hysteresis if we have a current path
    match (current, best_new) {
        (None, best) => best.cloned(),
        (Some(current), None) => Some(current.clone()),
        (Some(current), Some(new)) => {
            // Never switch from direct to relay
            if current.is_direct() && new.is_relay() {
                return Some(current.clone());
            }

            // Check if new path is significantly better
            let current_eff = current.effective_rtt();
            let new_eff = new.effective_rtt();

            if current_eff > new_eff + RTT_SWITCHING_MIN {
                // New path is significantly better
                Some(new.clone())
            } else {
                // Keep current path (hysteresis)
                Some(current.clone())
            }
        }
    }
}

/// Find the path with lowest effective RTT
fn find_best_by_rtt<'a>(paths: &[&'a PathCandidate]) -> Option<&'a PathCandidate> {
    paths.iter().min_by_key(|p| p.effective_rtt()).copied()
}

/// Compare IPv4 and IPv6 paths, applying IPv6 advantage
pub fn select_v4_v6(
    v4_addr: SocketAddr,
    v4_rtt: Duration,
    v6_addr: SocketAddr,
    v6_rtt: Duration,
) -> (SocketAddr, Duration) {
    // Apply IPv6 advantage
    let v6_effective = v6_rtt.saturating_sub(IPV6_RTT_ADVANTAGE);

    if v6_effective <= v4_rtt {
        (v6_addr, v6_rtt)
    } else {
        (v4_addr, v4_rtt)
    }
}

// ============================================================================
// PathManager for tracking and closing redundant paths
// ============================================================================

use std::collections::HashMap;

/// Minimum number of direct paths to keep open
pub const MIN_DIRECT_PATHS: usize = 2;

/// Information about a tracked path
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Socket address of the path
    pub addr: SocketAddr,
    /// Type of path (direct or relay)
    pub path_type: PathType,
    /// Measured RTT if available
    pub rtt: Option<Duration>,
    /// Whether the path is currently open
    pub is_open: bool,
}

impl PathInfo {
    /// Create a new direct path info
    pub fn direct(addr: SocketAddr) -> Self {
        Self {
            addr,
            path_type: PathType::Direct,
            rtt: None,
            is_open: true,
        }
    }

    /// Create a new relay path info
    pub fn relay(addr: SocketAddr) -> Self {
        Self {
            addr,
            path_type: PathType::Relay,
            rtt: None,
            is_open: true,
        }
    }

    /// Create path info with RTT
    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }
}

/// Manager for tracking and closing redundant paths
///
/// Manages open paths and closes redundant ones when a best path is selected.
/// Rules:
/// 1. Never close relay paths (they're fallback)
/// 2. Keep at least MIN_DIRECT_PATHS direct paths open
/// 3. Never close the selected path
#[derive(Debug, Default)]
pub struct PathManager {
    /// All tracked paths
    paths: HashMap<SocketAddr, PathInfo>,
    /// Currently selected best path
    selected_path: Option<SocketAddr>,
    /// Minimum number of direct paths to keep
    min_direct_paths: usize,
}

impl PathManager {
    /// Create a new path manager
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
            selected_path: None,
            min_direct_paths: MIN_DIRECT_PATHS,
        }
    }

    /// Create a path manager with custom minimum direct paths
    pub fn with_min_direct_paths(min_direct_paths: usize) -> Self {
        Self {
            paths: HashMap::new(),
            selected_path: None,
            min_direct_paths,
        }
    }

    /// Add a path to track
    pub fn add_path(&mut self, info: PathInfo) {
        self.paths.insert(info.addr, info);
    }

    /// Remove a path
    pub fn remove_path(&mut self, addr: &SocketAddr) {
        self.paths.remove(addr);
        if self.selected_path.as_ref() == Some(addr) {
            self.selected_path = None;
        }
    }

    /// Set the selected (best) path
    pub fn set_selected_path(&mut self, addr: SocketAddr) {
        self.selected_path = Some(addr);
    }

    /// Get the selected path
    pub fn selected_path(&self) -> Option<SocketAddr> {
        self.selected_path
    }

    /// Check if a path is tracked
    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.paths.contains_key(addr)
    }

    /// Check if a path is a relay path
    pub fn is_relay_path(&self, addr: &SocketAddr) -> bool {
        self.paths
            .get(addr)
            .map(|p| p.path_type == PathType::Relay)
            .unwrap_or(false)
    }

    /// Count of open direct paths
    pub fn direct_path_count(&self) -> usize {
        self.paths
            .values()
            .filter(|p| p.path_type == PathType::Direct && p.is_open)
            .count()
    }

    /// Count of open relay paths
    pub fn relay_path_count(&self) -> usize {
        self.paths
            .values()
            .filter(|p| p.path_type == PathType::Relay && p.is_open)
            .count()
    }

    /// Get all open paths
    pub fn open_paths(&self) -> Vec<&PathInfo> {
        self.paths.values().filter(|p| p.is_open).collect()
    }

    /// Close redundant paths, returning list of closed addresses
    ///
    /// Rules:
    /// 1. Only close direct paths (never relay - they're fallback)
    /// 2. Don't close the selected path
    /// 3. Keep at least min_direct_paths direct paths open
    pub fn close_redundant_paths(&mut self) -> Vec<SocketAddr> {
        let Some(selected) = self.selected_path else {
            return Vec::new();
        };

        // Count open direct paths
        let open_direct: Vec<_> = self
            .paths
            .iter()
            .filter(|(_, p)| p.path_type == PathType::Direct && p.is_open)
            .map(|(addr, _)| *addr)
            .collect();

        // Don't close if at or below minimum
        if open_direct.len() <= self.min_direct_paths {
            return Vec::new();
        }

        // Calculate how many we can close
        let excess = open_direct.len() - self.min_direct_paths;

        // Close excess direct paths (not selected)
        let mut to_close = Vec::new();
        for addr in open_direct {
            if to_close.len() >= excess {
                break;
            }
            if addr != selected {
                to_close.push(addr);
            }
        }

        // Mark as closed
        for addr in &to_close {
            if let Some(path) = self.paths.get_mut(addr) {
                path.is_open = false;
            }
        }

        tracing::debug!(
            closed = to_close.len(),
            remaining = self.direct_path_count(),
            "Closed redundant paths"
        );

        to_close
    }

    /// Update RTT for a path
    pub fn update_rtt(&mut self, addr: &SocketAddr, rtt: Duration) {
        if let Some(path) = self.paths.get_mut(addr) {
            path.rtt = Some(rtt);
        }
    }

    /// Mark a path as open
    pub fn mark_open(&mut self, addr: &SocketAddr) {
        if let Some(path) = self.paths.get_mut(addr) {
            path.is_open = true;
        }
    }

    /// Mark a path as closed
    pub fn mark_closed(&mut self, addr: &SocketAddr) {
        if let Some(path) = self.paths.get_mut(addr) {
            path.is_open = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v4_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), port))
    }

    fn v6_addr(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            port,
            0,
            0,
        ))
    }

    #[test]
    fn test_selects_lower_rtt_path() {
        let paths = vec![
            PathCandidate::new(v4_addr(5000), Duration::from_millis(50)),
            PathCandidate::new(v4_addr(5001), Duration::from_millis(20)),
            PathCandidate::new(v4_addr(5002), Duration::from_millis(100)),
        ];

        let selected = select_best_path(&paths, None);

        assert_eq!(selected.as_ref().map(|p| p.addr.port()), Some(5001));
    }

    #[test]
    fn test_hysteresis_prevents_flapping() {
        let current = PathCandidate::new(v4_addr(5000), Duration::from_millis(50));

        let paths = vec![
            current.clone(),
            // Only 2ms better - should NOT switch (needs 5ms improvement)
            PathCandidate::new(v4_addr(5001), Duration::from_millis(48)),
        ];

        let selected = select_best_path(&paths, Some(&current));

        // Should keep current path (hysteresis)
        assert_eq!(selected.as_ref().map(|p| p.addr.port()), Some(5000));
    }

    #[test]
    fn test_switches_when_significantly_better() {
        let current = PathCandidate::new(v4_addr(5000), Duration::from_millis(50));

        let paths = vec![
            current.clone(),
            // 10ms better - should switch (exceeds 5ms threshold)
            PathCandidate::new(v4_addr(5001), Duration::from_millis(40)),
        ];

        let selected = select_best_path(&paths, Some(&current));

        assert_eq!(selected.as_ref().map(|p| p.addr.port()), Some(5001));
    }

    #[test]
    fn test_ipv6_preference() {
        let paths = vec![
            PathCandidate::new(v4_addr(5000), Duration::from_millis(50)),
            // IPv6 with same RTT should win due to 3ms advantage
            PathCandidate::new(v6_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        assert!(selected.as_ref().map(|p| p.addr.is_ipv6()).unwrap_or(false));
    }

    #[test]
    fn test_ipv6_advantage_applied_correctly() {
        let paths = vec![
            // IPv4 is 2ms faster, but IPv6 gets 3ms advantage
            PathCandidate::new(v4_addr(5000), Duration::from_millis(48)),
            PathCandidate::new(v6_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        // IPv6 should win (50 - 3 = 47 effective RTT < 48)
        assert!(selected.as_ref().map(|p| p.addr.is_ipv6()).unwrap_or(false));
    }

    #[test]
    fn test_direct_preferred_over_relay() {
        let paths = vec![
            PathCandidate::direct(v4_addr(5000), Duration::from_millis(100)),
            // Relay is faster but direct should be preferred
            PathCandidate::relay(v4_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        assert!(selected.as_ref().map(|p| p.is_direct()).unwrap_or(false));
    }

    #[test]
    fn test_falls_back_to_relay_when_no_direct() {
        let paths = vec![
            PathCandidate::relay(v4_addr(5000), Duration::from_millis(100)),
            PathCandidate::relay(v4_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        // Should select faster relay
        assert_eq!(selected.as_ref().map(|p| p.addr.port()), Some(5001));
    }

    #[test]
    fn test_never_switches_from_direct_to_relay() {
        let current = PathCandidate::direct(v4_addr(5000), Duration::from_millis(100));

        let paths = vec![
            current.clone(),
            // Much faster relay should NOT cause switch
            PathCandidate::relay(v4_addr(5001), Duration::from_millis(10)),
        ];

        let selected = select_best_path(&paths, Some(&current));

        assert!(selected.as_ref().map(|p| p.is_direct()).unwrap_or(false));
    }

    #[test]
    fn test_empty_paths_returns_none() {
        let paths: Vec<PathCandidate> = vec![];
        let selected = select_best_path(&paths, None);
        assert!(selected.is_none());
    }

    #[test]
    fn test_all_paths_same_rtt() {
        let paths = vec![
            PathCandidate::new(v4_addr(5000), Duration::from_millis(50)),
            PathCandidate::new(v4_addr(5001), Duration::from_millis(50)),
            PathCandidate::new(v4_addr(5002), Duration::from_millis(50)),
        ];

        // Should return one of them (first or deterministic choice)
        let selected = select_best_path(&paths, None);
        assert!(selected.is_some());
    }

    #[test]
    fn test_select_v4_v6_prefers_faster() {
        let (addr, rtt) = select_v4_v6(
            v4_addr(5000),
            Duration::from_millis(100),
            v6_addr(5001),
            Duration::from_millis(50),
        );

        // IPv6 is much faster, should be selected
        assert!(addr.is_ipv6());
        assert_eq!(rtt, Duration::from_millis(50));
    }

    #[test]
    fn test_select_v4_v6_applies_ipv6_advantage() {
        let (addr, _) = select_v4_v6(
            v4_addr(5000),
            Duration::from_millis(48),
            v6_addr(5001),
            Duration::from_millis(50),
        );

        // IPv6 effective RTT is 50-3=47 < 48, so IPv6 wins
        assert!(addr.is_ipv6());
    }

    // ===== PathManager Tests =====

    #[test]
    fn test_path_manager_closes_redundant_direct_paths() {
        let mut manager = PathManager::with_min_direct_paths(2);

        // Add 5 direct paths
        for port in 5000..5005 {
            manager.add_path(PathInfo::direct(v4_addr(port)));
        }

        // Select one as best
        manager.set_selected_path(v4_addr(5000));

        // Close redundant paths
        let closed = manager.close_redundant_paths();

        // Should close 3 (5 - min 2 = 3 excess)
        assert_eq!(closed.len(), 3);

        // Selected path should NOT be closed
        assert!(!closed.contains(&v4_addr(5000)));

        // Should have exactly 2 open direct paths remaining
        assert_eq!(manager.direct_path_count(), 2);
    }

    #[test]
    fn test_path_manager_keeps_minimum_direct_paths() {
        let mut manager = PathManager::with_min_direct_paths(2);

        // Add exactly 2 direct paths
        manager.add_path(PathInfo::direct(v4_addr(5000)));
        manager.add_path(PathInfo::direct(v4_addr(5001)));

        manager.set_selected_path(v4_addr(5000));

        // Try to close redundant - should close none
        let closed = manager.close_redundant_paths();
        assert!(closed.is_empty());
        assert_eq!(manager.direct_path_count(), 2);
    }

    #[test]
    fn test_path_manager_never_closes_relay_paths() {
        let mut manager = PathManager::with_min_direct_paths(1);

        // Add direct and relay paths
        manager.add_path(PathInfo::direct(v4_addr(5000)));
        manager.add_path(PathInfo::direct(v4_addr(5001)));
        manager.add_path(PathInfo::direct(v4_addr(5002)));
        manager.add_path(PathInfo::relay(v4_addr(6000)));
        manager.add_path(PathInfo::relay(v4_addr(6001)));

        manager.set_selected_path(v4_addr(5000));

        // Close redundant
        let closed = manager.close_redundant_paths();

        // Should only close direct paths, never relay
        for addr in &closed {
            assert!(!manager.is_relay_path(addr), "Closed a relay path!");
        }

        // Relay paths should still be open
        assert_eq!(manager.relay_path_count(), 2);
    }

    #[test]
    fn test_path_manager_does_not_close_selected_path() {
        let mut manager = PathManager::with_min_direct_paths(1);

        // Add 3 direct paths
        manager.add_path(PathInfo::direct(v4_addr(5000)));
        manager.add_path(PathInfo::direct(v4_addr(5001)));
        manager.add_path(PathInfo::direct(v4_addr(5002)));

        // Select the first one
        manager.set_selected_path(v4_addr(5000));

        let closed = manager.close_redundant_paths();

        // Should have closed 2 paths (3 - min 1 = 2)
        assert_eq!(closed.len(), 2);

        // Selected path must NOT be in closed list
        assert!(!closed.contains(&v4_addr(5000)));

        // Selected path should still be tracked
        assert!(manager.contains(&v4_addr(5000)));
    }

    #[test]
    fn test_path_manager_no_close_without_selected() {
        let mut manager = PathManager::with_min_direct_paths(1);

        // Add paths but don't select any
        manager.add_path(PathInfo::direct(v4_addr(5000)));
        manager.add_path(PathInfo::direct(v4_addr(5001)));
        manager.add_path(PathInfo::direct(v4_addr(5002)));

        // Without a selected path, should not close anything
        let closed = manager.close_redundant_paths();
        assert!(closed.is_empty());
    }

    #[test]
    fn test_path_manager_add_and_remove() {
        let mut manager = PathManager::new();

        let addr = v4_addr(5000);
        manager.add_path(PathInfo::direct(addr));
        assert!(manager.contains(&addr));

        manager.remove_path(&addr);
        assert!(!manager.contains(&addr));
    }

    #[test]
    fn test_path_manager_update_rtt() {
        let mut manager = PathManager::new();

        let addr = v4_addr(5000);
        manager.add_path(PathInfo::direct(addr));

        manager.update_rtt(&addr, Duration::from_millis(50));

        let paths = manager.open_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].rtt, Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_path_manager_mark_open_closed() {
        let mut manager = PathManager::new();

        let addr = v4_addr(5000);
        manager.add_path(PathInfo::direct(addr));

        assert_eq!(manager.direct_path_count(), 1);

        manager.mark_closed(&addr);
        assert_eq!(manager.direct_path_count(), 0);

        manager.mark_open(&addr);
        assert_eq!(manager.direct_path_count(), 1);
    }

    #[test]
    fn test_path_manager_selected_path_cleared_on_remove() {
        let mut manager = PathManager::new();

        let addr = v4_addr(5000);
        manager.add_path(PathInfo::direct(addr));
        manager.set_selected_path(addr);

        assert_eq!(manager.selected_path(), Some(addr));

        manager.remove_path(&addr);
        assert_eq!(manager.selected_path(), None);
    }
}
