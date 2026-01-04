//! BGP-based Geographic IP Provider
//!
//! This module provides IP-to-country and country-to-coordinates mappings
//! using open-source BGP routing data and curated lists.
//!
//! Data sources:
//! - ASN-to-country mappings from RIR delegations
//! - Country centroid coordinates for globe visualization
//! - IP prefix-to-ASN mappings for major networks

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Country information with coordinates
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields available for future dashboard enhancements
pub struct CountryInfo {
    /// ISO 3166-1 alpha-2 country code
    pub code: &'static str,
    /// Country name
    pub name: &'static str,
    /// Centroid latitude
    pub lat: f64,
    /// Centroid longitude
    pub lon: f64,
}

/// IPv4 prefix entry for ASN lookup
#[derive(Debug, Clone)]
struct Ipv4Prefix {
    /// Network address as u32
    network: u32,
    /// Netmask
    mask: u32,
    /// Origin ASN
    asn: u32,
}

impl Ipv4Prefix {
    fn new(octets: [u8; 4], prefix_len: u8, asn: u32) -> Self {
        let network = u32::from_be_bytes(octets);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Self {
            network: network & mask,
            mask,
            asn,
        }
    }

    fn matches(&self, ip: u32) -> bool {
        (ip & self.mask) == self.network
    }
}

/// BGP-based geographic IP provider
///
/// Data is loaded once at construction and never modified, making lookups lock-free.
pub struct BgpGeoProvider {
    /// IPv4 prefix-to-ASN mappings (sorted by prefix length, longest first)
    /// Lock-free: data is immutable after construction
    ipv4_prefixes: Vec<Ipv4Prefix>,
    /// ASN-to-country code mappings
    /// Lock-free: data is immutable after construction
    asn_countries: HashMap<u32, &'static str>,
    /// Country code-to-info mappings
    country_info: HashMap<&'static str, CountryInfo>,
}

impl BgpGeoProvider {
    /// Create a new BgpGeoProvider with embedded data
    ///
    /// All data is loaded at construction time, making subsequent lookups lock-free.
    pub fn new() -> Self {
        let mut provider = Self {
            ipv4_prefixes: Vec::new(),
            asn_countries: HashMap::new(),
            country_info: Self::build_country_info(),
        };
        provider.load_asn_data();
        provider.load_prefix_data();
        provider
    }

    /// Lookup geographic info for an IP address
    pub fn lookup(&self, ip: IpAddr) -> (f64, f64, Option<String>) {
        let ipv4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => {
                // Handle IPv4-mapped IPv6 addresses
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4
                } else {
                    // For native IPv6, return a default based on first segment
                    let segments = v6.segments();
                    // Use first segment to pick a region (very approximate)
                    return self.default_for_ipv6_segment(segments[0]);
                }
            }
        };

        // Try ASN-based lookup (lock-free since data is immutable)
        if let Some(asn) = self.lookup_asn(ipv4) {
            if let Some(&country) = self.asn_countries.get(&asn) {
                if let Some(info) = self.country_info.get(country) {
                    let (lat, lon) = self.add_jitter(info.lat, info.lon, ipv4);
                    return (lat, lon, Some(country.to_string()));
                }
            }
        }

        // Fallback: use first octet heuristics
        self.fallback_geo(ipv4)
    }

    /// Lookup ASN for an IPv4 address (lock-free)
    fn lookup_asn(&self, ip: Ipv4Addr) -> Option<u32> {
        let ip_u32 = u32::from(ip);
        for prefix in self.ipv4_prefixes.iter() {
            if prefix.matches(ip_u32) {
                return Some(prefix.asn);
            }
        }
        None
    }

    /// Add deterministic jitter based on IP to spread nodes
    fn add_jitter(&self, base_lat: f64, base_lon: f64, ip: Ipv4Addr) -> (f64, f64) {
        let octets = ip.octets();
        // Create a hash from the IP address
        let hash = octets
            .iter()
            .fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64));

        // Jitter range: ±0.5 degrees (about 50km at equator)
        let lat_jitter = ((hash % 1000) as f64 / 1000.0 - 0.5) * 1.0;
        let lon_jitter = (((hash >> 16) % 1000) as f64 / 1000.0 - 0.5) * 1.0;

        (base_lat + lat_jitter, base_lon + lon_jitter)
    }

    /// Default coordinates for IPv6 based on first segment
    fn default_for_ipv6_segment(&self, segment: u16) -> (f64, f64, Option<String>) {
        // Very rough approximation based on IPv6 allocation
        match segment >> 12 {
            0x2 => (51.5, -0.1, Some("GB".to_string())), // 2000::/4 - Europe heavy
            0x2a | 0x2b => (48.8, 2.3, Some("FR".to_string())), // European allocations
            _ => (40.7, -74.0, Some("US".to_string())),  // Default to US
        }
    }

    /// Fallback geo lookup using first octet heuristics
    fn fallback_geo(&self, ip: Ipv4Addr) -> (f64, f64, Option<String>) {
        let first = ip.octets()[0];

        // Approximate region by first octet (very rough)
        let (country, lat, lon) = match first {
            // European allocations
            2..=5 | 31..=47 | 62 | 77..=95 | 109 | 176..=183 | 192..=195 => ("GB", 51.5, -0.1),
            // North American allocations
            23..=24 | 63..=76 | 96..=108 | 184..=185 | 206..=209 => ("US", 40.7, -74.0),
            // Asia-Pacific allocations
            110..=126 | 202..=205 | 210..=223 => ("JP", 35.7, 139.7),
            // South American allocations
            186..=191 | 200..=201 => ("BR", -23.5, -46.6),
            // Default
            _ => ("US", 40.7, -74.0),
        };

        let (lat, lon) = self.add_jitter(lat, lon, ip);
        (lat, lon, Some(country.to_string()))
    }

    /// Build country info with coordinates
    fn build_country_info() -> HashMap<&'static str, CountryInfo> {
        let countries = [
            ("US", "United States", 37.09, -95.71),
            ("GB", "United Kingdom", 55.38, -3.44),
            ("DE", "Germany", 51.17, 10.45),
            ("FR", "France", 46.23, 2.21),
            ("NL", "Netherlands", 52.13, 5.29),
            ("FI", "Finland", 61.92, 25.75),
            ("SE", "Sweden", 60.13, 18.64),
            ("DK", "Denmark", 56.26, 9.50),
            ("NO", "Norway", 60.47, 8.47),
            ("JP", "Japan", 36.20, 138.25),
            ("KR", "South Korea", 35.91, 127.77),
            ("CN", "China", 35.86, 104.20),
            ("HK", "Hong Kong", 22.40, 114.11),
            ("SG", "Singapore", 1.35, 103.82),
            ("AU", "Australia", -25.27, 133.78),
            ("IN", "India", 20.59, 78.96),
            ("BR", "Brazil", -14.24, -51.93),
            ("AR", "Argentina", -38.42, -63.62),
            ("CL", "Chile", -35.68, -71.54),
            ("CA", "Canada", 56.13, -106.35),
            ("IT", "Italy", 41.87, 12.57),
            ("ES", "Spain", 40.46, -3.75),
            ("PL", "Poland", 51.92, 19.15),
            ("RU", "Russia", 61.52, 105.32),
            ("UA", "Ukraine", 48.38, 31.17),
            ("IE", "Ireland", 53.14, -7.69),
            ("CH", "Switzerland", 46.82, 8.23),
            ("AT", "Austria", 47.52, 14.55),
            ("BE", "Belgium", 50.50, 4.47),
            ("CZ", "Czech Republic", 49.82, 15.47),
            ("PT", "Portugal", 39.40, -8.22),
            ("NZ", "New Zealand", -40.90, 174.89),
            ("ZA", "South Africa", -30.56, 22.94),
            ("MX", "Mexico", 23.63, -102.55),
            ("TW", "Taiwan", 23.70, 121.00),
            ("TH", "Thailand", 15.87, 100.99),
            ("VN", "Vietnam", 14.06, 108.28),
            ("ID", "Indonesia", -0.79, 113.92),
            ("MY", "Malaysia", 4.21, 101.98),
            ("PH", "Philippines", 12.88, 121.77),
        ];

        countries
            .iter()
            .map(|&(code, name, lat, lon)| {
                (
                    code,
                    CountryInfo {
                        code,
                        name,
                        lat,
                        lon,
                    },
                )
            })
            .collect()
    }

    /// Load ASN-to-country mappings (called once during construction)
    fn load_asn_data(&mut self) {
        // Major cloud and hosting providers
        let asns: &[(u32, &str)] = &[
            // Amazon AWS
            (16509, "US"),
            (14618, "US"),
            // Microsoft Azure
            (8075, "US"),
            // Google Cloud
            (15169, "US"),
            (396982, "US"),
            // Cloudflare
            (13335, "US"),
            // Akamai
            (20940, "US"),
            // DigitalOcean
            (14061, "US"),
            (62567, "US"),
            // Linode
            (63949, "US"),
            // Vultr
            (20473, "US"),
            // OVH
            (16276, "FR"),
            // Hetzner
            (24940, "DE"),
            // Contabo
            (51167, "DE"),
            // Scaleway
            (12876, "FR"),
            // LeaseWeb
            (60781, "NL"),
            // Major ISPs - US
            (7922, "US"), // Comcast
            (701, "US"),  // Verizon
            (209, "US"),  // CenturyLink
            (7018, "US"), // AT&T
            (2914, "US"), // NTT America
            (174, "US"),  // Cogent
            (3356, "US"), // Lumen/Level3
            (6939, "US"), // Hurricane Electric
            // Major ISPs - Europe
            (3320, "DE"),  // Deutsche Telekom
            (5089, "GB"),  // Virgin Media
            (12322, "FR"), // Free
            (3215, "FR"),  // Orange
            (6830, "NL"),  // Liberty Global
            (2856, "GB"),  // BT
            (6805, "DE"),  // Telefonica Germany
            (3269, "IT"),  // Telecom Italia
            (6739, "ES"),  // Vodafone Spain
            (12389, "RU"), // Rostelecom
            (1299, "SE"),  // Telia
            // Major ISPs - Asia Pacific
            (4766, "KR"),   // Korea Telecom
            (45102, "CN"),  // Alibaba
            (37963, "CN"),  // Alibaba
            (132203, "CN"), // Tencent
            (45090, "CN"),  // Tencent
            (9498, "IN"),   // Bharti Airtel
            (4134, "CN"),   // Chinanet
            (4837, "CN"),   // China Unicom
            (17676, "JP"),  // SoftBank
            (6453, "IN"),   // TATA
            // Oracle Cloud
            (55967, "US"),
            (31898, "US"),
            // M247 (VPN infrastructure - UK based)
            (9009, "GB"),
            // Starlink / SpaceX
            // NOTE: Starlink IPs are registered in US regardless of user's physical location.
            // This is a known limitation of satellite internet - all traffic routes through
            // US ground stations. We mark as US which is technically correct for the IP registry.
            (14593, "US"),  // Starlink (primary)
            (396986, "US"), // SpaceX Services, Inc.
        ];

        for &(asn, country) in asns {
            self.asn_countries.insert(asn, country);
        }
    }

    /// Load IP prefix-to-ASN mappings (called once during construction)
    fn load_prefix_data(&mut self) {
        // Major cloud provider ranges
        let prefix_data: &[([u8; 4], u8, u32)] = &[
            // Amazon AWS
            ([52, 0, 0, 0], 10, 16509),
            ([54, 0, 0, 0], 8, 16509),
            ([3, 0, 0, 0], 8, 16509),
            // Google Cloud
            ([35, 192, 0, 0], 12, 15169),
            ([34, 64, 0, 0], 10, 15169),
            // Microsoft Azure
            ([40, 64, 0, 0], 10, 8075),
            ([20, 0, 0, 0], 8, 8075),
            // Cloudflare
            ([104, 16, 0, 0], 12, 13335),
            ([172, 64, 0, 0], 13, 13335),
            ([1, 1, 1, 0], 24, 13335),
            // DigitalOcean
            ([167, 99, 0, 0], 16, 14061),
            ([206, 189, 0, 0], 16, 14061),
            ([159, 65, 0, 0], 16, 14061),
            ([164, 90, 0, 0], 16, 14061),
            ([162, 243, 0, 0], 16, 14061),
            ([104, 131, 0, 0], 16, 14061),
            ([46, 101, 0, 0], 16, 14061),
            ([165, 22, 0, 0], 16, 14061),
            // Hetzner (AS24940) - Germany/Finland data centers
            ([88, 198, 0, 0], 16, 24940),
            ([78, 46, 0, 0], 15, 24940),
            ([88, 99, 0, 0], 16, 24940),
            ([5, 9, 0, 0], 16, 24940),
            ([95, 216, 0, 0], 16, 24940),
            ([65, 109, 0, 0], 16, 24940),
            ([138, 201, 0, 0], 16, 24940),
            ([148, 251, 0, 0], 16, 24940),
            ([144, 76, 0, 0], 16, 24940),
            // Hetzner Cloud ranges (missing before)
            ([116, 202, 0, 0], 16, 24940),
            ([116, 203, 0, 0], 16, 24940),
            ([128, 140, 0, 0], 16, 24940),
            ([49, 12, 0, 0], 16, 24940),
            ([49, 13, 0, 0], 16, 24940),
            ([157, 90, 0, 0], 16, 24940),
            ([168, 119, 0, 0], 16, 24940),
            // Hetzner Finland (65.21.x.x is AS24940)
            ([65, 21, 0, 0], 16, 24940),
            ([135, 181, 0, 0], 16, 24940),
            ([37, 27, 0, 0], 16, 24940),
            // OVH
            ([51, 68, 0, 0], 16, 16276),
            ([51, 77, 0, 0], 16, 16276),
            // Starlink / SpaceX
            // NOTE: Shows as US because Starlink IPs route through US ground stations
            ([98, 97, 0, 0], 16, 14593),
            ([98, 98, 0, 0], 15, 14593),
            ([143, 131, 0, 0], 16, 14593),
            ([150, 228, 0, 0], 16, 14593), // Europe/UK region
            ([206, 214, 0, 0], 16, 14593),
            ([206, 220, 0, 0], 16, 14593),
        ];

        for &(octets, len, asn) in prefix_data {
            self.ipv4_prefixes.push(Ipv4Prefix::new(octets, len, asn));
        }

        // Sort by prefix length (longest first for most-specific match)
        self.ipv4_prefixes.sort_by(|a, b| {
            // Count leading ones in mask (longer prefix = higher priority)
            b.mask.count_ones().cmp(&a.mask.count_ones())
        });
    }
}

impl Default for BgpGeoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_lookup() {
        let provider = BgpGeoProvider::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let (lat, lon, country) = provider.lookup(ip);

        assert_eq!(country, Some("US".to_string()));
        // Should be near US centroid with jitter
        assert!(lat > 30.0 && lat < 45.0);
        assert!(lon < -80.0 && lon > -110.0);
    }

    #[test]
    fn test_hetzner_lookup() {
        let provider = BgpGeoProvider::new();
        let ip = IpAddr::V4(Ipv4Addr::new(95, 216, 1, 1));
        let (lat, lon, country) = provider.lookup(ip);

        assert_eq!(country, Some("DE".to_string()));
        // Should be near Germany centroid with jitter
        assert!(lat > 45.0 && lat < 56.0);
        assert!(lon > 5.0 && lon < 16.0);
    }

    #[test]
    fn test_digitalocean_lookup() {
        let provider = BgpGeoProvider::new();
        let ip = IpAddr::V4(Ipv4Addr::new(159, 65, 100, 1));
        let (lat, _lon, country) = provider.lookup(ip);

        assert_eq!(country, Some("US".to_string()));
        assert!(lat > 30.0 && lat < 45.0);
    }

    #[test]
    fn test_jitter_determinism() {
        let provider = BgpGeoProvider::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let (lat1, lon1, _) = provider.lookup(ip);
        let (lat2, lon2, _) = provider.lookup(ip);

        // Same IP should give same coordinates (deterministic jitter)
        assert_eq!(lat1, lat2);
        assert_eq!(lon1, lon2);
    }

    #[test]
    fn test_different_ips_different_jitter() {
        let provider = BgpGeoProvider::new();

        let (lat1, lon1, _) = provider.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let (lat2, lon2, _) = provider.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 9)));

        // Different IPs should have different jitter
        assert!(lat1 != lat2 || lon1 != lon2);
    }
}
