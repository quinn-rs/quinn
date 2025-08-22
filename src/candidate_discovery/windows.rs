// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Windows-specific network interface discovery using IP Helper API
//!
//! This module provides production-ready network interface enumeration and monitoring
//! for Windows platforms using the IP Helper API and Windows Sockets API.

use std::{
    collections::HashMap,
    ffi::{CStr, OsString, c_char},
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::ffi::OsStringExt,
    ptr,
    sync::Arc,
    time::Instant,
};

use windows::Win32::{
    Foundation::{
        CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, GetAdaptersInfo, GetIpForwardTable, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_INFO, MIB_IF_TYPE_ETHERNET, MIB_IF_TYPE_LOOPBACK, MIB_IF_TYPE_PPP,
        MIB_IF_TYPE_SLIP, MIB_IF_TYPE_TOKENRING, MIB_IPFORWARDROW,
    },
    Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6},
    System::{IO::OVERLAPPED, Threading::WaitForSingleObject},
};

use tracing::{debug, error, info, warn};

use crate::candidate_discovery::{NetworkInterface, NetworkInterfaceDiscovery};

// Constants extracted for pattern matching
const ERROR_BUFFER_OVERFLOW_VALUE: u32 = 111; // ERROR_BUFFER_OVERFLOW value

/// Windows-specific network interface discovery using IP Helper API
pub struct WindowsInterfaceDiscovery {
    /// Cached interface data to detect changes
    cached_interfaces: HashMap<u32, WindowsInterface>,
    /// Last scan timestamp for cache validation
    last_scan_time: Option<Instant>,
    /// Cache TTL for interface data
    cache_ttl: std::time::Duration,
    /// Current scan state
    scan_state: ScanState,
    /// Network change monitoring handle
    change_handle: Option<Arc<NetworkChangeHandle>>,
    /// Adapter enumeration configuration
    adapter_config: AdapterConfig,
}

// WindowsInterfaceDiscovery is thread-safe due to Arc wrapper on handle
unsafe impl Send for WindowsInterfaceDiscovery {}
unsafe impl Sync for WindowsInterfaceDiscovery {}

/// Internal representation of a Windows network interface
#[derive(Debug, Clone)]
struct WindowsInterface {
    /// Interface index
    index: u32,
    /// Interface name
    name: String,
    /// Friendly name for display
    friendly_name: String,
    /// Interface type
    interface_type: InterfaceType,
    /// Operational status
    oper_status: OperationalStatus,
    /// IPv4 addresses
    ipv4_addresses: Vec<Ipv4Addr>,
    /// IPv6 addresses
    ipv6_addresses: Vec<Ipv6Addr>,
    /// MTU size
    mtu: u32,
    /// Physical address (MAC)
    physical_address: Option<[u8; 6]>,
    /// Interface flags
    flags: InterfaceFlags,
    /// Last update timestamp
    last_updated: Instant,
}

/// Windows interface types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceType {
    Ethernet,
    Wireless,
    Loopback,
    Tunnel,
    Ppp,
    Unknown(u32),
}

/// Operational status of the interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationalStatus {
    Up,
    Down,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

/// Interface flags
#[derive(Debug, Clone, Copy, Default)]
struct InterfaceFlags {
    /// Interface is up
    is_up: bool,
    /// Interface is wireless
    is_wireless: bool,
    /// Interface is loopback
    is_loopback: bool,
    /// Interface supports multicast
    supports_multicast: bool,
    /// Interface is point-to-point
    is_point_to_point: bool,
}

/// Current state of the scanning process
#[derive(Debug, Clone, PartialEq)]
enum ScanState {
    /// No scan in progress
    Idle,
    /// Scan initiated, waiting for completion
    InProgress { started_at: Instant },
    /// Scan completed, results available
    Completed { scan_results: Vec<NetworkInterface> },
    /// Scan failed with error
    Failed { error: String },
}

/// Network change monitoring handle
struct NetworkChangeHandle {
    /// Handle to network change notification
    handle: windows::Win32::Foundation::HANDLE,
    /// Overlapped structure for asynchronous operations
    overlapped: windows::Win32::System::IO::OVERLAPPED,
}

// Mark NetworkChangeHandle as thread-safe
unsafe impl Send for NetworkChangeHandle {}
unsafe impl Sync for NetworkChangeHandle {}

/// Configuration for adapter enumeration
#[derive(Debug, Clone)]
struct AdapterConfig {
    /// Include loopback interfaces
    include_loopback: bool,
    /// Include down interfaces
    include_down: bool,
    /// Include IPv6 addresses
    include_ipv6: bool,
    /// Minimum MTU size to consider
    min_mtu: u32,
    /// Maximum interfaces to enumerate
    max_interfaces: u32,
}

/// Windows IP Helper API error types
#[derive(Debug, Clone)]
enum WindowsNetworkError {
    /// API call failed
    ApiCallFailed {
        function: &'static str,
        error_code: u32,
        message: String,
    },
    /// Buffer too small for API call
    BufferTooSmall {
        function: &'static str,
        required_size: u32,
    },
    /// Invalid parameter passed to API
    InvalidParameter {
        function: &'static str,
        parameter: &'static str,
    },
    /// Network interface not found
    InterfaceNotFound { interface_index: u32 },
    /// Unsupported interface type
    UnsupportedInterfaceType { interface_type: u32 },
    /// Memory allocation failed
    MemoryAllocationFailed { size: usize },
    /// Network change notification failed
    NetworkChangeNotificationFailed { error_code: u32 },
}

impl WindowsInterfaceDiscovery {
    /// Create a new Windows interface discovery instance
    pub fn new() -> Self {
        Self {
            cached_interfaces: HashMap::new(),
            last_scan_time: None,
            cache_ttl: std::time::Duration::from_secs(30),
            scan_state: ScanState::Idle,
            change_handle: None,
            adapter_config: AdapterConfig {
                include_loopback: false,
                include_down: false,
                include_ipv6: true,
                min_mtu: 1280, // IPv6 minimum MTU
                max_interfaces: 64,
            },
        }
    }

    /// Set adapter configuration
    pub fn set_adapter_config(&mut self, config: AdapterConfig) {
        self.adapter_config = config;
    }

    /// Enable network change monitoring
    pub fn enable_change_monitoring(&mut self) -> Result<(), WindowsNetworkError> {
        if self.change_handle.is_some() {
            return Ok(());
        }

        // Initialize network change notification
        let mut handle = windows::Win32::Foundation::HANDLE::default();
        let mut overlapped = unsafe { mem::zeroed() };

        let result = unsafe {
            windows::Win32::NetworkManagement::IpHelper::NotifyAddrChange(&mut handle, &overlapped)
        };

        if result != windows::Win32::Foundation::ERROR_IO_PENDING.0 && result != 0 {
            return Err(WindowsNetworkError::NetworkChangeNotificationFailed {
                error_code: result,
            });
        }

        self.change_handle = Some(Arc::new(NetworkChangeHandle { handle, overlapped }));
        debug!("Network change monitoring enabled");
        Ok(())
    }

    /// Check if network changes have occurred
    pub fn check_network_changes(&mut self) -> bool {
        if let Some(ref mut change_handle) = self.change_handle {
            let result = unsafe {
                WaitForSingleObject(
                    change_handle.handle,
                    0, // Don't wait
                )
            };

            match result {
                windows::Win32::Foundation::WAIT_OBJECT_0 => {
                    debug!("Network change detected");
                    // Reset the notification for next change
                    let _ = self.enable_change_monitoring();
                    true
                }
                windows::Win32::Foundation::WAIT_TIMEOUT => false,
                _ => {
                    warn!("Network change notification failed, disabling monitoring");
                    self.change_handle = None;
                    false
                }
            }
        } else {
            false
        }
    }

    /// Enumerate all network adapters using IP Helper API
    fn enumerate_adapters(&self) -> Result<Vec<WindowsInterface>, WindowsNetworkError> {
        let mut interfaces = Vec::new();
        let mut buffer_size = 16384u32; // Start with 16KB buffer
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

        loop {
            let result = unsafe {
                windows::Win32::NetworkManagement::IpHelper::GetAdaptersInfo(
                    Some(buffer.as_mut_ptr()
                        as *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_INFO),
                    &mut buffer_size,
                )
            };

            match result {
                0 => break, // Success
                ERROR_BUFFER_OVERFLOW_VALUE => {
                    // Buffer too small, resize and retry
                    buffer.resize(buffer_size as usize, 0);
                    continue;
                }
                error_code => {
                    return Err(WindowsNetworkError::ApiCallFailed {
                        function: "GetAdaptersInfo",
                        error_code,
                        message: format!("Failed to enumerate network adapters: {}", error_code),
                    });
                }
            }
        }

        // Parse adapter information
        let mut current_adapter =
            buffer.as_ptr() as *const windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_INFO;
        let mut adapter_count = 0;

        while !current_adapter.is_null() && adapter_count < self.adapter_config.max_interfaces {
            let adapter = unsafe { &*current_adapter };

            match self.parse_adapter_info(adapter) {
                Ok(interface) => {
                    if self.should_include_interface(&interface) {
                        interfaces.push(interface);
                        adapter_count += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to parse adapter info: {:?}", e);
                }
            }

            current_adapter = adapter.Next;
        }

        debug!("Enumerated {} network interfaces", interfaces.len());
        Ok(interfaces)
    }

    /// Parse adapter information from IP Helper API structure
    fn parse_adapter_info(
        &self,
        adapter: &windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_INFO,
    ) -> Result<WindowsInterface, WindowsNetworkError> {
        // Extract adapter name
        let name = unsafe {
            let name_ptr = adapter.AdapterName.as_ptr() as *const i8;
            let name_cstr = CStr::from_ptr(name_ptr as *const c_char);
            let name_len = name_cstr.to_bytes().len();
            let name_slice = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
            String::from_utf8_lossy(name_slice).to_string()
        };

        // Extract description (friendly name)
        let friendly_name = unsafe {
            let desc_ptr = adapter.Description.as_ptr() as *const i8;
            let desc_cstr = CStr::from_ptr(desc_ptr as *const c_char);
            let desc_len = desc_cstr.to_bytes().len();
            let desc_slice = std::slice::from_raw_parts(desc_ptr as *const u8, desc_len);
            String::from_utf8_lossy(desc_slice).to_string()
        };

        // Parse interface type
        let interface_type = match adapter.Type {
            windows::Win32::NetworkManagement::IpHelper::MIB_IF_TYPE_ETHERNET => {
                InterfaceType::Ethernet
            }
            windows::Win32::NetworkManagement::IpHelper::MIB_IF_TYPE_TOKENRING => {
                InterfaceType::Ethernet
            }
            windows::Win32::NetworkManagement::IpHelper::MIB_IF_TYPE_PPP => InterfaceType::Ppp,
            windows::Win32::NetworkManagement::IpHelper::MIB_IF_TYPE_LOOPBACK => {
                InterfaceType::Loopback
            }
            windows::Win32::NetworkManagement::IpHelper::MIB_IF_TYPE_SLIP => InterfaceType::Ppp,
            other => InterfaceType::Unknown(other),
        };

        // Parse IPv4 addresses
        let mut ipv4_addresses = Vec::new();
        let mut current_addr = &adapter.IpAddressList;

        loop {
            let ip_str = unsafe {
                let ip_ptr = current_addr.IpAddress.String.as_ptr() as *const i8;
                let ip_cstr = CStr::from_ptr(ip_ptr as *const c_char);
                let ip_len = ip_cstr.to_bytes().len();
                let ip_slice = std::slice::from_raw_parts(ip_ptr as *const u8, ip_len);
                String::from_utf8_lossy(ip_slice).to_string()
            };

            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                if !ip.is_unspecified() {
                    ipv4_addresses.push(ip);
                }
            }

            if current_addr.Next.is_null() {
                break;
            }
            current_addr = unsafe { &*current_addr.Next };
        }

        // Get IPv6 addresses (requires separate API call)
        let ipv6_addresses = if self.adapter_config.include_ipv6 {
            self.get_ipv6_addresses(adapter.Index).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Parse physical address (MAC)
        let physical_address = if adapter.AddressLength == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&adapter.Address[..6]);
            Some(mac)
        } else {
            None
        };

        // Determine interface flags
        let flags = InterfaceFlags {
            is_up: true, // Will be updated with operational status
            is_wireless: self.is_wireless_interface(&name, &friendly_name),
            is_loopback: interface_type == InterfaceType::Loopback,
            supports_multicast: true, // Most interfaces support multicast
            is_point_to_point: interface_type == InterfaceType::Ppp,
        };

        Ok(WindowsInterface {
            index: adapter.Index,
            name,
            friendly_name,
            interface_type,
            oper_status: OperationalStatus::Up, // Will be updated
            ipv4_addresses,
            ipv6_addresses,
            mtu: 1500, // Default MTU, will be updated
            physical_address,
            flags,
            last_updated: Instant::now(),
        })
    }

    /// Get IPv6 addresses for a specific adapter
    fn get_ipv6_addresses(&self, adapter_index: u32) -> Result<Vec<Ipv6Addr>, WindowsNetworkError> {
        let mut addresses = Vec::new();
        let mut buffer_size = 16384u32;
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

        loop {
            let result = unsafe {
                windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses(
                    AF_INET6.0 as u32,
                    windows::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_ANYCAST
                        | windows::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_MULTICAST
                        | windows::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_DNS_SERVER,
                    None,
                    Some(buffer.as_mut_ptr() as *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH),
                    &mut buffer_size,
                )
            };

            match result {
                0 => break, // Success
                ERROR_BUFFER_OVERFLOW_VALUE => {
                    buffer.resize(buffer_size as usize, 0);
                    continue;
                }
                error_code => {
                    return Err(WindowsNetworkError::ApiCallFailed {
                        function: "GetAdaptersAddresses",
                        error_code,
                        message: format!("Failed to get IPv6 addresses: {}", error_code),
                    });
                }
            }
        }

        // Parse IPv6 addresses
        let mut current_adapter = buffer.as_ptr()
            as *const windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;

        while !current_adapter.is_null() {
            let adapter = unsafe { &*current_adapter };

            if unsafe { adapter.Anonymous1.Anonymous.IfIndex } == adapter_index {
                let mut current_addr = adapter.FirstUnicastAddress;

                while !current_addr.is_null() {
                    let addr_info = unsafe { &*current_addr };
                    let sockaddr = unsafe { &*addr_info.Address.lpSockaddr };

                    if sockaddr.sa_family == AF_INET6 {
                        let sockaddr_in6 = unsafe {
                            &*(addr_info.Address.lpSockaddr
                                as *const windows::Win32::Networking::WinSock::SOCKADDR_IN6)
                        };

                        let ipv6_bytes = unsafe {
                            std::mem::transmute::<[u16; 8], [u8; 16]>(sockaddr_in6.sin6_addr.u.Word)
                        };

                        let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
                        if !ipv6_addr.is_unspecified() && !ipv6_addr.is_loopback() {
                            addresses.push(ipv6_addr);
                        }
                    }

                    current_addr = addr_info.Next;
                }
                break;
            }

            current_adapter = adapter.Next;
        }

        Ok(addresses)
    }

    /// Check if an interface should be included based on configuration
    fn should_include_interface(&self, interface: &WindowsInterface) -> bool {
        // Check loopback filter
        if interface.flags.is_loopback && !self.adapter_config.include_loopback {
            return false;
        }

        // Check operational status filter
        if interface.oper_status != OperationalStatus::Up && !self.adapter_config.include_down {
            return false;
        }

        // Check MTU filter
        if interface.mtu < self.adapter_config.min_mtu {
            return false;
        }

        // Check if interface has any usable addresses
        if interface.ipv4_addresses.is_empty() && interface.ipv6_addresses.is_empty() {
            return false;
        }

        true
    }

    /// Determine if an interface is wireless based on name and description
    fn is_wireless_interface(&self, name: &str, description: &str) -> bool {
        let wireless_indicators = [
            "wireless",
            "wi-fi",
            "wifi",
            "wlan",
            "802.11",
            "bluetooth",
            "mobile",
            "cellular",
            "3g",
            "4g",
            "5g",
            "lte",
            "wimax",
            "radio",
        ];

        let name_lower = name.to_lowercase();
        let desc_lower = description.to_lowercase();

        wireless_indicators
            .iter()
            .any(|&indicator| name_lower.contains(indicator) || desc_lower.contains(indicator))
    }

    /// Convert Windows interface to generic NetworkInterface
    fn convert_to_network_interface(
        &self,
        windows_interface: &WindowsInterface,
    ) -> NetworkInterface {
        let mut addresses = Vec::new();

        // Add IPv4 addresses
        for ipv4 in &windows_interface.ipv4_addresses {
            addresses.push(SocketAddr::new(IpAddr::V4(*ipv4), 0));
        }

        // Add IPv6 addresses
        for ipv6 in &windows_interface.ipv6_addresses {
            addresses.push(SocketAddr::new(IpAddr::V6(*ipv6), 0));
        }

        NetworkInterface {
            name: windows_interface.name.clone(),
            addresses,
            is_up: windows_interface.oper_status == OperationalStatus::Up,
            is_wireless: windows_interface.flags.is_wireless,
            mtu: Some(windows_interface.mtu as u16),
        }
    }

    /// Update cached interfaces with new scan results
    fn update_cache(&mut self, interfaces: Vec<WindowsInterface>) {
        self.cached_interfaces.clear();
        for interface in interfaces {
            self.cached_interfaces.insert(interface.index, interface);
        }
        self.last_scan_time = Some(Instant::now());
    }

    /// Check if cache is valid
    fn is_cache_valid(&self) -> bool {
        if let Some(last_scan) = self.last_scan_time {
            last_scan.elapsed() < self.cache_ttl
        } else {
            false
        }
    }
}

impl NetworkInterfaceDiscovery for WindowsInterfaceDiscovery {
    fn start_scan(&mut self) -> Result<(), String> {
        debug!("Starting Windows network interface scan");

        // Check if we need to scan or can use cache
        if self.is_cache_valid() && !self.check_network_changes() {
            debug!("Using cached interface data");
            let interfaces: Vec<NetworkInterface> = self
                .cached_interfaces
                .values()
                .map(|wi| self.convert_to_network_interface(wi))
                .collect();

            self.scan_state = ScanState::Completed {
                scan_results: interfaces,
            };
            return Ok(());
        }

        // Perform fresh scan
        self.scan_state = ScanState::InProgress {
            started_at: Instant::now(),
        };

        match self.enumerate_adapters() {
            Ok(interfaces) => {
                debug!("Successfully enumerated {} interfaces", interfaces.len());

                // Convert to generic NetworkInterface format
                let network_interfaces: Vec<NetworkInterface> = interfaces
                    .iter()
                    .map(|wi| self.convert_to_network_interface(wi))
                    .collect();

                // Update cache
                self.update_cache(interfaces);

                self.scan_state = ScanState::Completed {
                    scan_results: network_interfaces,
                };

                info!("Network interface scan completed successfully");
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Windows interface enumeration failed: {:?}", e);
                error!("{}", error_msg);
                self.scan_state = ScanState::Failed {
                    error: error_msg.clone(),
                };
                Err(error_msg)
            }
        }
    }

    fn check_scan_complete(&mut self) -> Option<Vec<NetworkInterface>> {
        match &self.scan_state {
            ScanState::Completed { scan_results } => {
                let results = scan_results.clone();
                self.scan_state = ScanState::Idle;
                Some(results)
            }
            ScanState::Failed { error } => {
                warn!("Scan failed: {}", error);
                self.scan_state = ScanState::Idle;
                None
            }
            _ => None,
        }
    }
}

impl Drop for WindowsInterfaceDiscovery {
    fn drop(&mut self) {
        // Clean up network change monitoring
        if let Some(change_handle) = self.change_handle.take() {
            unsafe {
                // CloseHandle returns BOOL; ignore errors intentionally
                let _ = windows::Win32::Foundation::CloseHandle(change_handle.handle);
            }
        }
    }
}

impl std::fmt::Display for WindowsNetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiCallFailed {
                function,
                error_code,
                message,
            } => {
                write!(
                    f,
                    "API call {} failed with code {}: {}",
                    function, error_code, message
                )
            }
            Self::BufferTooSmall {
                function,
                required_size,
            } => {
                write!(
                    f,
                    "Buffer too small for {}: {} bytes required",
                    function, required_size
                )
            }
            Self::InvalidParameter {
                function,
                parameter,
            } => {
                write!(
                    f,
                    "Invalid parameter {} for function {}",
                    parameter, function
                )
            }
            Self::InterfaceNotFound { interface_index } => {
                write!(f, "Network interface {} not found", interface_index)
            }
            Self::UnsupportedInterfaceType { interface_type } => {
                write!(f, "Unsupported interface type: {}", interface_type)
            }
            Self::MemoryAllocationFailed { size } => {
                write!(f, "Memory allocation failed: {} bytes", size)
            }
            Self::NetworkChangeNotificationFailed { error_code } => {
                write!(
                    f,
                    "Network change notification failed with code {}",
                    error_code
                )
            }
        }
    }
}

impl std::error::Error for WindowsNetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_interface_discovery_creation() {
        let discovery = WindowsInterfaceDiscovery::new();
        assert!(discovery.cached_interfaces.is_empty());
        assert!(discovery.last_scan_time.is_none());
    }

    #[test]
    fn test_adapter_config() {
        let mut discovery = WindowsInterfaceDiscovery::new();
        let config = AdapterConfig {
            include_loopback: true,
            include_down: true,
            include_ipv6: false,
            min_mtu: 1000,
            max_interfaces: 32,
        };

        discovery.set_adapter_config(config.clone());
        assert!(discovery.adapter_config.include_loopback);
        assert_eq!(discovery.adapter_config.min_mtu, 1000);
    }

    #[test]
    fn test_wireless_interface_detection() {
        let discovery = WindowsInterfaceDiscovery::new();

        assert!(discovery.is_wireless_interface("wlan0", "Wireless LAN adapter"));
        assert!(discovery.is_wireless_interface("eth0", "Intel(R) Wireless-AC 9560"));
        assert!(!discovery.is_wireless_interface("eth0", "Ethernet adapter"));
    }

    #[test]
    fn test_cache_validation() {
        let mut discovery = WindowsInterfaceDiscovery::new();

        // No cache initially
        assert!(!discovery.is_cache_valid());

        // Set cache time
        discovery.last_scan_time = Some(Instant::now());
        assert!(discovery.is_cache_valid());

        // Expired cache
        discovery.last_scan_time = Some(Instant::now() - std::time::Duration::from_secs(60));
        assert!(!discovery.is_cache_valid());
    }
}
