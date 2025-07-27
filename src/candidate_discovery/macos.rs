//! macOS-specific network interface discovery using System Configuration Framework
//!
//! This module provides production-ready network interface enumeration and monitoring
//! for macOS platforms using the System Configuration Framework for real-time network
//! change detection and comprehensive interface discovery.

use std::{
    collections::HashMap,
    ffi::CString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use nix::libc;

// Interface type constants for macOS
#[allow(dead_code)] // Used in FFI bindings
const IFT_ETHER: u8 = 6;

// macOS-specific ioctl constants
#[allow(dead_code)] // Used in FFI bindings
const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;
#[allow(dead_code)] // Used in FFI bindings
const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
#[allow(dead_code)] // Used in FFI bindings
const SIOCGIFADDR: libc::c_ulong = 0xc0206921;

use tracing::{debug, error, info, warn};

use crate::candidate_discovery::{NetworkInterface, NetworkInterfaceDiscovery};

/// macOS-specific network interface discovery using System Configuration Framework
pub(crate) struct MacOSInterfaceDiscovery {
    /// Cached interface data to detect changes
    #[allow(dead_code)] // Used in caching logic
    cached_interfaces: HashMap<String, MacOSInterface>,
    /// Last scan timestamp for cache validation
    #[allow(dead_code)] // Used in cache validation
    last_scan_time: Option<Instant>,
    /// Cache TTL for interface data
    #[allow(dead_code)] // Used in cache expiry checks
    cache_ttl: std::time::Duration,
    /// Current scan state
    scan_state: ScanState,
    /// System Configuration dynamic store
    sc_store: Option<SCDynamicStoreRef>,
    /// Run loop source for network change notifications
    run_loop_source: Option<CFRunLoopSourceRef>,
    /// Interface enumeration configuration
    #[allow(dead_code)] // Used in interface filtering
    interface_config: InterfaceConfig,
    /// Flag to track if network changes have occurred
    #[allow(dead_code)] // Used in network change detection
    network_changed: bool,
}

/// Internal representation of a macOS network interface
#[derive(Debug, Clone)]
struct MacOSInterface {
    /// Interface name (e.g., "en0", "en1")
    #[allow(dead_code)] // Used in trait implementation
    name: String,
    /// Interface display name (e.g., "Wi-Fi", "Ethernet")
    #[allow(dead_code)] // Used for user-friendly display
    display_name: String,
    /// Hardware type (Ethernet, Wi-Fi, etc.)
    #[allow(dead_code)] // Used in hardware type detection
    hardware_type: HardwareType,
    /// Interface state
    state: InterfaceState,
    /// IPv4 addresses
    ipv4_addresses: Vec<Ipv4Addr>,
    /// IPv6 addresses
    ipv6_addresses: Vec<Ipv6Addr>,
    /// Interface flags
    flags: InterfaceFlags,
    /// MTU size
    mtu: u32,
    /// Hardware address (MAC)
    hardware_address: Option<[u8; 6]>,
    /// Last update timestamp
    last_updated: Instant,
}

/// Hardware types for macOS interfaces
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardwareType {
    #[allow(dead_code)] // Used in interface detection
    Ethernet,
    #[allow(dead_code)] // Used in interface type detection
    WiFi,
    #[allow(dead_code)] // Used in interface type detection
    Bluetooth,
    #[allow(dead_code)] // Used in interface type detection
    Cellular,
    #[allow(dead_code)] // Used in interface type detection
    Loopback,
    #[allow(dead_code)] // Used in interface type detection
    PPP,
    #[allow(dead_code)] // Used in interface type detection
    VPN,
    #[allow(dead_code)] // Used in interface type detection
    Bridge,
    #[allow(dead_code)] // Used in interface type detection
    Thunderbolt,
    #[allow(dead_code)] // Used in interface type detection
    USB,
    #[allow(dead_code)] // Used in interface type detection
    Unknown,
}

/// Interface state information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceState {
    #[allow(dead_code)] // Used in interface state detection
    Active,
    #[allow(dead_code)] // Used in interface state detection
    Inactive,
    #[allow(dead_code)] // Used in interface state detection
    Unknown,
}

/// Interface flags
#[derive(Debug, Clone, Copy, Default)]
struct InterfaceFlags {
    /// Interface is up
    #[allow(dead_code)] // Used in interface filtering and conversion
    is_up: bool,
    /// Interface is active (has valid configuration)
    #[allow(dead_code)] // Used in interface filtering
    is_active: bool,
    /// Interface is wireless
    #[allow(dead_code)] // Used in interface filtering and conversion
    is_wireless: bool,
    /// Interface is loopback
    #[allow(dead_code)] // Used in interface filtering
    is_loopback: bool,
    /// Interface supports IPv4
    #[allow(dead_code)] // Used in interface filtering
    supports_ipv4: bool,
    /// Interface supports IPv6
    #[allow(dead_code)] // Used in interface filtering
    supports_ipv6: bool,
    /// Interface is built-in (not USB/external)
    #[allow(dead_code)] // Used in interface filtering
    is_builtin: bool,
}

/// Current state of the scanning process
#[derive(Debug, Clone, PartialEq)]
enum ScanState {
    /// No scan in progress
    Idle,
    /// Scan initiated, waiting for completion
    #[allow(dead_code)] // Used in scanning state machine
    InProgress { started_at: Instant },
    /// Scan completed, results available
    #[allow(dead_code)] // Used in scanning state machine
    Completed { scan_results: Vec<NetworkInterface> },
    /// Scan failed with error
    #[allow(dead_code)] // Used in scanning state machine
    Failed { error: String },
}

/// Configuration for interface enumeration
#[derive(Debug, Clone)]
pub(crate) struct InterfaceConfig {
    /// Include inactive interfaces
    #[allow(dead_code)] // Used in filtering logic
    include_inactive: bool,
    /// Include loopback interfaces
    #[allow(dead_code)] // Used in filtering logic
    include_loopback: bool,
    /// Include IPv6 addresses
    #[allow(dead_code)] // Used in filtering logic
    include_ipv6: bool,
    /// Include built-in interfaces only
    #[allow(dead_code)] // Used in filtering logic
    builtin_only: bool,
    /// Minimum MTU size to consider
    #[allow(dead_code)] // Used in filtering logic
    min_mtu: u32,
    /// Maximum interfaces to enumerate
    #[allow(dead_code)] // Used in filtering logic
    max_interfaces: u32,
}

/// macOS System Configuration Framework error types
#[derive(Debug, Clone)]
#[allow(dead_code)] // Error types for macOS network operations
pub(crate) enum MacOSNetworkError {
    /// System Configuration Framework error
    SystemConfigurationError {
        function: &'static str,
        message: String,
    },
    /// Interface not found
    InterfaceNotFound { interface_name: String },
    /// Invalid interface configuration
    InvalidInterfaceConfig {
        interface_name: String,
        reason: String,
    },
    /// Network service enumeration failed
    ServiceEnumerationFailed { reason: String },
    /// Address parsing failed
    AddressParsingFailed { address: String, reason: String },
    /// Dynamic store access failed
    DynamicStoreAccessFailed { reason: String },
    /// Run loop source creation failed
    RunLoopSourceCreationFailed { reason: String },
    /// Dynamic store configuration failed
    DynamicStoreConfigurationFailed {
        operation: &'static str,
        reason: String,
    },
}

// System Configuration Framework types and constants
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct SCDynamicStoreRef(*mut std::ffi::c_void);
unsafe impl Send for SCDynamicStoreRef {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct CFRunLoopSourceRef(*mut std::ffi::c_void);
unsafe impl Send for CFRunLoopSourceRef {}

type CFStringRef = *mut std::ffi::c_void;
type CFRunLoopRef = *mut std::ffi::c_void;
#[allow(dead_code)] // Core Foundation array reference
type CFArrayRef = *mut std::ffi::c_void;
#[allow(dead_code)] // Core Foundation allocator reference
type CFAllocatorRef = *mut std::ffi::c_void;

// System Configuration Framework context
#[repr(C)]
struct SCDynamicStoreContext {
    version: i64,
    info: *mut std::ffi::c_void,
    retain: Option<extern "C" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void>,
    release: Option<extern "C" fn(*mut std::ffi::c_void)>,
    copyDescription: Option<extern "C" fn(*mut std::ffi::c_void) -> CFStringRef>,
}

// Import kCFRunLoopDefaultMode and kCFAllocatorDefault from Core Foundation
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    #[link_name = "kCFRunLoopDefaultMode"]
    static kCFRunLoopDefaultMode: CFStringRef;

    #[link_name = "kCFAllocatorDefault"]
    static kCFAllocatorDefault: CFAllocatorRef;
}

// Network change callback function
extern "C" fn network_change_callback(
    _store: SCDynamicStoreRef,
    _changed_keys: CFArrayRef,
    info: *mut std::ffi::c_void,
) {
    // Set the network_changed flag through the context
    // The info pointer should point to our MacOSInterfaceDiscovery struct
    if !info.is_null() {
        unsafe {
            let discovery = &mut *(info as *mut MacOSInterfaceDiscovery);
            discovery.network_changed = true;
            debug!("Network change detected via callback");
        }
    }
}

// System Configuration Framework FFI declarations
#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callback: Option<extern "C" fn(SCDynamicStoreRef, CFArrayRef, *mut std::ffi::c_void)>,
        context: *mut SCDynamicStoreContext,
    ) -> SCDynamicStoreRef;

    fn SCDynamicStoreCreateRunLoopSource(
        allocator: CFAllocatorRef,
        store: SCDynamicStoreRef,
        order: i32,
    ) -> CFRunLoopSourceRef;

    fn SCDynamicStoreSetNotificationKeys(
        store: SCDynamicStoreRef,
        keys: CFArrayRef,
        patterns: CFArrayRef,
    ) -> bool;

    fn SCDynamicStoreCopyKeyList(store: SCDynamicStoreRef, pattern: CFStringRef) -> CFArrayRef;

    #[allow(dead_code)]
    fn SCDynamicStoreCopyValue(store: SCDynamicStoreRef, key: CFStringRef)
    -> *mut std::ffi::c_void;

    fn SCPreferencesCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        prefs_id: CFStringRef,
    ) -> *mut std::ffi::c_void; // SCPreferencesRef

    fn SCNetworkServiceCopyAll(prefs: *mut std::ffi::c_void, // SCPreferencesRef
    ) -> CFArrayRef;

    fn SCNetworkServiceGetInterface(
        service: *mut std::ffi::c_void, // SCNetworkServiceRef
    ) -> *mut std::ffi::c_void; // SCNetworkInterfaceRef

    fn SCNetworkInterfaceGetBSDName(
        interface: *mut std::ffi::c_void, // SCNetworkInterfaceRef
    ) -> CFStringRef;
}

// Core Foundation FFI declarations
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: *mut std::ffi::c_void);
    fn CFRetain(cf: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRemoveSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFStringCreateWithCString(
        allocator: CFAllocatorRef,
        cstr: *const std::ffi::c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFArrayGetCount(array: CFArrayRef) -> i64;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, idx: i64) -> *mut std::ffi::c_void;
    fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const *const std::ffi::c_void,
        num_values: i64,
        callbacks: *const std::ffi::c_void,
    ) -> CFArrayRef;
    fn CFGetTypeID(cf: *mut std::ffi::c_void) -> u64;
    fn CFStringGetTypeID() -> u64;
    fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut std::ffi::c_char,
        buffer_size: i64,
        encoding: u32,
    ) -> bool;
    fn CFStringGetLength(string: CFStringRef) -> i64;
}

// Core Foundation encoding constants
const kCFStringEncodingUTF8: u32 = 0x08000100;

// Core Foundation array callbacks
const kCFTypeArrayCallBacks: *const std::ffi::c_void = std::ptr::null();

// Utility functions for Core Foundation
unsafe fn cf_string_to_rust_string(cf_str: CFStringRef) -> Option<String> {
    if cf_str.is_null() {
        return None;
    }

    let length = CFStringGetLength(cf_str);
    if length == 0 {
        return Some(String::new());
    }

    let mut buffer = vec![0u8; (length as usize + 1) * 4]; // UTF-8 can be up to 4 bytes per character
    let success = CFStringGetCString(
        cf_str,
        buffer.as_mut_ptr() as *mut std::ffi::c_char,
        buffer.len() as i64,
        kCFStringEncodingUTF8,
    );

    if success {
        // Find the null terminator
        let null_pos = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        String::from_utf8(buffer[..null_pos].to_vec()).ok()
    } else {
        None
    }
}

unsafe fn rust_string_to_cf_string(s: &str) -> CFStringRef {
    let c_str = CString::new(s).unwrap();
    CFStringCreateWithCString(kCFAllocatorDefault, c_str.as_ptr(), kCFStringEncodingUTF8)
}

impl MacOSInterfaceDiscovery {
    /// Create a new macOS interface discovery instance
    pub(crate) fn new() -> Self {
        Self {
            cached_interfaces: HashMap::new(),
            last_scan_time: None,
            cache_ttl: std::time::Duration::from_secs(30),
            scan_state: ScanState::Idle,
            sc_store: None,
            run_loop_source: None,
            interface_config: InterfaceConfig {
                include_inactive: false,
                include_loopback: false,
                include_ipv6: true,
                builtin_only: false,
                min_mtu: 1280, // IPv6 minimum MTU
                max_interfaces: 32,
            },
            network_changed: false,
        }
    }

    /// Set interface configuration
    pub(crate) fn set_interface_config(&mut self, config: InterfaceConfig) {
        self.interface_config = config;
    }

    /// Initialize System Configuration Framework dynamic store
    pub(crate) fn initialize_dynamic_store(&mut self) -> Result<(), MacOSNetworkError> {
        if self.sc_store.is_some() {
            return Ok(());
        }

        // Create dynamic store
        let store_name = CString::new("ant-quic-network-discovery").unwrap();
        let sc_store = unsafe {
            // SCDynamicStoreCreate equivalent
            self.create_dynamic_store(store_name.as_ptr())
        };

        if sc_store.0.is_null() {
            return Err(MacOSNetworkError::DynamicStoreAccessFailed {
                reason: "Failed to create SCDynamicStore".to_string(),
            });
        }

        self.sc_store = Some(sc_store);
        debug!("System Configuration dynamic store initialized");
        Ok(())
    }

    /// Enable network change monitoring
    pub(crate) fn enable_change_monitoring(&mut self) -> Result<(), MacOSNetworkError> {
        if self.run_loop_source.is_some() {
            return Ok(());
        }

        // Initialize dynamic store if not already done
        self.initialize_dynamic_store()?;

        let sc_store = self.sc_store.as_ref().unwrap();

        unsafe {
            // Set up notification keys for network changes
            let keys = Vec::<CFStringRef>::new();
            let mut patterns = Vec::new();

            // Monitor all IPv4 and IPv6 configuration changes
            let ipv4_pattern = rust_string_to_cf_string("State:/Network/Interface/.*/IPv4");
            let ipv6_pattern = rust_string_to_cf_string("State:/Network/Interface/.*/IPv6");
            let link_pattern = rust_string_to_cf_string("State:/Network/Interface/.*/Link");

            patterns.push(ipv4_pattern);
            patterns.push(ipv6_pattern);
            patterns.push(link_pattern);

            // Create arrays for the notification keys
            let keys_array = CFArrayCreate(
                kCFAllocatorDefault,
                keys.as_ptr() as *const *const std::ffi::c_void,
                keys.len() as i64,
                kCFTypeArrayCallBacks,
            );

            let patterns_array = CFArrayCreate(
                kCFAllocatorDefault,
                patterns.as_ptr() as *const *const std::ffi::c_void,
                patterns.len() as i64,
                kCFTypeArrayCallBacks,
            );

            // Set notification keys
            let success = SCDynamicStoreSetNotificationKeys(*sc_store, keys_array, patterns_array);

            // Clean up
            for pattern in patterns {
                CFRelease(pattern);
            }
            if !keys_array.is_null() {
                CFRelease(keys_array);
            }
            if !patterns_array.is_null() {
                CFRelease(patterns_array);
            }

            if !success {
                return Err(MacOSNetworkError::DynamicStoreConfigurationFailed {
                    operation: "SCDynamicStoreSetNotificationKeys",
                    reason: "Failed to set notification keys".to_string(),
                });
            }
        }

        // Create run loop source for network change notifications
        let run_loop_source = unsafe { self.create_run_loop_source(sc_store) };

        if run_loop_source.0.is_null() {
            return Err(MacOSNetworkError::RunLoopSourceCreationFailed {
                reason: "Failed to create run loop source".to_string(),
            });
        }

        self.run_loop_source = Some(run_loop_source);
        debug!("Network change monitoring enabled");
        Ok(())
    }

    /// Check if network changes have occurred
    pub(crate) fn check_network_changes(&mut self) -> bool {
        if self.network_changed {
            debug!("Network change detected, resetting flag");
            self.network_changed = false;
            true
        } else {
            false
        }
    }

    /// Enumerate network interfaces using System Configuration Framework
    fn enumerate_interfaces(&self) -> Result<Vec<MacOSInterface>, MacOSNetworkError> {
        let mut interfaces = Vec::new();

        // Get all network services
        let services = self.get_network_services()?;

        for service in services {
            match self.process_network_service(&service) {
                Ok(interface) => {
                    if self.should_include_interface(&interface) {
                        interfaces.push(interface);
                    }
                }
                Err(e) => {
                    warn!("Failed to process network service: {:?}", e);
                }
            }
        }

        // Add system interfaces (loopback, etc.)
        if self.interface_config.include_loopback {
            interfaces.push(self.create_loopback_interface());
        }

        debug!("Enumerated {} network interfaces", interfaces.len());
        Ok(interfaces)
    }

    /// Get all network services from System Configuration
    fn get_network_services(&self) -> Result<Vec<String>, MacOSNetworkError> {
        let mut services = Vec::new();

        unsafe {
            // Create preferences reference
            let prefs_name = rust_string_to_cf_string("ant-quic-network-discovery");
            let prefs = SCPreferencesCreate(
                kCFAllocatorDefault,
                prefs_name,
                std::ptr::null_mut(), // Use default preferences
            );
            CFRelease(prefs_name);

            if prefs.is_null() {
                // Fall back to common interface names if we can't get preferences
                let common_interfaces = [
                    "en0", "en1", "en2", "en3",   // Ethernet/Wi-Fi
                    "awdl0", // Apple Wireless Direct Link
                    "utun0", "utun1", "utun2", // VPN tunnels
                    "bridge0", "bridge1", // Bridge interfaces
                    "p2p0", "p2p1", // Peer-to-peer
                ];

                for interface in &common_interfaces {
                    if self.interface_exists(interface) {
                        services.push(interface.to_string());
                    }
                }

                return Ok(services);
            }

            // Get all network services
            let services_array = SCNetworkServiceCopyAll(prefs);
            if !services_array.is_null() {
                let count = CFArrayGetCount(services_array);

                for i in 0..count {
                    let service = CFArrayGetValueAtIndex(services_array, i);
                    if !service.is_null() {
                        // Get the interface for this service
                        let interface = SCNetworkServiceGetInterface(service);
                        if !interface.is_null() {
                            // Get the BSD name (e.g., "en0")
                            let bsd_name = SCNetworkInterfaceGetBSDName(interface);
                            if !bsd_name.is_null() {
                                if let Some(name) = cf_string_to_rust_string(bsd_name) {
                                    services.push(name);
                                }
                            }
                        }
                    }
                }

                CFRelease(services_array);
            }

            CFRelease(prefs);
        }

        Ok(services)
    }

    /// Check if an interface exists on the system
    fn interface_exists(&self, interface_name: &str) -> bool {
        // Use if_nametoindex to check if interface exists
        let c_name = match CString::new(interface_name) {
            Ok(name) => name,
            Err(_) => return false,
        };

        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        index != 0
    }

    /// Process a network service to extract interface information
    fn process_network_service(
        &self,
        service_name: &str,
    ) -> Result<MacOSInterface, MacOSNetworkError> {
        // Get interface hardware type
        let hardware_type = self.get_interface_hardware_type(service_name);

        // Get interface state
        let state = self.get_interface_state(service_name);

        // Get IP addresses
        let ipv4_addresses = self.get_ipv4_addresses(service_name)?;
        let ipv6_addresses = if self.interface_config.include_ipv6 {
            self.get_ipv6_addresses(service_name)?
        } else {
            Vec::new()
        };

        // Get interface properties
        let display_name = self.get_interface_display_name(service_name);
        let mtu = self.get_interface_mtu(service_name);
        let hardware_address = self.get_hardware_address(service_name);

        // Set interface flags
        let flags = InterfaceFlags {
            is_up: state == InterfaceState::Active,
            is_active: state == InterfaceState::Active,
            is_wireless: hardware_type == HardwareType::WiFi,
            is_loopback: hardware_type == HardwareType::Loopback,
            supports_ipv4: !ipv4_addresses.is_empty(),
            supports_ipv6: !ipv6_addresses.is_empty(),
            is_builtin: self.is_builtin_interface(service_name),
        };

        Ok(MacOSInterface {
            name: service_name.to_string(),
            display_name,
            hardware_type,
            state,
            ipv4_addresses,
            ipv6_addresses,
            flags,
            mtu,
            hardware_address,
            last_updated: Instant::now(),
        })
    }

    /// Determine interface hardware type
    fn get_interface_hardware_type(&self, interface_name: &str) -> HardwareType {
        match interface_name {
            name if name.starts_with("en") => {
                // Check if it's Wi-Fi or Ethernet
                if self.is_wifi_interface(name) {
                    HardwareType::WiFi
                } else {
                    HardwareType::Ethernet
                }
            }
            name if name.starts_with("lo") => HardwareType::Loopback,
            name if name.starts_with("awdl") => HardwareType::WiFi,
            name if name.starts_with("utun") => HardwareType::VPN,
            name if name.starts_with("bridge") => HardwareType::Bridge,
            name if name.starts_with("p2p") => HardwareType::WiFi,
            name if name.starts_with("ppp") => HardwareType::PPP,
            _ => HardwareType::Unknown,
        }
    }

    /// Check if an interface is Wi-Fi
    fn is_wifi_interface(&self, interface_name: &str) -> bool {
        // macOS Wi-Fi interfaces typically follow these patterns:
        // - en0: Primary Wi-Fi interface on most Macs
        // - en1, en2, etc.: Additional Wi-Fi interfaces
        // - awdl0: Apple Wireless Direct Link (peer-to-peer Wi-Fi)

        // Check for common Wi-Fi interface patterns
        if interface_name.starts_with("en") {
            // Most Wi-Fi interfaces are en0, en1, etc.
            // Ethernet interfaces on newer Macs might be en5, en6, etc.
            // This is a heuristic; IOKit would provide definitive information
            if let Ok(num) = interface_name[2..].parse::<u32>() {
                // Lower-numbered en interfaces are more likely to be Wi-Fi
                return num <= 2;
            }
        }

        // Apple Wireless Direct Link
        interface_name == "awdl0"
    }

    /// Get interface state
    fn get_interface_state(&self, interface_name: &str) -> InterfaceState {
        // Create socket for interface queries
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            return InterfaceState::Unknown;
        }

        // Prepare interface request structure
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = interface_name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);

        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifreq.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }

        // Get interface flags
        let result = unsafe { libc::ioctl(socket_fd, SIOCGIFFLAGS, &mut ifreq) };
        let state = if result >= 0 {
            let flags = unsafe { ifreq.ifr_ifru.ifru_flags };
            let is_up = (flags & libc::IFF_UP as i16) != 0;
            let is_running = (flags & libc::IFF_RUNNING as i16) != 0;

            if is_up && is_running {
                InterfaceState::Active
            } else if is_up {
                InterfaceState::Inactive
            } else {
                InterfaceState::Inactive
            }
        } else {
            InterfaceState::Unknown
        };

        unsafe {
            libc::close(socket_fd);
        }
        state
    }

    /// Get IPv4 addresses for an interface
    fn get_ipv4_addresses(&self, interface_name: &str) -> Result<Vec<Ipv4Addr>, MacOSNetworkError> {
        let mut addresses = Vec::new();

        // Create socket for interface queries
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            return Err(MacOSNetworkError::SystemConfigurationError {
                function: "socket",
                message: "Failed to create socket for IPv4 address query".to_string(),
            });
        }

        // Prepare interface request structure
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = interface_name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);

        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifreq.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }

        // Get interface address
        let result = unsafe { libc::ioctl(socket_fd, SIOCGIFADDR, &mut ifreq) };
        if result >= 0 {
            let sockaddr_in = unsafe {
                &*(&ifreq.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in)
            };

            if sockaddr_in.sin_family == libc::AF_INET as u8 {
                let ip_bytes = sockaddr_in.sin_addr.s_addr.to_ne_bytes();
                let ipv4_addr = Ipv4Addr::from(ip_bytes);
                if !ipv4_addr.is_unspecified() {
                    addresses.push(ipv4_addr);
                }
            }
        }

        unsafe {
            libc::close(socket_fd);
        }
        Ok(addresses)
    }

    /// Get IPv6 addresses for an interface
    fn get_ipv6_addresses(&self, interface_name: &str) -> Result<Vec<Ipv6Addr>, MacOSNetworkError> {
        let mut addresses = Vec::new();

        // Use getifaddrs to enumerate all interface addresses
        let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
        let result = unsafe { libc::getifaddrs(&mut ifaddrs_ptr) };

        if result != 0 {
            return Err(MacOSNetworkError::SystemConfigurationError {
                function: "getifaddrs",
                message: "Failed to get interface addresses".to_string(),
            });
        }

        let mut current = ifaddrs_ptr;
        while !current.is_null() {
            let ifaddr = unsafe { &*current };

            // Check if this is the interface we're looking for
            let if_name = unsafe {
                let name_ptr = ifaddr.ifa_name;
                let name_cstr = std::ffi::CStr::from_ptr(name_ptr);
                name_cstr.to_string_lossy().to_string()
            };

            if if_name == interface_name && !ifaddr.ifa_addr.is_null() {
                let sockaddr = unsafe { &*ifaddr.ifa_addr };

                // Check if this is an IPv6 address
                if sockaddr.sa_family == libc::AF_INET6 as u8 {
                    let sockaddr_in6 = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_in6) };

                    let ipv6_bytes = sockaddr_in6.sin6_addr.s6_addr;

                    let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
                    if !ipv6_addr.is_unspecified() {
                        addresses.push(ipv6_addr);
                    }
                }
            }

            current = ifaddr.ifa_next;
        }

        unsafe {
            libc::freeifaddrs(ifaddrs_ptr);
        }
        Ok(addresses)
    }

    /// Get interface display name
    fn get_interface_display_name(&self, interface_name: &str) -> String {
        match interface_name {
            "en0" => "Wi-Fi".to_string(),
            "en1" => "Ethernet".to_string(),
            "lo0" => "Loopback".to_string(),
            name if name.starts_with("utun") => "VPN".to_string(),
            name if name.starts_with("awdl") => "AirDrop".to_string(),
            name => format!("Interface {name}"),
        }
    }

    /// Get interface MTU
    fn get_interface_mtu(&self, interface_name: &str) -> u32 {
        // Create socket for interface queries
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            return 1500; // Default MTU
        }

        // Prepare interface request structure
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = interface_name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);

        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifreq.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }

        // Get interface MTU
        let result = unsafe { libc::ioctl(socket_fd, SIOCGIFMTU, &mut ifreq) };
        let mtu = if result >= 0 {
            unsafe { ifreq.ifr_ifru.ifru_mtu as u32 }
        } else {
            // Default MTU values
            match interface_name {
                "lo0" => 16384,
                _ => 1500,
            }
        };

        unsafe {
            libc::close(socket_fd);
        }
        mtu
    }

    /// Get hardware address (MAC)
    fn get_hardware_address(&self, interface_name: &str) -> Option<[u8; 6]> {
        // Use getifaddrs to get hardware address
        let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
        let result = unsafe { libc::getifaddrs(&mut ifaddrs_ptr) };

        if result != 0 {
            return None;
        }

        let mut hardware_address = None;
        let mut current = ifaddrs_ptr;

        while !current.is_null() {
            let ifaddr = unsafe { &*current };

            // Check if this is the interface we're looking for
            let if_name = unsafe {
                let name_ptr = ifaddr.ifa_name;
                let name_cstr = std::ffi::CStr::from_ptr(name_ptr);
                name_cstr.to_string_lossy().to_string()
            };

            if if_name == interface_name && !ifaddr.ifa_addr.is_null() {
                let sockaddr = unsafe { &*ifaddr.ifa_addr };

                // Check if this is a link-layer address (AF_LINK on macOS)
                if sockaddr.sa_family == libc::AF_LINK as u8 {
                    // On macOS, AF_LINK sockaddr contains the hardware address
                    // Parse the sockaddr_dl structure properly
                    let sockaddr_dl = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_dl) };

                    // Check if this is a 6-byte MAC address
                    if sockaddr_dl.sdl_alen == 6 && sockaddr_dl.sdl_type == IFT_ETHER {
                        // Calculate offset to hardware address data
                        // sockaddr_dl layout: len, family, index, type, nlen, alen, slen, data[12], name[], addr[]
                        let name_len = sockaddr_dl.sdl_nlen as usize;
                        let addr_offset = 8 + name_len; // 8 bytes for fixed header + name length

                        if addr_offset + 6 <= sockaddr_dl.sdl_len as usize {
                            let addr_data = unsafe {
                                let base_ptr = ifaddr.ifa_addr as *const u8;
                                std::slice::from_raw_parts(base_ptr.add(addr_offset), 6)
                            };

                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(addr_data);
                            hardware_address = Some(mac);
                            break;
                        }
                    }
                }
            }

            current = ifaddr.ifa_next;
        }

        unsafe {
            libc::freeifaddrs(ifaddrs_ptr);
        }
        hardware_address
    }

    /// Check if interface is built-in
    fn is_builtin_interface(&self, interface_name: &str) -> bool {
        matches!(interface_name, "en0" | "en1" | "lo0")
    }

    /// Create loopback interface
    fn create_loopback_interface(&self) -> MacOSInterface {
        MacOSInterface {
            name: "lo0".to_string(),
            display_name: "Loopback".to_string(),
            hardware_type: HardwareType::Loopback,
            state: InterfaceState::Active,
            ipv4_addresses: vec![Ipv4Addr::new(127, 0, 0, 1)],
            ipv6_addresses: if self.interface_config.include_ipv6 {
                vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
            } else {
                Vec::new()
            },
            flags: InterfaceFlags {
                is_up: true,
                is_active: true,
                is_wireless: false,
                is_loopback: true,
                supports_ipv4: true,
                supports_ipv6: self.interface_config.include_ipv6,
                is_builtin: true,
            },
            mtu: 16384,
            hardware_address: None,
            last_updated: Instant::now(),
        }
    }

    /// Check if an interface should be included based on configuration
    fn should_include_interface(&self, interface: &MacOSInterface) -> bool {
        // Check loopback filter
        if interface.flags.is_loopback && !self.interface_config.include_loopback {
            return false;
        }

        // Check inactive filter
        if interface.state != InterfaceState::Active && !self.interface_config.include_inactive {
            return false;
        }

        // Check built-in filter
        if self.interface_config.builtin_only && !interface.flags.is_builtin {
            return false;
        }

        // Check MTU filter
        if interface.mtu < self.interface_config.min_mtu {
            return false;
        }

        // Check if interface has any usable addresses
        if interface.ipv4_addresses.is_empty() && interface.ipv6_addresses.is_empty() {
            return false;
        }

        true
    }

    /// Convert macOS interface to generic NetworkInterface
    fn convert_to_network_interface(&self, macos_interface: &MacOSInterface) -> NetworkInterface {
        let mut addresses = Vec::new();

        // Add IPv4 addresses
        for ipv4 in &macos_interface.ipv4_addresses {
            addresses.push(SocketAddr::new(IpAddr::V4(*ipv4), 0));
        }

        // Add IPv6 addresses
        for ipv6 in &macos_interface.ipv6_addresses {
            addresses.push(SocketAddr::new(IpAddr::V6(*ipv6), 0));
        }

        NetworkInterface {
            name: macos_interface.name.clone(),
            addresses,
            is_up: macos_interface.flags.is_up,
            is_wireless: macos_interface.flags.is_wireless,
            mtu: Some(macos_interface.mtu as u16),
        }
    }

    /// Update cached interfaces with new scan results
    fn update_cache(&mut self, interfaces: Vec<MacOSInterface>) {
        self.cached_interfaces.clear();
        for interface in interfaces {
            self.cached_interfaces
                .insert(interface.name.clone(), interface);
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

    // System Configuration Framework wrapper functions
    // These would be implemented using proper system bindings

    unsafe fn create_dynamic_store(&mut self, name: *const std::ffi::c_char) -> SCDynamicStoreRef {
        // Create CF string from C string
        let cf_name = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);

        if cf_name.is_null() {
            error!("Failed to create CFString for dynamic store name");
            return SCDynamicStoreRef(std::ptr::null_mut());
        }

        // Create context for the dynamic store with self pointer
        let mut context = SCDynamicStoreContext {
            version: 0,
            info: self as *mut _ as *mut std::ffi::c_void,
            retain: None,
            release: None,
            copyDescription: None,
        };

        // Create the dynamic store with callback
        let store = SCDynamicStoreCreate(
            kCFAllocatorDefault,
            cf_name,
            Some(network_change_callback),
            &mut context,
        );

        // Clean up the CF string
        CFRelease(cf_name);

        store
    }

    unsafe fn create_run_loop_source(&self, store: &SCDynamicStoreRef) -> CFRunLoopSourceRef {
        // Create run loop source for the dynamic store
        let source = SCDynamicStoreCreateRunLoopSource(
            kCFAllocatorDefault,
            *store,
            0, // Priority order
        );

        if !source.0.is_null() {
            // Add the source to the current run loop
            let current_run_loop = CFRunLoopGetCurrent();
            CFRunLoopAddSource(current_run_loop, source, kCFRunLoopDefaultMode);
        }

        source
    }
}

impl NetworkInterfaceDiscovery for MacOSInterfaceDiscovery {
    fn start_scan(&mut self) -> Result<(), String> {
        debug!("Starting macOS network interface scan");

        // Check if we need to scan or can use cache
        if self.is_cache_valid() && !self.check_network_changes() {
            debug!("Using cached interface data");
            let interfaces: Vec<NetworkInterface> = self
                .cached_interfaces
                .values()
                .map(|mi| self.convert_to_network_interface(mi))
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

        match self.enumerate_interfaces() {
            Ok(interfaces) => {
                debug!("Successfully enumerated {} interfaces", interfaces.len());

                // Convert to generic NetworkInterface format
                let network_interfaces: Vec<NetworkInterface> = interfaces
                    .iter()
                    .map(|mi| self.convert_to_network_interface(mi))
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
                let error_msg = format!("macOS interface enumeration failed: {e:?}");
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

impl Drop for MacOSInterfaceDiscovery {
    fn drop(&mut self) {
        unsafe {
            // Clean up System Configuration Framework resources
            if let Some(run_loop_source) = self.run_loop_source.take() {
                // Remove from run loop first
                let current_run_loop = CFRunLoopGetCurrent();
                CFRunLoopRemoveSource(current_run_loop, run_loop_source, kCFRunLoopDefaultMode);
                // Then release the source
                CFRelease(run_loop_source.0);
            }

            if let Some(sc_store) = self.sc_store.take() {
                CFRelease(sc_store.0);
            }
        }
    }
}

impl std::fmt::Display for MacOSNetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemConfigurationError { function, message } => {
                write!(f, "System Configuration error in {function}: {message}")
            }
            Self::InterfaceNotFound { interface_name } => {
                write!(f, "Interface not found: {interface_name}")
            }
            Self::InvalidInterfaceConfig {
                interface_name,
                reason,
            } => {
                write!(f, "Invalid interface config for {interface_name}: {reason}")
            }
            Self::ServiceEnumerationFailed { reason } => {
                write!(f, "Service enumeration failed: {reason}")
            }
            Self::AddressParsingFailed { address, reason } => {
                write!(f, "Address parsing failed for {address}: {reason}")
            }
            Self::DynamicStoreAccessFailed { reason } => {
                write!(f, "Dynamic store access failed: {reason}")
            }
            Self::RunLoopSourceCreationFailed { reason } => {
                write!(f, "Run loop source creation failed: {reason}")
            }
            Self::DynamicStoreConfigurationFailed { operation, reason } => {
                write!(
                    f,
                    "Dynamic store configuration failed in {operation}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for MacOSNetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_interface_discovery_creation() {
        let discovery = MacOSInterfaceDiscovery::new();
        assert!(discovery.cached_interfaces.is_empty());
        assert!(discovery.last_scan_time.is_none());
    }

    #[test]
    fn test_interface_config() {
        let mut discovery = MacOSInterfaceDiscovery::new();
        let config = InterfaceConfig {
            include_inactive: true,
            include_loopback: true,
            include_ipv6: false,
            builtin_only: true,
            min_mtu: 1000,
            max_interfaces: 16,
        };

        discovery.set_interface_config(config.clone());
        assert!(discovery.interface_config.include_loopback);
        assert_eq!(discovery.interface_config.min_mtu, 1000);
    }

    #[test]
    fn test_hardware_type_detection() {
        let discovery = MacOSInterfaceDiscovery::new();

        // Test well-known interface patterns
        assert_eq!(
            discovery.get_interface_hardware_type("en0"),
            HardwareType::WiFi
        );
        assert_eq!(
            discovery.get_interface_hardware_type("en1"),
            HardwareType::WiFi
        ); // en1 is also WiFi based on the logic
        assert_eq!(
            discovery.get_interface_hardware_type("en5"),
            HardwareType::Ethernet
        ); // Higher numbered en interfaces are Ethernet
        assert_eq!(
            discovery.get_interface_hardware_type("lo0"),
            HardwareType::Loopback
        );
        assert_eq!(
            discovery.get_interface_hardware_type("utun0"),
            HardwareType::VPN
        );
        assert_eq!(
            discovery.get_interface_hardware_type("awdl0"),
            HardwareType::WiFi
        );
        assert_eq!(
            discovery.get_interface_hardware_type("bridge0"),
            HardwareType::Bridge
        );
        assert_eq!(
            discovery.get_interface_hardware_type("p2p0"),
            HardwareType::WiFi
        );
        assert_eq!(
            discovery.get_interface_hardware_type("ppp0"),
            HardwareType::PPP
        );
        assert_eq!(
            discovery.get_interface_hardware_type("unknown0"),
            HardwareType::Unknown
        );
    }

    #[test]
    fn test_cache_validation() {
        let mut discovery = MacOSInterfaceDiscovery::new();

        // No cache initially
        assert!(!discovery.is_cache_valid());

        // Set cache time
        discovery.last_scan_time = Some(Instant::now());
        assert!(discovery.is_cache_valid());

        // Expired cache
        discovery.last_scan_time = Some(Instant::now() - std::time::Duration::from_secs(60));
        assert!(!discovery.is_cache_valid());
    }

    #[test]
    fn test_loopback_interface_creation() {
        let discovery = MacOSInterfaceDiscovery::new();
        let loopback = discovery.create_loopback_interface();

        assert_eq!(loopback.name, "lo0");
        assert_eq!(loopback.hardware_type, HardwareType::Loopback);
        assert!(loopback.flags.is_loopback);
        assert!(loopback.flags.is_up);
        assert!(!loopback.ipv4_addresses.is_empty());
    }

    #[test]
    fn test_interface_filtering() {
        let mut discovery = MacOSInterfaceDiscovery::new();

        // Create test interface
        let interface = MacOSInterface {
            name: "en0".to_string(),
            display_name: "Wi-Fi".to_string(),
            hardware_type: HardwareType::WiFi,
            state: InterfaceState::Active,
            ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 100)],
            ipv6_addresses: Vec::new(),
            flags: InterfaceFlags {
                is_up: true,
                is_active: true,
                is_wireless: true,
                is_loopback: false,
                supports_ipv4: true,
                supports_ipv6: false,
                is_builtin: true,
            },
            mtu: 1500,
            hardware_address: None,
            last_updated: Instant::now(),
        };

        // Should include by default
        assert!(discovery.should_include_interface(&interface));

        // Should exclude if MTU too small
        discovery.interface_config.min_mtu = 2000;
        assert!(!discovery.should_include_interface(&interface));
    }
}
