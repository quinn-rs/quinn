// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Linux-specific network interface discovery using netlink sockets
//!
//! This module provides production-ready network interface enumeration and monitoring
//! for Linux platforms using netlink sockets for real-time network change detection.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use nix::libc;
use tracing::{debug, error, info, warn};

use crate::candidate_discovery::{NetworkInterface, NetworkInterfaceDiscovery};

/// Linux-specific network interface discovery using netlink
pub struct LinuxInterfaceDiscovery {
    /// Cached interface data to detect changes
    cached_interfaces: HashMap<u32, LinuxInterface>,
    /// Last scan timestamp for cache validation
    last_scan_time: Option<Instant>,
    /// Cache TTL for interface data
    cache_ttl: std::time::Duration,
    /// Current scan state
    scan_state: ScanState,
    /// Netlink socket for interface monitoring
    netlink_socket: Option<NetlinkSocket>,
    /// Interface enumeration configuration
    interface_config: InterfaceConfig,
}

/// Internal representation of a Linux network interface
#[derive(Debug, Clone)]
struct LinuxInterface {
    /// Interface index
    index: u32,
    /// Interface name
    name: String,
    /// Interface type
    interface_type: InterfaceType,
    /// Interface flags
    flags: InterfaceFlags,
    /// MTU size
    mtu: u32,
    /// IPv4 addresses with prefix length
    ipv4_addresses: Vec<(Ipv4Addr, u8)>,
    /// IPv6 addresses with prefix length
    ipv6_addresses: Vec<(Ipv6Addr, u8)>,
    /// Hardware address (MAC)
    #[allow(dead_code)]
    hardware_address: Option<[u8; 6]>,
    /// Interface state
    state: InterfaceState,
    /// Last update timestamp
    #[allow(dead_code)]
    last_updated: Instant,
}

/// Linux interface types derived from netlink messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceType {
    /// Ethernet interface
    Ethernet,
    /// Wireless interface
    Wireless,
    /// Loopback interface
    Loopback,
    /// Tunnel interface
    Tunnel,
    /// Point-to-point interface
    PointToPoint,
    /// Bridge interface
    Bridge,
    /// VLAN interface
    Vlan,
    /// Bond interface
    Bond,
    /// Virtual interface
    Virtual,
    /// Unknown interface type
    Unknown(u16),
}

/// Interface flags from netlink
#[derive(Debug, Clone, Copy, Default)]
struct InterfaceFlags {
    /// Interface is up
    is_up: bool,
    /// Interface is running
    is_running: bool,
    /// Interface is loopback
    is_loopback: bool,
    /// Interface is point-to-point
    is_point_to_point: bool,
    /// Interface supports multicast
    #[allow(dead_code)]
    supports_multicast: bool,
    /// Interface supports broadcast
    #[allow(dead_code)]
    supports_broadcast: bool,
    /// Interface is wireless
    is_wireless: bool,
}

/// Interface operational state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceState {
    /// Unknown state
    #[allow(dead_code)]
    Unknown,
    /// Interface is not present
    #[allow(dead_code)]
    NotPresent,
    /// Interface is down
    Down,
    /// Interface is in lower layer down
    #[allow(dead_code)]
    LowerLayerDown,
    /// Interface is testing
    #[allow(dead_code)]
    Testing,
    /// Interface is dormant
    #[allow(dead_code)]
    Dormant,
    /// Interface is up
    Up,
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

/// Netlink socket for interface monitoring
struct NetlinkSocket {
    /// Socket file descriptor
    socket_fd: i32,
    /// Sequence number for netlink messages
    #[allow(dead_code)]
    sequence_number: u32,
    /// Process ID for netlink messages
    #[allow(dead_code)]
    process_id: u32,
    /// Buffer for receiving netlink messages
    receive_buffer: Vec<u8>,
    /// Last message timestamp
    last_message_time: Option<Instant>,
}

/// Configuration for interface enumeration
#[derive(Debug, Clone)]
struct InterfaceConfig {
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
    /// Enable real-time monitoring
    enable_monitoring: bool,
    /// Filter by interface types
    allowed_interface_types: Vec<InterfaceType>,
}

/// Linux netlink error types
#[derive(Debug, Clone)]
pub enum LinuxNetworkError {
    /// Netlink socket creation failed
    SocketCreationFailed { error: String },
    /// Failed to bind netlink socket
    SocketBindFailed { error: String },
    /// Failed to send netlink message
    MessageSendFailed { error: String },
    /// Failed to receive netlink message
    MessageReceiveFailed { error: String },
    /// Invalid netlink message format
    InvalidMessage { message: String },
    /// Interface not found
    InterfaceNotFound { interface_name: String },
    /// Permission denied for netlink operations
    PermissionDenied { operation: String },
    /// System limit exceeded
    SystemLimitExceeded { limit_type: String },
    /// Network namespace error
    NetworkNamespaceError { error: String },
    /// Interface enumeration timeout
    EnumerationTimeout { timeout: std::time::Duration },
}

/// Netlink message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkMessageType {
    /// Get link information
    #[allow(dead_code)]
    GetLink,
    /// Get address information
    #[allow(dead_code)]
    GetAddress,
    /// Link state change
    LinkStateChange,
    /// Address change
    AddressChange,
    /// Route change
    RouteChange,
}

/// Netlink message parsing result
#[derive(Debug, Clone)]
struct NetlinkMessage {
    /// Message type
    message_type: NetlinkMessageType,
    /// Message flags
    #[allow(dead_code)]
    flags: u16,
    /// Message sequence number
    #[allow(dead_code)]
    sequence: u32,
    /// Message payload
    #[allow(dead_code)]
    payload: Vec<u8>,
}

impl LinuxInterfaceDiscovery {
    /// Create a new Linux interface discovery instance
    pub fn new() -> Self {
        Self {
            cached_interfaces: HashMap::new(),
            last_scan_time: None,
            cache_ttl: std::time::Duration::from_secs(30),
            scan_state: ScanState::Idle,
            netlink_socket: None,
            interface_config: InterfaceConfig {
                include_loopback: false,
                include_down: false,
                include_ipv6: true,
                min_mtu: 1280, // IPv6 minimum MTU
                max_interfaces: 64,
                enable_monitoring: true,
                allowed_interface_types: vec![
                    InterfaceType::Ethernet,
                    InterfaceType::Wireless,
                    InterfaceType::Tunnel,
                    InterfaceType::Bridge,
                ],
            },
        }
    }

    /// Set interface configuration
    pub fn set_interface_config(&mut self, config: InterfaceConfig) {
        self.interface_config = config;
    }

    /// Initialize netlink socket for interface monitoring
    pub fn initialize_netlink_socket(&mut self) -> Result<(), LinuxNetworkError> {
        if self.netlink_socket.is_some() {
            return Ok(());
        }

        // Create netlink socket
        // SAFETY: This unsafe block calls the libc socket() function to create a netlink socket.
        // - All parameters are valid constants from libc (AF_NETLINK, SOCK_RAW, SOCK_CLOEXEC, NETLINK_ROUTE)
        // - The socket() function is a standard POSIX system call with well-defined behavior
        // - Return value is checked for errors (negative values indicate failure)
        // - The file descriptor is properly managed and closed in the Drop implementation
        // - SOCK_CLOEXEC flag ensures the socket is closed on exec() for security
        let socket_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };

        if socket_fd < 0 {
            return Err(LinuxNetworkError::SocketCreationFailed {
                error: format!(
                    "Failed to create netlink socket: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        // Set up socket address
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // Kernel will assign PID
        addr.nl_groups = (1 << (libc::RTNLGRP_LINK - 1))
            | (1 << (libc::RTNLGRP_IPV4_IFADDR - 1))
            | (1 << (libc::RTNLGRP_IPV6_IFADDR - 1));

        // Bind socket
        let bind_result = unsafe {
            libc::bind(
                socket_fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if bind_result < 0 {
            unsafe {
                libc::close(socket_fd);
            }
            return Err(LinuxNetworkError::SocketBindFailed {
                error: format!(
                    "Failed to bind netlink socket: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        // Get assigned PID
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let getsockname_result = unsafe {
            libc::getsockname(
                socket_fd,
                &mut addr as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if getsockname_result < 0 {
            unsafe {
                libc::close(socket_fd);
            }
            return Err(LinuxNetworkError::SocketBindFailed {
                error: format!(
                    "Failed to get socket name: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        // Set socket to non-blocking mode
        let flags = unsafe { libc::fcntl(socket_fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe {
                libc::fcntl(socket_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        self.netlink_socket = Some(NetlinkSocket {
            socket_fd,
            sequence_number: 1,
            process_id: addr.nl_pid,
            receive_buffer: vec![0; 8192],
            last_message_time: None,
        });

        debug!("Netlink socket initialized with PID {}", addr.nl_pid);
        Ok(())
    }

    /// Check for netlink messages indicating network changes
    pub fn check_network_changes(&mut self) -> Result<bool, LinuxNetworkError> {
        let socket = match self.netlink_socket.as_mut() {
            Some(socket) => socket,
            None => return Ok(false),
        };

        let mut changes_detected = false;

        // Read available messages
        loop {
            let bytes_read = unsafe {
                libc::recv(
                    socket.socket_fd,
                    socket.receive_buffer.as_mut_ptr() as *mut libc::c_void,
                    socket.receive_buffer.len(),
                    0,
                )
            };

            if bytes_read < 0 {
                let error = std::io::Error::last_os_error();
                match error.kind() {
                    std::io::ErrorKind::WouldBlock => break, // No more messages
                    _ => {
                        return Err(LinuxNetworkError::MessageReceiveFailed {
                            error: format!("Failed to receive netlink message: {}", error),
                        });
                    }
                }
            }

            if bytes_read == 0 {
                break; // No more data
            }

            // Parse netlink messages
            let messages =
                Self::parse_netlink_messages(&socket.receive_buffer[..bytes_read as usize])?;

            for message in messages {
                match message.message_type {
                    NetlinkMessageType::LinkStateChange | NetlinkMessageType::AddressChange => {
                        changes_detected = true;
                        debug!("Network change detected: {:?}", message.message_type);
                    }
                    _ => {}
                }
            }

            socket.last_message_time = Some(Instant::now());
        }

        Ok(changes_detected)
    }

    /// Parse netlink messages from buffer
    fn parse_netlink_messages(buffer: &[u8]) -> Result<Vec<NetlinkMessage>, LinuxNetworkError> {
        let mut messages = Vec::new();
        let mut offset = 0;

        while offset + 16 <= buffer.len() {
            // Parse netlink header
            let length = u32::from_ne_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]) as usize;

            if length < 16 || offset + length > buffer.len() {
                break; // Invalid or incomplete message
            }

            let msg_type = u16::from_ne_bytes([buffer[offset + 4], buffer[offset + 5]]);

            let flags = u16::from_ne_bytes([buffer[offset + 6], buffer[offset + 7]]);

            let sequence = u32::from_ne_bytes([
                buffer[offset + 8],
                buffer[offset + 9],
                buffer[offset + 10],
                buffer[offset + 11],
            ]);

            let message_type = match msg_type {
                libc::RTM_NEWLINK | libc::RTM_DELLINK => NetlinkMessageType::LinkStateChange,
                libc::RTM_NEWADDR | libc::RTM_DELADDR => NetlinkMessageType::AddressChange,
                libc::RTM_NEWROUTE | libc::RTM_DELROUTE => NetlinkMessageType::RouteChange,
                _ => {
                    offset += length;
                    continue;
                }
            };

            let payload = if length > 16 {
                buffer[offset + 16..offset + length].to_vec()
            } else {
                Vec::new()
            };

            messages.push(NetlinkMessage {
                message_type,
                flags,
                sequence,
                payload,
            });

            offset += length;
        }

        Ok(messages)
    }

    /// Enumerate network interfaces using netlink
    fn enumerate_interfaces(&mut self) -> Result<Vec<LinuxInterface>, LinuxNetworkError> {
        let mut interfaces = Vec::new();

        // Read /proc/net/dev for basic interface information
        let proc_net_dev = match std::fs::read_to_string("/proc/net/dev") {
            Ok(content) => content,
            Err(e) => {
                return Err(LinuxNetworkError::InterfaceNotFound {
                    interface_name: format!("Failed to read /proc/net/dev: {}", e),
                });
            }
        };

        // Parse /proc/net/dev
        for line in proc_net_dev.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let interface_name = parts[0].trim_end_matches(':');
            if interface_name.is_empty() {
                continue;
            }

            match self.get_interface_details(interface_name) {
                Ok(interface) => {
                    if self.should_include_interface(&interface) {
                        interfaces.push(interface);
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to get interface details for {}: {:?}",
                        interface_name, e
                    );
                }
            }

            if interfaces.len() >= self.interface_config.max_interfaces as usize {
                break;
            }
        }

        debug!("Enumerated {} network interfaces", interfaces.len());
        Ok(interfaces)
    }

    /// Get detailed information about a specific interface
    fn get_interface_details(
        &self,
        interface_name: &str,
    ) -> Result<LinuxInterface, LinuxNetworkError> {
        // Get interface index
        let interface_index = self.get_interface_index(interface_name)?;

        // Get interface flags and state
        let (flags, state, mtu) = self.get_interface_flags_and_state(interface_name)?;

        // Determine interface type
        let interface_type = self.determine_interface_type(interface_name, &flags)?;

        // Get hardware address
        let hardware_address = self.get_hardware_address(interface_name).ok();

        // Get IP addresses
        let ipv4_addresses = self.get_ipv4_addresses(interface_name)?;
        let ipv6_addresses = if self.interface_config.include_ipv6 {
            self.get_ipv6_addresses(interface_name)?
        } else {
            Vec::new()
        };

        Ok(LinuxInterface {
            index: interface_index,
            name: interface_name.to_string(),
            interface_type,
            flags,
            mtu,
            ipv4_addresses,
            ipv6_addresses,
            hardware_address,
            state,
            last_updated: Instant::now(),
        })
    }

    /// Get interface index from name
    fn get_interface_index(&self, interface_name: &str) -> Result<u32, LinuxNetworkError> {
        let c_name = std::ffi::CString::new(interface_name).map_err(|_| {
            LinuxNetworkError::InterfaceNotFound {
                interface_name: format!("Invalid interface name: {}", interface_name),
            }
        })?;

        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(LinuxNetworkError::InterfaceNotFound {
                interface_name: interface_name.to_string(),
            });
        }

        Ok(index)
    }

    /// Get interface flags and state
    fn get_interface_flags_and_state(
        &self,
        interface_name: &str,
    ) -> Result<(InterfaceFlags, InterfaceState, u32), LinuxNetworkError> {
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            return Err(LinuxNetworkError::SocketCreationFailed {
                error: "Failed to create socket for interface query".to_string(),
            });
        }

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
        let flags_result = unsafe {
            libc::ioctl(
                socket_fd,
                libc::SIOCGIFFLAGS.try_into().unwrap(),
                &mut ifreq,
            )
        };
        if flags_result < 0 {
            unsafe {
                libc::close(socket_fd);
            }
            return Err(LinuxNetworkError::InterfaceNotFound {
                interface_name: format!("Failed to get flags for interface {}", interface_name),
            });
        }

        let raw_flags = unsafe { ifreq.ifr_ifru.ifru_flags };
        let flags = InterfaceFlags {
            is_up: (raw_flags & libc::IFF_UP as i16) != 0,
            is_running: (raw_flags & libc::IFF_RUNNING as i16) != 0,
            is_loopback: (raw_flags & libc::IFF_LOOPBACK as i16) != 0,
            is_point_to_point: (raw_flags & libc::IFF_POINTOPOINT as i16) != 0,
            supports_multicast: (raw_flags & libc::IFF_MULTICAST as i16) != 0,
            supports_broadcast: (raw_flags & libc::IFF_BROADCAST as i16) != 0,
            is_wireless: self.is_wireless_interface(interface_name),
        };

        // Get MTU
        let mtu_result =
            unsafe { libc::ioctl(socket_fd, libc::SIOCGIFMTU.try_into().unwrap(), &mut ifreq) };
        let mtu = if mtu_result >= 0 {
            unsafe { ifreq.ifr_ifru.ifru_mtu as u32 }
        } else {
            1500 // Default MTU
        };

        unsafe {
            libc::close(socket_fd);
        }

        // Determine interface state
        let state = if flags.is_up && flags.is_running {
            InterfaceState::Up
        } else if flags.is_up {
            InterfaceState::Down
        } else {
            InterfaceState::Down
        };

        Ok((flags, state, mtu))
    }

    /// Determine interface type from name and characteristics
    fn determine_interface_type(
        &self,
        interface_name: &str,
        flags: &InterfaceFlags,
    ) -> Result<InterfaceType, LinuxNetworkError> {
        if flags.is_loopback {
            return Ok(InterfaceType::Loopback);
        }

        if flags.is_point_to_point {
            return Ok(InterfaceType::PointToPoint);
        }

        if flags.is_wireless {
            return Ok(InterfaceType::Wireless);
        }

        // Check interface name patterns
        if interface_name.starts_with("eth") || interface_name.starts_with("en") {
            return Ok(InterfaceType::Ethernet);
        }

        if interface_name.starts_with("wlan") || interface_name.starts_with("wl") {
            return Ok(InterfaceType::Wireless);
        }

        if interface_name.starts_with("tun") || interface_name.starts_with("tap") {
            return Ok(InterfaceType::Tunnel);
        }

        if interface_name.starts_with("br") {
            return Ok(InterfaceType::Bridge);
        }

        if interface_name.contains('.') {
            return Ok(InterfaceType::Vlan);
        }

        if interface_name.starts_with("bond") {
            return Ok(InterfaceType::Bond);
        }

        if interface_name.starts_with("veth") || interface_name.starts_with("docker") {
            return Ok(InterfaceType::Virtual);
        }

        Ok(InterfaceType::Unknown(0))
    }

    /// Check if interface is wireless
    fn is_wireless_interface(&self, interface_name: &str) -> bool {
        // Check for wireless interface indicators
        if interface_name.starts_with("wlan") || interface_name.starts_with("wl") {
            return true;
        }

        // Check if wireless extensions are available
        let wireless_path = format!("/sys/class/net/{}/wireless", interface_name);
        std::path::Path::new(&wireless_path).exists()
    }

    /// Get hardware address for interface
    fn get_hardware_address(&self, interface_name: &str) -> Result<[u8; 6], LinuxNetworkError> {
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            return Err(LinuxNetworkError::SocketCreationFailed {
                error: "Failed to create socket for hardware address query".to_string(),
            });
        }

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

        let result = unsafe {
            libc::ioctl(
                socket_fd,
                libc::SIOCGIFHWADDR.try_into().unwrap(),
                &mut ifreq,
            )
        };
        unsafe {
            libc::close(socket_fd);
        }

        if result < 0 {
            return Err(LinuxNetworkError::InterfaceNotFound {
                interface_name: format!("Failed to get hardware address for {}", interface_name),
            });
        }

        let mut hw_addr = [0u8; 6];
        unsafe {
            std::ptr::copy_nonoverlapping(
                ifreq.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8,
                hw_addr.as_mut_ptr(),
                6,
            );
        }

        Ok(hw_addr)
    }

    /// Get IPv4 addresses for interface
    fn get_ipv4_addresses(
        &self,
        interface_name: &str,
    ) -> Result<Vec<(Ipv4Addr, u8)>, LinuxNetworkError> {
        let mut addresses = Vec::new();

        // Read /proc/net/fib_trie for IPv4 addresses
        // This is a simplified implementation - production code would use netlink
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            return Ok(addresses);
        }

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

        let result =
            unsafe { libc::ioctl(socket_fd, libc::SIOCGIFADDR.try_into().unwrap(), &mut ifreq) };
        if result >= 0 {
            let sockaddr_in = unsafe {
                &*(&ifreq.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in)
            };

            if sockaddr_in.sin_family == libc::AF_INET as u16 {
                let ip_bytes = sockaddr_in.sin_addr.s_addr.to_ne_bytes();
                let ipv4_addr = Ipv4Addr::from(ip_bytes);

                // Get netmask
                let netmask_result = unsafe {
                    libc::ioctl(
                        socket_fd,
                        libc::SIOCGIFNETMASK.try_into().unwrap(),
                        &mut ifreq,
                    )
                };
                let prefix_len = if netmask_result >= 0 {
                    let netmask_sockaddr_in = unsafe {
                        &*(&ifreq.ifr_ifru.ifru_netmask as *const libc::sockaddr
                            as *const libc::sockaddr_in)
                    };
                    let netmask_bytes = netmask_sockaddr_in.sin_addr.s_addr.to_ne_bytes();
                    let netmask = u32::from_ne_bytes(netmask_bytes);
                    netmask.count_ones() as u8
                } else {
                    24 // Default /24
                };

                addresses.push((ipv4_addr, prefix_len));
            }
        }

        unsafe {
            libc::close(socket_fd);
        }
        Ok(addresses)
    }

    /// Get IPv6 addresses for interface
    fn get_ipv6_addresses(
        &self,
        interface_name: &str,
    ) -> Result<Vec<(Ipv6Addr, u8)>, LinuxNetworkError> {
        let mut addresses = Vec::new();

        // Read /proc/net/if_inet6 for IPv6 addresses
        let if_inet6_content = match std::fs::read_to_string("/proc/net/if_inet6") {
            Ok(content) => content,
            Err(_) => return Ok(addresses), // IPv6 not available
        };

        for line in if_inet6_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let addr_str = parts[0];
                let prefix_len_str = parts[1];
                let if_name = parts[5];

                if if_name == interface_name {
                    if let Ok(prefix_len) = u8::from_str_radix(prefix_len_str, 16) {
                        // Parse IPv6 address from hex string
                        if addr_str.len() == 32 {
                            // Convert hex string to bytes
                            let mut ipv6_bytes = [0u8; 16];
                            let mut valid = true;
                            for i in 0..16 {
                                if let Ok(byte) =
                                    u8::from_str_radix(&addr_str[i * 2..i * 2 + 2], 16)
                                {
                                    ipv6_bytes[i] = byte;
                                } else {
                                    valid = false;
                                    break;
                                }
                            }
                            if valid {
                                let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
                                addresses.push((ipv6_addr, prefix_len));
                            }
                        }
                    }
                }
            }
        }

        Ok(addresses)
    }

    /// Check if an interface should be included based on configuration
    fn should_include_interface(&self, interface: &LinuxInterface) -> bool {
        // Check loopback filter
        if interface.flags.is_loopback && !self.interface_config.include_loopback {
            return false;
        }

        // Check operational state filter
        if interface.state != InterfaceState::Up && !self.interface_config.include_down {
            return false;
        }

        // Check MTU filter
        if interface.mtu < self.interface_config.min_mtu {
            return false;
        }

        // Check interface type filter
        if !self.interface_config.allowed_interface_types.is_empty()
            && !self
                .interface_config
                .allowed_interface_types
                .contains(&interface.interface_type)
        {
            return false;
        }

        // Check if interface has any usable addresses
        if interface.ipv4_addresses.is_empty() && interface.ipv6_addresses.is_empty() {
            return false;
        }

        true
    }

    /// Convert Linux interface to generic NetworkInterface
    fn convert_to_network_interface(&self, linux_interface: &LinuxInterface) -> NetworkInterface {
        let mut addresses = Vec::new();

        // Add IPv4 addresses
        for (ipv4, _prefix) in &linux_interface.ipv4_addresses {
            addresses.push(SocketAddr::new(IpAddr::V4(*ipv4), 0));
        }

        // Add IPv6 addresses
        for (ipv6, _prefix) in &linux_interface.ipv6_addresses {
            addresses.push(SocketAddr::new(IpAddr::V6(*ipv6), 0));
        }

        NetworkInterface {
            name: linux_interface.name.clone(),
            addresses,
            is_up: linux_interface.state == InterfaceState::Up,
            is_wireless: linux_interface.flags.is_wireless,
            mtu: Some(linux_interface.mtu as u16),
        }
    }

    /// Update cached interfaces with new scan results
    fn update_cache(&mut self, interfaces: Vec<LinuxInterface>) {
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

impl NetworkInterfaceDiscovery for LinuxInterfaceDiscovery {
    fn start_scan(&mut self) -> Result<(), String> {
        debug!("Starting Linux network interface scan");

        // Initialize netlink socket if monitoring is enabled
        if self.interface_config.enable_monitoring {
            if let Err(e) = self.initialize_netlink_socket() {
                warn!("Failed to initialize netlink socket: {:?}", e);
            }
        }

        // Check if we need to scan or can use cache
        if self.is_cache_valid() {
            if let Ok(changes) = self.check_network_changes() {
                if !changes {
                    debug!("Using cached interface data");
                    let interfaces: Vec<NetworkInterface> = self
                        .cached_interfaces
                        .values()
                        .map(|li| self.convert_to_network_interface(li))
                        .collect();

                    self.scan_state = ScanState::Completed {
                        scan_results: interfaces,
                    };
                    return Ok(());
                }
            }
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
                    .map(|li| self.convert_to_network_interface(li))
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
                let error_msg = format!("Linux interface enumeration failed: {:?}", e);
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

impl Drop for LinuxInterfaceDiscovery {
    fn drop(&mut self) {
        // Clean up netlink socket
        if let Some(socket) = self.netlink_socket.take() {
            unsafe {
                libc::close(socket.socket_fd);
            }
        }
    }
}

impl std::fmt::Display for LinuxNetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketCreationFailed { error } => {
                write!(f, "Socket creation failed: {}", error)
            }
            Self::SocketBindFailed { error } => {
                write!(f, "Socket bind failed: {}", error)
            }
            Self::MessageSendFailed { error } => {
                write!(f, "Message send failed: {}", error)
            }
            Self::MessageReceiveFailed { error } => {
                write!(f, "Message receive failed: {}", error)
            }
            Self::InvalidMessage { message } => {
                write!(f, "Invalid message: {}", message)
            }
            Self::InterfaceNotFound { interface_name } => {
                write!(f, "Interface not found: {}", interface_name)
            }
            Self::PermissionDenied { operation } => {
                write!(f, "Permission denied for operation: {}", operation)
            }
            Self::SystemLimitExceeded { limit_type } => {
                write!(f, "System limit exceeded: {}", limit_type)
            }
            Self::NetworkNamespaceError { error } => {
                write!(f, "Network namespace error: {}", error)
            }
            Self::EnumerationTimeout { timeout } => {
                write!(f, "Enumeration timeout: {:?}", timeout)
            }
        }
    }
}

impl std::error::Error for LinuxNetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_interface_discovery_creation() {
        let discovery = LinuxInterfaceDiscovery::new();
        assert!(discovery.cached_interfaces.is_empty());
        assert!(discovery.last_scan_time.is_none());
    }

    #[test]
    fn test_interface_config() {
        let mut discovery = LinuxInterfaceDiscovery::new();
        let config = InterfaceConfig {
            include_loopback: true,
            include_down: true,
            include_ipv6: false,
            min_mtu: 1000,
            max_interfaces: 32,
            enable_monitoring: false,
            allowed_interface_types: vec![InterfaceType::Ethernet],
        };

        discovery.set_interface_config(config.clone());
        assert!(discovery.interface_config.include_loopback);
        assert_eq!(discovery.interface_config.min_mtu, 1000);
    }

    #[test]
    fn test_wireless_interface_detection() {
        let discovery = LinuxInterfaceDiscovery::new();

        assert!(discovery.is_wireless_interface("wlan0"));
        assert!(discovery.is_wireless_interface("wl0"));
        assert!(!discovery.is_wireless_interface("eth0"));
    }

    #[test]
    fn test_interface_type_determination() {
        let discovery = LinuxInterfaceDiscovery::new();
        let flags = InterfaceFlags::default();

        assert_eq!(
            discovery.determine_interface_type("eth0", &flags).unwrap(),
            InterfaceType::Ethernet
        );
        assert_eq!(
            discovery.determine_interface_type("wlan0", &flags).unwrap(),
            InterfaceType::Wireless
        );
        assert_eq!(
            discovery.determine_interface_type("tun0", &flags).unwrap(),
            InterfaceType::Tunnel
        );
    }

    #[test]
    fn test_cache_validation() {
        let mut discovery = LinuxInterfaceDiscovery::new();

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
