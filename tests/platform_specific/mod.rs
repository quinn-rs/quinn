//! Platform-specific tests for ant-quic
//!
//! These tests verify platform-specific functionality and behavior

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
mod platform_common {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_socket_addr_creation() {
        // Test that basic socket address creation works on all platforms
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);
        assert_eq!(addr.port(), 9000);
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_platform_endianness() {
        // Verify endianness handling
        let value: u32 = 0x12345678;
        let bytes = value.to_be_bytes();
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78]);

        let value_le = value.to_le_bytes();
        #[cfg(target_endian = "little")]
        assert_eq!(value_le, [0x78, 0x56, 0x34, 0x12]);
        #[cfg(target_endian = "big")]
        assert_eq!(value_le, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_async_runtime_available() {
        // Verify async runtime is available
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod platform_linux {
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_proc_filesystem() {
        // Linux-specific: verify /proc filesystem is available
        assert!(Path::new("/proc").exists());
        assert!(Path::new("/proc/self").exists());

        // Check if we can read network statistics
        if let Ok(contents) = fs::read_to_string("/proc/net/dev") {
            assert!(contents.contains("lo:")); // Loopback interface
        }
    }

    #[test]
    fn test_linux_socket_options() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
        let fd = socket.as_raw_fd();
        assert!(fd >= 0);

        // Test Linux-specific socket options
        unsafe {
            let mut value: nix::libc::c_int = 0;
            let mut len = std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t;

            // Get SO_REUSEADDR
            let ret = nix::libc::getsockopt(
                fd,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_REUSEADDR,
                &mut value as *mut _ as *mut nix::libc::c_void,
                &mut len,
            );
            assert_eq!(ret, 0);
        }
    }

    #[test]
    #[cfg(feature = "network-discovery")]
    fn test_linux_network_interfaces() {
        use nix::ifaddrs::getifaddrs;

        // Test Linux network interface discovery
        let addrs = getifaddrs().expect("Failed to get network interfaces");
        let mut found_lo = false;

        for ifaddr in addrs {
            if ifaddr.interface_name == "lo" {
                found_lo = true;
                break;
            }
        }

        assert!(found_lo, "Loopback interface not found");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod platform_macos {
    use std::process::Command;

    #[test]
    fn test_macos_version() {
        // Get macOS version
        let output = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .expect("Failed to get macOS version");

        let version = String::from_utf8_lossy(&output.stdout);
        assert!(!version.is_empty());

        // Parse major version
        let major: u32 = version
            .split('.')
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // macOS 10.15+ or macOS 11+
        assert!(major >= 10);
    }

    #[test]
    fn test_macos_network_interfaces() {
        use std::process::Command;

        // Use ifconfig to list interfaces
        let output = Command::new("ifconfig")
            .arg("-a")
            .output()
            .expect("Failed to run ifconfig");

        let interfaces = String::from_utf8_lossy(&output.stdout);

        // Check for common macOS interfaces
        assert!(interfaces.contains("lo0:")); // Loopback
        assert!(interfaces.contains("en")); // Ethernet/WiFi
    }

    #[test]
    #[cfg(feature = "platform-verifier")]
    fn test_macos_keychain_available() {
        use std::process::Command;

        // Check if security command is available (indicates Keychain access)
        let output = Command::new("security").arg("list-keychains").output();

        assert!(output.is_ok(), "Keychain access not available");
    }
}

#[cfg(all(test, target_os = "windows"))]
mod platform_windows {
    use std::process::Command;

    #[test]
    fn test_windows_version() {
        // Get Windows version using cmd
        let output = Command::new("cmd")
            .args(&["/C", "ver"])
            .output()
            .expect("Failed to get Windows version");

        let version = String::from_utf8_lossy(&output.stdout);
        assert!(version.contains("Windows") || version.contains("Microsoft"));
    }

    #[test]
    fn test_windows_network_interfaces() {
        use std::process::Command;

        // Use ipconfig to list interfaces
        let output = Command::new("ipconfig")
            .arg("/all")
            .output()
            .expect("Failed to run ipconfig");

        let interfaces = String::from_utf8_lossy(&output.stdout);

        // Check for adapter information
        assert!(interfaces.contains("adapter") || interfaces.contains("Adapter"));
    }

    #[test]
    fn test_windows_socket_options() {
        use std::net::UdpSocket;
        use std::os::windows::io::AsRawSocket;
        use windows::Win32::Networking::WinSock::{
            SO_REUSEADDR, SOCKET, SOCKET_ERROR, SOL_SOCKET, getsockopt,
        };
        use windows::core::PSTR;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
        let raw_socket = SOCKET(socket.as_raw_socket() as usize);

        unsafe {
            let mut value: i32 = 0;
            let mut len = std::mem::size_of::<i32>() as i32;

            let ret = getsockopt(
                raw_socket,
                SOL_SOCKET as i32,
                SO_REUSEADDR as i32,
                PSTR::from_raw(&mut value as *mut _ as *mut u8),
                &mut len,
            );

            assert_ne!(ret, SOCKET_ERROR);
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod platform_wasm {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm_platform() {
        // Basic WASM platform test
        assert_eq!(std::mem::size_of::<usize>(), 4); // 32-bit pointers
    }

    #[wasm_bindgen_test]
    fn test_wasm_time() {
        // Test that we can get time in WASM
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let _duration = Duration::from_millis(1);
        let _elapsed = start.elapsed();
    }
}

// Cross-platform network utilities tests
#[cfg(test)]
mod network_utils {
    use ant_quic::config::EndpointConfig;

    #[test]
    fn test_endpoint_config_cross_platform() {
        // Test that endpoint configuration works on all platforms
        let config = EndpointConfig::default();

        // These should work on all platforms
        assert!(config.get_max_udp_payload_size() > 0);

        #[cfg(not(target_os = "windows"))]
        {
            // Unix-specific tests
            assert!(config.get_max_udp_payload_size() >= 1200);
        }

        #[cfg(target_os = "windows")]
        {
            // Windows-specific tests
            assert!(config.get_max_udp_payload_size() >= 1200);
        }
    }
}

// Platform-specific crypto tests
#[cfg(all(test, feature = "rustls-ring"))]
mod crypto_platform_tests {
    #[test]
    fn test_ring_crypto_available() {
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).expect("Failed to generate random bytes");

        // Verify randomness (very basic check)
        assert!(!buf.iter().all(|&b| b == 0));
    }
}

#[cfg(all(test, feature = "rustls-aws-lc-rs"))]
mod crypto_aws_lc_tests {
    #[test]
    fn test_aws_lc_crypto_available() {
        use aws_lc_rs::rand;

        let mut buf = [0u8; 32];
        rand::fill(&mut buf).expect("Failed to generate random bytes");

        // Verify randomness (very basic check)
        assert!(!buf.iter().all(|&b| b == 0));
    }
}
