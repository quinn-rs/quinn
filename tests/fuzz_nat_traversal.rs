//! Fuzz testing for NAT traversal frame parsing
//!
//! This module provides fuzz targets to test NAT traversal frame parsing
//! with malformed and edge-case inputs to ensure robustness.

use ant_quic::coding::{BufExt, BufMutExt};
use ant_quic::VarInt;
use bytes::{Buf, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

// Frame type constants from the RFC
const FRAME_TYPE_ADD_ADDRESS_IPV4: u64 = 0x3d7e90;
const FRAME_TYPE_ADD_ADDRESS_IPV6: u64 = 0x3d7e91;
const FRAME_TYPE_PUNCH_ME_NOW_IPV4: u64 = 0x3d7e92;
const FRAME_TYPE_PUNCH_ME_NOW_IPV6: u64 = 0x3d7e93;
const FRAME_TYPE_REMOVE_ADDRESS: u64 = 0x3d7e94;

/// Fuzz target for ADD_ADDRESS frame parsing
pub fn fuzz_add_address_frame(data: &[u8]) {
    if data.len() < 4 {
        return; // Need at least frame type
    }

    let mut buf = BytesMut::from(data);

    // Extract frame type
    let frame_type = match buf.get_u32() as u64 {
        FRAME_TYPE_ADD_ADDRESS_IPV4 => {
            fuzz_add_address_ipv4(&mut buf);
        }
        FRAME_TYPE_ADD_ADDRESS_IPV6 => {
            fuzz_add_address_ipv6(&mut buf);
        }
        _ => {
            // Invalid frame type, should be handled gracefully
            return;
        }
    }
}

/// Fuzz ADD_ADDRESS IPv4 frame parsing
fn fuzz_add_address_ipv4(buf: &mut BytesMut) {
    // Try to parse sequence number
    let seq_result = buf.get_var();
    if seq_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _sequence = seq_result.unwrap();

    // Try to parse IPv4 address and port
    if buf.remaining() < 6 {
        return; // Not enough data
    }

    let _addr_bytes = buf.get_slice(4);
    let _port = buf.get_u16();

    // Any remaining data should be handled gracefully
}

/// Fuzz ADD_ADDRESS IPv6 frame parsing
fn fuzz_add_address_ipv6(buf: &mut BytesMut) {
    // Try to parse sequence number
    let seq_result = buf.get_var();
    if seq_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _sequence = seq_result.unwrap();

    // Try to parse IPv6 address and port
    if buf.remaining() < 18 {
        return; // Not enough data
    }

    let _addr_bytes = buf.get_slice(16);
    let _port = buf.get_u16();

    // Any remaining data should be handled gracefully
}

/// Fuzz target for PUNCH_ME_NOW frame parsing
pub fn fuzz_punch_me_now_frame(data: &[u8]) {
    if data.len() < 4 {
        return; // Need at least frame type
    }

    let mut buf = BytesMut::from(data);

    // Extract frame type
    let frame_type = match buf.get_u32() as u64 {
        FRAME_TYPE_PUNCH_ME_NOW_IPV4 => {
            fuzz_punch_me_now_ipv4(&mut buf);
        }
        FRAME_TYPE_PUNCH_ME_NOW_IPV6 => {
            fuzz_punch_me_now_ipv6(&mut buf);
        }
        _ => {
            // Invalid frame type, should be handled gracefully
            return;
        }
    }
}

/// Fuzz PUNCH_ME_NOW IPv4 frame parsing
fn fuzz_punch_me_now_ipv4(buf: &mut BytesMut) {
    // Try to parse round number
    let round_result = buf.get_var();
    if round_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _round = round_result.unwrap();

    // Try to parse paired sequence number
    let seq_result = buf.get_var();
    if seq_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _paired_sequence = seq_result.unwrap();

    // Try to parse IPv4 address and port
    if buf.remaining() < 6 {
        return; // Not enough data
    }

    let _addr_bytes = buf.get_slice(4);
    let _port = buf.get_u16();

    // Any remaining data should be handled gracefully
}

/// Fuzz PUNCH_ME_NOW IPv6 frame parsing
fn fuzz_punch_me_now_ipv6(buf: &mut BytesMut) {
    // Try to parse round number
    let round_result = buf.get_var();
    if round_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _round = round_result.unwrap();

    // Try to parse paired sequence number
    let seq_result = buf.get_var();
    if seq_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _paired_sequence = seq_result.unwrap();

    // Try to parse IPv6 address and port
    if buf.remaining() < 18 {
        return; // Not enough data
    }

    let _addr_bytes = buf.get_slice(16);
    let _port = buf.get_u16();

    // Any remaining data should be handled gracefully
}

/// Fuzz target for REMOVE_ADDRESS frame parsing
pub fn fuzz_remove_address_frame(data: &[u8]) {
    if data.len() < 4 {
        return; // Need at least frame type
    }

    let mut buf = BytesMut::from(data);

    // Extract frame type
    let frame_type = buf.get_u32() as u64;
    if frame_type != FRAME_TYPE_REMOVE_ADDRESS {
        return; // Invalid frame type
    }

    // Try to parse sequence number
    let seq_result = buf.get_var();
    if seq_result.is_err() {
        return; // Invalid VarInt, should be handled gracefully
    }

    let _sequence = seq_result.unwrap();

    // Any remaining data should be handled gracefully
}

/// Fuzz target for general frame parsing with arbitrary data
pub fn fuzz_frame_parsing(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut buf = BytesMut::from(data);

    // Try to extract what might be a frame type
    if buf.remaining() < 4 {
        return;
    }

    let potential_frame_type = buf.get_u32() as u64;

    // Test different frame types
    match potential_frame_type {
        FRAME_TYPE_ADD_ADDRESS_IPV4 => fuzz_add_address_ipv4(&mut buf),
        FRAME_TYPE_ADD_ADDRESS_IPV6 => fuzz_add_address_ipv6(&mut buf),
        FRAME_TYPE_PUNCH_ME_NOW_IPV4 => fuzz_punch_me_now_ipv4(&mut buf),
        FRAME_TYPE_PUNCH_ME_NOW_IPV6 => fuzz_punch_me_now_ipv6(&mut buf),
        FRAME_TYPE_REMOVE_ADDRESS => fuzz_remove_address_frame(data), // Restart with full data
        _ => {
            // Unknown frame type - test robustness
            // Try to parse as if it were any of the known frame types
            let mut test_buf = BytesMut::from(data);
            test_buf.advance(4); // Skip frame type

            // Try parsing as each frame type to ensure no panics
            let _ = fuzz_add_address_ipv4(&mut test_buf.clone());
            let _ = fuzz_add_address_ipv6(&mut test_buf.clone());
            let _ = fuzz_punch_me_now_ipv4(&mut test_buf.clone());
            let _ = fuzz_punch_me_now_ipv6(&mut test_buf.clone());
            let _ = fuzz_remove_address_frame(data);
        }
    }
}

/// Fuzz target for VarInt parsing (critical for frame parsing)
pub fn fuzz_varint_parsing(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut buf = BytesMut::from(data);

    // Try to parse VarInt - should not panic on any input
    let _ = buf.get_var();

    // Try to create VarInt from arbitrary u64 values
    if data.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[0..8]);
        let arbitrary_u64 = u64::from_le_bytes(bytes);

        let _ = VarInt::from_u64(arbitrary_u64);
    }
}

/// Fuzz target for address parsing
pub fn fuzz_address_parsing(data: &[u8]) {
    if data.len() < 6 {
        return;
    }

    // Try to parse IPv4 address and port
    if data.len() >= 6 {
        let mut ipv4_bytes = [0u8; 4];
        ipv4_bytes.copy_from_slice(&data[0..4]);
        let port = u16::from_le_bytes([data[4], data[5]]);

        let _ipv4_addr = Ipv4Addr::from(ipv4_bytes);
        let _socket_addr_v4 = SocketAddr::from((_ipv4_addr, port));
    }

    // Try to parse IPv6 address and port
    if data.len() >= 18 {
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes.copy_from_slice(&data[0..16]);
        let port = u16::from_le_bytes([data[16], data[17]]);

        let _ipv6_addr = Ipv6Addr::from(ipv6_bytes);
        let _socket_addr_v6 = SocketAddr::from((_ipv6_addr, port));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_targets_with_valid_data() {
        // Test with valid ADD_ADDRESS IPv4 frame
        let mut valid_data = BytesMut::new();
        valid_data.put_u32(FRAME_TYPE_ADD_ADDRESS_IPV4 as u32);
        valid_data.put_u8(0x2a); // sequence = 42
        valid_data.extend_from_slice(&[192, 168, 1, 100]); // IPv4
        valid_data.put_u16(8080); // port

        fuzz_add_address_frame(&valid_data);

        // Test with valid PUNCH_ME_NOW IPv4 frame
        let mut valid_punch_data = BytesMut::new();
        valid_punch_data.put_u32(FRAME_TYPE_PUNCH_ME_NOW_IPV4 as u32);
        valid_punch_data.put_u8(0x05); // round = 5
        valid_punch_data.put_u8(0x2a); // sequence = 42
        valid_punch_data.extend_from_slice(&[10, 0, 0, 1]); // IPv4
        valid_punch_data.put_u16(1234); // port

        fuzz_punch_me_now_frame(&valid_punch_data);

        // Test with valid REMOVE_ADDRESS frame
        let mut valid_remove_data = BytesMut::new();
        valid_remove_data.put_u32(FRAME_TYPE_REMOVE_ADDRESS as u32);
        valid_remove_data.put_u8(0x2a); // sequence = 42

        fuzz_remove_address_frame(&valid_remove_data);
    }

    #[test]
    fn test_fuzz_targets_with_invalid_data() {
        // Test with completely invalid data
        let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
        fuzz_frame_parsing(&invalid_data);

        // Test with truncated data
        let truncated_data = vec![0x80, 0x3d, 0x7e, 0x90]; // Just frame type
        fuzz_frame_parsing(&truncated_data);

        // Test with oversized VarInt
        let oversized_varint = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        fuzz_varint_parsing(&oversized_varint);
    }

    #[test]
    fn test_fuzz_targets_with_malformed_data() {
        // Test with malformed addresses
        let malformed_ipv4 = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        fuzz_address_parsing(&malformed_ipv4);

        // Test with oversized data
        let oversized_data = vec![0; 1000];
        fuzz_frame_parsing(&oversized_data);

        // Test with empty data
        let empty_data = vec![];
        fuzz_frame_parsing(&empty_data);
    }
}