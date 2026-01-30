// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use tracing::{debug, trace};

use crate::Instant;
use crate::connection::spaces::PacketSpace;
use crate::crypto::{HeaderKey, KeyPair, PacketKey};
use crate::packet::{Packet, PartialDecode, SpaceId};
use crate::token::ResetToken;
use crate::{RESET_TOKEN_SIZE, TransportError};

/// Removes header protection of a packet, or returns `None` if the packet was dropped
pub(super) fn unprotect_header(
    partial_decode: PartialDecode,
    spaces: &[PacketSpace; 3],
    zero_rtt_crypto: Option<&ZeroRttCrypto>,
    stateless_reset_token: Option<ResetToken>,
) -> Option<UnprotectHeaderResult> {
    let header_crypto = if partial_decode.is_0rtt() {
        if let Some(crypto) = zero_rtt_crypto {
            Some(&*crypto.header)
        } else {
            debug!("dropping unexpected 0-RTT packet");
            return None;
        }
    } else if let Some(space) = partial_decode.space() {
        if let Some(ref crypto) = spaces[space].crypto {
            Some(&*crypto.header.remote)
        } else {
            debug!(
                "discarding unexpected {:?} packet ({} bytes)",
                space,
                partial_decode.len(),
            );
            return None;
        }
    } else {
        // Unprotected packet
        None
    };

    let packet = partial_decode.data();
    let stateless_reset = packet.len() >= RESET_TOKEN_SIZE + 5
        && stateless_reset_token.as_deref() == Some(&packet[packet.len() - RESET_TOKEN_SIZE..]);

    match partial_decode.finish(header_crypto) {
        Ok(packet) => Some(UnprotectHeaderResult {
            packet: Some(packet),
            stateless_reset,
        }),
        Err(_) if stateless_reset => Some(UnprotectHeaderResult {
            packet: None,
            stateless_reset: true,
        }),
        Err(e) => {
            trace!("unable to complete packet decoding: {}", e);
            None
        }
    }
}

pub(super) struct UnprotectHeaderResult {
    /// The packet with the now unprotected header (`None` in the case of stateless reset packets
    /// that fail to be decoded)
    pub(super) packet: Option<Packet>,
    /// Whether the packet was a stateless reset packet
    pub(super) stateless_reset: bool,
}

/// Decrypts a packet's body in-place
pub(super) fn decrypt_packet_body(
    packet: &mut Packet,
    spaces: &[PacketSpace; 3],
    zero_rtt_crypto: Option<&ZeroRttCrypto>,
    conn_key_phase: bool,
    prev_crypto: Option<&PrevCrypto>,
    next_crypto: Option<&KeyPair<Box<dyn PacketKey>>>,
) -> Result<Option<DecryptPacketResult>, Option<TransportError>> {
    if !packet.header.is_protected() {
        // Unprotected packets also don't have packet numbers
        return Ok(None);
    }
    let space = packet.header.space();
    let rx_packet = spaces[space].rx_packet;
    let number = packet.header.number().ok_or(None)?.expand(rx_packet + 1);
    let packet_key_phase = packet.header.key_phase();

    let mut crypto_update = false;
    let crypto = if packet.header.is_0rtt() {
        &zero_rtt_crypto.unwrap().packet
    } else if packet_key_phase == conn_key_phase || space != SpaceId::Data {
        &spaces[space].crypto.as_ref().unwrap().packet.remote
    } else if let Some(prev) = prev_crypto.and_then(|crypto| {
        // If this packet comes prior to acknowledgment of the key update by the peer,
        if crypto.end_packet.is_none_or(|(pn, _)| number < pn) {
            // use the previous keys.
            Some(crypto)
        } else {
            // Otherwise, this must be a remotely-initiated key update, so fall through to the
            // final case.
            None
        }
    }) {
        &prev.crypto.remote
    } else {
        // We're in the Data space with a key phase mismatch and either there is no locally
        // initiated key update or the locally initiated key update was acknowledged by a
        // lower-numbered packet. The key phase mismatch must therefore represent a new
        // remotely-initiated key update.
        crypto_update = true;
        &next_crypto.unwrap().remote
    };

    crypto
        .decrypt(number, &packet.header_data, &mut packet.payload)
        .map_err(|_| {
            trace!("decryption failed with packet number {}", number);
            None
        })?;

    if !packet.reserved_bits_valid() {
        return Err(Some(TransportError::PROTOCOL_VIOLATION(
            "reserved bits set",
        )));
    }

    let mut outgoing_key_update_acked = false;
    if let Some(prev) = prev_crypto {
        if prev.end_packet.is_none() && packet_key_phase == conn_key_phase {
            outgoing_key_update_acked = true;
        }
    }

    if crypto_update {
        // Validate incoming key update
        if number <= rx_packet || prev_crypto.is_some_and(|x| x.update_unacked) {
            return Err(Some(TransportError::KEY_UPDATE_ERROR("")));
        }
    }

    Ok(Some(DecryptPacketResult {
        number,
        outgoing_key_update_acked,
        incoming_key_update: crypto_update,
    }))
}

pub(super) struct DecryptPacketResult {
    /// The packet number
    pub(super) number: u64,
    /// Whether a locally initiated key update has been acknowledged by the peer
    pub(super) outgoing_key_update_acked: bool,
    /// Whether the peer has initiated a key update
    pub(super) incoming_key_update: bool,
}

pub(super) struct PrevCrypto {
    /// The keys used for the previous key phase, temporarily retained to decrypt packets sent by
    /// the peer prior to its own key update.
    pub(super) crypto: KeyPair<Box<dyn PacketKey>>,
    /// The incoming packet that ends the interval for which these keys are applicable, and the time
    /// of its receipt.
    ///
    /// Incoming packets should be decrypted using these keys iff this is `None` or their packet
    /// number is lower. `None` indicates that we have not yet received a packet using newer keys,
    /// which implies that the update was locally initiated.
    pub(super) end_packet: Option<(u64, Instant)>,
    /// Whether the following key phase is from a remotely initiated update that we haven't acked
    pub(super) update_unacked: bool,
}

pub(super) struct ZeroRttCrypto {
    pub(super) header: Box<dyn HeaderKey>,
    pub(super) packet: Box<dyn PacketKey>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};

    use crate::crypto::{CryptoError, Keys};
    use crate::packet::{FixedLengthConnectionIdParser, Header, PacketNumber, SpaceId};
    use crate::transport_error::Code;
    use crate::{ConnectionId, Instant};

    /// Realistic sample size for AES-GCM header protection (16 bytes)
    const REALISTIC_SAMPLE_SIZE: usize = 16;

    struct TestHeaderKey;

    impl HeaderKey for TestHeaderKey {
        fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

        fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

        fn sample_size(&self) -> usize {
            REALISTIC_SAMPLE_SIZE
        }
    }

    struct TestPacketKey;

    impl PacketKey for TestPacketKey {
        fn encrypt(&self, _packet: u64, _buf: &mut [u8], _header_len: usize) {}

        fn decrypt(
            &self,
            _packet: u64,
            _header: &[u8],
            _payload: &mut BytesMut,
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn tag_len(&self) -> usize {
            0
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            u64::MAX
        }
    }

    fn test_packet_keys() -> KeyPair<Box<dyn PacketKey>> {
        KeyPair {
            local: Box::new(TestPacketKey),
            remote: Box::new(TestPacketKey),
        }
    }

    fn test_keys() -> Keys {
        Keys {
            header: KeyPair {
                local: Box::new(TestHeaderKey),
                remote: Box::new(TestHeaderKey),
            },
            packet: test_packet_keys(),
        }
    }

    fn spaces_with_crypto() -> [PacketSpace; 3] {
        let now = Instant::now();
        let mut spaces = [
            PacketSpace::new(now),
            PacketSpace::new(now),
            PacketSpace::new(now),
        ];
        spaces[SpaceId::Data].crypto = Some(test_keys());
        spaces
    }

    /// Build short packet bytes with sufficient padding for header protection.
    /// Header protection requires at least sample_size (16) bytes after pn_offset + 4.
    fn short_packet_bytes(first_byte: u8, packet_number: u8, payload: &[u8]) -> BytesMut {
        let mut bytes = Vec::with_capacity(2 + payload.len());
        bytes.push(first_byte);
        bytes.push(packet_number);
        bytes.extend_from_slice(payload);
        // Ensure minimum size for header protection sampling
        // pn_offset is 1 (after first byte), need 4 + sample_size bytes after that
        let min_size = 1 + 4 + REALISTIC_SAMPLE_SIZE;
        while bytes.len() < min_size {
            bytes.push(0x00);
        }
        BytesMut::from(bytes.as_slice())
    }

    fn decode_short_packet(bytes: BytesMut) -> PartialDecode {
        let supported_versions = crate::DEFAULT_SUPPORTED_VERSIONS.to_vec();
        PartialDecode::new(
            bytes,
            &FixedLengthConnectionIdParser::new(0),
            &supported_versions,
            false,
        )
        .unwrap()
        .0
    }

    fn short_packet(packet_number: u8, key_phase: bool, first_byte: u8) -> Packet {
        Packet {
            header: Header::Short {
                spin: false,
                key_phase,
                dst_cid: ConnectionId::new(&[]),
                number: PacketNumber::U8(packet_number),
            },
            header_data: Bytes::from(vec![first_byte]),
            payload: BytesMut::from(&[0u8; 8][..]),
        }
    }

    #[test]
    fn unprotect_header_sets_stateless_reset_for_matching_token() {
        let token_bytes = [0xAB; RESET_TOKEN_SIZE];
        let stateless_reset_token = Some(ResetToken::from(token_bytes));

        let mut payload = vec![0u8; 3];
        payload.extend_from_slice(&token_bytes);

        let bytes = short_packet_bytes(0x40, 0x01, &payload);
        let partial = decode_short_packet(bytes);
        let spaces = spaces_with_crypto();

        let result = unprotect_header(partial, &spaces, None, stateless_reset_token)
            .expect("packet should be decoded");

        assert!(result.packet.is_some());
        assert!(result.stateless_reset);
    }

    #[test]
    fn unprotect_header_ignores_non_matching_token() {
        let token_bytes = [0xAB; RESET_TOKEN_SIZE];
        let stateless_reset_token = Some(ResetToken::from([0xCD; RESET_TOKEN_SIZE]));

        let mut payload = vec![0u8; 3];
        payload.extend_from_slice(&token_bytes);

        let bytes = short_packet_bytes(0x40, 0x01, &payload);
        let partial = decode_short_packet(bytes);
        let spaces = spaces_with_crypto();

        let result = unprotect_header(partial, &spaces, None, stateless_reset_token)
            .expect("packet should be decoded");

        assert!(result.packet.is_some());
        assert!(!result.stateless_reset);
    }

    #[test]
    fn decrypt_packet_body_rejects_reserved_bits() {
        let mut spaces = spaces_with_crypto();
        spaces[SpaceId::Data].rx_packet = 0;

        let mut packet = short_packet(1, false, 0x58);

        let result = decrypt_packet_body(&mut packet, &spaces, None, false, None, None);

        let err = result
            .err()
            .expect("should be error")
            .expect("should have transport error");
        assert_eq!(err.code, Code::PROTOCOL_VIOLATION);
    }

    #[test]
    fn decrypt_packet_body_reports_key_update_errors() {
        // Test case 1: packet number <= rx_packet triggers KEY_UPDATE_ERROR
        let mut spaces = spaces_with_crypto();
        spaces[SpaceId::Data].rx_packet = 10;

        let mut packet = short_packet(10, true, 0x44);
        let next_crypto = test_packet_keys();

        let result =
            decrypt_packet_body(&mut packet, &spaces, None, false, None, Some(&next_crypto));

        let err = result
            .err()
            .expect("should be error")
            .expect("should have transport error");
        assert_eq!(err.code, Code::KEY_UPDATE_ERROR);

        // Test case 2: prev_crypto.update_unacked triggers KEY_UPDATE_ERROR
        let mut spaces = spaces_with_crypto();
        spaces[SpaceId::Data].rx_packet = 0;

        let mut packet = short_packet(1, true, 0x44);
        let prev_crypto = PrevCrypto {
            crypto: test_packet_keys(),
            end_packet: Some((0, Instant::now())),
            update_unacked: true,
        };
        let next_crypto = test_packet_keys();

        let result = decrypt_packet_body(
            &mut packet,
            &spaces,
            None,
            false,
            Some(&prev_crypto),
            Some(&next_crypto),
        );

        let err = result
            .err()
            .expect("should be error")
            .expect("should have transport error");
        assert_eq!(err.code, Code::KEY_UPDATE_ERROR);
    }

    #[test]
    fn decrypt_packet_body_returns_result_for_valid_packet() {
        let mut spaces = spaces_with_crypto();
        spaces[SpaceId::Data].rx_packet = 0;

        let mut packet = short_packet(1, false, 0x40);

        let result = decrypt_packet_body(&mut packet, &spaces, None, false, None, None)
            .expect("decryption should succeed")
            .expect("protected packet should return result");

        assert_eq!(result.number, 1);
        assert!(!result.outgoing_key_update_acked);
        assert!(!result.incoming_key_update);
    }

    #[test]
    fn unprotect_header_rejects_too_short_packet() {
        // Test that packets too short for header protection sampling are rejected.
        // With REALISTIC_SAMPLE_SIZE = 16, need at least pn_offset + 4 + 16 = 21 bytes
        // for a packet with 1-byte pn_offset (short header, no DCID).
        let spaces = spaces_with_crypto();

        // Create a packet that's too short (only 10 bytes)
        // This is shorter than pn_offset (1) + 4 + sample_size (16) = 21 bytes
        let too_short =
            BytesMut::from(&[0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]);

        let supported_versions = crate::DEFAULT_SUPPORTED_VERSIONS.to_vec();
        let partial_result = PartialDecode::new(
            too_short,
            &FixedLengthConnectionIdParser::new(0),
            &supported_versions,
            false,
        );

        // PartialDecode::new may succeed (it just parses the header structure)
        // The sample_size check happens in finish() when header protection is applied
        if let Ok((partial, _)) = partial_result {
            // Now try to unprotect - this should fail due to insufficient bytes for sampling
            let result = unprotect_header(partial, &spaces, None, None);
            assert!(
                result.is_none(),
                "Packet too short for header protection should be rejected during unprotect"
            );
        }
        // If PartialDecode::new itself fails, that's also acceptable
    }
}
