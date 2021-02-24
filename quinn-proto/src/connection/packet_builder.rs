use tracing::trace;

use crate::{
    crypto::{PacketKey, Session},
    generic::Connection,
    packet::{PartialEncode, SpaceId},
};

pub(super) struct PacketBuilder {
    pub datagram_start: usize,
    pub space: SpaceId,
    pub partial_encode: PartialEncode,
    pub ack_eliciting: bool,
    pub exact_number: u64,
    pub short_header: bool,
    pub min_size: usize,
    pub max_size: usize,
    pub tag_len: usize,
    pub span: tracing::Span,
}

impl PacketBuilder {
    pub fn pad_to(&mut self, min_size: u16) {
        let prev = self.min_size;
        self.min_size = self.datagram_start + (min_size as usize) - self.tag_len;
        debug_assert!(self.min_size >= prev, "padding must not shrink datagram");
    }

    /// Encrypt packet, returning the length of the packet and whether padding was added
    pub fn finish<S: Session>(
        self: PacketBuilder,
        conn: &mut Connection<S>,
        buffer: &mut Vec<u8>,
    ) -> (usize, bool) {
        let pad = buffer.len() < self.min_size;
        if pad {
            trace!("PADDING * {}", self.min_size - buffer.len());
            buffer.resize(self.min_size, 0);
        }

        let space = &conn.spaces[self.space];
        let (header_crypto, packet_crypto) = if let Some(ref crypto) = space.crypto {
            (&crypto.header.local, &crypto.packet.local)
        } else if self.space == SpaceId::Data {
            let zero_rtt = conn.zero_rtt_crypto.as_ref().unwrap();
            (&zero_rtt.header, &zero_rtt.packet)
        } else {
            unreachable!("tried to send {:?} packet without keys", self.space);
        };

        debug_assert_eq!(
            packet_crypto.tag_len(),
            self.tag_len,
            "Mismatching crypto tag len"
        );

        buffer.resize(buffer.len() + packet_crypto.tag_len(), 0);
        debug_assert!(buffer.len() <= self.datagram_start + conn.path.mtu as usize);
        let encode_start = self.partial_encode.start;
        let packet_buf = &mut buffer[encode_start..];
        self.partial_encode.finish(
            packet_buf,
            header_crypto,
            Some((self.exact_number, packet_crypto)),
        );
        self.span
            .with_subscriber(|(id, dispatch)| dispatch.exit(id));

        (buffer.len() - encode_start, pad)
    }
}
