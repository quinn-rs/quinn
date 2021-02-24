use crate::packet::{PartialEncode, SpaceId};

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
}
