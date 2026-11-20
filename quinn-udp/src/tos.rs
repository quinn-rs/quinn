use crate::EcnCodepoint;

/// Socket-level TOS / traffic class, with ECN bits masked off
#[derive(Debug, Copy, Clone)]
#[must_use]
pub(crate) struct Tos(u8);

impl Tos {
    /// Preserve the socket's DSCP marking, discarding its ECN codepoint
    pub(crate) fn new(bits: u8) -> Self {
        Self(bits & !0b11)
    }

    /// Encode the socket's DSCP marking with the per-packet ECN codepoint
    #[must_use]
    pub(crate) fn encode(self, ecn: Option<EcnCodepoint>) -> libc::c_int {
        libc::c_int::from(self.0) | ecn.map_or(0, |ecn| ecn as libc::c_int)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_preserves_dscp_and_replaces_ecn() {
        for bits in 0..=u8::MAX {
            let tos = Tos::new(bits);
            for (ecn, expected_ecn) in [
                (None, 0),
                (Some(EcnCodepoint::Ect0), 2),
                (Some(EcnCodepoint::Ect1), 1),
                (Some(EcnCodepoint::Ce), 3),
            ] {
                let encoded = tos.encode(ecn);
                assert_eq!(encoded >> 2, libc::c_int::from(bits >> 2));
                assert_eq!(encoded & 0b11, expected_ecn);
            }
        }
    }
}
