//! Address discovery types from
//! <https://datatracker.ietf.org/doc/draft-seemann-quic-address-discovery/>

use crate::VarInt;

/// The role of each participant.
///
/// When enabled, this is reported as a transport parameter.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub(crate) struct Role {
    pub(crate) send_reports: bool,
    pub(crate) receive_reports: bool,
}

impl TryFrom<VarInt> for Role {
    type Error = crate::transport_parameters::Error;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        let mut role = Self::default();
        match value.0 {
            0 => role.send_reports = true,
            1 => role.receive_reports = true,
            2 => {
                role.send_reports = true;
                role.receive_reports = true;
            }
            _ => return Err(crate::transport_parameters::Error::IllegalValue),
        }

        Ok(role)
    }
}

impl Role {
    /// Whether address discovery is disabled.
    pub(crate) fn is_disabled(&self) -> bool {
        !self.receive_reports && !self.send_reports
    }

    /// Whether this peer should report observed addresses to the other peer.
    pub(crate) fn should_report(&self, other: &Self) -> bool {
        self.send_reports && other.receive_reports
    }

    /// Gives the [`VarInt`] representing this [`Role`] as a transport parameter.
    pub(crate) fn as_transport_parameter(&self) -> Option<VarInt> {
        match (self.send_reports, self.receive_reports) {
            (true, true) => Some(VarInt(2)),
            (true, false) => Some(VarInt(0)),
            (false, true) => Some(VarInt(1)),
            (false, false) => None,
        }
    }
}
