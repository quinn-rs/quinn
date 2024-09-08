use std::time::Instant;

pub(crate) struct ReceiverTimestampConfig {
    pub exponent: u64,
    pub basis: u64,
    pub instant_basis: Instant,
}

impl ReceiverTimestampConfig {
    fn new(basis: u64, exponent: u64, instant_basis: Instant) -> Self {
        ReceiverTimestampConfig {
            exponent,
            basis,
            instant_basis,
        }
    }
}
