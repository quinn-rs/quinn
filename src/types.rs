use rand::{thread_rng, Rng};

pub struct Endpoint {
    pub dst_cid: u64,
    pub src_pn: u32,
    pub hs_cid: u64,
}

impl Endpoint {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        Endpoint {
            dst_cid: rng.gen(),
            hs_cid: 0,
            src_pn: rng.gen(),
        }
    }
}

pub enum TransportParameter {
    InitialMaxStreamData(u32),
    InitialMaxData(u32),
    InitialMaxStreamIdBidi(u32),
    IdleTimeout(u16),
    OmitConnectionId,
    MaxPacketSize(u16),
    StatelessResetToken(Vec<u8>),
    AckDelayExponent(u8),
    InitialMaxStreamIdUni(u32),
}
