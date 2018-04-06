pub enum Packet {
    Short(ShortPacket),
    Long(LongPacket),
}

pub struct LongPacket {
    ptype: LongType,
    conn_id: u64,
    version: u32,
    number: u32,
    payload: Vec<Frame>,
}

pub enum LongType {
    Initial = 0x7f,
    Retry = 0x7e,
    Handshake = 0x7d,
    Protected = 0x7c,
}

pub struct ShortPacket {
    ptype: ShortType,
    conn_id: Option<u64>,
    number: u32,
    payload: Vec<Frame>,
}

pub enum ShortType {
    One = 0x0,
    Two = 0x1,
    Four = 0x2,
}

pub struct NegotiationPacket {
    conn_id: u64,
    version: u32,
    supported: Vec<u32>,
}

pub enum Frame {
    Padding = 0x0,
    ResetStream = 0x1,
    ConnectionClose = 0x2,
    ApplicationClose = 0x3,
    MaxData = 0x4,
    MaxStreamData = 0x5,
    MaxStreamId = 0x6,
    Ping = 0x7,
    Blocked = 0x8,
    StreamBlocked = 0x9,
    StreamIdBlocked = 0xa,
    NewConnectionId = 0xb,
    StopSending = 0xc,
    Ack = 0xd,
    PathChallenge = 0xe,
    PathResponse = 0xf,
    Stream = 0x10,
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
