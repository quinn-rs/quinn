#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

extern crate proto;
use proto::fuzzing::{
    ConnectionState, ResetStream, Retransmits, Streams, StreamsState, TransportParameters,
};
use proto::{Dir, Side, StreamId, VarInt};

#[derive(Arbitrary, Debug)]
struct StreamParams {
    side: Side,
    max_remote_uni: u16,
    max_remote_bi: u16,
    send_window: u16,
    receive_window: u16,
    stream_receive_window: u16,
    dir: Dir,
    transport_params: TransportParameters,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Open,
    Accept(Dir),
    Finish(StreamId),
    ReceivedStopSending(StreamId, VarInt),
    ReceivedReset(ResetStream),
    Reset(StreamId),
}

fuzz_target!(|input: (StreamParams, Vec<Operation>)| {
    let (params, operations) = input;
    let (mut pending, conn_state) = (Retransmits::default(), ConnectionState::Established);
    let mut state = StreamsState::new(
        params.side,
        params.max_remote_uni.into(),
        params.max_remote_bi.into(),
        params.send_window.into(),
        params.receive_window.into(),
        params.stream_receive_window.into(),
    );
    let mut stream = Streams::new(&mut state, &mut pending, &conn_state);

    for operation in operations {
        match operation {
            Operation::Open => {
                stream.open(params.dir);
            }
            Operation::Accept(dir) => {
                stream.accept(dir);
            }
            Operation::Finish(id) => {
                let _ = stream.finish(id);
            }
            Operation::ReceivedStopSending(sid, err_code) => {
                stream.state().received_stop_sending(sid, err_code);
            }
            Operation::ReceivedReset(rs) => {
                let _ = stream.state().received_reset(rs);
            }
            Operation::Reset(id) => {
                let _ = stream.reset(id, 0u32.into());
            }
        }
    }
});
