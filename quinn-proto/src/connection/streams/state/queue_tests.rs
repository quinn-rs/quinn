use super::*;
use crate::{SendStream, WriteError, connection::State as ConnState, connection::Streams};

fn state(credit: u32) -> StreamsState {
    let mut state = StreamsState::new(
        Side::Client,
        0u32.into(),
        0u32.into(),
        1 << 24,
        1024u32.into(),
        1024u32.into(),
    );
    state.set_params(&TransportParameters {
        initial_max_streams_uni: 1024u32.into(),
        initial_max_data: credit.into(),
        initial_max_stream_data_uni: 1_000_000u32.into(),
        ..TransportParameters::default()
    });
    state
}

fn open(state: &mut StreamsState) -> StreamId {
    Streams {
        state,
        conn_state: &ConnState::Established,
    }
    .open(Dir::Uni)
    .unwrap()
}

fn stream<'a>(
    state: &'a mut StreamsState,
    pending: &'a mut Retransmits,
    id: StreamId,
) -> SendStream<'a> {
    SendStream {
        id,
        state,
        pending,
        conn_state: &ConnState::Established,
    }
}

fn reset_ack(state: &mut StreamsState, pending: &mut Retransmits, id: StreamId) {
    stream(state, pending, id).reset(0u32.into()).unwrap();
    // Exercise the stream state transition; encrypted packet delivery is tested
    // separately by the connection-level tests.
    pending.reset_stream.retain(|frame| frame.0 != id);
    state.reset_acked(id);
}

#[test]
fn reset_ack_prunes_blocked_streams_without_write_credit() {
    let mut state = state(0);
    let mut pending = Retransmits::default();
    let live = open(&mut state);
    assert_eq!(
        stream(&mut state, &mut pending, live).write(b"x"),
        Err(WriteError::Blocked)
    );
    for _ in 0..128 {
        let id = open(&mut state);
        assert_eq!(
            stream(&mut state, &mut pending, id).write(b"x"),
            Err(WriteError::Blocked)
        );
        reset_ack(&mut state, &mut pending, id);
        while state.poll().is_some() {}
        assert_eq!(state.write_limit(), 0);
        assert!(!state.send.contains_key(&id));
        assert_eq!(state.connection_blocked, vec![live]);
    }
    state.received_max_data(1u32.into());
    assert_eq!(state.poll(), Some(StreamEvent::Writable { id: live }));
    assert!(state.connection_blocked.is_empty());
    assert_eq!(
        stream(&mut state, &mut pending, live).write(b"x").unwrap(),
        1
    );
}

#[test]
fn empty_writes_and_retransmits_have_one_pending_entry() {
    for chunks in [false, true] {
        let mut state = state(1_000_000);
        let mut pending = Retransmits::default();
        let id = open(&mut state);
        for _ in 0..128 {
            if chunks {
                let mut empty = [bytes::Bytes::new(), bytes::Bytes::new()];
                assert_eq!(
                    stream(&mut state, &mut pending, id)
                        .write_chunks(&mut empty)
                        .unwrap()
                        .bytes,
                    0
                );
            } else {
                assert_eq!(stream(&mut state, &mut pending, id).write(b"").unwrap(), 0);
            }
            state.retransmit(frame::StreamMeta {
                id,
                offsets: 0..0,
                fin: false,
            });
            assert_eq!(state.pending.len(), 1);
        }
        stream(&mut state, &mut pending, id).finish().unwrap();
        let frames = state.write_stream_frames(&mut Vec::new(), 1200, true);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].fin);
        assert!(frames[0].offsets.is_empty());
        for frame in frames {
            state.received_ack_of(frame);
        }
        while state.poll().is_some() {}
        assert!(!state.send.contains_key(&id));
        assert_eq!(state.pending.len(), 0);
    }
}

#[test]
fn reset_ack_prunes_pending_heap_and_nonfair_next() {
    for fair in [false, true] {
        for transmit_before_poll in [false, true] {
            let mut state = state(1_000_000);
            let mut pending = Retransmits::default();
            let id = open(&mut state);
            stream(&mut state, &mut pending, id)
                .write(&[0; 4096])
                .unwrap();
            let frames = state.write_stream_frames(&mut Vec::new(), 100, fair);
            assert!(!frames.is_empty());
            assert_eq!(state.pending.len(), 1);
            assert_eq!(state.pending.next.is_some(), !fair);
            reset_ack(&mut state, &mut pending, id);
            if transmit_before_poll {
                assert!(
                    state
                        .write_stream_frames(&mut Vec::new(), 1200, fair)
                        .is_empty()
                );
            }
            while state.poll().is_some() {}
            assert_eq!(state.pending.len(), 0);
            assert!(state.connection_blocked.is_empty());
        }
    }
}

#[test]
fn finish_ack_overtaking_retransmit_prunes_pending_entry() {
    let mut state = state(1000);
    let mut pending = Retransmits::default();
    let id = open(&mut state);
    stream(&mut state, &mut pending, id).write(b"x").unwrap();
    stream(&mut state, &mut pending, id).finish().unwrap();
    let frame = state
        .write_stream_frames(&mut Vec::new(), 1200, true)
        .pop()
        .unwrap();
    state.retransmit(frame.clone());
    state.received_ack_of(frame.clone());
    state.received_ack_of(frame);
    while state.poll().is_some() {}
    assert!(!state.send.contains_key(&id));
    assert_eq!(state.pending.len(), 0);
}

#[test]
fn pruning_preserves_priority_recency_and_nonfair_next() {
    for fair in [false, true] {
        let mut state = state(1_000_000);
        let mut pending = Retransmits::default();
        let ids: Vec<_> = (0..4).map(|_| open(&mut state)).collect();
        for &id in &ids {
            stream(&mut state, &mut pending, id)
                .write(&[0; 4096])
                .unwrap();
        }
        let first = state.write_stream_frames(&mut Vec::new(), 100, fair);
        assert_eq!(first[0].id, ids[0]);
        reset_ack(&mut state, &mut pending, ids[1]);
        while state.poll().is_some() {}
        let next = state.write_stream_frames(&mut Vec::new(), 100, fair);
        assert_eq!(next[0].id, if fair { ids[2] } else { ids[0] });
        // High priority must still take precedence when there is no nonfair next.
        let priority = open(&mut state);
        stream(&mut state, &mut pending, priority)
            .set_priority(10)
            .unwrap();
        stream(&mut state, &mut pending, priority)
            .write(b"x")
            .unwrap();
        let next = state.write_stream_frames(&mut Vec::new(), 100, fair);
        assert_eq!(next[0].id, if fair { priority } else { ids[0] });
    }
}
