use super::*;
use crate::{
    RecvStream, SendStream, WriteError,
    connection::{State as ConnState, Streams},
};

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
fn multiple_retirements_coalesce_queue_cleanup_until_poll() {
    for (blocked, fair) in [(false, true), (false, false), (true, true)] {
        let mut state = state(if blocked { 0 } else { 1_000_000 });
        let mut pending = Retransmits::default();
        let ids: Vec<_> = (0..64).map(|_| open(&mut state)).collect();
        let live_ids: Vec<_> = ids.iter().skip(1).step_by(2).copied().collect();

        for &id in &ids {
            if blocked {
                assert_eq!(
                    stream(&mut state, &mut pending, id).write(b"x"),
                    Err(WriteError::Blocked)
                );
            } else {
                assert_eq!(
                    stream(&mut state, &mut pending, id).write(&[0; 4096]),
                    Ok(4096)
                );
            }
        }

        if !fair {
            let frames = state.write_stream_frames(&mut Vec::new(), 100, false);
            assert_eq!(frames[0].id, ids[0]);
            assert!(state.pending.next.is_some());
        }

        for &id in ids.iter().step_by(2) {
            reset_ack(&mut state, &mut pending, id);
        }

        assert_eq!(state.send.len(), 32);
        if blocked {
            assert_eq!(state.connection_blocked.len(), 64);
            assert!(state.blocked_queue_dirty);
        } else {
            assert_eq!(state.pending.len(), 64);
            assert!(state.pending_queue_dirty);
        }

        // All retirements above are cleaned by the first poll. A later poll must
        // not repeat the queue scan or change the surviving membership.
        for _ in 0..2 {
            assert_eq!(state.poll(), None);
            assert!(!state.pending_queue_dirty);
            assert!(!state.blocked_queue_dirty);
            if blocked {
                assert_eq!(state.connection_blocked, live_ids);
            } else {
                let mut queued: Vec<_> = state.pending.iter().map(|stream| stream.id).collect();
                queued.sort_unstable();
                assert_eq!(queued, live_ids);
                assert!(state.pending.next.is_none());
            }
        }
    }
}

#[test]
fn retiring_remote_send_half_preserves_live_receive_half() {
    for finish in [false, true] {
        let mut state = state(1);
        state.set_max_concurrent(Dir::Bi, 1u32.into());
        state.set_params(&TransportParameters {
            initial_max_data: 1u32.into(),
            initial_max_stream_data_bidi_local: 1024u32.into(),
            ..TransportParameters::default()
        });
        let mut pending = Retransmits::default();
        let id = StreamId::new(Side::Server, Dir::Bi, 0);
        assert!(state.send.is_empty());
        assert_eq!(
            state.received(
                frame::Stream {
                    id,
                    offset: 0,
                    fin: false,
                    data: bytes::Bytes::from_static(b"request"),
                },
                7,
            ),
            Ok(ShouldTransmit(false))
        );
        assert_eq!(
            Streams {
                state: &mut state,
                conn_state: &ConnState::Established,
            }
            .accept(Dir::Bi),
            Some(id)
        );
        stream(&mut state, &mut pending, id).write(b"x").unwrap();
        assert_eq!(
            stream(&mut state, &mut pending, id).write(b"x"),
            Err(WriteError::Blocked)
        );
        if finish {
            stream(&mut state, &mut pending, id).finish().unwrap();
            let frame = state
                .write_stream_frames(&mut Vec::new(), 1200, true)
                .pop()
                .unwrap();
            state.retransmit(frame.clone());
            state.received_ack_of(frame);
        } else {
            reset_ack(&mut state, &mut pending, id);
        }
        while state.poll().is_some() {}
        assert_eq!(state.write_limit(), 0);
        assert!(state.send.is_empty());
        assert!(state.connection_blocked.is_empty());
        assert_eq!(state.pending.len(), 0);
        assert!(state.recv.contains_key(&id));
        assert_eq!(state.max_remote[Dir::Bi as usize], 1);

        // The receive half is still live. A later MAX_STREAM_DATA must not recreate
        // the retired send half of the remote stream.
        state.received_max_stream_data(id, 2048u32.into()).unwrap();
        assert!(state.send.is_empty());

        // The receive half is still live. The application must consume both
        // buffered data and FIN before Quinn returns stream concurrency credit.
        let fin = frame::Stream {
            id,
            offset: 7,
            fin: true,
            data: bytes::Bytes::new(),
        };
        assert_eq!(state.received(fin.clone(), 0), Ok(ShouldTransmit(false)));
        assert_eq!(state.poll(), Some(StreamEvent::Readable { id }));
        {
            let mut recv = RecvStream {
                id,
                state: &mut state,
                pending: &mut pending,
            };
            let mut chunks = recv.read(true).unwrap();
            let chunk = chunks.next(usize::MAX).unwrap().unwrap();
            assert_eq!(chunk.offset, 0);
            assert_eq!(chunk.bytes, bytes::Bytes::from_static(b"request"));
            assert_eq!(chunks.next(usize::MAX).unwrap(), None);
            // Repeated EOF and finalize/drop must not return the credit twice.
            assert_eq!(chunks.next(usize::MAX).unwrap(), None);
            let _ = chunks.finalize();
        }
        assert!(state.send.is_empty());
        assert!(!state.recv.contains_key(&id));
        assert_eq!(state.max_remote[Dir::Bi as usize], 2);
        assert_eq!(state.allocated_remote_count[Dir::Bi as usize], 1);
        assert_eq!(state.send_streams, 0);

        // Late frames and duplicate acknowledgements must not resurrect either
        // half or issue more concurrency credit.
        assert_eq!(state.received(fin, 0), Ok(ShouldTransmit(false)));
        state.received_max_stream_data(id, 4096).unwrap();
        state.reset_acked(id);
        state.received_ack_of(frame::StreamMeta {
            id,
            offsets: 0..1,
            fin: true,
        });
        assert_eq!(state.poll(), None);
        assert!(state.send.is_empty());
        assert!(!state.recv.contains_key(&id));
        assert_eq!(state.max_remote[Dir::Bi as usize], 2);
        assert_eq!(state.send_streams, 0);
    }
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
fn retransmit_all_for_0rtt_does_not_duplicate_pending_entries() {
    for fair in [false, true] {
        for max_buf_size in [100, 8192] {
            let mut state = state(4096);
            let mut pending = Retransmits::default();
            let id = open(&mut state);
            stream(&mut state, &mut pending, id)
                .write(&[0; 4096])
                .unwrap();
            stream(&mut state, &mut pending, id).finish().unwrap();

            let frames = state.write_stream_frames(&mut Vec::new(), max_buf_size, fair);
            assert!(!frames.is_empty());
            let still_pending = max_buf_size == 100;
            assert_eq!(state.pending.len(), usize::from(still_pending));
            assert_eq!(state.pending.next.is_some(), !fair && still_pending);

            // Retry must requeue transmitted data, or keep an existing queue entry.
            state.retransmit_all_for_0rtt();
            state.retransmit_all_for_0rtt();
            assert_eq!(state.pending.len(), 1);
            assert!(state.send[&id].as_ref().unwrap().pending_queue);
            assert_eq!(state.pending.next.is_some(), !fair && still_pending);

            let frames = state.write_stream_frames(&mut Vec::new(), 8192, fair);
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].id, id);
            assert_eq!(frames[0].offsets, 0..4096);
            assert!(frames[0].fin);
            assert_eq!(state.pending.len(), 0);
            assert!(!state.send[&id].as_ref().unwrap().pending_queue);
            state.received_ack_of(frames[0].clone());
            assert_eq!(state.poll(), Some(StreamEvent::Finished { id }));
            assert!(state.send.is_empty());
        }
    }
}

#[test]
fn zero_rtt_rejection_clears_queues_and_reuses_stream_id() {
    for fair in [false, true] {
        for dir in Dir::iter() {
            let mut state = state(8192);
            state.set_params(&TransportParameters {
                initial_max_streams_uni: 3u32.into(),
                initial_max_streams_bidi: 3u32.into(),
                initial_max_data: 8192u32.into(),
                initial_max_stream_data_uni: 1_000_000u32.into(),
                initial_max_stream_data_bidi_remote: 1_000_000u32.into(),
                ..TransportParameters::default()
            });
            let mut pending = Retransmits::default();
            let ids: Vec<_> = (0..3)
                .map(|_| {
                    Streams {
                        state: &mut state,
                        conn_state: &ConnState::Established,
                    }
                    .open(dir)
                    .unwrap()
                })
                .collect();
            for &id in &ids[..2] {
                stream(&mut state, &mut pending, id)
                    .write(&[0; 4096])
                    .unwrap();
            }
            let frames = state.write_stream_frames(&mut Vec::new(), 100, fair);
            assert!(!frames.is_empty());
            // Both the heap and the nonfair next slot are populated when !fair.
            assert_eq!(state.pending.streams.len(), if fair { 2 } else { 1 });
            assert_eq!(state.pending.next.is_some(), !fair);

            let blocked = ids[2];
            assert_eq!(
                stream(&mut state, &mut pending, blocked).write(b"x"),
                Err(WriteError::Blocked)
            );
            assert_eq!(state.connection_blocked, vec![blocked]);

            state.zero_rtt_rejected();
            assert!(state.send.is_empty());
            assert!(state.recv.is_empty());
            assert!(state.connection_blocked.is_empty());
            assert_eq!(state.pending.len(), 0);
            assert_eq!(state.data_sent, 0);
            assert_eq!(state.buffered_data, 0);
            assert_eq!(state.send_streams, 0);
            assert_eq!(state.next, [0, 0]);
            assert_eq!(state.write_limit(), 8192);
            assert_eq!(state.poll(), None);

            // The connection also discards control frames from the rejected flight.
            pending = Retransmits::default();
            for id in ids {
                let reused = Streams {
                    state: &mut state,
                    conn_state: &ConnState::Established,
                }
                .open(dir)
                .unwrap();
                assert_eq!(reused, id);
                assert!(state.send[&id].is_none());
                assert_eq!(stream(&mut state, &mut pending, reused).write(b"x"), Ok(1));
                assert!(state.send[&id].as_ref().unwrap().pending_queue);
                assert!(!state.send[&id].as_ref().unwrap().connection_blocked);
                stream(&mut state, &mut pending, reused).finish().unwrap();
                assert_eq!(state.pending.len(), 1);
                let frames = state.write_stream_frames(&mut Vec::new(), 1200, fair);
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].id, id);
                assert_eq!(frames[0].offsets, 0..1);
                assert!(frames[0].fin);
                assert!(!state.send[&id].as_ref().unwrap().pending_queue);
                state.received_ack_of(frames[0].clone());
                assert_eq!(state.poll(), Some(StreamEvent::Finished { id }));
                assert_eq!(state.poll(), None);
                assert!(state.send.is_empty());
                assert_eq!(state.pending.len(), 0);
                assert!(state.connection_blocked.is_empty());
            }
        }
    }
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
