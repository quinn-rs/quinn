//! Benchmarks for the `SentPackets` storage.
//!
//! Run with `cargo bench -p quinn-proto --features __bench`.

use std::{hint::black_box, ops::Bound};

use criterion::{Criterion, criterion_group, criterion_main};
use quinn_proto::bench::{SentPackets, bench_packet};

/// Steady state of a healthy 200 Mbps connection at ~100 ms RTT:
/// - the congestion window holds ~BDP ≈ 2.5 MB ≈ 2048 packets of 1200 B
/// - packets are sent back-to-back
/// - the peer acks every round except the newest packet and one "lost" packet in the middle
fn typical_connection(c: &mut Criterion) {
    const WINDOW: u64 = 2048; // packets per round (~cwnd / MTU)
    const ROUNDS: u64 = 128;

    c.bench_function("sent_packets/typical_connection", |b| {
        b.iter(|| {
            let mut packets = SentPackets::default();
            for round in 0..ROUNDS {
                let base = round * WINDOW;

                // Send a window of packets; one is an ACK-only (size 0) reply.
                for offset in 0..WINDOW {
                    let (size, ack_eliciting) = if offset == 3 {
                        (0, false)
                    } else {
                        (1200, true)
                    };
                    packets.insert(base + offset, bench_packet(size, ack_eliciting));
                }

                // The peer acks everything but the newest packet and one "lost" packet.
                let largest_acked = base + WINDOW - 2;
                let lost = base + WINDOW / 2;

                // on_ack_received looks up the largest acked packet.
                black_box(packets.get(largest_acked));

                // Loss detection walks everything below the largest acked pn
                for (pn, _) in packets.range(0..largest_acked) {
                    black_box(pn);
                }

                // Time-based loss reaps entries older than this round (the "lost" packet from before).
                let stale: Vec<u64> = packets.range(0..base).map(|(pn, _)| pn).collect();
                for pn in stale {
                    let _ = packets.remove(pn);
                }

                // Ack processing collects then removes the newly acked packets.
                let acked: Vec<u64> = packets
                    .range(base..=largest_acked)
                    .filter(|(pn, _)| *pn != lost)
                    .map(|(pn, _)| pn)
                    .collect();
                for pn in acked {
                    let _ = packets.remove(pn);
                }

                // maybe_queue_probe scans from the oldest in-flight packet.
                for (_, probe) in packets.range(..).take(2) {
                    black_box(probe);
                }

                let _ = packets.has_in_flight();
            }

            let last = packets.get(ROUNDS * WINDOW - 1);
            black_box(last);

            // discard_space / 0-RTT rejection drains the entire space.
            for packet in packets.into_values() {
                black_box(packet);
            }
        })
    });
}

/// The peer stops acking while we keep sending.
///
/// We maintain a tail of non-ack-eliciting packets that makes the packet-number span grow
/// while the number of live entries stays constant.
fn unacked_non_eliciting_tail(c: &mut Criterion) {
    const PINNED: u64 = 50;
    const MAX_UNACKED_NON_ACK_ELICTING_TAIL: u64 = 1_000;
    const TAIL: u64 = 20_000;

    c.bench_function("sent_packets/unacked_non_eliciting_tail", |b| {
        b.iter(|| {
            let mut packets = SentPackets::default();
            for pn in 0..PINNED {
                packets.insert(pn, bench_packet(1200, true));
            }
            let largest_ack_eliciting_sent = PINNED - 1;
            let mut tail = 0;

            for i in 0..TAIL {
                // Evict the oldest retained non-ack-eliciting packet before sending the new one.
                if tail > MAX_UNACKED_NON_ACK_ELICTING_TAIL {
                    let oldest = packets
                        .range((
                            Bound::Excluded(largest_ack_eliciting_sent),
                            Bound::Unbounded,
                        ))
                        .next()
                        .expect("tail packets are retained")
                        .0;
                    let forgotten = packets.remove(oldest);
                    black_box(forgotten);
                } else {
                    tail += 1;
                }
                packets.insert(PINNED + i, bench_packet(0, false));

                if i % 256 == 255 {
                    // The loss-timer/PTO path keeps probing the pinned flight.
                    let _ = packets.has_in_flight();
                    if let Some((_, probe)) = packets.range(..).next() {
                        black_box(probe);
                    }
                    for (pn, _) in packets.range(0..PINNED) {
                        black_box(pn);
                    }
                }
            }

            let oldest = packets
                .range((
                    Bound::Excluded(largest_ack_eliciting_sent),
                    Bound::Unbounded,
                ))
                .next();
            black_box(oldest);
        })
    });
}

/// The peer stops acking, and periodic PTO probes keep being sent.
///
/// Probes are ack-eliciting, they consolidate the previous hole and reset the non-ack-eliciting tail window.
fn pto_probe_holes(c: &mut Criterion) {
    const PINNED: u64 = 50;
    const MAX_UNACKED_NON_ACK_ELICTING_TAIL: u64 = 1_000;
    const CYCLES: u64 = 8; // PTO probe cycles
    const TAIL_PER_CYCLE: u64 = 2_000;

    c.bench_function("sent_packets/pto_probe_holes", |b| {
        b.iter(|| {
            let mut packets = SentPackets::default();
            for pn in 0..PINNED {
                packets.insert(pn, bench_packet(1200, true));
            }
            let mut largest_ack_eliciting_sent = PINNED - 1;
            let mut pn = PINNED;

            for _cycle in 0..CYCLES {
                let mut tail = 0;
                for _ in 0..TAIL_PER_CYCLE {
                    if tail > MAX_UNACKED_NON_ACK_ELICTING_TAIL {
                        let oldest = packets
                            .range((
                                Bound::Excluded(largest_ack_eliciting_sent),
                                Bound::Unbounded,
                            ))
                            .next()
                            .expect("tail packets are retained")
                            .0;
                        let forgotten = packets.remove(oldest);
                        black_box(forgotten);
                    } else {
                        tail += 1;
                    }
                    packets.insert(pn, bench_packet(0, false));
                    pn += 1;
                }

                // The PTO probe is ack-eliciting, in-flight and never acked, so it stays.
                // The tail window restarts after it.
                packets.insert(pn, bench_packet(1200, true));
                largest_ack_eliciting_sent = pn;
                pn += 1;

                let _ = packets.has_in_flight();
                if let Some((_, probe)) = packets.range(..).next() {
                    black_box(probe);
                }
                for (pn, _) in packets.range(0..PINNED) {
                    black_box(pn);
                }
            }

            let _ = packets.has_in_flight();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = typical_connection, unacked_non_eliciting_tail, pto_probe_holes,
}
criterion_main!(benches);
