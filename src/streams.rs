use bytes::BufMut;

use futures::future::{self, Future};
use futures::sync::oneshot;
use futures::task;

use std::collections::{HashMap, VecDeque};
use std::iter;
use std::sync::{Arc, Mutex};

use super::{QuicError, QuicResult};
use codec::{BufLen, Codec};
use frame::{Frame, StreamFrame, StreamIdBlockedFrame};
use types::Side;

#[derive(Clone)]
pub struct Streams {
    inner: Arc<Mutex<Inner>>,
}

impl Streams {
    pub fn new(side: Side) -> Self {
        let mut open = [
            OpenStreams::new(),
            OpenStreams::new(),
            OpenStreams::new(),
            OpenStreams::new(),
        ];
        open[0].next = Some(0);

        Self {
            inner: Arc::new(Mutex::new(Inner {
                side,
                task: None,
                streams: HashMap::new(),
                open,
                control: VecDeque::new(),
                send_queue: VecDeque::new(),
            })),
        }
    }

    pub fn set_task(&mut self, task: task::Task) {
        let mut me = self.inner.lock().unwrap();
        me.task = Some(task);
    }

    pub fn poll_send<T: BufMut>(&mut self, payload: &mut T) {
        let mut me = self.inner.lock().unwrap();
        while let Some(frame) = me.control.pop_front() {
            frame.encode(payload);
        }

        while let Some((id, start, mut end)) = me.send_queue.pop_front() {
            if payload.remaining_mut() < 16 {
                me.send_queue.push_front((id, start, end));
                break;
            }

            let mut frame = StreamFrame {
                id,
                fin: false,
                offset: start as u64,
                len: Some((end - start) as u64),
                data: Vec::new(),
            };

            let len = end - start;
            if len > payload.remaining_mut() {
                let pivot = start + payload.remaining_mut() - frame.buf_len();
                me.send_queue.push_front((id, pivot, end));
                end = pivot;
                frame.len = Some((end - start) as u64);
            }

            let mut stream = &me.streams[&id];
            let offset = stream.send_offset;
            let (start, mut end) = (start - offset, end - offset);
            let slices = stream.queued.as_slices();

            if start < slices.0.len() && end <= slices.0.len() {
                frame.data.extend(&slices.0[start..end]);
            } else if start < slices.0.len() {
                frame.data.extend(&slices.0[start..]);
                end -= slices.0.len();
                frame.data.extend(&slices.1[..end]);
            } else {
                let (start, end) = (start - slices.0.len(), end - slices.0.len());
                frame.data.extend(&slices.1[start..end]);
            }

            debug_assert_eq!(frame.len, Some((end - start) as u64));
            let frame = Frame::Stream(frame);
            frame.encode(payload);
        }
    }

    pub fn get_stream(&self, id: u64) -> Option<StreamRef> {
        let me = self.inner.lock().unwrap();
        if me.streams.contains_key(&id) {
            Some(StreamRef {
                inner: self.inner.clone(),
                id,
            })
        } else {
            None
        }
    }

    pub fn init_send(&mut self, dir: Dir) -> QuicResult<StreamRef> {
        let mut me = self.inner.lock().unwrap();
        let stype = (me.side.to_bit() + dir.to_bit()) as usize;
        let next = me.open[stype].next;

        if let Some(id) = next {
            me.open[stype].next = if id + 4 < me.open[stype].max {
                Some(id + 4)
            } else {
                None
            };
        }

        next.map(|id| {
            me.streams.insert(id, Stream::new());
            StreamRef {
                inner: self.inner.clone(),
                id,
            }
        }).ok_or_else(|| {
            QuicError::General(format!(
                "{:?} not allowed to send on stream {:?} [init send]",
                me.side, next
            ))
        })
    }

    pub fn update_max_id(&mut self, id: u64) {
        let mut me = self.inner.lock().unwrap();
        me.open[(id % 4) as usize].max = id;
    }

    pub fn received(&mut self, frame: &StreamFrame) -> QuicResult<()> {
        let mut me = self.inner.lock().unwrap();
        let id = frame.id;
        if Dir::from_id(id) == Dir::Uni && Side::from_id(id) == me.side {
            return Err(QuicError::General(format!(
                "{:?} not allowed to receive on stream {:?} [direction]",
                me.side, id
            )));
        }

        if !me.streams.contains_key(&id) {
            let stype = (id % 4) as usize;
            if let Some(id) = me.open[stype].next {
                me.open[stype].next = if id + 4 <= me.open[stype].max {
                    Some(id + 4)
                } else {
                    None
                };
            } else {
                return Err(QuicError::General(format!(
                    "{:?} not allowed to receive on stream {:?} [limited]",
                    me.side, id
                )));
            }
        }

        let stream = me.streams.entry(id).or_insert_with(Stream::new);
        let offset = frame.offset as usize;
        let expected = stream.recv_offset + stream.received.len();
        if offset == expected {
            stream.received.extend(&frame.data);
        } else if offset > expected {
            stream
                .received
                .extend(iter::repeat(0).take(offset - expected));
            stream.received.extend(&frame.data);
        } else {
            return Err(QuicError::General(format!(
                "unhandled receive: {:?} {:?} {:?}",
                frame.offset, frame.len, expected
            )));
        }

        Ok(())
    }

    pub fn request_stream(self, id: u64) -> Box<Future<Item = Streams, Error = QuicError>> {
        let consumer = {
            let mut me = self.inner.lock().unwrap();
            let consumer = {
                let open = me.open.get_mut((id % 4) as usize).unwrap();
                if id > open.max {
                    let (p, c) = oneshot::channel::<u64>();
                    open.updates.push(p);
                    Some(c)
                } else {
                    None
                }
            };
            if consumer.is_some() {
                me.control
                    .push_back(Frame::StreamIdBlocked(StreamIdBlockedFrame(id)));
                if let Some(ref mut task) = me.task {
                    task.notify();
                }
            }
            consumer
        };

        match consumer {
            Some(c) => Box::new(
                c.map(|_| self)
                    .map_err(|_| QuicError::General("StreamIdBlocked future canceled".into())),
            ),
            None => Box::new(future::ok(self)),
        }
    }
}

pub struct StreamRef {
    inner: Arc<Mutex<Inner>>,
    pub id: u64,
}

impl StreamRef {
    pub fn send(&mut self, buf: &[u8]) -> QuicResult<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut me = self.inner.lock().unwrap();
        if Dir::from_id(self.id) == Dir::Uni && Side::from_id(self.id) != me.side {
            return Err(QuicError::General(format!(
                "{:?} not allowed to send on stream {:?} [send]",
                me.side, self.id
            )));
        }

        let (start, end) = {
            let stream = me.streams.get_mut(&self.id).unwrap();
            let start = stream.send_offset + stream.queued.len();
            stream.queued.extend(buf);
            (start, start + buf.len())
        };

        me.send_queue.push_back((self.id, start, end));
        Ok(())
    }

    pub fn received(&self) -> QuicResult<Vec<u8>> {
        let mut me = self.inner.lock().unwrap();
        if Dir::from_id(self.id) == Dir::Uni && Side::from_id(self.id) == me.side {
            return Err(QuicError::General(format!(
                "{:?} not allowed to receive on stream {:?}",
                me.side, self.id
            )));
        }
        let stream = me.streams.get_mut(&self.id).unwrap();
        let vec = stream.received.drain(..).collect::<Vec<u8>>();
        stream.recv_offset += vec.len();
        Ok(vec)
    }
}

struct Inner {
    side: Side,
    task: Option<task::Task>,
    streams: HashMap<u64, Stream>,
    open: [OpenStreams; 4],
    control: VecDeque<Frame>,
    send_queue: VecDeque<(u64, usize, usize)>,
}

#[derive(Default)]
struct Stream {
    send_offset: usize,
    recv_offset: usize,
    queued: VecDeque<u8>,
    received: VecDeque<u8>,
}

impl Stream {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
struct OpenStreams {
    next: Option<u64>,
    max: u64,
    updates: Vec<oneshot::Sender<u64>>,
}

impl OpenStreams {
    fn new() -> Self {
        Self {
            next: None,
            max: 0,
            updates: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Dir {
    Bidi,
    Uni,
}

impl Dir {
    fn from_id(id: u64) -> Self {
        if id & 2 == 2 {
            Dir::Uni
        } else {
            Dir::Bidi
        }
    }

    fn to_bit(&self) -> u64 {
        match self {
            Dir::Bidi => 0,
            Dir::Uni => 2,
        }
    }
}
