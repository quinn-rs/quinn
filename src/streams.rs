use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use types::Side;

pub struct Streams {
    inner: Arc<Mutex<Inner>>,
}

impl Streams {
    pub fn new(side: Side) -> Self {
        let mut open = [OpenStreams::new(); 4];
        if let Side::Client = side {
            open[0].next = Some(0);
        }

        Self {
            inner: Arc::new(Mutex::new(Inner {
                side,
                streams: HashMap::new(),
                open,
            })),
        }
    }

    pub fn init_send(&mut self, dir: Dir) -> Option<StreamRef> {
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
        })
    }

    pub fn update_max_id(&mut self, id: u64) {
        let mut me = self.inner.lock().unwrap();
        me.open[(id % 4) as usize].max = id;
    }

    pub fn received(&mut self, id: u64) -> Option<StreamRef> {
        let mut me = self.inner.lock().unwrap();
        match me.streams.get(&id) {
            Some(_) => Some(StreamRef {
                inner: self.inner.clone(),
                id,
            }),
            None => {
                let stype = (id % 4) as usize;
                if id > me.open[stype].max {
                    None
                } else {
                    me.streams.insert(id, Stream::new());
                    Some(StreamRef {
                        inner: self.inner.clone(),
                        id,
                    })
                }
            }
        }
    }
}

pub struct StreamRef {
    inner: Arc<Mutex<Inner>>,
    id: u64,
}

impl StreamRef {
    pub fn get_offset(&self) -> u64 {
        let me = self.inner.lock().unwrap();
        me.streams[&self.id].offset
    }

    pub fn set_offset(&mut self, new: u64) {
        let mut me = self.inner.lock().unwrap();
        let stream = me.streams.get_mut(&self.id).unwrap();
        stream.offset = new;
    }
}

struct Inner {
    side: Side,
    streams: HashMap<u64, Stream>,
    open: [OpenStreams; 4],
}

struct Stream {
    offset: u64,
    queued: VecDeque<Vec<u8>>,
    received: VecDeque<Vec<u8>>,
}

impl Stream {
    fn new() -> Self {
        Self {
            offset: 0,
            queued: VecDeque::new(),
            received: VecDeque::new(),
        }
    }
}

#[derive(Clone, Copy)]
struct OpenStreams {
    next: Option<u64>,
    max: u64,
}

impl OpenStreams {
    fn new() -> Self {
        Self { next: None, max: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Dir {
    Bidi,
    Uni,
}

impl Dir {
    fn to_bit(&self) -> u64 {
        match self {
            Dir::Bidi => 0,
            Dir::Uni => 2,
        }
    }
}
