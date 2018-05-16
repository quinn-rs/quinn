use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use types::Side;

pub struct Streams {
    inner: Arc<Mutex<Inner>>,
}

impl Streams {
    pub fn new(side: Side) -> Self {
        let (next_send_bidi, next_recv_bidi) = if let Side::Client = side {
            (Some(0), None)
        } else {
            (None, Some(0))
        };

        Self {
            inner: Arc::new(Mutex::new(Inner {
                side,
                streams: HashMap::new(),
                max_send_uni: 0,
                max_recv_uni: 0,
                max_send_bidi: 0,
                max_recv_bidi: 0,
                next_send_uni: None,
                next_recv_uni: None,
                next_send_bidi,
                next_recv_bidi,
            })),
        }
    }

    pub fn init_send(&mut self, dir: Dir) -> Option<StreamRef> {
        let mut me = self.inner.lock().unwrap();

        let next = if let Dir::Bidi = dir {
            me.next_send_bidi
        } else {
            me.next_send_uni
        };

        if let Some(id) = next {
            if Dir::Bidi == dir && id + 4 < me.max_send_bidi {
                me.next_send_bidi = Some(id + 4);
            } else if Dir::Bidi != dir && id + 4 < me.max_send_uni {
                me.next_send_uni = Some(id + 4);
            }
        }

        next.map(|id| {
            me.streams.insert(id, Stream::new());
            StreamRef {
                inner: self.inner.clone(),
                id,
            }
        })
    }

    pub fn received(&mut self, id: u64) -> Option<StreamRef> {
        let mut me = self.inner.lock().unwrap();
        match me.streams.get(&id) {
            Some(_) => Some(StreamRef {
                inner: self.inner.clone(),
                id,
            }),
            None => {
                let dir = Dir::from_id(id);
                if (Dir::Bidi == dir && id > me.max_recv_bidi)
                    || (Dir::Uni == dir && id > me.max_recv_uni)
                {
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
    max_send_uni: u64,
    max_recv_uni: u64,
    max_send_bidi: u64,
    max_recv_bidi: u64,
    next_send_uni: Option<u64>,
    next_recv_uni: Option<u64>,
    next_send_bidi: Option<u64>,
    next_recv_bidi: Option<u64>,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Dir {
    Bidi,
    Uni,
}

impl Dir {
    pub fn from_id(id: u64) -> Self {
        if id & 2 == 2 {
            Dir::Uni
        } else {
            Dir::Bidi
        }
    }
}
