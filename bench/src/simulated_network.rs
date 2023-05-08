use std::collections::VecDeque;
use std::io::{Error, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit, UdpState};
use quinn::AsyncUdpSocket;

use queue::InboundQueue;

#[derive(Debug)]
pub struct InMemorySocketHandle {
    pub network: Arc<InMemoryNetwork>,
    pub addr: SocketAddr,
}

impl AsyncUdpSocket for InMemorySocketHandle {
    fn poll_send(
        &self,
        _state: &UdpState,
        _cx: &mut std::task::Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, Error>> {
        let now = Instant::now();
        for transmit in transmits {
            let transmit = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents.clone(),
                src_ip: Some(self.addr.ip()),
                segment_size: transmit.segment_size,
            };

            self.network.send(now, self.addr, transmit);
        }

        if transmits.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(transmits.len()))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let socket = self.network.socket(self.addr);
        let mut inbound = socket.inbound.lock().unwrap();

        let max_transmits = meta.len();
        let mut received = 0;

        let out = meta.iter_mut().zip(bufs);
        for (in_transit, (meta, buf)) in inbound.receive(max_transmits).zip(out) {
            received += 1;
            let transmit = in_transit.transmit;

            // Meta
            meta.addr = in_transit.source_addr;
            meta.ecn = transmit.ecn;
            meta.dst_ip = Some(transmit.destination.ip());
            meta.len = transmit.contents.len();
            meta.stride = transmit.segment_size.unwrap_or(meta.len);

            // Buffer
            buf[..transmit.contents.len()].copy_from_slice(&transmit.contents);
        }

        if received == 0 {
            if inbound.is_empty() {
                // Store the waker so we can be notified of new transmits
                let mut waker = socket.waker.lock().unwrap();
                if waker.is_none() {
                    *waker = Some(cx.waker().clone())
                }
            } else {
                // Wake up next time we can read
                let next_read = inbound.time_of_next_receive();
                let waker = cx.waker().clone();
                tokio::task::spawn(async move {
                    tokio::time::sleep_until(next_read.into()).await;
                    waker.wake();
                });
            }

            Poll::Pending
        } else {
            Poll::Ready(Ok(received))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

#[derive(Clone, Debug)]
pub struct InMemorySocket {
    addr: SocketAddr,
    inbound: Arc<Mutex<InboundQueue>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl InMemorySocket {
    pub fn new(addr: SocketAddr, link_delay: Duration, link_capacity: usize) -> InMemorySocket {
        InMemorySocket {
            addr,
            inbound: Arc::new(Mutex::new(InboundQueue::new(link_delay, link_capacity))),
            waker: Arc::new(Mutex::new(None)),
        }
    }
}

// This mod is meant to enforce encapsulation of InboundQueue's private fields
mod queue {
    use super::*;

    #[derive(Debug)]
    pub struct InboundQueue {
        queue: VecDeque<InTransitData>,
        bytes_in_transit: usize,
        link_delay: Duration,
        link_capacity: usize,
    }

    impl InboundQueue {
        pub(super) fn new(link_delay: Duration, link_capacity: usize) -> Self {
            Self {
                queue: VecDeque::new(),
                bytes_in_transit: 0,
                link_delay,
                link_capacity,
            }
        }

        pub(super) fn send(&mut self, data: InTransitData) -> bool {
            if self.bytes_in_transit + data.transmit.contents.len() <= self.link_capacity {
                self.bytes_in_transit += data.transmit.contents.len();
                self.queue.push_back(data);
                true
            } else {
                false
            }
        }

        pub(super) fn is_empty(&self) -> bool {
            self.queue.is_empty()
        }

        pub(super) fn receive(
            &mut self,
            max_transmits: usize,
        ) -> impl Iterator<Item = InTransitData> + '_ {
            let now = Instant::now();
            let transmits_to_read = self
                .queue
                .iter()
                .take(max_transmits)
                .take_while(|t| t.sent + self.link_delay <= now)
                .count();

            for data in self.queue.iter().take(transmits_to_read) {
                self.bytes_in_transit -= data.transmit.contents.len();
            }

            self.queue.drain(..transmits_to_read)
        }

        pub(super) fn time_of_next_receive(&self) -> Instant {
            self.queue[0].sent + self.link_delay
        }
    }
}

#[derive(Debug)]
pub struct InMemoryNetwork {
    pub sockets: Vec<InMemorySocket>,
}

impl InMemoryNetwork {
    /// Initializes a new [`InMemoryNetwork`] with one socket for the server and one for the client
    ///
    /// The link capacity is measured in bytes per `link_delay`
    pub fn initialize(link_delay: Duration, link_capacity: usize) -> Self {
        let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        let client_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8081);

        Self {
            sockets: vec![
                InMemorySocket::new(server_addr, link_delay, link_capacity),
                InMemorySocket::new(client_addr, link_delay, link_capacity),
            ],
        }
    }

    /// Returns a handle to the server's socket
    pub fn server_socket(self: Arc<InMemoryNetwork>) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.sockets[0].addr,
            network: self.clone(),
        }
    }

    /// Returns a handle to the client's socket
    pub fn client_socket(self: Arc<InMemoryNetwork>) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.sockets[1].addr,
            network: self.clone(),
        }
    }

    /// Returns the socket bound to the provided address
    fn socket(&self, addr: SocketAddr) -> InMemorySocket {
        self.sockets
            .iter()
            .find(|s| s.addr == addr)
            .cloned()
            .expect("socket does not exist")
    }

    /// Sends a [`Transmit`] to its destination
    fn send(&self, now: Instant, source_addr: SocketAddr, transmit: Transmit) {
        let socket = self.socket(transmit.destination);
        let sent = socket.inbound.lock().unwrap().send(InTransitData {
            source_addr,
            transmit,
            sent: now,
        });

        if sent {
            // Wake the receiver if it is waiting for incoming transmits
            let mut opt_waker = socket.waker.lock().unwrap();
            if let Some(waker) = opt_waker.take() {
                waker.wake();
            }
        }
    }
}

#[derive(Debug)]
struct InTransitData {
    source_addr: SocketAddr,
    transmit: Transmit,
    sent: Instant,
}
