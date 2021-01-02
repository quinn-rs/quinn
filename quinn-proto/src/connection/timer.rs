use std::time::Instant;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum Timer {
    /// When to send an ack-eliciting probe packet or declare unacked packets lost
    LossDetection = 0,
    /// When to close the connection after no activity
    Idle = 1,
    /// When the close timer expires, the connection has been gracefully terminated.
    Close = 2,
    /// When keys are discarded because they should not be needed anymore
    KeyDiscard = 3,
    /// When to give up on validating a new path to the peer
    PathValidation = 4,
    /// When to send a `PING` frame to keep the connection alive
    KeepAlive = 5,
    /// When pacing will allow us to send a packet
    Pacing = 6,
    /// When to invalidate old CID and proactively push new one via NEW_CONNECTION_ID frame
    PushNewCid = 7,
}

impl Timer {
    pub(crate) const VALUES: [Self; 8] = [
        Timer::LossDetection,
        Timer::Idle,
        Timer::Close,
        Timer::KeyDiscard,
        Timer::PathValidation,
        Timer::KeepAlive,
        Timer::Pacing,
        Timer::PushNewCid,
    ];
}

/// A table of data associated with each distinct kind of `Timer`
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct TimerTable {
    data: [Option<Instant>; 8],
}

impl TimerTable {
    pub fn set(&mut self, timer: Timer, time: Instant) {
        self.data[timer as usize] = Some(time);
    }

    pub fn get(&self, timer: Timer) -> Option<Instant> {
        self.data[timer as usize]
    }

    pub fn stop(&mut self, timer: Timer) {
        self.data[timer as usize] = None;
    }

    pub fn next_timeout(&self) -> Option<Instant> {
        self.data.iter().filter_map(|&x| x).min()
    }

    pub fn is_expired(&self, timer: Timer, after: Instant) -> bool {
        self.data[timer as usize].map_or(false, |x| x <= after)
    }
}
