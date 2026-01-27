use std::fmt::Debug;

const MAX_FILTER_LEN: usize = 3;

/// Based on Linux kernel code released here:
/// <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f672258391b42a5c7cc2732c9c063e56a85c8dbe>
///
/// Kathleen Nichols' algorithm for tracking the maximum
/// value of a data stream over some fixed time interval.  (E.g.,
/// the maximum Bandwidth achieved over the past 3 rounds.) It uses constant
/// space and constant time per update yet almost always delivers
/// the same maximum as an implementation that has to keep all the
/// data in the window.
///
/// The algorithm keeps track of the best, 2nd best & 3rd highest max
/// values, maintaining an invariant that the measurement time of
/// the n'th best >= n-1'th best. It also makes sure that the three
/// values are widely separated in the time window since that bounds
/// the worst case error when that data is monotonically increasing
/// over the window.
///
/// Upon getting a new max, we can forget everything earlier because
/// it has no value - the new max is >= everything else in the window
/// by definition, and it samples the most recent one. So we restart fresh on
/// every new max and overwrites 2nd & 3rd choices. The same property
/// holds for 2nd & 3rd best.
///
#[derive(Copy, Clone, Debug)]
pub(super) struct MaxFilter {
    window: u64,
    // sample on index 0 has the maximum value followed in descending order
    // by samples on index 1 and then 2
    samples: [MaxSample; MAX_FILTER_LEN],
}

impl MaxFilter {
    pub(super) fn new(window: u64) -> Self {
        Self {
            window,
            samples: [Default::default(); MAX_FILTER_LEN],
        }
    }
    pub(super) fn get_max(&self) -> u64 {
        self.samples[0].value.unwrap_or(0)
    }

    /// `current_round` represents a sequence number counting upwards, it can eventually reset to 0
    /// and continue counting upwards.
    /// `measurement` is what is tracked as the max values over time
    pub(super) fn update_max(&mut self, current_round: u64, measurement: u64) {
        let sample = MaxSample {
            round: current_round,
            value: Some(measurement),
        };

        if self.samples[0].value.is_none()  /* uninitialised */
            || /* found new max? */ sample.value >= self.samples[0].value
            || /* nothing left in window? */ sample.round - self.samples[2].round > self.window
        {
            self.samples.fill(sample); /* forget earlier samples */
            return;
        }

        if sample.value >= self.samples[1].value {
            self.samples[1] = sample;
            self.samples[2] = sample;
        } else if sample.value >= self.samples[2].value {
            self.samples[2] = sample;
        }

        self.subwin_update(sample);
    }

    /// As time advances, update the 1st, 2nd, and 3rd choices.
    fn subwin_update(&mut self, sample: MaxSample) {
        let dt = sample.round - self.samples[0].round;
        if dt > self.window {
            /*
             * Passed entire window without a new sample so make 2nd
             * choice the new sample & 3rd choice the new 2nd choice.
             * we may have to iterate this since our 2nd choice
             * may also be outside the window (we checked on entry
             * that the third choice was in the window).
             */
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = sample;
            if sample.round - self.samples[0].round > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = sample;
            }
        } else if self.samples[1].round == self.samples[0].round && dt > self.window / 4 {
            /*
             * We've passed a quarter of the window without a new sample
             * so take a 2nd choice from the 2nd quarter of the window.
             */
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if self.samples[2].round == self.samples[1].round && dt > self.window / 2 {
            /*
             * We've passed half the window without finding a new sample
             * so take a 3rd choice from the last half of the window
             */
            self.samples[2] = sample;
        }
    }
}

impl Default for MaxFilter {
    fn default() -> Self {
        Self {
            window: 10,
            samples: [Default::default(); MAX_FILTER_LEN],
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct MaxSample {
    /// `round` count, not a timestamp as per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.1>
    /// can also be a count of cycle as per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#section-5.5.6>
    round: u64,
    value: Option<u64>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let round = 25;
        let mut max_filter = MaxFilter::default();
        max_filter.update_max(round + 1, 100);
        assert_eq!(100, max_filter.get_max());
        max_filter.update_max(round + 3, 120);
        assert_eq!(120, max_filter.get_max());
        max_filter.update_max(round + 5, 160);
        assert_eq!(160, max_filter.get_max());
        max_filter.update_max(round + 7, 100);
        assert_eq!(160, max_filter.get_max());
        max_filter.update_max(round + 10, 100);
        assert_eq!(160, max_filter.get_max());
        max_filter.update_max(round + 14, 100);
        assert_eq!(160, max_filter.get_max());
        max_filter.update_max(round + 16, 100);
        assert_eq!(100, max_filter.get_max());
        max_filter.update_max(round + 18, 130);
        assert_eq!(130, max_filter.get_max());
    }
}
