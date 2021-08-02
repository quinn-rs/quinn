use hdrhistogram::Histogram;
use quinn::StreamId;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

pub struct Stats {
    /// Test start time
    start_instant: Instant,
    /// Test start system time
    start: SystemTime,
    /// Durations of uploads
    upload_duration: Histogram<u64>,
    /// Durations of downloads
    download_duration: Histogram<u64>,
    /// Time from finishing the upload until receiving the first byte of the response
    fbl: Histogram<u64>,
    /// Throughput for uploads
    upload_throughput: Histogram<u64>,
    /// Throughput for downloads
    download_throughput: Histogram<u64>,
    /// The total amount of requests executed
    requests: usize,
    /// Stats accumulated over each interval
    intervals: Vec<Interval>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            start_instant: Instant::now(),
            start: SystemTime::now(),
            upload_duration: Histogram::new(3).unwrap(),
            download_duration: Histogram::new(3).unwrap(),
            fbl: Histogram::new(3).unwrap(),
            upload_throughput: Histogram::new(3).unwrap(),
            download_throughput: Histogram::new(3).unwrap(),
            requests: 0,
            intervals: vec![],
        }
    }
}

impl Stats {
    pub fn on_interval(&mut self, start: Instant, stream_stats: &OpenStreamStats) {
        let mut interval = Interval::new(start - self.start_instant, self.start_instant.elapsed());
        let mut guard = stream_stats.0.lock().unwrap();

        guard.retain(|stream_stats| {
            self.record(stream_stats.clone());
            interval.record_stream_stats(stream_stats.clone());
            // Retain if not finished yet
            !stream_stats.finished.load(Ordering::SeqCst)
        });

        self.intervals.push(interval);
    }

    fn record(&mut self, stream_stats: Arc<StreamStats>) {
        if stream_stats.finished.load(Ordering::SeqCst) {
            let duration = stream_stats.duration.load(Ordering::SeqCst) as u64;
            let bps = throughput_bytes_per_second(duration, stream_stats.request_size);

            if stream_stats.sender {
                self.upload_throughput.record(bps as u64).unwrap();
                self.upload_duration.record(duration).unwrap();
            } else {
                self.download_throughput.record(bps as u64).unwrap();
                self.download_duration.record(duration).unwrap();
                self.fbl
                    .record(stream_stats.first_byte_latency.load(Ordering::SeqCst) as u64)
                    .unwrap();
                self.requests += 1;
            }
        }
    }

    pub fn print(&self) {
        let dt = self.start_instant.elapsed();
        let rps = self.requests as f64 / dt.as_secs_f64();

        println!("Overall stats:");
        println!(
            "RPS: {:.2} ({} requests in {:4.2?})",
            rps, self.requests, dt,
        );
        println!();

        println!("Stream metrics:\n");

        println!("      │ Upload Duration │ Download Duration | FBL        | Upload Throughput | Download Throughput");
        println!("──────┼─────────────────┼───────────────────┼────────────┼───────────────────┼────────────────────");

        let print_metric = |label: &'static str, get_metric: fn(&Histogram<u64>) -> u64| {
            println!(
                " {} │ {:>15} │ {:>17} │  {:>9} │ {:11.2} MiB/s │ {:13.2} MiB/s",
                label,
                format!(
                    "{:.2?}",
                    Duration::from_micros(get_metric(&self.upload_duration))
                ),
                format!(
                    "{:.2?}",
                    Duration::from_micros(get_metric(&self.download_duration))
                ),
                format!("{:.2?}", Duration::from_micros(get_metric(&self.fbl))),
                get_metric(&self.upload_throughput) as f64 / 1024.0 / 1024.0,
                get_metric(&self.download_throughput) as f64 / 1024.0 / 1024.0,
            );
        };

        print_metric("AVG ", |hist| hist.mean() as u64);
        print_metric("P0  ", |hist| hist.value_at_quantile(0.00));
        print_metric("P10 ", |hist| hist.value_at_quantile(0.10));
        print_metric("P50 ", |hist| hist.value_at_quantile(0.50));
        print_metric("P90 ", |hist| hist.value_at_quantile(0.90));
        print_metric("P100", |hist| hist.value_at_quantile(1.00));
        println!();
    }
}

/// Statistics for the currently open streams
#[derive(Clone, Default)]
pub struct OpenStreamStats(Arc<Mutex<Vec<Arc<StreamStats>>>>);

impl OpenStreamStats {
    pub fn new_sender(&self, stream: &quinn::SendStream, upload_size: u64) -> Arc<StreamStats> {
        let send_stream_stats = StreamStats {
            id: stream.id(),
            request_size: upload_size,
            bytes: Default::default(),
            sender: true,
            finished: Default::default(),
            duration: Default::default(),
            first_byte_latency: Default::default(),
        };
        let send_stream_stats = Arc::new(send_stream_stats);
        self.push(send_stream_stats.clone());
        send_stream_stats
    }

    pub fn new_receiver(&self, stream: &quinn::RecvStream, download_size: u64) -> Arc<StreamStats> {
        let recv_stream_stats = StreamStats {
            id: stream.id(),
            request_size: download_size,
            bytes: Default::default(),
            sender: false,
            finished: Default::default(),
            duration: Default::default(),
            first_byte_latency: Default::default(),
        };
        let recv_stream_stats = Arc::new(recv_stream_stats);
        self.push(recv_stream_stats.clone());
        recv_stream_stats
    }

    fn push(&self, stream_stats: Arc<StreamStats>) {
        self.0.lock().unwrap().push(stream_stats);
    }
}

pub struct StreamStats {
    id: StreamId,
    request_size: u64,
    bytes: AtomicUsize,
    sender: bool,
    finished: AtomicBool,
    duration: AtomicU64,
    first_byte_latency: AtomicU64,
}

impl StreamStats {
    pub fn on_first_byte(&self, latency: Duration) {
        self.first_byte_latency
            .store(latency.as_micros() as u64, Ordering::SeqCst);
    }

    pub fn on_bytes(&self, bytes: usize) {
        self.bytes.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn finish(&self, duration: Duration) {
        self.duration
            .store(duration.as_micros() as u64, Ordering::SeqCst);
        self.finished.store(true, Ordering::SeqCst);
    }
}

struct Interval {
    streams: Vec<StreamIntervalStats>,
    period: IntervalPeriod,
}

impl Interval {
    fn new(start: Duration, end: Duration) -> Self {
        let period = IntervalPeriod {
            start: start.as_secs_f64(),
            end: end.as_secs_f64(),
            seconds: (end - start).as_secs_f64(),
        };

        Self {
            streams: vec![],
            period,
        }
    }

    fn record_stream_stats(&mut self, stream_stats: Arc<StreamStats>) {
        let bytes = stream_stats.bytes.swap(0, Ordering::SeqCst);
        self.streams.push(StreamIntervalStats {
            id: stream_stats.id,
            bytes,
            sender: stream_stats.sender,
        })
    }
}

struct IntervalPeriod {
    start: f64,
    end: f64,
    seconds: f64,
}

struct StreamIntervalStats {
    id: StreamId,
    bytes: usize,
    sender: bool,
}

fn throughput_bytes_per_second(duration_in_micros: u64, size: u64) -> f64 {
    (size as f64) / (duration_in_micros as f64 / 1000000.0)
}
