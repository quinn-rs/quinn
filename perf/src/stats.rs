use hdrhistogram::Histogram;
use std::time::{Duration, Instant};

pub struct RequestStats {
    start: Instant,
    pub upload_start: Option<Instant>,
    pub download_start: Option<Instant>,
    pub first_byte: Option<Instant>,
    pub download_end: Option<Instant>,
    upload_size: u64,
    download_size: u64,
    pub success: bool,
}

impl RequestStats {
    pub fn new(upload_size: u64, download_size: u64) -> Self {
        Self {
            start: Instant::now(),
            upload_start: None,
            download_start: None,
            first_byte: None,
            upload_size,
            download_size,
            download_end: None,
            success: false,
        }
    }
}

pub struct Stats {
    /// Test start time
    start: Instant,
    /// Durations of complete requests
    duration: Histogram<u64>,
    /// Time from finishing the upload until receiving the first byte of the response
    fbl: Histogram<u64>,
    /// Throughput for uploads
    upload_throughput: Histogram<u64>,
    /// Throughput for downloads
    download_throughput: Histogram<u64>,
    /// The total amount of requests executed
    requests: usize,
    /// The amount of successful requests
    success: usize,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            duration: Histogram::new(3).unwrap(),
            fbl: Histogram::new(3).unwrap(),
            upload_throughput: Histogram::new(3).unwrap(),
            download_throughput: Histogram::new(3).unwrap(),
            requests: 0,
            success: 0,
        }
    }
}

impl Stats {
    pub fn record(&mut self, request: RequestStats) {
        self.requests += 1;
        self.success += if request.success { 1 } else { 0 };

        // Record the remaining metrics only if the request is successful
        // In this case all timings are available
        if !request.success {
            return;
        }

        let duration = request.download_end.unwrap().duration_since(request.start);
        self.duration.record(duration.as_millis() as u64).unwrap();

        let fbl = request
            .first_byte
            .unwrap()
            .duration_since(request.download_start.unwrap());
        self.fbl.record(fbl.as_millis() as u64).unwrap();

        let download_duration = request
            .download_end
            .unwrap()
            .duration_since(request.download_start.unwrap());
        let download_bps = throughput_bps(download_duration, request.download_size);
        self.download_throughput
            .record(download_bps as u64)
            .unwrap();

        let upload_duration = request
            .download_start
            .unwrap()
            .duration_since(request.upload_start.unwrap());
        let upload_bps = throughput_bps(upload_duration, request.upload_size);
        self.upload_throughput.record(upload_bps as u64).unwrap();
    }

    pub fn print(&self) {
        let dt = self.start.elapsed();
        let rps = self.requests as f64 / dt.as_secs_f64();

        println!("Overall stats:");
        println!(
            "RPS: {:.2} ({} requests in {:4.2?})",
            rps, self.requests, dt,
        );
        println!(
            "Success rate: {:4.2}%",
            100.0 * self.success as f64 / self.requests as f64,
        );
        println!();

        println!("Stream metrics:\n");

        println!("      │ Duration  │ FBL       | Upload Throughput | Download Throughput");
        println!("──────┼───────────┼───────────┼───────────────────┼────────────────────");

        let print_metric = |label: &'static str, get_metric: fn(&Histogram<u64>) -> u64| {
            println!(
                " {} │ {:>9} │ {:>9} │ {:11.2} MiB/s │ {:13.2} MiB/s",
                label,
                format!("{:.2?}", Duration::from_millis(get_metric(&self.duration))),
                format!("{:.2?}", Duration::from_millis(get_metric(&self.fbl))),
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

fn throughput_bps(duration: Duration, size: u64) -> f64 {
    (size as f64) / (duration.as_secs_f64())
}
