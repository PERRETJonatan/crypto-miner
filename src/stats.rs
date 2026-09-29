//! Runtime statistics shared between the engine, the backend and the API.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct Stats {
    started: Instant,
    started_unix: u64,
    algorithm: String,
    /// Total hashes per worker thread.
    pub thread_hashes: Vec<AtomicU64>,
    pub shares_accepted: AtomicU64,
    pub shares_rejected: AtomicU64,
    pub blocks_found: AtomicU64,
    pub backend: Mutex<BackendStatus>,
    samples: Mutex<VecDeque<(Instant, Vec<u64>)>>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BackendStatus {
    /// "stratum" or "solo".
    pub kind: String,
    pub endpoint: String,
    pub connected: bool,
    pub difficulty: Option<f64>,
    pub job_id: Option<String>,
    pub height: Option<u64>,
    pub last_error: Option<String>,
    pub last_share_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub version: &'static str,
    pub algorithm: String,
    pub started_unix: u64,
    pub uptime_secs: u64,
    pub hashrate: Hashrate,
    pub threads: Vec<ThreadStatus>,
    pub total_hashes: u64,
    pub shares: Shares,
    pub blocks_found: u64,
    pub backend: BackendStatus,
}

#[derive(Debug, Serialize)]
pub struct Hashrate {
    pub h10s: f64,
    pub h60s: f64,
    pub h15m: f64,
}

#[derive(Debug, Serialize)]
pub struct ThreadStatus {
    pub id: usize,
    pub hashrate_10s: f64,
    pub total_hashes: u64,
}

#[derive(Debug, Serialize)]
pub struct Shares {
    pub accepted: u64,
    pub rejected: u64,
}

const MAX_WINDOW: Duration = Duration::from_secs(15 * 60);

impl Stats {
    pub fn new(threads: usize, algorithm: &str) -> Self {
        Self {
            started: Instant::now(),
            started_unix: unix_now(),
            algorithm: algorithm.to_string(),
            thread_hashes: (0..threads).map(|_| AtomicU64::new(0)).collect(),
            shares_accepted: AtomicU64::new(0),
            shares_rejected: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            backend: Mutex::new(BackendStatus::default()),
            samples: Mutex::new(VecDeque::new()),
        }
    }

    /// Record a hash-counter sample. Call periodically (about once a second).
    pub fn sample(&self) {
        let now = Instant::now();
        let counts = self.thread_hashes.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        let mut samples = self.samples.lock().unwrap();
        samples.push_back((now, counts));
        while samples.front().is_some_and(|(t, _)| now - *t > MAX_WINDOW + Duration::from_secs(1)) {
            samples.pop_front();
        }
    }

    /// Per-thread hashrate over roughly the last `window`.
    fn rates(&self, window: Duration) -> Vec<f64> {
        let samples = self.samples.lock().unwrap();
        let Some((t_last, last)) = samples.back() else {
            return vec![0.0; self.thread_hashes.len()];
        };
        let first = samples
            .iter()
            .find(|(t, _)| *t_last - *t <= window)
            .unwrap_or(samples.front().unwrap());
        let secs = (*t_last - first.0).as_secs_f64();
        if secs <= 0.0 {
            return vec![0.0; last.len()];
        }
        last.iter().zip(&first.1).map(|(b, a)| (b - a) as f64 / secs).collect()
    }

    pub fn update_backend(&self, f: impl FnOnce(&mut BackendStatus)) {
        f(&mut self.backend.lock().unwrap());
    }

    pub fn record_share(&self, accepted: bool) {
        if accepted {
            self.shares_accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.shares_rejected.fetch_add(1, Ordering::Relaxed);
        }
        self.update_backend(|b| b.last_share_unix = Some(unix_now()));
    }

    pub fn snapshot(&self) -> Snapshot {
        let r10 = self.rates(Duration::from_secs(10));
        let sum = |v: &[f64]| v.iter().sum::<f64>();
        let totals: Vec<u64> = self.thread_hashes.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        Snapshot {
            version: env!("CARGO_PKG_VERSION"),
            algorithm: self.algorithm.clone(),
            started_unix: self.started_unix,
            uptime_secs: self.started.elapsed().as_secs(),
            hashrate: Hashrate {
                h10s: sum(&r10),
                h60s: sum(&self.rates(Duration::from_secs(60))),
                h15m: sum(&self.rates(MAX_WINDOW)),
            },
            threads: r10
                .iter()
                .zip(&totals)
                .enumerate()
                .map(|(id, (rate, total))| ThreadStatus { id, hashrate_10s: *rate, total_hashes: *total })
                .collect(),
            total_hashes: totals.iter().sum(),
            shares: Shares {
                accepted: self.shares_accepted.load(Ordering::Relaxed),
                rejected: self.shares_rejected.load(Ordering::Relaxed),
            },
            blocks_found: self.blocks_found.load(Ordering::Relaxed),
            backend: self.backend.lock().unwrap().clone(),
        }
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Human readable hashrate, e.g. "12.34 MH/s".
pub fn format_hashrate(h: f64) -> String {
    const UNITS: [&str; 6] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
    let mut v = h;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.2} {}", UNITS[i])
}
