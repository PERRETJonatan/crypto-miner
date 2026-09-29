//! Multi-threaded mining engine.
//!
//! Backends publish work with [`Engine::set_work`]. Worker threads split it
//! into chunks of `(extranonce, nonce range)` taken from a shared counter, so
//! no two threads ever hash the same header/nonce pair. Solutions are sent
//! back over a channel.

use crate::algo::{Algorithm, NonceHasher};
use crate::stats::Stats;
use crate::work::{Solution, Work};
use primitive_types::U256;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, warn};

/// Nonces per chunk handed to a thread (2^24).
const CHUNK_BITS: u32 = 24;
/// Chunks per extranonce roll: 2^8 chunks * 2^24 nonces = full 32-bit space.
const CHUNKS_PER_ROLL_BITS: u32 = 32 - CHUNK_BITS;
/// How many nonces are hashed between checks for new work.
const BATCH: u64 = 1 << 16;

struct ActiveWork {
    work: Work,
    algorithm: Box<dyn Algorithm>,
    target: U256,
    next_chunk: AtomicU64,
}

struct Shared {
    current: RwLock<Option<Arc<ActiveWork>>>,
    generation: AtomicU64,
    wake: (Mutex<()>, Condvar),
    shutdown: AtomicBool,
    stats: Arc<Stats>,
    solutions: UnboundedSender<Solution>,
}

pub struct Engine {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Engine {
    pub fn start(threads: usize, stats: Arc<Stats>, solutions: UnboundedSender<Solution>) -> Self {
        let shared = Arc::new(Shared {
            current: RwLock::new(None),
            generation: AtomicU64::new(0),
            wake: (Mutex::new(()), Condvar::new()),
            shutdown: AtomicBool::new(false),
            stats,
            solutions,
        });
        let threads = (0..threads)
            .map(|i| {
                let shared = shared.clone();
                std::thread::Builder::new()
                    .name(format!("miner-{i}"))
                    .spawn(move || worker(i, shared))
                    .expect("spawn worker thread")
            })
            .collect();
        Self { shared, threads }
    }

    /// Replace the current work. `None` pauses all workers.
    pub fn set_work(&self, work: Option<Work>) {
        let active = work.map(|work| {
            let algorithm = work.template.algorithm().build();
            let target = work.template.target();
            Arc::new(ActiveWork { work, algorithm, target, next_chunk: AtomicU64::new(0) })
        });
        *self.shared.current.write().unwrap() = active;
        self.shared.generation.fetch_add(1, Ordering::SeqCst);
        let _guard = self.shared.wake.0.lock().unwrap();
        self.shared.wake.1.notify_all();
    }

    pub fn shutdown(self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        self.set_work(None);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

impl Shared {
    /// Sleep until the generation moves past `seen` (or a timeout elapses).
    fn wait_for_new_work(&self, seen: u64) {
        let guard = self.wake.0.lock().unwrap();
        let _ = self
            .wake
            .1
            .wait_timeout_while(guard, Duration::from_secs(1), |_| {
                self.generation.load(Ordering::SeqCst) == seen && !self.shutdown.load(Ordering::SeqCst)
            })
            .unwrap();
    }
}

fn worker(index: usize, shared: Arc<Shared>) {
    // (generation, extranonce, hasher) for the header currently being hashed.
    let mut cached: Option<(u64, u64, Box<dyn NonceHasher>)> = None;

    while !shared.shutdown.load(Ordering::SeqCst) {
        let generation = shared.generation.load(Ordering::SeqCst);
        let Some(active) = shared.current.read().unwrap().clone() else {
            cached = None;
            shared.wait_for_new_work(generation);
            continue;
        };

        let chunk = active.next_chunk.fetch_add(1, Ordering::Relaxed);
        let extranonce = chunk >> CHUNKS_PER_ROLL_BITS;
        let nonce_start = (chunk & ((1 << CHUNKS_PER_ROLL_BITS) - 1)) << CHUNK_BITS;

        if !matches!(&cached, Some((g, e, _)) if *g == generation && *e == extranonce) {
            let template = &active.work.template;
            let Some(header) = template.header(extranonce) else {
                // Template exhausted: nothing to do until new work arrives.
                shared.wait_for_new_work(generation);
                continue;
            };
            match active.algorithm.hasher(&header, template.nonce_offset()) {
                Ok(h) => cached = Some((generation, extranonce, h)),
                Err(e) => {
                    error!("cannot hash work {}: {e:#}", active.work.id);
                    shared.wait_for_new_work(generation);
                    continue;
                }
            }
        }
        let hasher = &mut cached.as_mut().unwrap().2;

        let end = nonce_start + (1 << CHUNK_BITS);
        let mut nonce = nonce_start;
        while nonce < end {
            let count = BATCH.min(end - nonce);
            hasher.scan(nonce as u32, count as u32, &active.target, &mut |n, hash| {
                let solution = Solution { work_id: active.work.id, extranonce, nonce: n, hash };
                if shared.solutions.send(solution).is_err() {
                    warn!("solution channel closed");
                }
            });
            shared.stats.thread_hashes[index].fetch_add(count, Ordering::Relaxed);
            nonce += count;
            if shared.generation.load(Ordering::Relaxed) != generation {
                break;
            }
        }
    }
}
