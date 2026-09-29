mod algo;
mod api;
mod backend;
mod engine;
mod stats;
mod work;

use algo::AlgorithmKind;
use anyhow::{Context, Result};
use backend::BackendConfig;
use clap::{Parser, Subcommand};
use engine::Engine;
use primitive_types::U256;
use serde::Deserialize;
use stats::{format_hashrate, Stats};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use work::{Work, WorkTemplate};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mine using a config file.
    Run {
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
    },
    /// Measure hashrate without any network connection.
    Bench {
        #[arg(short, long, value_enum, default_value = "sha256d")]
        algorithm: BenchAlgorithm,
        /// Worker threads (0 = all cores).
        #[arg(short, long, default_value_t = 0)]
        threads: usize,
        #[arg(short, long, default_value_t = 10)]
        seconds: u64,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum BenchAlgorithm {
    Sha256d,
}

impl From<BenchAlgorithm> for AlgorithmKind {
    fn from(a: BenchAlgorithm) -> Self {
        match a {
            BenchAlgorithm::Sha256d => AlgorithmKind::Sha256d,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Config {
    algorithm: AlgorithmKind,
    /// Worker threads (0 = all cores).
    #[serde(default)]
    threads: usize,
    /// Status API address; omit to disable.
    api_listen: Option<SocketAddr>,
    backend: BackendConfig,
}

fn thread_count(requested: usize) -> usize {
    if requested > 0 {
        requested
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    match Cli::parse().command {
        Command::Run { config } => run(config).await,
        Command::Bench { algorithm, threads, seconds } => bench(algorithm.into(), thread_count(threads), seconds).await,
    }
}

async fn run(path: PathBuf) -> Result<()> {
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg: Config = toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let threads = thread_count(cfg.threads);
    let algorithm = cfg.algorithm;
    info!("starting {} miner with {threads} threads", algorithm.build().name());

    let stats = Arc::new(Stats::new(threads, algorithm.build().name()));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let engine = Arc::new(Engine::start(threads, stats.clone(), tx));

    spawn_sampler(stats.clone());
    spawn_reporter(stats.clone());
    if let Some(addr) = cfg.api_listen {
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = api::serve(addr, stats).await {
                tracing::error!("status API failed: {e:#}");
            }
        });
    }

    let backend = async {
        match cfg.backend {
            BackendConfig::Stratum(c) => backend::stratum::run(c, algorithm, engine.clone(), rx, stats.clone()).await,
            BackendConfig::Solo(c) => backend::solo::run(c, algorithm, engine.clone(), rx, stats.clone()).await,
        }
    };
    tokio::select! {
        r = backend => r?,
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    if let Ok(engine) = Arc::try_unwrap(engine) {
        tokio::task::spawn_blocking(move || engine.shutdown()).await?;
    }
    let s = stats.snapshot();
    info!("total hashes {}, shares {}/{}, blocks {}", s.total_hashes, s.shares.accepted, s.shares.rejected, s.blocks_found);
    Ok(())
}

fn spawn_sampler(stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            stats.sample();
        }
    });
}

fn spawn_reporter(stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.tick().await;
        loop {
            tick.tick().await;
            let s = stats.snapshot();
            info!(
                "hashrate {} (60s {}) | shares {} accepted, {} rejected",
                format_hashrate(s.hashrate.h10s),
                format_hashrate(s.hashrate.h60s),
                s.shares.accepted,
                s.shares.rejected
            );
        }
    });
}

/// Fixed header with an unreachable target, for benchmarking.
struct BenchTemplate(AlgorithmKind);

impl WorkTemplate for BenchTemplate {
    fn algorithm(&self) -> AlgorithmKind {
        self.0
    }

    fn target(&self) -> U256 {
        U256::zero()
    }

    fn nonce_offset(&self) -> usize {
        76
    }

    fn header(&self, extranonce: u64) -> Option<Vec<u8>> {
        let mut h = vec![0u8; 80];
        h[4..12].copy_from_slice(&extranonce.to_le_bytes());
        Some(h)
    }
}

async fn bench(algorithm: AlgorithmKind, threads: usize, seconds: u64) -> Result<()> {
    info!("benchmarking {} on {threads} threads for {seconds}s", algorithm.build().name());
    let stats = Arc::new(Stats::new(threads, algorithm.build().name()));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let engine = Engine::start(threads, stats.clone(), tx);
    engine.set_work(Some(Work { id: 1, template: Arc::new(BenchTemplate(algorithm)) }));

    let start = std::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let elapsed = start.elapsed().as_secs_f64();
    let snap = stats.snapshot();
    tokio::task::spawn_blocking(move || engine.shutdown()).await?;

    for t in &snap.threads {
        println!("thread {:>2}: {}", t.id, format_hashrate(t.total_hashes as f64 / elapsed));
    }
    println!("total:     {}", format_hashrate(snap.total_hashes as f64 / elapsed));
    Ok(())
}
