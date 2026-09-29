//! Stratum v1 pool client (Bitcoin flavour: subscribe / authorize / notify /
//! set_difficulty / submit).

use crate::algo::{meets_target, AlgorithmKind};
use crate::engine::Engine;
use crate::stats::Stats;
use crate::work::{
    compact_to_target, difficulty_to_target, hash_difficulty, hash_to_hex, merkle_root, sha256d, Solution, Work,
    WorkTemplate,
};
use anyhow::{anyhow, bail, Context, Result};
use primitive_types::U256;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct StratumConfig {
    /// e.g. "stratum+tcp://pool.example.com:3333"
    pub url: String,
    /// Usually "<wallet or account>.<worker name>".
    pub user: String,
    #[serde(default = "default_password")]
    pub password: String,
}

fn default_password() -> String {
    "x".into()
}

/// Jobs kept around so late solutions can still be submitted.
const KEPT_JOBS: usize = 16;
/// Reconnect if the pool is silent for this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct Job {
    id: String,
    prevhash: [u8; 32],
    coinb1: Vec<u8>,
    coinb2: Vec<u8>,
    branch: Vec<[u8; 32]>,
    version: u32,
    nbits: u32,
    ntime: u32,
}

struct StratumTemplate {
    algorithm: AlgorithmKind,
    job: Job,
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    target: U256,
}

impl StratumTemplate {
    fn extranonce2(&self, n: u64) -> Option<Vec<u8>> {
        let size = self.extranonce2_size;
        if size < 8 && n >> (8 * size) != 0 {
            return None;
        }
        let mut out = vec![0u8; size.saturating_sub(8)];
        let be = n.to_be_bytes();
        out.extend_from_slice(&be[8 - size.min(8)..]);
        Some(out)
    }
}

impl WorkTemplate for StratumTemplate {
    fn algorithm(&self) -> AlgorithmKind {
        self.algorithm
    }

    fn target(&self) -> U256 {
        self.target
    }

    fn nonce_offset(&self) -> usize {
        76
    }

    fn header(&self, extranonce: u64) -> Option<Vec<u8>> {
        let en2 = self.extranonce2(extranonce)?;
        let coinbase = [&self.job.coinb1[..], &self.extranonce1, &en2, &self.job.coinb2].concat();
        let root = merkle_root(sha256d(&coinbase), &self.job.branch);

        let mut h = Vec::with_capacity(80);
        h.extend_from_slice(&self.job.version.to_le_bytes());
        h.extend_from_slice(&self.job.prevhash);
        h.extend_from_slice(&root);
        h.extend_from_slice(&self.job.ntime.to_le_bytes());
        h.extend_from_slice(&self.job.nbits.to_le_bytes());
        h.extend_from_slice(&[0u8; 4]);
        Some(h)
    }
}

pub async fn run(
    cfg: StratumConfig,
    algorithm: AlgorithmKind,
    engine: Arc<Engine>,
    mut solutions: UnboundedReceiver<Solution>,
    stats: Arc<Stats>,
) -> Result<()> {
    let addr = cfg
        .url
        .strip_prefix("stratum+tcp://")
        .unwrap_or(&cfg.url)
        .trim_end_matches('/')
        .to_string();
    stats.update_backend(|b| {
        b.kind = "stratum".into();
        b.endpoint = cfg.url.clone();
    });

    let mut backoff = Duration::from_secs(1);
    loop {
        let mut session = Session::new(&cfg, algorithm, &engine, &stats);
        let result = session.run(&addr, &mut solutions).await;
        engine.set_work(None);
        let authorized = session.authorized;
        stats.update_backend(|b| {
            b.connected = false;
            b.job_id = None;
            if let Err(e) = &result {
                b.last_error = Some(format!("{e:#}"));
            }
        });
        match result {
            Ok(()) => info!("pool closed the connection"),
            Err(e) => warn!("pool connection error: {e:#}"),
        }
        if authorized {
            backoff = Duration::from_secs(1);
        }
        info!("reconnecting in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

struct Session<'a> {
    cfg: &'a StratumConfig,
    algorithm: AlgorithmKind,
    engine: &'a Engine,
    stats: &'a Stats,
    authorized: bool,
    extranonce1: Option<Vec<u8>>,
    extranonce2_size: usize,
    difficulty: f64,
    current_job: Option<Job>,
    next_work_id: u64,
    /// Recent work, newest last, to match solutions to jobs.
    works: VecDeque<(u64, Arc<StratumTemplate>)>,
    next_request_id: u64,
    /// Pending submits: request id -> share difficulty.
    pending: HashMap<u64, f64>,
}

impl<'a> Session<'a> {
    fn new(cfg: &'a StratumConfig, algorithm: AlgorithmKind, engine: &'a Engine, stats: &'a Stats) -> Self {
        Self {
            cfg,
            algorithm,
            engine,
            stats,
            authorized: false,
            extranonce1: None,
            extranonce2_size: 4,
            difficulty: 1.0,
            current_job: None,
            next_work_id: 1,
            works: VecDeque::new(),
            next_request_id: 10,
            pending: HashMap::new(),
        }
    }

    async fn run(&mut self, addr: &str, solutions: &mut UnboundedReceiver<Solution>) -> Result<()> {
        info!("connecting to pool {addr}");
        let stream = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(addr))
            .await
            .context("connect timed out")?
            .with_context(|| format!("connect to {addr}"))?;
        stream.set_nodelay(true)?;
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();

        let agent = concat!("crypto-miner/", env!("CARGO_PKG_VERSION"));
        send(&mut write, json!({"id": 1, "method": "mining.subscribe", "params": [agent]})).await?;
        send(
            &mut write,
            json!({"id": 2, "method": "mining.authorize", "params": [self.cfg.user, self.cfg.password]}),
        )
        .await?;

        // Drop solutions left over from a previous connection.
        while solutions.try_recv().is_ok() {}

        loop {
            tokio::select! {
                line = tokio::time::timeout(IDLE_TIMEOUT, lines.next_line()) => {
                    let Some(line) = line.context("pool idle timeout")?? else { return Ok(()) };
                    if line.trim().is_empty() {
                        continue;
                    }
                    debug!("<- {line}");
                    let msg: Value = serde_json::from_str(&line).with_context(|| format!("bad JSON from pool: {line}"))?;
                    self.handle_message(msg)?;
                }
                Some(solution) = solutions.recv() => {
                    if let Some(req) = self.submit_request(&solution) {
                        send(&mut write, req).await?;
                    }
                }
            }
        }
    }

    fn handle_message(&mut self, msg: Value) -> Result<()> {
        if let Some(method) = msg.get("method").and_then(Value::as_str) {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            return self.handle_notification(method, &params);
        }
        let id = msg.get("id").and_then(Value::as_u64);
        let error = msg.get("error").filter(|e| !e.is_null());
        let result = msg.get("result").cloned().unwrap_or(Value::Null);
        match id {
            Some(1) => {
                if let Some(e) = error {
                    bail!("subscribe failed: {e}");
                }
                let en1 = result.get(1).and_then(Value::as_str).ok_or_else(|| anyhow!("subscribe: missing extranonce1"))?;
                self.extranonce1 = Some(hex::decode(en1).context("extranonce1")?);
                self.extranonce2_size = result.get(2).and_then(Value::as_u64).unwrap_or(4) as usize;
                info!("subscribed (extranonce1={en1}, extranonce2_size={})", self.extranonce2_size);
            }
            Some(2) => {
                if error.is_some() || result != Value::Bool(true) {
                    bail!("authorization failed for {}: {}", self.cfg.user, error.unwrap_or(&result));
                }
                self.authorized = true;
                self.stats.update_backend(|b| {
                    b.connected = true;
                    b.last_error = None;
                });
                info!("authorized as {}", self.cfg.user);
            }
            Some(id) => {
                if let Some(share_diff) = self.pending.remove(&id) {
                    let accepted = error.is_none() && result == Value::Bool(true);
                    self.stats.record_share(accepted);
                    if accepted {
                        info!("share accepted (diff {share_diff:.4})");
                    } else {
                        warn!("share rejected: {}", error.unwrap_or(&result));
                    }
                }
            }
            None => debug!("ignoring message without id: {msg}"),
        }
        Ok(())
    }

    fn handle_notification(&mut self, method: &str, params: &Value) -> Result<()> {
        match method {
            "mining.set_difficulty" => {
                let diff = params.get(0).and_then(Value::as_f64).ok_or_else(|| anyhow!("set_difficulty: bad params"))?;
                info!("pool difficulty set to {diff}");
                self.difficulty = diff;
                self.stats.update_backend(|b| b.difficulty = Some(diff));
                // Re-issue the current job with the new target.
                if let Some(job) = self.current_job.clone() {
                    self.publish(job);
                }
            }
            "mining.notify" => {
                let job = parse_notify(params)?;
                let clean = params.get(8).and_then(Value::as_bool).unwrap_or(false);
                info!("new job {} (clean={clean})", job.id);
                self.publish(job);
            }
            "mining.set_extranonce" => {
                let en1 = params.get(0).and_then(Value::as_str).ok_or_else(|| anyhow!("set_extranonce: bad params"))?;
                self.extranonce1 = Some(hex::decode(en1)?);
                if let Some(size) = params.get(1).and_then(Value::as_u64) {
                    self.extranonce2_size = size as usize;
                }
            }
            "client.reconnect" => bail!("pool requested reconnect"),
            "client.show_message" => info!("pool message: {params}"),
            other => debug!("ignoring pool method {other}"),
        }
        Ok(())
    }

    fn publish(&mut self, job: Job) {
        let Some(extranonce1) = self.extranonce1.clone() else {
            warn!("job received before subscribe response, ignoring");
            return;
        };
        let template = Arc::new(StratumTemplate {
            algorithm: self.algorithm,
            job: job.clone(),
            extranonce1,
            extranonce2_size: self.extranonce2_size,
            target: difficulty_to_target(self.difficulty),
        });
        let id = self.next_work_id;
        self.next_work_id += 1;
        self.works.push_back((id, template.clone()));
        while self.works.len() > KEPT_JOBS {
            self.works.pop_front();
        }
        self.stats.update_backend(|b| b.job_id = Some(job.id.clone()));
        self.current_job = Some(job);
        self.engine.set_work(Some(Work { id, template }));
    }

    fn submit_request(&mut self, solution: &Solution) -> Option<Value> {
        let (_, template) = self.works.iter().find(|(id, _)| *id == solution.work_id)?;
        let en2 = template.extranonce2(solution.extranonce)?;
        let share_diff = hash_difficulty(&solution.hash);
        if meets_target(&solution.hash, &compact_to_target(template.job.nbits)) {
            info!("share also meets the network target: possible block {}", hash_to_hex(&solution.hash));
            self.stats.blocks_found.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let id = self.next_request_id;
        self.next_request_id += 1;
        self.pending.insert(id, share_diff);
        debug!("submitting share job={} nonce={:08x} diff={share_diff:.2}", template.job.id, solution.nonce);
        Some(json!({
            "id": id,
            "method": "mining.submit",
            "params": [
                self.cfg.user,
                template.job.id,
                hex::encode(en2),
                format!("{:08x}", template.job.ntime),
                format!("{:08x}", solution.nonce),
            ],
        }))
    }
}

async fn send(write: &mut (impl AsyncWriteExt + Unpin), msg: Value) -> Result<()> {
    let mut line = msg.to_string();
    debug!("-> {line}");
    line.push('\n');
    write.write_all(line.as_bytes()).await.context("write to pool")?;
    Ok(())
}

fn parse_notify(p: &Value) -> Result<Job> {
    let s = |i: usize| p.get(i).and_then(Value::as_str).ok_or_else(|| anyhow!("mining.notify: bad param {i}"));
    let u32_hex = |i: usize| -> Result<u32> { Ok(u32::from_str_radix(s(i)?, 16)?) };

    // Stratum sends prevhash as eight 32-bit words, each byte-swapped.
    let raw: [u8; 32] = hex::decode(s(1)?)?.try_into().map_err(|_| anyhow!("prevhash must be 32 bytes"))?;
    let mut prevhash = [0u8; 32];
    for (dst, src) in prevhash.chunks_mut(4).zip(raw.chunks(4)) {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }

    let branch = p
        .get(4)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mining.notify: bad merkle branch"))?
        .iter()
        .map(|v| {
            let bytes = hex::decode(v.as_str().unwrap_or_default())?;
            bytes.try_into().map_err(|_| anyhow!("merkle branch entry must be 32 bytes"))
        })
        .collect::<Result<Vec<[u8; 32]>>>()?;

    Ok(Job {
        id: s(0)?.to_string(),
        prevhash,
        coinb1: hex::decode(s(2)?)?,
        coinb2: hex::decode(s(3)?)?,
        branch,
        version: u32_hex(5)?,
        nbits: u32_hex(6)?,
        ntime: u32_hex(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extranonce2_encoding() {
        let t = StratumTemplate {
            algorithm: AlgorithmKind::Sha256d,
            job: parse_notify(&json!(["j", "00".repeat(32), "", "", [], "20000000", "1d00ffff", "5f000000", true])).unwrap(),
            extranonce1: vec![],
            extranonce2_size: 2,
            target: U256::MAX,
        };
        assert_eq!(t.extranonce2(0x0102), Some(vec![1, 2]));
        assert_eq!(t.extranonce2(0x10000), None);
    }

    #[test]
    fn prevhash_word_swap() {
        let prevhash = "00010203".to_string() + &"00".repeat(28);
        let job = parse_notify(&json!(["j", prevhash, "", "", [], "1", "1", "1", true])).unwrap();
        assert_eq!(&job.prevhash[..4], &[3, 2, 1, 0]);
    }
}
