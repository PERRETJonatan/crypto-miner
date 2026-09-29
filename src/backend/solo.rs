//! Solo mining against a Bitcoin Core compatible node (getblocktemplate /
//! submitblock over JSON-RPC).

use crate::algo::AlgorithmKind;
use crate::engine::Engine;
use crate::stats::Stats;
use crate::work::{hash_to_hex, merkle_branch, merkle_root, Solution, Work, WorkTemplate};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use bitcoin::{absolute, transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use primitive_types::U256;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct SoloConfig {
    /// e.g. "http://127.0.0.1:8332"
    pub rpc_url: String,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    /// Path to the node's `.cookie` file (used when user/password are unset).
    pub rpc_cookie: Option<PathBuf>,
    /// Address that receives the block reward.
    pub payout_address: String,
    /// Tag written into the coinbase scriptSig.
    #[serde(default = "default_tag")]
    pub coinbase_tag: String,
    /// Refresh the template (to include new transactions) this often.
    #[serde(default = "default_refresh")]
    pub template_refresh_secs: u64,
}

fn default_tag() -> String {
    "/crypto-miner/".into()
}

fn default_refresh() -> u64 {
    30
}

struct Rpc {
    http: reqwest::Client,
    url: String,
    user: String,
    password: String,
}

impl Rpc {
    fn new(cfg: &SoloConfig) -> Result<Self> {
        let (user, password) = match (&cfg.rpc_user, &cfg.rpc_password, &cfg.rpc_cookie) {
            (Some(u), Some(p), _) => (u.clone(), p.clone()),
            (_, _, Some(path)) => {
                let cookie = std::fs::read_to_string(path).with_context(|| format!("read cookie {}", path.display()))?;
                let (u, p) = cookie.trim().split_once(':').ok_or_else(|| anyhow!("malformed cookie file"))?;
                (u.to_string(), p.to_string())
            }
            _ => bail!("solo mode needs rpc_user + rpc_password or rpc_cookie"),
        };
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        Ok(Self { http, url: cfg.rpc_url.clone(), user, password })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "1.0", "id": "crypto-miner", "method": method, "params": params});
        let resp: Value = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("RPC {method}"))?
            .json()
            .await
            .with_context(|| format!("RPC {method}: bad response"))?;
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            bail!("RPC {method} failed: {err}");
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}

struct SoloTemplate {
    algorithm: AlgorithmKind,
    height: u64,
    version: i32,
    prev_hash: [u8; 32],
    time: u32,
    bits: u32,
    target: U256,
    coinbase_value: u64,
    payout_script: ScriptBuf,
    witness_commitment: Option<ScriptBuf>,
    tag: Vec<u8>,
    branch: Vec<[u8; 32]>,
    raw_txs: Vec<Vec<u8>>,
}

impl SoloTemplate {
    fn coinbase(&self, extranonce: u64) -> Transaction {
        let mut extra = PushBytesBuf::new();
        extra.extend_from_slice(&extranonce.to_le_bytes()).unwrap();
        let mut tag = PushBytesBuf::new();
        // scriptSig must stay under 100 bytes.
        tag.extend_from_slice(&self.tag[..self.tag.len().min(64)]).unwrap();
        let script_sig = Builder::new()
            .push_int(self.height as i64) // BIP34
            .push_slice(extra)
            .push_slice(tag)
            .into_script();

        let mut output = vec![TxOut { value: Amount::from_sat(self.coinbase_value), script_pubkey: self.payout_script.clone() }];
        let mut witness = Witness::new();
        if let Some(commitment) = &self.witness_commitment {
            output.push(TxOut { value: Amount::ZERO, script_pubkey: commitment.clone() });
            // Witness reserved value.
            witness.push([0u8; 32]);
        }
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint::null(), script_sig, sequence: Sequence::MAX, witness }],
            output,
        }
    }

    fn block_hex(&self, extranonce: u64, nonce: u32) -> String {
        let mut header = self.header(extranonce).expect("solo templates always roll");
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let mut block = header;
        write_compact_size(&mut block, 1 + self.raw_txs.len() as u64);
        block.extend(bitcoin::consensus::serialize(&self.coinbase(extranonce)));
        for tx in &self.raw_txs {
            block.extend_from_slice(tx);
        }
        hex::encode(block)
    }
}

impl WorkTemplate for SoloTemplate {
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
        let txid = self.coinbase(extranonce).compute_txid();
        let root = merkle_root(bitcoin::hashes::Hash::to_byte_array(txid), &self.branch);
        let mut h = Vec::with_capacity(80);
        h.extend_from_slice(&self.version.to_le_bytes());
        h.extend_from_slice(&self.prev_hash);
        h.extend_from_slice(&root);
        h.extend_from_slice(&self.time.to_le_bytes());
        h.extend_from_slice(&self.bits.to_le_bytes());
        h.extend_from_slice(&[0u8; 4]);
        Some(h)
    }
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Parse a hash given in display (big-endian) hex into internal byte order.
fn display_hash(v: &Value, field: &str) -> Result<[u8; 32]> {
    let s = v.get(field).and_then(Value::as_str).ok_or_else(|| anyhow!("template missing {field}"))?;
    let mut bytes: [u8; 32] = hex::decode(s)?.try_into().map_err(|_| anyhow!("{field} must be 32 bytes"))?;
    bytes.reverse();
    Ok(bytes)
}

fn parse_template(t: &Value, cfg: &SoloConfig, payout_script: &ScriptBuf, algorithm: AlgorithmKind) -> Result<SoloTemplate> {
    let num = |f: &str| t.get(f).and_then(Value::as_i64).ok_or_else(|| anyhow!("template missing {f}"));
    let txs = t.get("transactions").and_then(Value::as_array).ok_or_else(|| anyhow!("template missing transactions"))?;
    let txids = txs.iter().map(|tx| display_hash(tx, "txid")).collect::<Result<Vec<_>>>()?;
    let raw_txs = txs
        .iter()
        .map(|tx| Ok(hex::decode(tx.get("data").and_then(Value::as_str).ok_or_else(|| anyhow!("tx missing data"))?)?))
        .collect::<Result<Vec<_>>>()?;
    let target_hex = t.get("target").and_then(Value::as_str).ok_or_else(|| anyhow!("template missing target"))?;
    let bits_hex = t.get("bits").and_then(Value::as_str).ok_or_else(|| anyhow!("template missing bits"))?;
    let witness_commitment = t
        .get("default_witness_commitment")
        .and_then(Value::as_str)
        .map(|s| hex::decode(s).map(ScriptBuf::from_bytes))
        .transpose()?;

    Ok(SoloTemplate {
        algorithm,
        height: num("height")? as u64,
        version: num("version")? as i32,
        prev_hash: display_hash(t, "previousblockhash")?,
        time: num("curtime")? as u32,
        bits: u32::from_str_radix(bits_hex, 16)?,
        target: U256::from_big_endian(&hex::decode(target_hex)?),
        coinbase_value: num("coinbasevalue")? as u64,
        payout_script: payout_script.clone(),
        witness_commitment,
        tag: cfg.coinbase_tag.as_bytes().to_vec(),
        branch: merkle_branch(&txids),
        raw_txs,
    })
}

pub async fn run(
    cfg: SoloConfig,
    algorithm: AlgorithmKind,
    engine: Arc<Engine>,
    mut solutions: UnboundedReceiver<Solution>,
    stats: Arc<Stats>,
) -> Result<()> {
    let rpc = Rpc::new(&cfg)?;
    stats.update_backend(|b| {
        b.kind = "solo".into();
        b.endpoint = cfg.rpc_url.clone();
    });

    // Resolve the payout address against the node's network.
    let payout_script = loop {
        match rpc.call("getblockchaininfo", json!([])).await {
            Ok(info) => {
                let chain = info.get("chain").and_then(Value::as_str).unwrap_or("main");
                let network = Network::from_core_arg(chain).map_err(|e| anyhow!("unknown chain {chain}: {e}"))?;
                let address = Address::from_str(&cfg.payout_address)
                    .context("invalid payout_address")?
                    .require_network(network)
                    .with_context(|| format!("payout_address is not a {chain} address"))?;
                info!("node on {chain}, paying rewards to {address}");
                break address.script_pubkey();
            }
            Err(e) => {
                warn!("node unreachable: {e:#}");
                stats.update_backend(|b| b.last_error = Some(format!("{e:#}")));
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    let mut current: Option<(u64, Arc<SoloTemplate>)> = None;
    let mut next_work_id = 1u64;
    let mut last_refresh = Instant::now() - Duration::from_secs(3600);
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let stale = match (&current, rpc.call("getbestblockhash", json!([])).await) {
                    (_, Err(e)) => {
                        warn!("node error: {e:#}");
                        stats.update_backend(|b| { b.connected = false; b.last_error = Some(format!("{e:#}")); });
                        engine.set_work(None);
                        current = None;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    (None, Ok(_)) => true,
                    (Some((_, t)), Ok(best)) => {
                        let best = display_hash(&json!({"h": best}), "h")?;
                        best != t.prev_hash || last_refresh.elapsed().as_secs() >= cfg.template_refresh_secs
                    }
                };
                if !stale {
                    continue;
                }
                match rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await
                    .and_then(|t| parse_template(&t, &cfg, &payout_script, algorithm))
                {
                    Ok(template) => {
                        let template = Arc::new(template);
                        let new_block = current.as_ref().is_none_or(|(_, t)| t.prev_hash != template.prev_hash);
                        if new_block {
                            info!("new block template: height {} with {} txs", template.height, template.raw_txs.len());
                        } else {
                            debug!("refreshed template: {} txs", template.raw_txs.len());
                        }
                        stats.update_backend(|b| {
                            b.connected = true;
                            b.last_error = None;
                            b.height = Some(template.height);
                            b.job_id = Some(template.height.to_string());
                            b.difficulty = Some(crate::work::target_to_difficulty(&template.target));
                        });
                        let id = next_work_id;
                        next_work_id += 1;
                        engine.set_work(Some(Work { id, template: template.clone() }));
                        current = Some((id, template));
                        last_refresh = Instant::now();
                    }
                    Err(e) => {
                        warn!("getblocktemplate failed: {e:#}");
                        stats.update_backend(|b| b.last_error = Some(format!("{e:#}")));
                    }
                }
            }
            Some(solution) = solutions.recv() => {
                let Some((id, template)) = &current else { continue };
                if solution.work_id != *id {
                    debug!("dropping solution for outdated template");
                    continue;
                }
                let hash = hash_to_hex(&solution.hash);
                info!("BLOCK FOUND at height {}: {hash}", template.height);
                let block = template.block_hex(solution.extranonce, solution.nonce);
                match rpc.call("submitblock", json!([block])).await {
                    Ok(Value::Null) => {
                        info!("block {hash} accepted by node");
                        stats.blocks_found.fetch_add(1, Ordering::Relaxed);
                        stats.record_share(true);
                    }
                    Ok(reason) => {
                        warn!("block {hash} rejected: {reason}");
                        stats.record_share(false);
                    }
                    Err(e) => warn!("submitblock failed: {e:#}"),
                }
                // Force a new template right away.
                engine.set_work(None);
                current = None;
                tick.reset_immediately();
            }
        }
    }
}
