# crypto-miner

Pluggable multi-algorithm CPU miner with two work sources:

- **Stratum v1** pool mining (`mining.subscribe/authorize/notify/set_difficulty/submit`)
- **Solo** mining against a Bitcoin Core compatible node (`getblocktemplate` / `submitblock`)

It exposes a local JSON status API for the monitoring platform.

## Usage

```sh
cargo build --release
./target/release/crypto-miner bench               # hashrate test, no network
cp config.example.toml config.toml                 # then edit
./target/release/crypto-miner run -c config.toml
RUST_LOG=debug ./target/release/crypto-miner run   # show raw Stratum traffic
```

Status: `curl http://127.0.0.1:4048/api/v1/status`

## Layout

| Path | Role |
| --- | --- |
| `src/algo/` | `Algorithm` / `NonceHasher` traits and implementations (`sha256d` with midstate) |
| `src/work.rs` | `WorkTemplate` (source of headers), `Work`, `Solution`, targets & merkle helpers |
| `src/engine.rs` | Worker threads; splits work into `(extranonce, 2^24-nonce chunk)` units |
| `src/backend/` | `stratum.rs` pool client, `solo.rs` node RPC client |
| `src/stats.rs`, `src/api.rs` | Hashrate / share accounting and the HTTP status API |

## Adding an algorithm

1. Implement `Algorithm` + `NonceHasher` in `src/algo/<name>.rs`.
2. Add a variant to `AlgorithmKind`.
3. If its jobs aren't Bitcoin-style headers, add a backend/template that produces them
   (e.g. Monero's Stratum dialect sends ready-made blobs with the nonce at offset 39).
