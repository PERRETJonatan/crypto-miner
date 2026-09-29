# Node Monitoring Protocol (NMP) — v1

Status: **Draft** · Applies to: `crypto-miner` ≥ 0.1 and the monitoring platform

This document specifies how mining nodes report to, and are managed by, the
monitoring platform. It covers identity, authentication, transport, the message
set, data schemas and error handling.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

---

## 1. Overview

```
 ┌─────────────┐   (A) push: WebSocket, node dials out   ┌──────────────┐
 │  Node       │ ──────────────────────────────────────▶ │  Platform    │
 │ crypto-miner│                                         │  (ingest +   │
 │             │ ◀────────────────────────────────────── │   dashboard) │
 │  :4048 HTTP │   (B) pull: platform polls HTTP API     └──────────────┘
 └─────────────┘
```

A **node** is one running `crypto-miner` process. The **platform** collects
telemetry from many nodes, stores it, and can send commands back.

There are two transports, which share the same data schemas:

| Mode | Direction | When to use |
| --- | --- | --- |
| **(A) Push** — WebSocket | Node → Platform (outbound connection) | Default. Works behind NAT or a firewall, gives real-time events, and carries commands. |
| **(B) Pull** — HTTP/JSON | Platform → Node | LAN setups and debugging, or when the platform can reach nodes directly. Read-only. |

A node MUST implement Pull. A node SHOULD implement Push when a platform URL is
configured.

### 1.1 Implementation status

| Feature | Status |
| --- | --- |
| `GET /api/v1/health` | ✅ implemented |
| `GET /api/v1/status` (snapshot schema §5.1, without `node` block) | ✅ implemented |
| `node` identity block, `GET /api/v1/events`, Pull auth token | ⏳ planned |
| Push transport (§4) | ⏳ planned |
| Commands (§6) | ⏳ planned |
| Host metrics (§5.2) | ⏳ planned |

---

## 2. Conventions

- **Encoding:** UTF-8 JSON. Field names are `snake_case`.
- **Time:** integer Unix seconds (UTC) in fields suffixed `_unix`. Durations use
  an explicit unit suffix (`_secs`, `_ms`).
- **Hashrate:** floating-point hashes per second (H/s). No pre-scaled units.
- **Difficulty:** floating point in the coin's native difficulty scale (for
  sha256d, difficulty 1 = target `0x00000000FFFF0000…`).
- **Hashes:** hex strings in conventional display order (block explorer order).
- **Unknown fields:** receivers MUST ignore fields they don't recognise. This is
  how minor versions stay compatible.
- **Nullable:** a field that is `null` or absent means "unknown / not applicable".
  It never means zero.

---

## 3. Identity & authentication

### 3.1 Node identity

| Field | Description |
| --- | --- |
| `node_id` | UUIDv4 the node generates on first start and stores in `node_id` next to the config. Stable across restarts and upgrades. |
| `name` | Human label from config (default: hostname). Not unique. |
| `labels` | Free-form `{string: string}` map from config, e.g. `{"site": "home", "rig": "laptop"}`. Used by the platform for grouping and filtering. |

### 3.2 Enrollment (Push)

1. The operator creates the node on the platform. The platform returns a
   **node token**: an opaque random string of ≥ 32 bytes, shown once.
2. The operator puts it in the node config:
   ```toml
   [platform]
   url = "wss://platform.example.com/nmp/v1"
   token = "nmp_xxxxxxxxxxxxxxxxxxxxxxxx"
   ```
3. On connect, the node sends the token as `Authorization: Bearer <token>`
   during the WebSocket upgrade. The platform binds the token to the first
   `node_id` presented. A different `node_id` using the same token is rejected
   with `4003`, so a leaked token can't be silently cloned onto other machines.

The platform stores only a hash of each token. Tokens can be revoked. Revoking
closes any open session with `4001`.

### 3.3 Pull authentication

- By default, the HTTP API binds to `127.0.0.1` and requires no auth.
- If `api_listen` is not a loopback address, the node MUST require
  `Authorization: Bearer <api_token>` (config `api_token`). Otherwise it MUST
  refuse to start the API.
- Pull is read-only in v1. It never accepts commands.

### 3.4 Transport security

- Push MUST use `wss://` (TLS 1.2+). `ws://` is allowed only when the platform
  host is loopback, for development.
- Nodes MUST validate the platform certificate. A config option MAY pin a CA
  bundle.

---

## 4. Push transport (WebSocket)

Endpoint: `wss://<platform>/nmp/v1`. The WebSocket subprotocol is `nmp.v1`.
Each WebSocket text frame carries exactly one message.

### 4.1 Envelope

Every message has this shape:

```json
{
  "type": "status",
  "seq": 1042,
  "ts_unix": 1790673507,
  "ref": null,
  "payload": { }
}
```

| Field | Description |
| --- | --- |
| `type` | Message type (§4.3). |
| `seq` | Sender-local monotonic counter. Starts at 1 per session for the platform. For the node, it continues across reconnects (§4.5). |
| `ts_unix` | When the sender created the message. |
| `ref` | For replies, the `seq` of the message being answered. Otherwise `null`. |
| `payload` | Type-specific body. |

### 4.2 Session lifecycle

```
Node                                   Platform
 │── WS upgrade (Bearer token) ─────────▶│
 │── hello ─────────────────────────────▶│
 │◀──────────────────────────── welcome ──│   (or close 4001/4003/4010)
 │── status (full snapshot) ────────────▶│
 │── event* (replayed backlog) ─────────▶│
 │        … steady state …               │
 │── status every report_interval ──────▶│
 │── event (as they happen) ────────────▶│
 │◀──────────────────────────── command ──│
 │── command_result ────────────────────▶│
 │◀──────────────────────────────── ack ──│   (periodically, highest seq stored)
```

- The node MUST send `hello` within 10 s of the upgrade. If it doesn't, the
  platform closes the connection with `4008`.
- Keepalive uses WebSocket ping/pong frames every 30 s from either side. If no
  frame arrives for 90 s, the connection is dead.
- **Reconnect:** exponential backoff of 1 s, 2 s, 4 s … capped at 60 s, with
  ±20 % jitter. Backoff resets after a session has lasted 60 s. Mining MUST
  continue while disconnected from the platform, because the platform is never
  on the mining critical path.

### 4.3 Message types

| Type | Direction | Purpose |
| --- | --- | --- |
| `hello` | N → P | Identify the node and its capabilities. |
| `welcome` | P → N | Accept the session and send settings. |
| `status` | N → P | Periodic full telemetry snapshot (§5.1). |
| `event` | N → P | Discrete occurrence (§5.3). |
| `ack` | P → N | Highest node `seq` the platform has durably stored. |
| `command` | P → N | Request an action (§6). |
| `command_result` | N → P | Outcome of a command. |
| `error` | both | Non-fatal protocol error (§7). |

#### `hello`

```json
{
  "protocol": "nmp/1",
  "node": {
    "node_id": "5f0c7a0e-2d7f-4a53-9a55-2e0f8d7c1b21",
    "name": "laptop",
    "labels": { "site": "home" },
    "software": "crypto-miner",
    "version": "0.1.0"
  },
  "host": {
    "os": "linux",
    "arch": "x86_64",
    "cpu_model": "Intel(R) Core(TM) i5-3210M CPU @ 2.50GHz",
    "logical_cpus": 4,
    "memory_bytes": 8249270272
  },
  "capabilities": {
    "algorithms": ["sha256d"],
    "backends": ["stratum", "solo"],
    "commands": ["pause", "resume", "set_threads", "reload_config", "restart"],
    "host_metrics": false
  },
  "last_acked_seq": 1030
}
```

`last_acked_seq` is the highest `seq` the node saw acknowledged in any earlier
session. It is `0` on first connect.

#### `welcome`

```json
{
  "session_id": "b8e1…",
  "report_interval_secs": 10,
  "event_filter": ["share_rejected", "block_found", "backend_connected", "backend_disconnected", "error"],
  "resume_from_seq": 1031,
  "server_time_unix": 1790673500
}
```

- `report_interval_secs`: how often to send `status`. Allowed range is 5–300.
- `event_filter`: event kinds to send. An empty list means none. If the field
  is absent, send all kinds. `share_accepted` is high-volume, so platforms
  SHOULD leave it out and rely on counters in `status`.
- `resume_from_seq`: the node replays buffered messages with `seq ≥` this value
  (§4.5).
- The node SHOULD log a warning if its clock differs from `server_time_unix` by
  more than 60 s.

### 4.4 Acknowledgements

The platform sends `{"type": "ack", "payload": {"seq": N}}` once it has stored
every node message up to and including `seq` N. It sends one at least every
`report_interval_secs`. Acks are cumulative.

### 4.5 Offline buffering & replay

- The node keeps un-acked `event` messages in a ring buffer: 10 000 entries,
  in memory by default, optionally on disk. When the buffer overflows, the
  oldest entries are dropped and an `event` of kind `events_dropped` with the
  lost count is queued.
- `status` messages are **not** buffered. Only the latest snapshot matters, and
  a fresh one is sent right after `welcome`.
- After `welcome`, the node replays buffered events with `seq ≥
  resume_from_seq` in order, then sends live traffic.
- The platform MUST de-duplicate by `(node_id, seq)`.

---

## 5. Data schemas

### 5.1 Status snapshot

Returned by `GET /api/v1/status` (Pull) and sent as the `status` payload (Push).
Fields marked † are planned additions. All the others exist today.

```jsonc
{
  "node": {                                        // †
    "node_id": "5f0c7a0e-…", "name": "laptop", "labels": { "site": "home" }
  },
  "version": "0.1.0",
  "algorithm": "sha256d",
  "started_unix": 1790673501,
  "uptime_secs": 6,
  "paused": false,                                 // †
  "hashrate": { "h10s": 2381127.5, "h60s": 2380012.0, "h15m": 2379544.1 },
  "threads": [
    { "id": 0, "hashrate_10s": 600743.2, "total_hashes": 3735552 }
  ],
  "total_hashes": 14811136,
  "shares": {
    "accepted": 3,
    "rejected": 0,
    "stale": 0                                     // †
  },
  "blocks_found": 0,
  "backend": {
    "kind": "stratum",
    "endpoint": "stratum+tcp://pool.example.com:3333",
    "connected": true,
    "difficulty": 0.001,
    "job_id": "job1",
    "height": null,
    "last_error": null,
    "last_share_unix": 1790673507,
    "latency_ms": 42                               // †
  },
  "host": { }                                      // † see §5.2, present if host_metrics
}
```

| Field | Meaning |
| --- | --- |
| `hashrate.h10s/h60s/h15m` | Average over the last 10 s / 60 s / 15 min. It covers less time than that when uptime is shorter. |
| `threads[].total_hashes` | Monotonic counter since process start. The platform computes its own rates from deltas. |
| `shares.accepted/rejected` | Monotonic since start. In solo mode these count submitted blocks. |
| `blocks_found` | Stratum: shares that also met the network target. Solo: blocks the node accepted. |
| `backend.difficulty` | Stratum: pool share difficulty. Solo: network difficulty. |
| `backend.height` | Block height being mined (solo only; `null` for stratum). |
| `backend.endpoint` | MUST NOT include credentials. Stratum `user`/`password` and RPC credentials are never reported. |

**Counter resets:** every counter resets to 0 when the process restarts. The
platform detects a restart when `started_unix` changes and MUST treat the
counters as a new series.

### 5.2 Host metrics (†, optional)

```json
{
  "cpu_usage_pct": 97.5,
  "cpu_temp_c": 78.0,
  "load_avg": [3.9, 3.8, 3.6],
  "memory_used_bytes": 3120000000,
  "power_w": null
}
```

A metric that isn't available is `null`. The node only sends this block when
the `host_metrics` capability is true.

### 5.3 Events

`event` payload:

```json
{ "kind": "share_rejected", "data": { "job_id": "job1", "difficulty": 0.0012, "reason": "[23,\"low diff\",null]" } }
```

| `kind` | `data` fields |
| --- | --- |
| `started` | `config_hash` (sha256 of the config with secrets removed) |
| `stopping` | `reason` |
| `backend_connected` | `kind`, `endpoint` |
| `backend_disconnected` | `kind`, `endpoint`, `error` |
| `job_changed` | `job_id`, `clean`, `height` |
| `difficulty_changed` | `difficulty` |
| `share_accepted` | `job_id`, `difficulty` |
| `share_rejected` | `job_id`, `difficulty`, `reason` |
| `block_found` | `hash`, `height`, `accepted` (bool), `reason` |
| `paused` / `resumed` | `by` (`"command"` or `"local"`) |
| `error` | `component`, `message` |
| `events_dropped` | `count` |

Pull equivalent (†): `GET /api/v1/events?since_seq=N&limit=100` returns
`{"events": [<envelope>…], "next_seq": M}` from the same ring buffer.

---

## 6. Commands (Push only)

`command` payload:

```json
{ "command_id": "c0ffee01-…", "name": "set_threads", "args": { "threads": 2 }, "expires_unix": 1790673600 }
```

The node answers with `command_result`, with `ref` set to the command's `seq`:

```json
{ "command_id": "c0ffee01-…", "ok": true, "error": null, "result": { "threads": 2 } }
```

| Name | Args | Effect |
| --- | --- | --- |
| `pause` | – | Stop hashing but stay connected to the backend. |
| `resume` | – | Resume hashing. |
| `set_threads` | `threads` (int ≥ 0; 0 = all cores) | Change the worker count at runtime. |
| `reload_config` | – | Re-read the local config file. |
| `restart` | – | Graceful process restart. Requires a supervisor (systemd etc.). |
| `get_status` | – | Send a `status` right away. |

Rules:

- The node MUST ignore a command whose `expires_unix` has passed, answering
  `ok:false, error:"expired"`. The node MUST execute each `command_id` at most
  once.
- Unknown commands get `ok:false, error:"unsupported"`.
- **Security boundary:** v1 has no command that changes the payout address,
  pool credentials, or node RPC settings. Those change only by editing the
  config on the machine. If the platform is compromised, an attacker can
  disrupt mining but cannot redirect earnings. Any future remote-config command
  MUST be opt-in per node (`[platform] allow_remote_config = true`) and SHOULD
  require an operator signature.

---

## 7. Errors

### 7.1 WebSocket close codes

| Code | Meaning | Node reaction |
| --- | --- | --- |
| 1000 | Normal close | Reconnect with backoff |
| 4000 | Malformed message | Reconnect with backoff; log |
| 4001 | Invalid or revoked token | **Do not reconnect** until config changes; keep mining |
| 4003 | Token bound to another `node_id` | **Do not reconnect**; keep mining |
| 4008 | Handshake timeout | Reconnect with backoff |
| 4010 | Unsupported protocol version | Do not reconnect; log |
| 4029 | Rate limited | Reconnect after at least 60 s |
| 4500 | Platform internal error | Reconnect with backoff |

### 7.2 `error` message

This is for non-fatal problems, where the session stays open:

```json
{ "code": "invalid_payload", "message": "status.hashrate missing", "ref_seq": 1042 }
```

### 7.3 HTTP (Pull)

| Status | Meaning |
| --- | --- |
| `200` | JSON body |
| `401` | Missing or invalid `api_token` |
| `404` | Unknown path |
| `503` | Node starting up; retry |

---

## 8. Limits & rate guidance

| Item | Limit |
| --- | --- |
| Message size | 64 KiB. Receivers MAY close with `4000` if exceeded. |
| `status` rate | At most 1 per `report_interval_secs`, plus 1 on `get_status` |
| `event` rate | Node SHOULD coalesce above 20/s (e.g. into a count) |
| Pull polling | Platform SHOULD NOT poll one node more than once every 5 s |

---

## 9. Versioning

- The protocol version is in the path (`/nmp/v1`, `/api/v1`) and in
  `hello.protocol`.
- **Minor, compatible changes** (new optional fields, new event kinds, new
  commands advertised in `capabilities`) don't change the version.
- **Breaking changes** bump the major version. The platform SHOULD support
  N and N-1 at the same time.

---

## 10. Node configuration (reference)

```toml
name = "laptop"
[labels]
site = "home"

api_listen = "127.0.0.1:4048"
# api_token = "..."            # required if api_listen is not loopback

[platform]                      # omit this whole section to disable Push
url = "wss://platform.example.com/nmp/v1"
token = "nmp_xxxxxxxxxxxxxxxxxxxxxxxx"
host_metrics = true
event_buffer = 10000
# allow_remote_config = false   # reserved; no effect in v1
```
