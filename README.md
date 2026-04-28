# `open_ring` — pure-Python read-only driver for the Oura Ring 4 BLE protocol

A clean-room reimplementation of the Oura Ring's BLE→biometric data pipeline,
based on static RE of `libringeventparser.so` (arm64-v8a build) and empirical
verification against on-device DB rows.

**No vendored binaries. No proprietary blobs. Stdlib + `bleak` + `cryptography`.**

## *Not Affiliated with Oura Health Oy*
## What's implemented

### Wire-level

- ✅ Outer-frame parsing (24/24 opcodes — battery, time-sync, handshake, subscribe, history-fetch, parameter RPC…)
- ✅ Inner-record TLV walker
- ✅ AES-128-ECB-PKCS5 handshake (`cryptography` lib OR `openssl` subprocess fallback)
- ✅ `auth_key` extraction from `assa-store.realm`
- ✅ Per-type wire-format decoders for **31 record types** (79% strong decode, 0% errors):
  - High-confidence: `0x60 IBI` (incl. 11-bit IBI + amp bit-pack with shift),
    `0x42 TimeSync`, `0x46 Temp`, `0x5d HRV`, `0x53 Wear / 0x45 StateChange`,
    `0x6f SpO2`, `0x4a PpgAmplitude`, `0x76 BedtimePeriod`, …
  - Auto-extracted: `0x73 EHR trace`, `0x74 EHR ACM intensity`, `0x80 GreenIbiQuality`,
    `0x82 ScanStart`, `0x83 ScanEnd`, `0x77 SpO2-DC`, `0x6c FeatureSession`,
    `0x6e SpO2-IBI/amp`, `0x49/0x4c/0x4f SleepSummary 1-3`, `0x50 ActivityInfo`,
    `0x5b BleConnection`, `0x5e Selftest`, `0x6b MotionPeriod`,
    `0x72 SleepAcmPeriod`, `0x75 SleepTemp`, `0x7e/0x7f RealSteps`, …

### Driver

- ✅ **Live BLE transport** (`bleak`-based async `OuraRingClient`) with auto-reconnect, handshake, time-sync, event-subscribe, and autonomous catch-up
- ✅ **Offline replay** mode against btsnoop captures (`oura_ring.replay`) — same envelope schema as live
- ✅ **JSONL output envelope** — one record per line, streaming-friendly
- ✅ **Synthetic events** for control-plane / lifecycle visibility (see "Two planes" below)

### Two planes

The driver separates two distinct concerns:

**1. Autonomous catch-up (data plane)** — on every (re)connect, the driver requests history-fetch to retrieve records buffered while disconnected. Surfaced as `_HISTORY_FETCH_REQ` / `_HISTORY_FETCH_RESP` events. Verified: **327 fetches across 167 reconnects = 1.96 per reconnect** in the test capture.

**2. On-demand control (control plane)** — high-level methods to actively configure the ring:

| Method | What it does |
|---|---|
| `await client.set_spo2(on)` | Toggle SpO₂ sampling |
| `await client.set_activity_hr(on)` | Toggle activity heart-rate detection |
| `await client.set_dhr_mode(mode, sub_mode)` | Set Daytime HR mode + sub-mode |
| `await client.request_hr_on_demand()` | Trigger the documented burst HR check |
| `await client.read_param(0x04)` | Read 4-byte SpO₂ struct |
| `await client.write_param_byte0(p, v)` | Generic byte-0 write |
| `await client.request_history(sub, cur)` | Manual delta-sync fetch |

Surfaced as `_PARAM_READ` / `_PARAM_READ_RESP` / `_PARAM_WRITE_B0` / `_PARAM_WRITE_B2` / `_PARAM_PUSH` synthetic events.

### State models

Two small dataclasses that consume the JSONL stream and track ring + driver state — no I/O, no transport coupling:

| `RingState` | `ClientState` |
|---|---|
| BLE link, identity (firmware/serial) | Connection phase (DISCONNECTED → CONNECTING → HANDSHAKING → SUBSCRIBED → STREAMING) |
| Unified `StateChange` enum (current state + name + text) | Handshake / time-sync counters |
| Sub-state machines: DHR, CVA, A:SA, EHR (parsed from `0x43` debug strings) | Records seen + per-type coverage (count, last counter, last session) |
| Battery (level%, voltage mV), charging, orientation | Autonomous catch-up: history fetches, cursors per sub-op |
| `params[pid]` — last-seen 4-byte parameter struct per ID | On-demand control: per-param read/write/push counts |

```python
from oura_ring import replay, RingState, ClientState

ring = RingState()
client = ClientState()
for rec in replay("capture.log"):
    ring.apply(rec)
    client.apply(rec)
print(client.snapshot())   # {phase: STREAMING, handshake_count: 168, …}
print(ring.snapshot())     # {state: 3 STATE_FINGER_USER_ACTIVE, dhr_state: 1, …}
```

## End-to-end validation

Full regression suite in `verify_claims.py`. Latest run:

```
## Verification — 147 claims tested
   PASS=143  FAIL=4
```

The 4 FAILs are real falsifications of pre-existing markdown claims (battery sub-ops, jzlog framing, temp channel scaling, `_FIELD_NUMBER` count). Highlights of what's verified:

- Wire-truth: ATT MTU=247, 484/484 handshake nonce/proof pairs verify against `auth_key`, 166/166 time-sync formula checks
- Round-trip vs on-device DB:
  - **IBI**: 99.7% coverage, average matches DB within **1.3 ms** (845.0 vs 846.3)
  - **IBI amplitude**: max matches exactly (16256), median within 10%
  - **TempEvent.temp3_c**: 100% in [25, 40] °C
  - Firmware version `2.10.4` ✓, bootloader `1.0.1` ✓, ring_type=6 (Gen 4) ✓
- State machines: DHR `0→1→4→2→0` main loop reproduced (573 cycles, 11.0% retry rate matches the analysis-note's ~10%); CVA per-state counts balanced; A:SA `1,1`/`1,2` ping-pong at top
- **Causal proof**: every observed SpO₂ toggle write is followed by an `O2Mode;N` debug string within seconds (10 writes → 12 strings)

## Quick start

```sh
# Replay an existing btsnoop capture as JSONL on stdout
python3 -m oura_ring.cli replay sunday_evening.log | head

# Live stream from a ring (requires `pip install bleak` + a paired ring)
python3 -m oura_ring.cli live --mac A0:38:F8:A4:09:C9 --realm path/to/assa-store.realm
```

```python
import asyncio
from oura_ring import RingState, ClientState
from oura_ring.transport import OuraRingClient

async def main():
    ring = RingState()
    client_state = ClientState()
    async with OuraRingClient(mac="A0:...", realm_path="assa-store.realm") as r:
        # Toggle SpO2 on demand
        await r.set_spo2(True)

        async for rec in r.stream():
            ring.apply(rec)
            client_state.apply(rec)
            if rec.type == "API_IBI_AND_AMPLITUDE_EVENT":
                print(rec.data["ibi_ms"], rec.data["amp"])
            if rec.type == "_PARAM_PUSH":
                print("ring config changed:", ring.params)

asyncio.run(main())
```

## JSONL envelope

Common shape, one line per record:

```json
{"t":1777033068525,"rt":76522,"ctr":11609,"sess":2,"tag":"0x60","type":"API_IBI_AND_AMPLITUDE_EVENT","data":{"ibi_ms":[555,867,843,827,817,764],"amp":[0,896,992,1168,1024,928],"amp_shift":4}}
```

| Field | Always present | Meaning |
|---|---|---|
| `t`    | yes | UTC ms (Unix epoch), time-sync corrected |
| `rt`   | inner records only | Ring-time uint32 from TLV header |
| `ctr`  | inner records only | Per-type counter |
| `sess` | inner records only | Session id |
| `tag`  | yes | Wire byte hex (`"0xNN"`) OR underscore-prefixed for synthetic |
| `type` | yes | Canonical name (`API_*`) or `_*` synthetic |
| `data` | yes | Type-specific decoded fields (or `{"hex":"..."}` fallback) |

## Synthetic event types

| Type | When emitted | Plane |
|---|---|---|
| `_HANDSHAKE_NONCE` / `_PROOF` / `_OK` / `_FAIL` | Handshake sequence | Lifecycle |
| `_TIME_SYNC_REQ` / `_TIME_SYNC_REPLY` | 0x12 / 0x13 | Lifecycle |
| `_BATTERY` | 0x0d battery response (voltage_mv) | Lifecycle |
| `_DISCONNECT` | BLE link drop (live only) | Lifecycle |
| `_HISTORY_FETCH_REQ` / `_HISTORY_FETCH_RESP` | 0x10 / 0x11 with cursor | **Autonomous catch-up** |
| `_PARAM_READ` / `_PARAM_READ_RESP` | 0x2F sub 0x20 / 0x21 | **On-demand control** |
| `_PARAM_WRITE_B0` / `_PARAM_WRITE_B2` | 0x2F sub 0x22 / 0x26 | **On-demand control** |
| `_PARAM_PUSH` | 0x2F sub 0x28 (unsolicited from ring) | **On-demand control** |
| `_STATE_PULSE` | 0x1f autonomous state-machine pulse | Lifecycle |

## What's NOT implemented yet

- 🟡 Live BLE transport is **untestable from this dev box** (no ring) — the
  decode pipeline is shared 1:1 with offline replay (which IS verified), so
  the live path needs only end-user smoke-testing on a real ring.
- 🟡 `0x61 API_DEBUG_DATA` (46 sub-types per RTTI) emits raw hex — needs a
  sub-dispatcher; deferred (no high-priority fields, mostly diagnostic).
- 🟡 `0x81 CvaRawPpgData` / `0x68 RawPpgData` are **stateful** (lib reads
  `RingEventParser::session()` buffers) — fall through to raw-hex fallback.
- 🟡 Two firmware-extension tags `0x33` and `0x85` (no parser symbol in the lib).

## Architecture

```
btsnoop/BLE bytes
   │
   ▼
framing.parse_outer_frames / parse_inner_records   ← TLV / opcode walker
   │
   ▼
decoders.decode(type_byte, payload)                ← per-type wire decoders
                                                     (data plane)
   │
   ▼   replay._outer_to_record / transport._outer_to_records
envelope.Record                                    ← typed dataclass
   │
   ├──→  consumer (your code) — JSONL stdout, file, network
   │
   └──→  state.RingState.apply(rec)
         state.ClientState.apply(rec)              ← state-tracking models
                                                     (both planes)
```

## Provenance

This driver is built directly off the verified findings in `oura_truth_table.md`
and the auto-extracted parser metadata in `wireformat_extract.json`. The high-
frequency wire-format decoders (IBI bit-pack, HRV pair-walk, Temp signed/100,
StateChange template, etc.) are byte-for-byte derived from disassembly of
`libringeventparser.so` (arm64-v8a, md5 `9941cfb8214faf55150a0b6082127e90`).

Round-trip empirical validation: pure-Python IBI decoder produces 77,760 values
from the 70-hour `sunday_evening.log` capture; the on-device DB persists 77,985
IBI rows over the same capture's 76-hour superset window. Average IBI: driver
845.0 ms, DB 846.3 ms (delta 1.3 ms — within sample-clock noise).
## License Information
This project is licensed under the GNU General Public License version 3. See the LICENSE file for details.
