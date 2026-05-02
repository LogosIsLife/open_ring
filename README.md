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
- ✅ Per-type wire-format decoders for **35 stateless types + 1 stateful (`0x81 CvaRawPpg`) + 17 DebugData (`0x61`) sub-types**, 0% decode errors. On the 70 h `sunday_evening.log` test capture (117,662 inner records, 34 distinct types):
  - **97.5% strong-decode** (114,694 records — typed semantic fields, cross-validated against the on-device DB and/or the proto schema):
    - `0x60 IBI` — 11-bit bit-packed IBI + amp with shift; **avg matches on-device DB to 1.3 ms** over 77 k samples
    - `0x46 Temp` — temp1/2/3 °C ranges **match DB exactly**
    - `0x5d HRV` — HR avg matches IBI-derived avg within **0.2 BPM**
    - `0x47 MotionEvent` — `acm_x/y/z` ranges **match DB byte-for-byte exact**
    - `0x6f Spo2` — 16,905 per-sample percent values in physiologically perfect 80–100% range
    - `0x80 GreenIbiQuality` — 43,859 per-sample 11-bit IBI-ms + 2-bit/3-bit quality flags
    - `0x81 CvaRawPpgData` — **45,851 raw 24-bit ADC samples = exact prefix of the DB's `TimeseriesDbPpgSample`, 100% sample-for-sample**
    - `0x61 DEBUG_DATA` — sub-byte dispatched into 17 typed parsers (~99.5% of debug records, including 1 bit-packed, 1 stateful, and **4 sub-types the lib's own dispatch table maps to its default-throw branch but which carry real structure the app consumes downstream**): `OpenAfePpgSettingsData` (5,861), `SleepStatistics` (2,723), `AfeStatisticsValues` (2,710 — header/continuation framing), `FlashUsageStatistics`/`BleUsageStatistics`/`PeriodInfoStatistics` (1,368 each), `**AfePeriodTick**` (1,323 — sub 0x3b, alternating 50Hz/25Hz periods 661/662 split), `PpgSignalQualityStats` (1,074 — bit-stream MSB-first, ibi_quality validated [0..95]%), `FuelGaugeStatistics` (511 — battery/voltage cross-checked with BatteryLevelChanged), `AcmConfigurationChanged` (329), `EventSyncStatistics` (227 — `mtu=247`), `EventSyncCacheStatistics` (227), `BatteryLevelChanged` (135), `**PeriodicCounter**` (111 — sub 0x30), `**PpgCont**` (69 — sub 0x3c), `FingerDetection` (68), `**DebugDataText**` (77 — sub 0x04, ASCII strings: `EHRts;NN`, `chg_rp;…`, `DF-…`)
    - `0x42 TimeSync`, `0x43 DebugEventInd`, `0x45 StateChangeInd / 0x53 WearEvent`,
      `0x76 BedtimePeriod`, `0x4a PpgAmplitudeInd`, `0x41 RingStartInd`, `0x69 TempPeriod`,
      `0x73 EHR trace`, `0x74 EHR ACM intensity`, `0x6e SpO2-IBI/amp`, `0x7e/0x7f RealSteps`,
      `0x77 SpO2-DC`, `0x6c FeatureSession`, `0x82 ScanStart` / `0x83 ScanEnd`,
      `0x50 ActivityInfo`, `0x5b BleConnection`, `0x5e Selftest`,
      `0x6b MotionPeriod`, `0x72 SleepAcmPeriod`, `0x49 / 0x4c / 0x4f SleepSummary 1-3`
  - **2.3% weak / type-only** (2,651 records): hex-only types where the lib itself has no field structure (`0x6a SleepPeriodInfo2` 2,177, `0x75 SleepTemp` 315, `0x79 TagEvent` 60, `0x5c UserInfo` 3) + 96 rare DD records (2 stateful sub-types `0x36`/`0x3d` and 7 sub-bytes seen ≤10 times in the entire 70 h capture)
  - **0.3% no-decoder** (317 records): 2 unmapped firmware-extension tags `0x33` (240) / `0x85` (77)

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

Full regression suite in `tools/verify_claims.py`. Latest run:

```
## Verification — 207 claims tested
   PASS=204  FAIL=3
```

The 3 FAILs are real falsifications of pre-existing markdown claims
(`_FIELD_NUMBER` count off by 3, jzlog framing not uniform, battery sub-ops).
Highlights of what's verified:

- Wire-truth: ATT MTU=247, 484/484 handshake nonce/proof pairs verify against `auth_key`, 166/166 time-sync formula checks
- Round-trip vs on-device data (Realm dumps + SQLite):
  - **IBI**: 99.7% coverage, average matches DB within **1.3 ms** (845.0 vs 846.3)
  - **IBI amplitude**: max matches exactly (16256), median within 10%
  - **TempEvent.temp1/2/3_c**: ranges match DB `temperature_1/2/3` *exactly*
    (`[24.10..41.74]`, `[28.00..46.00]`, `[20.28..37.71]`)
  - **MotionEvent.acm_x/y/z**: ranges match DB `acm_average_x/y/z` byte-for-byte
    (`[-968..1016]`, `[-1024..1016]`, `[-1000..992]`)
  - **HRV.hr_bpm avg = 70.8** matches IBI-derived avg (60000/845 = **71.0 BPM**) within 0.2 BPM — cross-decoder consistency
  - **SpO₂**: 16,905 per-sample percent values in 80–100% range, mean 93.3%
  - **GreenIbiQuality**: 43,859 per-sample `value_11bit` in IBI-ms range `[320..2000]`
  - **CvaRawPpg (raw 24-bit ADC samples)**: 45,851 driver samples = exact prefix of `TimeseriesDbPpgSample`, sample-for-sample, in order — 100% (stateful `CvaPpgDecoder` mirrors lib's `decode_ppg_event_bytes`)
  - **DebugData (0x61) sub-dispatch**: 17 sub-types (~99.5% of 19,645 debug records) decoded with cross-validated values: `EventSyncStatistics.mtu == 247` (matches K8), `FuelGaugeStatistics.battery_pct ∈ [49.4..91.1]%`, `voltage ∈ [3533..4142] mV` (lithium-cell), `BatteryLevelChanged.voltage ∈ [3534..4141] mV` agrees with FuelGauge envelope **independently**, `PpgSignalQualityStats.ibi_quality_percentage ∈ [0..95]%`, `AfePeriodTick.period_us ∈ {20000, 40000}` (50Hz/25Hz, exactly balanced 661/662 in 1,323 records), `AcmConfigurationChanged.mode ∈ [0..4]` (full proto enum), and **4 sub-types the lib's table maps to default-throw but which carry app-consumed structure** (decoded empirically: ASCII strings, period ticks, periodic counters, PPG-cont headers)
  - DailyReadiness scores ∈ [0..100] across 11 days; DailySleep scores [0..100] across 4 days; all 16 sub-score contributors in range
  - Firmware version `2.10.4` ✓, bootloader `1.0.1` ✓, ring_type=6 (Gen 4) ✓
- Pipeline cardinality (Wire → DbRawEvent): **100.3% completeness**, 32/34 types persist 1:1; `0x43` debug strings + `0x33` firmware extension intentionally filtered
- State machines: DHR `0→1→4→2→0` main loop reproduced (573 cycles, 11.0% retry rate matches the analysis-note's ~10%); CVA per-state counts balanced; A:SA `1,1`/`1,2` ping-pong at top
- **Causal proof**: every observed SpO₂ toggle write is followed by an `O2Mode;N` debug string within seconds (10 writes → 12 strings)
- **Soft-reset opcode discovered** in `thursday.log`: phone `0e 01 ff` → ring `0f 01 00` → reboot in 22-35 s; 3/3 reset commands correlate with `RingStartInd` events

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
- 🟡 `0x61 API_DEBUG_DATA` — 17 of 31 observed sub-types now decoded (~99.5%
  of debug records). 4 of those decoders cover sub-bytes the lib's own
  dispatch table maps to its default-throw branch (`RepParseError`) — yet the
  app clearly consumes them downstream because each carries highly regular
  structure (alternating period ticks, ASCII debug strings, PPG-continuation
  headers). Decoded empirically + validated by truth-table claims. The
  ~96 remaining DD records are 2 stateful sub-types (`0x36 charger_information`,
  `0x3d charger_debug_information` — both use Session) plus 7 rare sub-bytes
  seen ≤10 times in 70 h capture.
- 🟡 `0x68 API_RAW_PPG_DATA` — type defined in the enum but never observed on
  the wire in any captured log. The lib's overload `decode_ppg_event_bytes(…,
  OldPPG_State_v1)` lives at `libringeventparser.so 0x2c1268` if a corpus
  appears.
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
