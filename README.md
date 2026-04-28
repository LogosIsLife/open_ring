# `open_ring` — pure-Python read-only driver for the Oura Ring 4 BLE protocol
A clean-room reimplementation of the Oura Ring's BLE→biometric data pipeline,
based on static RE of `libringeventparser.so` (arm64-v8a build) and empirical
verification against on-device DB rows.

**No vendored binaries. No proprietary blobs. Stdlib + (eventually) `bleak`.**

## *Not Affiliated with Oura Health Oy*
## What's implemented

- ✅ Outer-frame parsing (24/24 opcodes — battery, time-sync, handshake, subscribe…)
- ✅ Inner-record TLV walker
- ✅ **Live BLE transport** (`bleak`-based async client `OuraRingClient`)
  with auto-reconnect, handshake, time-sync, and event subscribe
- ✅ Per-type wire-format decoders for **31 record types** (79% of all records
  in a typical capture decode to typed fields, 0% errors):
  - High-confidence: `0x60 IBI` (incl. 11-bit IBI + amp bit-pack with shift),
    `0x42 TimeSync`, `0x46 Temp`, `0x5d HRV`, `0x53 Wear / 0x45 StateChange`,
    `0x6f SpO2`, `0x4a PpgAmplitude`, `0x76 BedtimePeriod`, …
  - Auto-extracted: `0x73 EHR trace`, `0x74 EHR ACM intensity`, `0x80 GreenIbiQuality`,
    `0x82 ScanStart`, `0x83 ScanEnd`, `0x77 SpO2-DC`, `0x6c FeatureSession`,
    `0x6e SpO2-IBI/amp`, `0x49/0x4c/0x4f SleepSummary 1-3`, `0x50 ActivityInfo`,
    `0x5b BleConnection`, `0x5e Selftest`, `0x6b MotionPeriod`,
    `0x72 SleepAcmPeriod`, `0x75 SleepTemp`, `0x7e/0x7f RealSteps`, …
- ✅ JSONL output envelope (one record per line, streaming-friendly)
- ✅ Synthetic events for handshake / time-sync / battery / disconnect / state-pulse
- ✅ Offline replay against btsnoop captures
- ✅ AES-128-ECB-PKCS5 handshake (via `cryptography` lib OR `openssl` subprocess)
- ✅ `auth_key` extraction from `assa-store.realm`
- ✅ End-to-end round-trip-validated against the on-device DB:
  - IBI: 99.7% coverage, avg matches within **1.3 ms** (845.0 vs 846.3)
  - IBI amplitude: max matches exactly (16256), median matches within 10%
  - TempEvent: 100% of decoded `temp3_c` in [25, 40] °C

## What's NOT implemented yet

- 🟡 Live BLE transport is **untestable from this dev box** (no ring) — the
  decode pipeline is shared 1:1 with offline replay (which IS verified), so
  the live path needs only end-user smoke-testing on a real ring.
- 🟡 `0x61 API_DEBUG_DATA` (46 sub-types per RTTI) emits raw hex — needs a
  sub-dispatcher; deferred (no high-priority fields, mostly diagnostic).
- 🟡 `0x81 CvaRawPpgData` / `0x68 RawPpgData` are **stateful** (lib reads
  `RingEventParser::session()` buffers) — fall through to raw-hex fallback.
- 🟡 Two firmware-extension tags `0x33` and `0x85` (no parser symbol in the lib).

## Quick start

```sh
# Replay an existing btsnoop capture as JSONL on stdout
python3 -m oura_ring.cli replay sunday_evening.log | head

# Live stream from a ring (requires `pip install bleak` + a real ring)
python3 -m oura_ring.cli live --mac A0:38:F8:A4:09:C9 --realm path/to/assa-store.realm

# As a library — async live mode
python3 -c "
import asyncio
from oura_ring.transport import OuraRingClient

async def main():
    async with OuraRingClient(mac='A0:...', realm_path='assa-store.realm') as r:
        async for rec in r.stream():
            if rec.type == 'API_IBI_AND_AMPLITUDE_EVENT':
                print(rec.data['ibi_ms'], rec.data['amp'])

asyncio.run(main())
"

# Or sync, for those allergic to asyncio
python3 -c "
from oura_ring.transport import stream_sync
for rec in stream_sync(mac='A0:...', realm_path='assa-store.realm'):
    print(rec.to_json())
"

# Offline as a library
python3 -c "
from oura_ring import replay
for rec in replay('sunday_evening.log'):
    if rec.type == 'API_IBI_AND_AMPLITUDE_EVENT':
        print(rec.data['ibi_ms'], rec.data['amp'])
"
```

## JSONL envelope schema

```json
{
  "t":    1777033068525,
  "rt":   76522,
  "ctr":  11609,
  "sess": 2,
  "tag":  "0x60",
  "type": "API_IBI_AND_AMPLITUDE_EVENT",
  "data": {
    "ibi_ms": [555, 867, 843, 827, 817, 764]
  }
}
```

| Field | Always present | Meaning |
|---|---|---|
| `t`    | yes | UTC time in ms (Unix epoch) — time-sync corrected |
| `rt`   | inner records only | Ring-time uint32 from TLV header (omitted for synthetic events) |
| `ctr`  | inner records only | Per-type counter (uint16 from TLV header) |
| `sess` | inner records only | Session id (uint16 from TLV header) |
| `tag`  | yes | Wire byte hex string (`"0xNN"`) OR underscore-prefixed (`"_BATTERY"`) for synthetic |
| `type` | yes | Canonical name (`API_*` from `RingEventType` enum, or `_*` synthetic) |
| `data` | yes | Type-specific decoded fields (or `{"hex": "...", "len": N}` fallback) |

## Synthetic event types

| Type | Emitted when | Fields |
|---|---|---|
| `_HANDSHAKE_NONCE` | Ring sends `2F 10 2C <nonce:15>` | `nonce_hex` |
| `_HANDSHAKE_PROOF` | Phone sends `2F 11 2D <proof:16>` | `proof_hex` |
| `_HANDSHAKE_OK`/`_HANDSHAKE_FAIL` | Ring sends `2F 02 2E <status>` | `status` |
| `_TIME_SYNC_REQ` | Phone sends `12 09 ...` | `token`, `time_counter` |
| `_TIME_SYNC_REPLY` | Ring sends `13 05 ...` | `ack_code`, `time_echo` |
| `_BATTERY` | Ring sends `0d 06 ...` | `voltage_mv`, `state_bytes` |

## Architecture

```
btsnoop/BLE bytes
   │
   ▼
framing.parse_outer_frames / parse_inner_records   ← TLV / opcode walker
   │
   ▼
decoders.decode(type_byte, payload)                ← per-type wire-format decoders
   │
   ▼
envelope.Record                                    ← typed dataclass
   │
   ▼ .to_json()
JSONL on stdout / generator yield
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
