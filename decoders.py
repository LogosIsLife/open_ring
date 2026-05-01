"""Per-record-type wire-format decoders.

Each decoder takes the raw payload bytes (the part after the 6-byte TLV header)
and returns a dict suitable for the JSONL `data` field.

Most decoders are pure functions: payload → dict. The stateful raw-PPG decoder
is exposed as `CvaPpgDecoder` (instance state), and the dispatcher's `decode()`
remains stateless. Callers (replay/transport) own one `CvaPpgDecoder` per
session and post-enrich 0x81 records.

Decoders raise ValueError on malformed input; the dispatcher catches and
emits a `_DECODE_ERROR` event.
"""
from __future__ import annotations

import math
import struct
from typing import Any, Callable

from .enums import STATE_CHANGE, MOTION_STATE, RING_EVENT_TYPE


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _i8(b: int) -> int:
    """Sign-extend a single byte to a Python int (mirrors aarch64 sxtb)."""
    return b - 0x100 if b & 0x80 else b


def _u16(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


def _i16(b: bytes, off: int) -> int:
    v = b[off] | (b[off + 1] << 8)
    return v - 0x10000 if v & 0x8000 else v


def _u32(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def _i32(b: bytes, off: int) -> int:
    v = _u32(b, off)
    return v - 0x100000000 if v & 0x80000000 else v


# ----------------------------------------------------------------------------
# Stateful: CvaRawPpgData (0x81) — see libringeventparser.so
# `decode_ppg_event_bytes(EventPayload, RawPpgMeasurement, CvaPPG_State_v1)` at
# 0x2c09d0. The state object (16 bytes used: mode_flag, sub_counter, accumulator,
# last_value) is held in `RingEventParser::session()` at +0xc8 and reused across
# 0x81 records within a single sampler session.
#
# Wire format (one byte at a time):
#   - 0x80 byte           → marker: start of an absolute sample. Resets
#                            accumulator and sub_counter; mode_flag = 1.
#   - bytes after 0x80    → 3 bytes assembled little-endian into a u24, then
#                            sign-extended to s32 (OR 0xff000000 if the high
#                            byte's MSB is set) → emit one absolute sample.
#   - any other byte b    → signed int8 delta added to last_value → emit one
#                            sample.
#
# Cardinality: 99.4% of observed 0x81 wire records are 14 bytes. Within a burst
# of records, samples accumulate; the 0x80 markers re-anchor when the signal
# drifts beyond ±127 from the previous sample.
# ----------------------------------------------------------------------------


class CvaPpgDecoder:
    """Stateful decoder for `0x81 API_CVA_RAW_PPG_DATA`.

    Owners (replay/transport) instantiate one decoder per sampler session and
    call `feed(payload)` for each 0x81 record's bytes. The returned list is
    the samples emitted by THIS record (24-bit signed ADC counts). Internal
    state persists across calls so deltas resolve against the prior absolute.

    Reset on observed session boundary (new `sess`, ctr discontinuity, or an
    explicit FeatureSession capability transition for cva_ppg_sampler).
    """

    __slots__ = ("mode_flag", "sub_counter", "accumulator", "last_value",
                 "samples_total", "absolutes_total", "deltas_total",
                 "records_fed", "bytes_fed")

    def __init__(self) -> None:
        self.reset()
        self.samples_total = 0
        self.absolutes_total = 0
        self.deltas_total = 0
        self.records_fed = 0
        self.bytes_fed = 0

    def reset(self) -> None:
        self.mode_flag = 0     # 0 = expecting marker/delta, 1 = collecting absolute
        self.sub_counter = 0   # 0..3 byte-index within current absolute
        self.accumulator = 0   # u32 LE byte assembly
        self.last_value = 0    # s32 last emitted sample

    def feed(self, payload: bytes) -> list[int]:
        out: list[int] = []
        for b in payload:
            if self.mode_flag:
                # Collecting bytes 0..2 of absolute sample (LE)
                if self.sub_counter <= 2:
                    self.accumulator |= (b << (self.sub_counter * 8))
                    self.sub_counter += 1
                if self.sub_counter == 3:
                    # Sign-extend if the third byte's high bit is set
                    if b & 0x80:
                        sample = self.accumulator | 0xff000000
                        sample -= 0x100000000
                    else:
                        sample = self.accumulator
                    self.last_value = sample
                    out.append(sample)
                    self.absolutes_total += 1
                    self.mode_flag = 0
            else:
                if b == 0x80:
                    # New absolute marker: reset accumulator + sub_counter
                    self.accumulator = 0
                    self.sub_counter = 0
                    self.mode_flag = 1
                else:
                    # Signed-int8 delta against last_value
                    delta = b - 0x100 if b & 0x80 else b
                    self.last_value = self.last_value + delta
                    out.append(self.last_value)
                    self.deltas_total += 1
        self.samples_total += len(out)
        self.records_fed += 1
        self.bytes_fed += len(payload)
        return out


# ----------------------------------------------------------------------------
# Strong-decode types (wire format verified end-to-end via lib disasm)
# ----------------------------------------------------------------------------

def decode_time_sync_ind(p: bytes) -> dict[str, Any]:
    """0x42 — fixed 9 bytes:
        <token:1><time_counter:3 LE><const:5>
    time_counter = int(unix_time) // 256
    """
    if len(p) != 9:
        raise ValueError(f"TimeSyncInd payload must be 9 bytes, got {len(p)}")
    counter = p[1] | (p[2] << 8) | (p[3] << 16)
    return {
        "token": p[0],
        "time_counter": counter,
        "ring_unix_time_approx_s": counter * 256,  # ring's view of unix_time, rounded
    }


def decode_debug_event_ind(p: bytes) -> dict[str, Any]:
    """0x43 — variable-length ASCII text (declared `repeated bytes` in proto;
    not UTF-8 enforced, but in practice ASCII state-machine strings).
    """
    text = p.decode("ascii", errors="replace")
    return {"text": text}


def decode_temp_event(p: bytes) -> dict[str, Any]:
    """0x46 — even-size payload [4..14]; int16_LE / 100.0 → °C for ALL channels.

    Disasm note: the lib uses `ldrh` (unsigned) for offsets 0,2 and `ldrsh`
    (signed) for offsets 4..12. In practice temp1/2 never go negative, so the
    value range is identical to signed/100. Verified row-for-row against the
    on-device DB: all three observable channels match within rounding.

    Missing channels: signed-int16(-32768)/100 = -327.68 is the sentinel; we
    emit `null`.
    """
    n = len(p)
    if n < 4 or n > 14 or n % 2 != 0:
        raise ValueError(f"TempEvent payload size must be even in [4..14], got {n}")

    def _temp(off: int, signed: bool):
        if off + 2 > n: return None
        v = (_i16(p, off) if signed else _u16(p, off)) / 100.0
        return None if v == -327.68 else v

    return {
        "temp1_c": _temp(0,  False),
        "temp2_c": _temp(2,  False),
        "temp3_c": _temp(4,  True),
        "temp4_c": _temp(6,  True),
        "temp5_c": _temp(8,  True),
        "temp6_c": _temp(10, True),
        "temp7_c": _temp(12, True),
    }


def decode_state_change_ind(p: bytes) -> dict[str, Any]:
    """0x45 — <state:u8><text:bytes(size-1)>
    The state byte is a StateChange enum value.
    """
    if len(p) < 1:
        raise ValueError("StateChangeInd payload too short")
    state = p[0]
    text = p[1:].decode("ascii", errors="replace")
    return {
        "state": state,
        "state_name": STATE_CHANGE.get(state),
        "text": text,
    }


def decode_wear_event(p: bytes) -> dict[str, Any]:
    """0x53 — same wire format as StateChangeInd (shared template)."""
    return decode_state_change_ind(p)


def decode_hrv_event(p: bytes) -> dict[str, Any]:
    """0x5d — even-size payload [2..12]; pairs of (HR_5min:u8, RMSSD_5min:u8)
    each pair is one 5-minute window. Timestamps reconstructed by caller using
    `utc_time_ms - (n-1)*300_000` (last pair = current; spaced 5 min back).
    """
    n = len(p)
    if n < 2 or n > 12 or n % 2 != 0:
        raise ValueError(f"HrvEvent payload must be even in [2..12], got {n}")
    pairs = []
    for i in range(0, n, 2):
        pairs.append({"hr_bpm": p[i], "rmssd_ms": p[i + 1]})
    return {"samples_5min": pairs}


def decode_ibi_and_amplitude_event(p: bytes) -> dict[str, Any]:
    """0x60 — exactly 14 bytes; bit-packed encoding for 6× (IBI, amplitude) pairs.

    IBI extraction (verified end-to-end against on-device DB):
      For i in 0..5, IBI[i] (11-bit) is composed:
        bit 0       = byte (6+i) bit 0
        bits 1-2    = byte 12 bits (6-7,4-5,2-3,0-1) for i in 0..3,
                      byte 13 bits (6-7,4-5)        for i in 4..5
        bits 3-10   = byte i (full 8 bits at positions 3..10)

    Amplitude extraction (per parse_api_ibi_and_amplitude_event @ 0x2bc1b4-0x2bc21c):
      nibble = byte 13 & 0x0F
      shift  = 0 if nibble == 7 else nibble + 1
      amp[i] = (byte (6+i) >> 1) << shift          # upper 7 bits, scaled
    """
    if len(p) != 14:
        raise ValueError(f"IbiAndAmplitudeEvent payload must be 14 bytes, got {len(p)}")

    b12 = p[12]
    b13 = p[13]

    # IBI: 11-bit values, bit-packed across all 14 bytes
    mid_bits = [
        (b12 >> 5) & 0x6,   # IBI[0]: bits 6-7 of b12
        (b12 >> 3) & 0x6,   # IBI[1]: bits 4-5
        (b12 >> 1) & 0x6,   # IBI[2]: bits 2-3
        (b12 << 1) & 0x6,   # IBI[3]: bits 0-1
        (b13 >> 5) & 0x6,   # IBI[4]: bits 6-7 of b13
        (b13 >> 3) & 0x6,   # IBI[5]: bits 4-5
    ]
    ibi_ms = []
    for i in range(6):
        high = p[i] << 3
        low  = p[6 + i] & 0x1
        mid  = mid_bits[i]
        ibi_ms.append(high | mid | low)

    # Amplitude: shared shift derived from byte 13 low nibble
    nibble = b13 & 0x0F
    shift = 0 if nibble == 7 else nibble + 1
    amp = [(p[6 + i] >> 1) << shift for i in range(6)]

    return {
        "ibi_ms": ibi_ms,
        "amp": amp,
        "amp_shift": shift,
    }


def decode_spo2_event(p: bytes) -> dict[str, Any]:
    """0x6f — payload size [1..14]. Wire format derived from disasm of
    `parse_api_spo2_event` @ 0x2c62b8:

      byte 0:           <hdr_high:4 high nibble><hdr_low:4 low nibble>
                         (high nibble stored shifted ×128 in lib's struct;
                          low nibble stored as-is — likely a flag)
      bytes 1..size-1:  per-sample SpO₂ percent values (uint8)
      optional 0xff:    terminator at last byte (excluded from sample list)

    Verified: observed payload `68 5d 5d 5d ... 5d` decodes to header_high=6,
    header_low=8, spo2_percent=[93]*13 — all 93% readings.
    """
    if len(p) < 1:
        raise ValueError("Spo2Event payload too short")
    samples_end = len(p) - 1 if len(p) > 1 and p[-1] == 0xff else len(p)
    return {
        "header_high": p[0] >> 4,
        "header_low":  p[0] & 0x0F,
        "spo2_percent": list(p[1:samples_end]),
    }


def decode_bedtime_period(p: bytes) -> dict[str, Any]:
    """0x76 — 8 bytes: 2× uint32 LE.
        offsets 0..3: start_rt (ring_time uint32)
        offsets 4..7: end_rt (ring_time uint32)
    Both converted to UTC ms by the lib via TimeMapping; we emit the raw
    uint32 ring_time values.
    """
    if len(p) < 8:
        raise ValueError(f"BedtimePeriod payload must be ≥8 bytes, got {len(p)}")
    return {
        "start_ring_time": _u32(p, 0),
        "end_ring_time": _u32(p, 4),
    }


def decode_ppg_amplitude_ind(p: bytes) -> dict[str, Any]:
    """0x4a — uint16 LE / 65535.0 → float [0..1] (normalized PPG amplitude)."""
    if len(p) < 2:
        raise ValueError(f"PpgAmplitudeInd payload must be ≥2 bytes, got {len(p)}")
    raw = _u16(p, 0)
    return {
        "amplitude_normalized": raw / 65535.0,
        "amplitude_raw_u16": raw,
    }


def decode_temp_period(p: bytes) -> dict[str, Any]:
    """0x69 — fixed 2 bytes: int16 LE temperature value (units TBD)."""
    if len(p) != 2:
        raise ValueError(f"TempPeriod payload must be 2 bytes, got {len(p)}")
    return {"temp_raw": _i16(p, 0)}


# ----------------------------------------------------------------------------
# Auto-extracted wire formats (size + offset map known; field names heuristic)
# ----------------------------------------------------------------------------

def decode_ehr_acm_intensity_event(p: bytes) -> dict[str, Any]:
    """0x74 — even-size [2..14]; 7× int16 LE at offsets 0,2,4,6,8,10,12 (uint16
    per auto-extractor). Field names not yet mapped to proto schema.
    """
    n = len(p)
    if n < 2 or n > 14 or n % 2 != 0:
        raise ValueError(f"EhrAcmIntensityEvent size must be even in [2..14], got {n}")
    fields = []
    for i in range(0, n, 2):
        fields.append(_u16(p, i))
    return {"u16_values": fields}


def decode_motion_event(p: bytes) -> dict[str, Any]:
    """0x47 — payload size [4..6]. Wire format derived from disasm of
    `parse_api_motion_events` @ 0x2acf24:

      byte 0:  <flags_high:3 (top 3 bits)><flags_low:5 (bottom 5 bits)>
      byte 1:  signed int8 → ×8.0 → acm_x  (output[+8]  as float)
      byte 2:  signed int8 → ×8.0 → acm_y  (output[+0xc] as float)
      byte 3:  signed int8 → ×8.0 → acm_z  (output[+0x10] as float)
      byte 4 (size ≥ 5): bit 6 must be 0 (validation), bit 7 = `flag_b4_bit7`,
                          bits 0-5 = `low6_b4` (6-bit field; orientation-related)
      byte 5 (size ≥ 6): bit 6 must be 0 (validation), bits 0-5 = `low6_b5`

    The ×8 scaling produces values in roughly [-1024..+1024] from int8 input.
    DB MotionPeriod.acm_average_x ranges 576/-56/-328 (sample) — fits the range.
    """
    n = len(p)
    if n < 4 or n > 6:
        raise ValueError(f"MotionEvent payload size must be in [4..6], got {n}")
    out: dict[str, Any] = {
        "flags_high": p[0] >> 5,
        "flags_low":  p[0] & 0x1F,
        # Signed int8 → ×8 — empirical scale from disasm; units inferred from
        # DB acm_average_x range (~ -512..+576 for typical wear)
        "acm_x": _i8(p[1]) * 8,
        "acm_y": _i8(p[2]) * 8,
        "acm_z": _i8(p[3]) * 8,
    }
    if n >= 5:
        if p[4] & 0x40:
            raise ValueError("MotionEvent byte4 bit 6 must be 0")
        out["flag_b4_bit7"] = (p[4] >> 7) & 1
        out["low6_b4"]      = p[4] & 0x3F
    if n >= 6:
        if p[5] & 0x40:
            raise ValueError("MotionEvent byte5 bit 6 must be 0")
        out["low6_b5"] = p[5] & 0x3F
    return out


def decode_motion_period(p: bytes) -> dict[str, Any]:
    """0x6b — uses MotionState enum; minimal verified field is motion_state_30s
    at offset 0 (uint8). Full field map TBD.
    """
    if len(p) < 1:
        raise ValueError("MotionPeriod payload too short")
    state = p[0]
    return {
        "motion_state_30s": state,
        "motion_state_name": MOTION_STATE.get(state),
        "trailing_hex": p[1:].hex(),
    }


def decode_real_steps_features(p: bytes) -> dict[str, Any]:
    """0x7e / 0x7f — fixed 14 bytes; 14× uint8 at offsets 0..13.
    Field names map to FFTset sub-messages (first/second/third FFT) per spec;
    signal-processing meaning of each byte not yet documented.
    """
    if len(p) != 14:
        raise ValueError(f"RealSteps payload must be 14 bytes, got {len(p)}")
    return {"u8_values": list(p)}


def decode_green_ibi_and_amp_event(p: bytes) -> dict[str, Any]:
    """0x80 (proto-side type GreenIbiAndAmpEvent) — fixed 14 bytes; 14× uint8."""
    if len(p) != 14:
        raise ValueError(f"GreenIbiAndAmp payload must be 14 bytes, got {len(p)}")
    return {"u8_values": list(p)}


def decode_ring_start_ind(p: bytes) -> dict[str, Any]:
    """0x41 — fixed 14 bytes per auto-extractor.
    Auto-extracted offsets: +00:32 +04:8 +09:8 +0a:8 +0b:8 +0c:8 +0d:8.
    Likely: timestamp@0(u32), then various firmware/config bytes.
    """
    if len(p) < 14:
        raise ValueError(f"RingStartInd payload too short ({len(p)})")
    return {
        "timestamp_u32": _u32(p, 0),
        "byte_4": p[4], "byte_9": p[9], "byte_a": p[0xa], "byte_b": p[0xb],
        "byte_c": p[0xc], "byte_d": p[0xd],
    }


# ----------------------------------------------------------------------------
# Promoted from wireformat_extract.json — offsets verified by static RE,
# proto-side field names from `Ringeventparser.java` where mapped, generic
# names (`u8_at_off_X`) where not.
# ----------------------------------------------------------------------------

def decode_activity_info_event(p: bytes) -> dict[str, Any]:
    """0x50 — payload [1..14]; first byte is an activity-class enum.
    Auto-extractor only found offset 0 (loop pattern hides further reads).
    """
    if len(p) < 1:
        raise ValueError("ActivityInfoEvent payload too short")
    return {"activity_byte_0": p[0], "trailing_hex": p[1:].hex()}


def decode_ble_connection_ind(p: bytes) -> dict[str, Any]:
    """0x5b — link-quality telemetry. Full layout TBD; emit first ~10 bytes
    as generic u8 reads (matches the auto-extractor's pattern of small-offset
    reads at 0,1,6,7,8,9).
    """
    fields: dict[str, Any] = {}
    for i, off in enumerate([0, 1, 6, 7, 8, 9]):
        if off < len(p):
            fields[f"u8_at_off_{off}"] = p[off]
    fields["trailing_hex"] = p[10:].hex() if len(p) > 10 else ""
    fields["len"] = len(p)
    return fields


def decode_selftest_event(p: bytes) -> dict[str, Any]:
    """0x5e — 2× uint16 LE at offsets 0,2 per auto-extractor.
    Proto: `repeated int32 passed_test`, `repeated int32 failed_test` plus a timestamp.
    """
    if len(p) < 4:
        raise ValueError("SelftestEvent payload too short (<4)")
    return {
        "u16_at_off_0": _u16(p, 0),
        "u16_at_off_2": _u16(p, 2),
        "trailing_hex": p[4:].hex(),
    }


def decode_feature_session(p: bytes) -> dict[str, Any]:
    """0x6c — variable size (3..7 observed); first 3 bytes are header
    (some_byte, capability, status). The remainder is one of 12 session-type
    payloads (oneof in proto); per-version decoding deferred.
    """
    if len(p) < 3:
        raise ValueError(f"FeatureSession payload too short ({len(p)})")
    out: dict[str, Any] = {
        "byte_0": p[0], "capability": p[1], "status": p[2],
    }
    if len(p) > 3:
        out["session_payload_hex"] = p[3:].hex()
        out["session_payload_len"] = len(p) - 3
    return out


def decode_spo2_ibi_and_amplitude_event(p: bytes) -> dict[str, Any]:
    """0x6e — fixed 13 bytes; 13× uint8.
    Like 0x60 but for SpO2 measurement context; bit-pack pattern is similar
    but with a different payload size, suggesting fewer beats per record.
    Conservative decode: emit raw bytes for downstream analysis.
    """
    if len(p) != 13:
        raise ValueError(f"Spo2IbiAndAmplitude payload must be 13 bytes, got {len(p)}")
    return {"u8_values": list(p)}


def decode_sleep_acm_period(p: bytes) -> dict[str, Any]:
    """0x72 — fixed 12 bytes; 6× uint8 at offsets 6..11 per auto-extractor.
    Proto fields not yet mapped; offsets 0..5 likely contain a header.
    """
    if len(p) != 12:
        raise ValueError(f"SleepAcmPeriod payload must be 12 bytes, got {len(p)}")
    return {
        "header_hex": p[0:6].hex(),
        "u8_at_off_6_11": list(p[6:12]),
    }


def decode_ehr_trace_event(p: bytes) -> dict[str, Any]:
    """0x73 — payload [5..14]; uint8 reads at offsets 4..13 per auto-extractor.
    Highest-volume "schema known" record (13k records in 70 h captures).
    Likely encodes per-sample exercise heart-rate metrics.
    """
    n = len(p)
    if n < 5 or n > 14:
        raise ValueError(f"EhrTraceEvent payload size [5..14], got {n}")
    return {
        "header_hex": p[:4].hex() if n >= 4 else p.hex(),
        "samples_u8": list(p[4:]),
    }


def decode_sleep_temp_event(p: bytes) -> dict[str, Any]:
    """0x75 — payload [2..15]; auto-extractor only found 64-bit reads (likely
    stack-frame loads, not wire). Emit raw bytes.
    """
    n = len(p)
    if n < 2 or n > 15:
        raise ValueError(f"SleepTempEvent payload size [2..15], got {n}")
    return {"hex": p.hex(), "len": n}


def decode_spo2_dc_event(p: bytes) -> dict[str, Any]:
    """0x77 — variable size; first byte at offset 0 per auto-extractor.
    Proto: `channel_index, beat_index, timestamp, dc[]` (one DC sample stream
    per channel). Loop pattern hides the per-sample reads.
    """
    if len(p) < 1:
        raise ValueError("Spo2DcEvent payload too short")
    return {
        "channel_index": p[0],
        "trailing_hex": p[1:].hex(),
        "len": len(p),
    }


def decode_green_ibi_quality_event(p: bytes) -> dict[str, Any]:
    """0x80 — `API_GREEN_IBI_QUALITY_EVENT`. Wire format derived from disasm
    of `parse_api_green_ibi_quality_event` @ 0x2c70d0.

    The parser is *partially stateful* (reads `RingEventParser::session()`
    flags at offsets 0x8 / 0x20 to gate processing), but the per-sample
    payload format is deterministic:

      payload is N pairs of bytes where N = floor(payload_size / 2).
      Each pair is (b_low, b_high) at offsets 2*i, 2*i+1:
        value_11bit = (b_low << 3) | (b_high & 0x07)   ← likely IBI in ms
        quality_a   = (b_high >> 3) & 0x03             ← 2-bit quality flag
        quality_b   = (b_high >> 5)                    ← 3-bit quality flag

    Verified against observed payload `84 27 5f 2f 5e 0e 60 10 ef 52 fa b0 77 b3`
    → 7 samples decoded. Each sample's 11-bit value is in IBI-plausible range.
    """
    n = len(p)
    if n < 2 or n % 2 != 0:
        raise ValueError(f"GreenIbiQuality payload must be even ≥ 2, got {n}")
    samples = []
    for i in range(0, n, 2):
        b_low, b_high = p[i], p[i + 1]
        samples.append({
            "value_11bit": (b_low << 3) | (b_high & 0x07),
            "quality_a":   (b_high >> 3) & 0x03,
            "quality_b":   (b_high >> 5) & 0x07,
        })
    return {"samples": samples, "_note": "parser is partially stateful (reads session flags); per-sample fields are deterministic"}


def decode_scan_start(p: bytes) -> dict[str, Any]:
    """0x82 — variable size; uint8 reads at offsets 0,1,2 per auto-extractor.
    Proto: `triggering_feature, trigger_reason, classification_metric, candidate_slot_1..6`.
    """
    if len(p) < 3:
        raise ValueError("ScanStart payload too short")
    return {
        "triggering_feature": p[0],
        "trigger_reason": p[1],
        "classification_metric": p[2],
        "candidate_slots": list(p[3:9]) if len(p) >= 9 else list(p[3:]),
        "trailing_hex": p[9:].hex() if len(p) > 9 else "",
    }


def decode_scan_end(p: bytes) -> dict[str, Any]:
    """0x83 — variable size (2..18 observed); payload encodes scan results.
    Proto: `success_code, scan_duration_sec, slot/channel_id/pd_mask × 4`.
    """
    if len(p) < 1:
        raise ValueError("ScanEnd payload empty")
    out: dict[str, Any] = {"success_code": p[0]}
    if len(p) >= 4:
        out["u16_at_off_2"] = _u16(p, 2)
    out["trailing_hex"] = p[(4 if len(p) >= 4 else 1):].hex()
    out["len"] = len(p)
    return out


def decode_sleep_summary_1(p: bytes) -> dict[str, Any]:
    """0x49 — 2× uint16 LE at offsets 0,2 per auto-extractor."""
    if len(p) < 4:
        raise ValueError("SleepSummary1 payload too short")
    return {"u16_at_off_0": _u16(p, 0), "u16_at_off_2": _u16(p, 2),
            "trailing_hex": p[4:].hex()}


def decode_sleep_summary_2(p: bytes) -> dict[str, Any]:
    """0x4c — fixed 14 bytes; uint16 at off 8, uint32 at off 10."""
    if len(p) != 14:
        raise ValueError(f"SleepSummary2 payload must be 14 bytes, got {len(p)}")
    return {
        "header_hex": p[:8].hex(),
        "u16_at_off_8": _u16(p, 8),
        "u32_at_off_10": _u32(p, 10),
    }


def decode_sleep_summary_3(p: bytes) -> dict[str, Any]:
    """0x4f — fixed 11 bytes; mixed widths per auto-extractor."""
    if len(p) != 11:
        raise ValueError(f"SleepSummary3 payload must be 11 bytes, got {len(p)}")
    return {
        "byte_0": p[0], "byte_1": p[1],
        "u16_at_off_2": _u16(p, 2),
        "u32_at_off_4": _u32(p, 4),
        "u16_at_off_8": _u16(p, 8),
        "byte_10": p[10],
    }


def decode_alert_event(p: bytes) -> dict[str, Any]:
    """`API_ALERT_EVENT` (parse_api_alert_event, 128 B function) — first byte
    at offset 0 is the alert type / code.
    """
    if len(p) < 1:
        raise ValueError("AlertEvent payload too short")
    return {"alert_byte_0": p[0], "trailing_hex": p[1:].hex()}


def decode_tag_event(p: bytes) -> dict[str, Any]:
    """0x79 — small payload; raw byte dump."""
    return {"hex": p.hex(), "len": len(p)}


def decode_user_info(p: bytes) -> dict[str, Any]:
    """0x5c — rare; raw byte dump."""
    return {"hex": p.hex(), "len": len(p)}


def decode_sleep_period_info_2(p: bytes) -> dict[str, Any]:
    """0x6a — no `parse_api_sleep_period_info_2` symbol in the lib; the type
    appears in captures but the parser is either inlined or shared with another
    handler. Emit raw bytes so consumers see something.
    """
    return {"hex": p.hex(), "len": len(p), "_note": "no dedicated parser symbol in lib"}


# ----------------------------------------------------------------------------
# Fallback for stateful or unmapped types
# ----------------------------------------------------------------------------

def decode_raw_hex(p: bytes) -> dict[str, Any]:
    """Emit raw hex so consumers see SOMETHING for types not yet decoded."""
    return {"hex": p.hex(), "len": len(p)}


# ----------------------------------------------------------------------------
# Dispatch table
# ----------------------------------------------------------------------------

DECODERS: dict[int, Callable[[bytes], dict[str, Any]]] = {
    # Strong-decode (verified end-to-end)
    0x41: decode_ring_start_ind,
    0x42: decode_time_sync_ind,
    0x43: decode_debug_event_ind,
    0x45: decode_state_change_ind,
    0x46: decode_temp_event,
    0x47: decode_motion_event,
    0x4a: decode_ppg_amplitude_ind,
    0x53: decode_wear_event,
    0x5d: decode_hrv_event,
    0x60: decode_ibi_and_amplitude_event,
    0x69: decode_temp_period,
    0x6b: decode_motion_period,
    0x6f: decode_spo2_event,
    0x74: decode_ehr_acm_intensity_event,
    0x76: decode_bedtime_period,
    0x7e: decode_real_steps_features,
    0x7f: decode_real_steps_features,

    # Promoted from auto-extracted wire format
    0x49: decode_sleep_summary_1,
    0x4c: decode_sleep_summary_2,
    0x4f: decode_sleep_summary_3,
    0x50: decode_activity_info_event,
    0x5b: decode_ble_connection_ind,
    0x5e: decode_selftest_event,
    0x6c: decode_feature_session,
    0x6e: decode_spo2_ibi_and_amplitude_event,
    0x72: decode_sleep_acm_period,
    0x73: decode_ehr_trace_event,
    0x75: decode_sleep_temp_event,
    0x77: decode_spo2_dc_event,
    0x80: decode_green_ibi_quality_event,
    0x82: decode_scan_start,
    0x83: decode_scan_end,

    # Generic/passthrough (no parser symbol or low-priority)
    0x5c: decode_user_info,
    0x6a: decode_sleep_period_info_2,
    0x79: decode_tag_event,
}


def decode(type_byte: int, payload: bytes) -> dict[str, Any]:
    """Decode a payload by type. Falls back to raw hex if the type is unmapped
    or if the decoder raises ValueError on malformed input.
    """
    fn = DECODERS.get(type_byte, decode_raw_hex)
    try:
        d = fn(payload)
        if fn is decode_raw_hex:
            d["_decoder"] = "raw_hex_fallback"
        return d
    except ValueError as e:
        return {"_decode_error": str(e), "hex": payload.hex(), "len": len(payload)}


def canonical_type(type_byte: int) -> str:
    return RING_EVENT_TYPE.get(type_byte, f"UNKNOWN_0x{type_byte:02x}")
