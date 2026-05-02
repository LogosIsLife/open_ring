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
    """0x75 — `parse_api_sleep_temp_event` @ 0x2bc518. Variable-length:
    N u16-LE values, each = temperature_centi_degrees (raw / 100.0 → °C).
    Timestamps assigned at 30-second intervals ending at utc_time_ms (so the
    last sample is at `t`, the previous at `t-30s`, etc.). Lib requires
    payload size to be even and in roughly [2..30].
    """
    n = len(p)
    if n == 0 or n & 1:
        raise ValueError(f"SleepTempEvent payload size must be even and >0, got {n}")
    n_samples = n // 2
    temps_c = [(p[i] | (p[i + 1] << 8)) / 100.0 for i in range(0, n, 2)]
    return {
        "n_samples": n_samples,
        "temps_c": temps_c,
        "sample_interval_s": 30,
        "_note": "samples are spaced 30s ending at this record's t",
    }


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
    """0x79 — variable-length record dispatched by byte 0.
    Empirical: byte 0 ∈ {0x02, 0x03}; sizes mostly 4 bytes (compact event) or
    occasionally 14/5 bytes (extended). No matching `parse_api_tag_event`
    symbol in the lib — this type may actually be alert/atlas-related under
    a different proto type. We surface byte 0 as `event_kind` and the rest
    as raw bytes."""
    if not p:
        raise ValueError("TagEvent payload empty")
    return {
        "event_kind": p[0],
        "fields_hex": p[1:].hex(),
        "len": len(p),
    }


def decode_user_info(p: bytes) -> dict[str, Any]:
    """0x5c — rare; `parse_user_info_update` @ 0x2ac4a0. Surface raw bytes
    plus byte 0 as kind."""
    if not p:
        raise ValueError("UserInfo payload empty")
    return {
        "user_info_kind": p[0],
        "fields_hex": p[1:].hex(),
        "len": len(p),
    }


def decode_sleep_period_info_2(p: bytes) -> dict[str, Any]:
    """0x6a — `parse_api_sleep_period_info` @ 0x2ad23c (the lib symbol is shared
    with the Java enum's `_2` suffix). Wire (10 bytes):

      <average_hr:u8>     — bpm * 0.5  (so wire 130 = 65 BPM)
      <hr_trend:s8>       — signed * 0.0625
      <mzci:u8>           — * 0.0625
      <dzci:u8>           — * 0.0625
      <breath:u8>         — / 8.0  (breaths/min, fixed-point 3-frac-bits)
      <breath_v:u8>       — / 8.0
      <motion_count:u8>   — bounded < 121, else throw RepNumericRangeError
      <sleep_state:s8>    — bounded < 3, else throw  (0/1/2 enum)
      <cv:u16-LE>         — / 65536.0  → float in [0..1)

    Float multipliers extracted from .rodata @ 0x117840: (0.5, 0.0625, 0.0625, 0.0625).
    """
    if len(p) < 10:
        raise ValueError(f"SleepPeriodInfo payload must be >=10 bytes, got {len(p)}")
    motion_count = p[6]
    if motion_count >= 0x79:
        raise ValueError(f"motion_count={motion_count} out of range [0..120]")
    sleep_state = _i8(p[7])
    if not (0 <= sleep_state < 3):
        raise ValueError(f"sleep_state={sleep_state} out of range [0..2]")
    cv_raw = p[8] | (p[9] << 8)
    return {
        "average_hr": p[0] * 0.5,
        "hr_trend": _i8(p[1]) * 0.0625,
        "mzci": p[2] * 0.0625,
        "dzci": p[3] * 0.0625,
        "breath": p[4] / 8.0,
        "breath_v": p[5] / 8.0,
        "motion_count": motion_count,
        "sleep_state": sleep_state,
        "cv": cv_raw / 65536.0,
    }


# ----------------------------------------------------------------------------
# 0x61 API_DEBUG_DATA — sub-byte dispatched, 46 sub-types per RTTI in the lib
#
# parse_api_debug_data at libringeventparser.so 0x2ae0a0 reads the first byte of
# the payload (offset 0), subtracts 2, jump-table dispatches to one of ~46
# parsers. Sub-byte mapping was extracted from the table at .rodata 0x121937.
#
# Sub-type wire formats are derived from the per-parser disassembly. Many share
# a common shape: per-event statistics where `timestamp` is the EVENT'S
# `utc_time_ms` (already in `Record.t`), and the payload carries the stats.
# ----------------------------------------------------------------------------


def _dd_sleep_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x09 DebugDataSleepStatistics — parse_sleep_statistics @ 0x2aed30.
    Wire (14 bytes): <sub:1><ticks_in_deep_sleep:u32 LE><ticks_in_sleep:u32 LE>
                     <ticks_awake:u32 LE><pfsm_state:u8>
    `timestamp` proto field comes from event.utc_time_ms (Record.t)."""
    if len(p) < 14:
        raise ValueError(f"sleep_statistics payload must be >=14 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataSleepStatistics",
        "ticks_in_deep_sleep": _u32(p, 1),
        "ticks_in_sleep": _u32(p, 5),
        "ticks_awake": _u32(p, 9),
        "pfsm_state": p[13],
    }


def _dd_flash_usage_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x0a DebugDataFlashUsageStatistics — parse_flash_usage_statistics @ 0x2aef60.
    Wire (13 bytes): <sub:1><ticks_reading:u32><ticks_writing:u32><ticks_erasing:u32>"""
    if len(p) < 13:
        raise ValueError(f"flash_usage payload must be >=13 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataFlashUsageStatistics",
        "ticks_reading_flash": _u32(p, 1),
        "ticks_writing_flash": _u32(p, 5),
        "ticks_erasing_flash": _u32(p, 9),
    }


def _dd_period_info_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x0c DebugDataPeriodInfoStatistics — parse_period_info_statistics @ 0x2af190.
    Wire (10 bytes): <sub:1><ticks_measuring_last_period:u32>
                     <systime_spent_in_last_state_raw:u32><pfsm_state:u8>
    `systime_spent_in_last_state_s` (float) = raw_u32 / 10.0."""
    if len(p) < 10:
        raise ValueError(f"period_info payload must be >=10 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataPeriodInfoStatistics",
        "ticks_measuring_last_period": _u32(p, 1),
        "systime_spent_in_last_state_s": _u32(p, 5) / 10.0,
        "pfsm_state": p[9],
    }


def _dd_ble_usage_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x0d DebugDataBleUsageStatistics — parse_ble_usage_statistics @ 0x2afea0.
    Wire (13 bytes): <sub:1><ticks_fast:u32><ticks_slow:u32><ticks_advertising:u32>"""
    if len(p) < 13:
        raise ValueError(f"ble_usage payload must be >=13 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataBleUsageStatistics",
        "ticks_fast_mode": _u32(p, 1),
        "ticks_slow_mode": _u32(p, 5),
        "ticks_advertising_mode": _u32(p, 9),
    }


def _dd_fuel_gauge_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x14 DebugDataFuelGaugeStatistics — parse_fuel_gauge_statistics @ 0x2b0684.
    Wire (14 bytes):
      <sub:1>
      <battery_pct_raw:u16>             (fixed-point: raw / 256.0 → percent)
      <average_battery_voltage_mv:u16>
      <average_current_consumption:i32> (signed)
      <remaining_capacity:u16>
      <coulomb_high:s8><coulomb_mid:u8><coulomb_low:u8>  (signed 24-bit)
    """
    if len(p) < 14:
        raise ValueError(f"fuel_gauge payload must be >=14 bytes, got {len(p)}")
    cc = (_i8(p[11]) << 16) | (p[12] << 8) | p[13]
    return {
        "_dd": "DebugDataFuelGaugeStatistics",
        "battery_percentage": _u16(p, 1) / 256.0,
        "average_battery_voltage_mv": _u16(p, 3),
        "average_current_consumption": _i32(p, 5),
        "remaining_capacity": _u16(p, 9),
        "coulomb_counter": cc,
    }


def _dd_event_sync_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x1a DebugDataEventSyncStatistics — parse_event_sync_statistics @ 0x2b1174.
    Wire (12 bytes): <sub:1><connection_interval:u16>
                     <synced_bytes_count:u32><sync_duration_ms:u32><mtu:u8>"""
    if len(p) < 12:
        raise ValueError(f"event_sync payload must be >=12 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataEventSyncStatistics",
        "connection_interval": _u16(p, 1),
        "synced_bytes_count": _u32(p, 3),
        "sync_duration_in_ms": _u32(p, 7),
        "mtu": p[11],
    }


def _dd_event_sync_cache_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x23 DebugDataEventSyncCacheStatistics — parse_event_sync_cache_statistics @ 0x2b2a9c.
    Wire (13 bytes): each of 4 fields = u16-LE | (u8 << 16) → effective u24 LE.
    Layout: <sub:1>
            <hdr_cache_lo:u16><hdr_cache_hi:u8>
            <hdr_flash_lo:u16><hdr_flash_hi:u8>
            <evt_cache_lo:u16><evt_cache_hi:u8>
            <evt_flash_lo:u16><evt_flash_hi:u8>"""
    if len(p) < 13:
        raise ValueError(f"event_sync_cache payload must be >=13 bytes, got {len(p)}")
    def u24(lo_off: int, hi_off: int) -> int:
        return _u16(p, lo_off) | (p[hi_off] << 16)
    return {
        "_dd": "DebugDataEventSyncCacheStatistics",
        "header_read_count_from_cache": u24(1, 3),
        "header_read_count_from_flash": u24(4, 6),
        "event_read_count_from_cache": u24(7, 9),
        "event_read_count_from_flash": u24(10, 12),
    }


def _dd_acm_configuration_changed(p: bytes) -> dict[str, Any]:
    """0x61/0x29 DebugDataAcmConfigurationChanged — parse_acm_configuration_change @ 0x2b4304.
    Wire (8 bytes): <sub:1><mode:u8><acc_odr:u8><acc_range:u8>
                    <gyro_odr:u8><gyro_range:u8><event_mask_and_fifo:u16>
    The trailing u16 holds the accelerator-enabled-event-mask and the requested
    FIFO sample depth (proto field 8); the lib stores it as a single u16 so we
    surface the raw value."""
    if len(p) < 8:
        raise ValueError(f"acm_config payload must be >=8 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataAcmConfigurationChanged",
        "accelerometer_mode": p[1],
        "accelerometer_odr": p[2],
        "accelerometer_range": p[3],
        "gyroscope_odr": p[4],
        "gyroscope_range": p[5],
        "event_mask_and_fifo_u16": _u16(p, 6),
    }


class _BitStream:
    """LSB-first within each byte, MSB-first across the stream.
    Mirrors `parse_dd_ppg_sq_stat` at libringeventparser.so 0x2b6ec0.
    Reading N bits at (byte_off, bit_off) consumes them across byte boundaries
    and accumulates with left-shift, so bits read first end up in the high
    positions of the returned int."""

    __slots__ = ("buf", "byte_off", "bit_off")

    def __init__(self, buf: bytes, start_off: int = 0) -> None:
        self.buf = buf
        self.byte_off = start_off
        self.bit_off = 0

    def read(self, nbits: int) -> int:
        if not (0 <= nbits <= 32):
            raise ValueError(f"nbits {nbits} out of range")
        out = 0
        bits_consumed = 0
        while bits_consumed < nbits:
            if self.byte_off >= len(self.buf):
                raise ValueError("bit-stream underflow")
            byte = self.buf[self.byte_off]
            bits_avail = 8 - self.bit_off
            take = min(nbits - bits_consumed, bits_avail)
            mask = (1 << take) - 1
            val = (byte >> self.bit_off) & mask
            out = (out << take) | val
            self.bit_off += take
            if self.bit_off == 8:
                self.bit_off = 0
                self.byte_off += 1
            bits_consumed += take
        return out


def _dd_ppg_signal_quality_stats(p: bytes) -> dict[str, Any]:
    """0x61/0x35 DebugDataPpgSignalQualityStats — parse_ppg_signal_quality_stats @ 0x2b714c.

    Wire layout:
      <sub:1>
      <byte_1:u8>           high nibble = ppg_measurement_slot_1, low nibble = slot_2
      <byte_2:s8>           low 7 bits = tune_reason; sign bit must be 0 (else throw)
      <byte_3:u8>           led_channel_description_1 (per-record, often 30 = 0x1e)
      <byte_4:s8>           low 6 bits = content_mask flags 0..5; sign bit must be 0
      <bit-packed payload:* N bits per set flag, MSB-first across byte boundaries>

    Per-flag bit-widths (from dispatch at 0x2b71e8 onwards):
      flag 0 = 9 bits   → snr_value (left-shifted 11 in lib's accumulator combine)
      flag 1 = 4 + 8 b  → ac_amplitude (mantissa<<exponent encoding)
      flag 2 = 15 bits  → dc_value
      flag 3 = 9 bits   → coupling_index
      flag 4 = 4 bits   → tune_reason_extended
      flag 5 = 7 bits   → ibi_quality_percentage  (most common — ~all observed records)
      flag 6            → stateful (uses session); not decoded here
    """
    if len(p) < 5:
        raise ValueError(f"ppg_signal_quality_stats payload must be >=5 bytes, got {len(p)}")
    b1 = p[1]
    b2 = p[2]
    b3 = p[3]
    b4 = p[4]
    if b2 & 0x80 or b4 & 0x80:
        raise ValueError("ppg_signal_quality_stats validity bit set")
    content_mask = b4 & 0x3F
    out: dict[str, Any] = {
        "_dd": "DebugDataPpgSignalQualityStats",
        "ppg_measurement_slot_1": b1 >> 4,
        "ppg_measurement_slot_2": b1 & 0x0F,
        "tune_reason": b2 & 0x7F,
        "led_channel_description_1": b3,
        "content_mask": content_mask,
    }
    if b4 & 0x40:
        out["stateful_flag_set"] = True
        out["bit_payload_hex"] = p[5:].hex()
        return out
    if len(p) > 5:
        bs = _BitStream(p, start_off=5)
        try:
            if content_mask & 0x01:
                out["snr_value"] = bs.read(9)
            if content_mask & 0x02:
                shift = bs.read(4)
                val = bs.read(8)
                out["ac_amplitude"] = val << shift
            if content_mask & 0x04:
                out["dc_value"] = bs.read(15)
            if content_mask & 0x08:
                out["coupling_index"] = bs.read(9)
            if content_mask & 0x10:
                out["tune_reason_extended"] = bs.read(4)
            if content_mask & 0x20:
                out["ibi_quality_percentage"] = bs.read(7)
        except ValueError:
            out["bit_payload_truncated"] = True
            out["bit_payload_hex"] = p[5:].hex()
    return out


def _dd_afe_statistics_values(p: bytes) -> dict[str, Any]:
    """0x61/0x28 DebugDataAfeStatisticsValues — parse_afe_statistics_values @ 0x2b37cc.

    Stateful: byte 1 distinguishes record kind (1 = session-header, 0 = continuation).
    The lib accumulates per-LED measurement counts across multiple records into a
    `DebugData_State_v1` at session()+0x138 and emits a single ParsedEvent at
    session-end. We surface the per-record kind + raw stats; full structured
    aggregation would mirror CvaPpgDecoder (left as future work). In the test
    capture all 2,710 records carry zero-stats, so this minimal decode loses
    nothing measurable — it correctly identifies the session structure."""
    if len(p) < 14:
        raise ValueError(f"afe_statistics_values payload must be >=14 bytes, got {len(p)}")
    kind_byte = p[1]
    return {
        "_dd": "DebugDataAfeStatisticsValues",
        "record_kind": "header" if kind_byte == 1 else ("continuation" if kind_byte == 0 else f"unknown_{kind_byte}"),
        "kind_byte": kind_byte,
        "stats_hex": p[2:].hex(),
        "all_stats_zero": all(b == 0 for b in p[2:]),
    }


def _dd_finger_detection(p: bytes) -> dict[str, Any]:
    """0x61/0x15 DebugDataFingerDetection — parse_finger_detection @ 0x2b08f0.
    Wire (9 bytes): <sub:1><detection_data:u64 LE> — single u64 carrying detection
    state bits (proto field semantics not exposed; surface the raw u64)."""
    if len(p) < 9:
        raise ValueError(f"finger_detection payload must be >=9 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataFingerDetection",
        "detection_u64": int.from_bytes(p[1:9], "little"),
    }


def _dd_battery_level_changed(p: bytes) -> dict[str, Any]:
    """0x61/0x24 DebugDataBatteryLevelChanged — parse_battery_level_changed @ 0x2ae568.
    Wire (≥5 bytes): <sub:1><battery_percentage:u8><battery_voltage_mv:u16 LE><reason:u8>

    Empirical (sunday_evening.log): pct ∈ [49..100], mv ∈ [3534..4141] —
    matches FuelGaugeStatistics independently. The percentage byte is the
    integer percent directly (0..100), NOT the fixed-point /256 form used
    by FuelGaugeStatistics.battery_percentage."""
    if len(p) < 5:
        raise ValueError(f"battery_level_changed payload must be >=5 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataBatteryLevelChanged",
        "battery_percentage": p[1],
        "battery_voltage_mv": _u16(p, 2),
        "reason": p[4],
    }


def _dd_lib_no_parser(p: bytes) -> dict[str, Any]:
    """Sub-bytes that map to the default-throw entry of the lib's dispatch
    table — the lib emits RepParseError for these. We surface them with an
    explicit `_dd` label so they're not confused with sub-bytes whose parser
    we just haven't written."""
    return {
        "_dd": "lib_no_parser",
        "sub_byte": p[0],
        "hex": p[1:].hex(),
        "len": len(p),
    }


# The lib's `parse_api_debug_data` dispatch table maps these 4 sub-bytes to its
# default-throw branch (RepParseError). BUT empirical inspection of the wire
# bytes shows they're NOT random garbage — each carries structure that the app
# clearly consumes downstream (debug-string buffers, periodic state reports).
# We decode them empirically:
#
#   0x04 (77 obs):    ASCII text debug strings (EHRts/chg_rp/DF-…); same
#                      family as 0x43 DEBUG_EVENT_IND, just routed through 0x61.
#   0x30 (111 obs):   1-byte counter (0x07/0x08) followed by 11 constant
#                      bytes — looks like a periodic counter/heartbeat.
#   0x3b (1,323 obs): u16 LE at offset 2 alternates between 40000 / 20000
#                      (exactly balanced 662/661) — AFE sample-rate ticks.
#   0x3c (69 obs):    Variable-length record; first 3 bytes always 0xff 0x01
#                      0x00 (header), then a sub-sub-byte (commonly 0x09).


# ---- Smaller, lower-volume DD sub-types: minimal decoders that surface the
# proto type label + the raw bytes. Each lib parser exists; field-level decode
# left as future work since these are <10 records each in our 70 h capture. ----

def _dd_security_failure(p: bytes) -> dict[str, Any]:
    """0x61/0x0f — parse_security_failure @ 0x2af828. Multi-case dispatch
    on byte 1 (failure kind). Bytes 2..4 = u8 sub-fields; bytes 4..6 = u16."""
    if len(p) < 5:
        raise ValueError("security_failure payload too short")
    return {"_dd": "DebugDataSecurityFailure", "kind": p[1], "fields_hex": p[2:].hex()}


def _dd_bootloader_debug_log(p: bytes) -> dict[str, Any]:
    """0x61/0x1b — parse_bootloader_debug_log @ 0x2b13a4. Variable-length;
    typically ≥7 bytes."""
    return {"_dd": "DebugDataBootLoaderDebugLog", "fields_hex": p[1:].hex(), "len": len(p)}


def _dd_fuel_gauge_register_dump(p: bytes) -> dict[str, Any]:
    """0x61/0x1e — parse_fuel_gauge_register_dump @ 0x2b1f70. Wire (≥14 bytes):
    <reg_id_a:u16 LE><body:8 bytes><reg_id_b:u16 LE>."""
    if len(p) < 14:
        raise ValueError("fuel_gauge_register_dump payload too short")
    return {
        "_dd": "DebugDataFuelGaugeRegisterDump",
        "reg_id_a": _u16(p, 2),
        "reg_id_b": _u16(p, 12),
        "body_hex": p[4:12].hex(),
    }


def _dd_ring_hw_information(p: bytes) -> dict[str, Any]:
    """0x61/0x1f — parse_ring_hw_information @ 0x2b21a8. Reads u32 at +3."""
    if len(p) < 9:
        raise ValueError("ring_hw_information payload too short")
    return {"_dd": "DebugDataRingHwInformation", "u32_at_3": _u32(p, 3), "fields_hex": p[1:].hex()}


def _dd_charging_ended_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x20 — parse_charging_ended_statistics @ 0x2b23f0. Reads u32 at +1, u32 at +7."""
    if len(p) < 12:
        raise ValueError("charging_ended_statistics payload too short")
    return {
        "_dd": "DebugDataChargingEndStatistics",
        "u32_at_1": _u32(p, 1),
        "u32_at_7": _u32(p, 7),
        "fields_hex": p[1:].hex(),
    }


def _dd_fuel_gauge_logging_registers(p: bytes) -> dict[str, Any]:
    """0x61/0x21 — parse_fuel_gauge_logging_registers @ 0x2b2628. Reads 8 bytes at +1."""
    if len(p) < 9:
        raise ValueError("fuel_gauge_logging_registers payload too short")
    return {"_dd": "DebugDataFuelGaugeLoggingRegisters", "registers_hex": p[1:9].hex()}


def _dd_hardware_test_start_values(p: bytes) -> dict[str, Any]:
    """0x61/0x25 — parse_hardware_test_start_values @ 0x2b2cec. Reads u16 at +2, 8 bytes at +5."""
    if len(p) < 13:
        raise ValueError("hardware_test_start_values payload too short")
    return {
        "_dd": "DebugDataHardwareTestStartValues",
        "u16_at_2": _u16(p, 2),
        "body_hex": p[5:13].hex(),
    }


def _dd_charging_ended_statistics_continued(p: bytes) -> dict[str, Any]:
    """0x61/0x27 — parse_charging_ended_statistics_continued @ 0x2b359c. Reads
    8 bytes at +1, u32 at +9."""
    if len(p) < 13:
        raise ValueError("charging_ended_statistics_continued payload too short")
    return {
        "_dd": "DebugDataChargingEndStatisticsContinued",
        "body_hex": p[1:9].hex(),
        "u32_at_9": _u32(p, 9),
    }


def _dd_field_test_information(p: bytes) -> dict[str, Any]:
    """0x61/0x2a — parse_field_test_information @ 0x2b47ac. Multi-case on byte 1."""
    if len(p) < 2:
        raise ValueError("field_test_information payload too short")
    return {"_dd": "DebugDataFieldTestInformation", "kind": p[1], "fields_hex": p[2:].hex()}


def _dd_stack_usage_statistics(p: bytes) -> dict[str, Any]:
    """0x61/0x2b — parse_stack_usage_statistics @ 0x2b4ac8. Reads 8 bytes at +1, u32 at +9."""
    if len(p) < 13:
        raise ValueError("stack_usage_statistics payload too short")
    return {
        "_dd": "DebugDataStackUsageStatistics",
        "stack_high_watermarks_hex": p[1:9].hex(),
        "u32_at_9": _u32(p, 9),
    }


def _dd_daily_drop_sample(p: bytes) -> dict[str, Any]:
    """0x61/0x3f — parse_daily_drop_sample @ 0x2bb4a4. Reads 3 u8 fields at +1..+3."""
    if len(p) < 4:
        raise ValueError("daily_drop_sample payload too short")
    return {
        "_dd": "DebugDataDailyDropSample",
        "byte_1": p[1],
        "byte_2": p[2],
        "byte_3": p[3],
        "fields_hex": p[4:].hex(),
    }


# ---- Stateful DD sub-types: per-record structured decode + multi-record kind
# label. Full session-state aggregation (matching `Session+0x138 DebugData_State_v1`)
# is left as future work; consumers can build it on top using `_dd` + `kind`. ----


def _dd_charger_information(p: bytes) -> dict[str, Any]:
    """0x61/0x36 — `parse_charger_information` @ 0x2b80c0. Stateful: each record
    contributes one `sub_sub_type` (low 7 bits of byte 1) to a session-level
    accumulator at `Session+0x138`. The lib emits `ChargerLinkParams` /
    `ChargerFirmwareAndPsn` / `ChargerSelfTestResult` after the session is
    flushed. We surface per-record structure:

      <sub:1><kind:u8>           kind bit 7 = `is_session_start`,
                                  kind bits 0..6 = `sub_sub_type` (0..4):
        - 0x01: ASCII text       (e.g. firmware/PSN: "60503789")
        - 0x02: u32 timestamp(?)
        - 0x03: charger self-test sub-record
        - 0x04: 2× u32 link params (stored at session +0x164/+0x168)
      <body>:                    sub-sub-type-specific bytes
    """
    if len(p) < 2:
        raise ValueError("charger_information payload too short")
    kind = p[1]
    sst = kind & 0x7F
    is_start = bool(kind >> 7)
    out: dict[str, Any] = {
        "_dd": "DebugDataChargerInformation",
        "is_session_start": is_start,
        "sub_sub_type": sst,
    }
    body = p[2:]
    if sst == 0x01 and body:
        try:
            out["text"] = body.decode("ascii", errors="replace")
        except Exception:
            out["body_hex"] = body.hex()
    elif sst == 0x04 and len(body) >= 8:
        out["link_param_a"] = _u32(body, 0)
        out["link_param_b"] = _u32(body, 4)
        if len(body) > 8:
            out["body_tail_hex"] = body[8:].hex()
    else:
        out["body_hex"] = body.hex()
    return out


def _dd_charger_debug_information(p: bytes) -> dict[str, Any]:
    """0x61/0x3d — `parse_charger_debug_information` @ 0x2b9f24. Stateful:
    `record_kind == 0` is a header announcing what's coming; `record_kind == 1`
    is a continuation data part. Helpers:
      `process_charger_debug_header` @ 0x2b9878
      `process_charger_debug_data_part` @ 0x2b9af4
      `is_charger_debug_info_ready` @ 0x2b9588
      `emit_charger_debug_info` @ 0x2b95d8 — fires when all parts are received.

    Per-record fields:
      - record_kind = "header" (0) | "continuation" (1)
      - For headers: `meta_hex` (≥7 bytes encoding sub-type + length + flags)
      - For continuations: `data_hex` (variable-length payload bytes)
    """
    if len(p) < 2:
        raise ValueError("charger_debug_information payload too short")
    kind = p[1]
    out: dict[str, Any] = {"_dd": "DebugDataChargerDebugInformation", "kind_byte": kind}
    body = p[2:]
    if kind == 0:
        out["record_kind"] = "header"
        out["meta_hex"] = body.hex()
    elif kind == 1:
        out["record_kind"] = "continuation"
        out["data_hex"] = body.hex()
    else:
        out["record_kind"] = f"unknown_{kind}"
        out["body_hex"] = body.hex()
    return out


def _dd_hardware_test_result_values(p: bytes) -> dict[str, Any]:
    """0x61/0x26 — `parse_hardware_test_result_values` @ 0x2b2f24. Stateful:
    records arrive in triples (phase 0 = init, 1 = mid, 2 = final). Each phase
    populates different offsets in the session state at +0x138. Per-record
    fields by phase:
      - phase 0 (init):  bytes 2..6 = small u8 fields, bytes 6..10 = i32, bytes 10..12 = u16
      - phase 1 (mid):   bytes 2..4 = u16, bytes 4..6 = u16  (stored at session +0x1c2/+0x1c4)
      - phase 2 (final): bytes 2..6 = i32, bytes 6..10 = u32 (more storage)
    """
    if len(p) < 2:
        raise ValueError("hardware_test_result_values payload too short")
    phase = p[1]
    out: dict[str, Any] = {"_dd": "DebugDataHardwareTestResultValues", "phase_byte": phase}
    body = p[2:]
    if phase == 0:
        out["phase"] = "init"
        if len(body) >= 12:
            out["init_byte_2"] = body[0]
            out["init_byte_3"] = body[1]
            out["init_i32_at_4"] = _i32(body, 2)
            out["init_i32_at_8"] = _i32(body, 6) if len(body) >= 10 else None
            if len(body) > 10:
                out["init_tail_hex"] = body[10:].hex()
        else:
            out["body_hex"] = body.hex()
    elif phase == 1:
        out["phase"] = "mid"
        if len(body) >= 4:
            out["mid_u16_a"] = _u16(body, 0)
            out["mid_u16_b"] = _u16(body, 2)
        else:
            out["body_hex"] = body.hex()
    elif phase == 2:
        out["phase"] = "final"
        if len(body) >= 8:
            out["final_i32_at_2"] = _i32(body, 0)
            out["final_u32_at_6"] = _u32(body, 4)
        else:
            out["body_hex"] = body.hex()
    else:
        out["phase"] = f"unknown_{phase}"
        out["body_hex"] = body.hex()
    return out


def _dd_alt_text(p: bytes) -> dict[str, Any]:
    """0x61/0x04 — ASCII debug strings routed through DD instead of 0x43."""
    return {
        "_dd": "DebugDataText",
        "text": p[1:].decode("ascii", errors="replace"),
    }


def _dd_alt_periodic_counter(p: bytes) -> dict[str, Any]:
    """0x61/0x30 — 1-byte counter + constant payload."""
    if len(p) < 2:
        raise ValueError(f"alt_periodic payload must be >=2 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataPeriodicCounter",
        "counter_byte": p[1],
        "trailing_hex": p[2:].hex(),
    }


def _dd_alt_afe_period_tick(p: bytes) -> dict[str, Any]:
    """0x61/0x3b — AFE sample-period tick. Layout (7 bytes):
       <sub:1><pad:2><period_us:u16 LE><pad:2>
    Empirical: alternates between 40000 us (25 Hz) and 20000 us (50 Hz)."""
    if len(p) < 7:
        raise ValueError(f"afe_period_tick payload must be >=7 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataAfePeriodTick",
        "period_us": _u16(p, 3),
    }


def _dd_alt_ppg_cont(p: bytes) -> dict[str, Any]:
    """0x61/0x3c — Variable-length record, fixed 3-byte header `ff 01 00`,
    then 1 sub-sub-byte and a tail. Empirical: 91% of records have sub-sub
    `0x09` (9 unaccounted bytes follow). Co-occurs with `PPG_cont;NN` debug
    strings, suggesting a PPG continuation/control record."""
    if len(p) < 5:
        raise ValueError(f"alt_ppg_cont payload must be >=5 bytes, got {len(p)}")
    return {
        "_dd": "DebugDataPpgCont",
        "header_3b_hex": p[1:4].hex(),
        "sub_sub_byte": p[4],
        "tail_hex": p[5:].hex(),
    }


def _dd_open_afe_ppg_settings_data(p: bytes) -> dict[str, Any]:
    """0x61/0x33 DebugDataOpenAfePpgSettingsData — parse_open_afe_ppg_settings_data @ 0x2b5cb4.
    The full settings record (14 bytes) is chip-variant specific (MAX86171/3/8) with
    vendor PD/LED/ADC/DAC parameters; without per-vendor decoders we surface:
      - chip_variant byte at offset 1 (0x01=MAX86171, 0x02=MAX86173, 0x03=MAX86178)
      - settings_hex (remaining bytes)
    Note: the lib REQUIRES len > 12; shorter records (8B) are RepParseError'd
    and surface here as `chip_variant_only`."""
    if len(p) < 2:
        raise ValueError(f"open_afe_ppg_settings payload must be >=2 bytes, got {len(p)}")
    chip = p[1]
    chip_name = {0x01: "MAX86171", 0x02: "MAX86173", 0x03: "MAX86178"}.get(chip, f"unknown_0x{chip:02x}")
    out = {
        "_dd": "DebugDataOpenAfePpgSettingsData",
        "chip_variant": chip,
        "chip_variant_name": chip_name,
    }
    if len(p) >= 14:
        out["settings_hex"] = p[2:].hex()
    else:
        out["truncated"] = True
        out["payload_hex"] = p[2:].hex()
    return out


# Sub-byte → decoder dispatch (extracted from .rodata jump table at 0x121937).
# Sub-bytes whose lib table-entry is the default-throw (e.g. 0x03..0x08, 0x0b,
# 0x13, 0x16, 0x2f, 0x30, 0x39, 0x3b, 0x3c) get the `lib_no_parser` decoder so
# consumers can distinguish "lib emits RepParseError" from "we haven't written
# the decoder yet". The active table covers ~96% of all 0x61 records.
_DD_SUB_DECODERS: dict[int, Callable[[bytes], dict[str, Any]]] = {
    0x04: _dd_alt_text,                       # ASCII (lib throws but app uses)
    0x09: _dd_sleep_statistics,
    0x0a: _dd_flash_usage_statistics,
    0x0c: _dd_period_info_statistics,
    0x0d: _dd_ble_usage_statistics,
    0x0f: _dd_security_failure,
    0x14: _dd_fuel_gauge_statistics,
    0x15: _dd_finger_detection,
    0x1a: _dd_event_sync_statistics,
    0x1b: _dd_bootloader_debug_log,
    0x1e: _dd_fuel_gauge_register_dump,
    0x1f: _dd_ring_hw_information,
    0x20: _dd_charging_ended_statistics,
    0x21: _dd_fuel_gauge_logging_registers,
    0x23: _dd_event_sync_cache_statistics,
    0x24: _dd_battery_level_changed,
    0x25: _dd_hardware_test_start_values,
    0x26: _dd_hardware_test_result_values,    # stateful (Session)
    0x27: _dd_charging_ended_statistics_continued,
    0x28: _dd_afe_statistics_values,
    0x29: _dd_acm_configuration_changed,
    0x2a: _dd_field_test_information,
    0x2b: _dd_stack_usage_statistics,
    0x30: _dd_alt_periodic_counter,           # lib-no-parser-but-structured
    0x33: _dd_open_afe_ppg_settings_data,
    0x35: _dd_ppg_signal_quality_stats,
    0x36: _dd_charger_information,            # stateful (Session)
    0x3b: _dd_alt_afe_period_tick,            # lib-no-parser-but-structured
    0x3c: _dd_alt_ppg_cont,                   # lib-no-parser-but-structured
    0x3d: _dd_charger_debug_information,      # stateful (Session)
    0x3f: _dd_daily_drop_sample,
}
# Sub-bytes that map to the lib's default-throw branch AND we have not
# observed enough of to reverse-engineer (or which appear not in our captures):
_DD_LIB_NO_PARSER: set[int] = {0x03, 0x05, 0x06, 0x07, 0x08, 0x0b, 0x13,
                                0x16, 0x2f, 0x39}


def decode_debug_data(p: bytes) -> dict[str, Any]:
    """0x61 API_DEBUG_DATA — first byte selects sub-type per RTTI dispatch."""
    if not p:
        raise ValueError("DebugData payload is empty")
    sub = p[0]
    fn = _DD_SUB_DECODERS.get(sub)
    if fn is None:
        if sub in _DD_LIB_NO_PARSER:
            return _dd_lib_no_parser(p)
        return {
            "_dd": f"unknown_sub_0x{sub:02x}",
            "sub_byte": sub,
            "hex": p.hex(),
            "len": len(p),
        }
    out = fn(p)
    out["sub_byte"] = sub
    return out


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
    0x61: decode_debug_data,
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
