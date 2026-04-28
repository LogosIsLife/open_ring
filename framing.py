"""Wire framing.

Two layers:
  1. Outer frame on either characteristic: <op:1><len:1><sub:1><payload:len-1>
     Multiple frames may pack into one ATT value; consume `2 + len` and loop.
  2. Inner record stream on the notify char: TLV
     <type:1><len:1><ctr_lo:1><ctr_hi:1><sess_lo:1><sess_hi:1><payload:len-4>
     Records concatenate up to MTU.

A single notification value may carry EITHER outer frames OR inner records.
The first byte disambiguates: if it's a known outer-frame opcode, treat the
value as outer frames; otherwise as inner-record stream.
"""
from __future__ import annotations

from dataclasses import dataclass


# Outer-frame opcode catalog. Bidirectional (phone↔ring); no
# "phone-only" or "ring-only" coloring at this layer.
OPCODES: dict[int, str] = {
    0x06: "identity_req",       0x07: "identity_resp",
    0x08: "time_or_id_req",     0x09: "time_or_id_resp",
    0x0c: "battery_req",        0x0d: "battery_resp",
    0x10: "history_fetch",      0x11: "history_fetch_resp",
    0x12: "time_sync_req",      0x13: "time_sync_resp",
    0x16: "subscribe",          0x17: "subscribe_ack",
    0x18: "event_subscribe",    0x19: "event_resp",
    0x1c: "state_cmd",          0x1d: "state_cmd_resp",
    0x1e: "state_query",        0x1f: "state_query_resp",
    0x24: "fw_authorize",
    0x28: "data_flush",         0x29: "data_flush_ack",
    0x2b: "fw_progress",
    0x2c: "fw_bulk",
    0x2f: "secure_session",
}


@dataclass
class OuterFrame:
    opcode: int
    sub_op: int | None       # first byte of payload, by convention
    body: bytes              # everything AFTER length, INCLUDING sub_op
    raw: bytes               # entire frame including opcode + length

    @property
    def name(self) -> str:
        return OPCODES.get(self.opcode, f"unknown_{self.opcode:02x}")


@dataclass
class InnerRecord:
    type_byte: int
    counter: int             # uint16 LE
    session: int             # uint16 LE
    payload: bytes           # bytes after the 4-byte ctr+sess header


def parse_outer_frames(value: bytes) -> list[OuterFrame]:
    """Return zero or more outer frames packed into one ATT value.

    Stops parsing on the first byte that isn't a known opcode (which
    typically signals an inner-record stream instead).
    """
    out: list[OuterFrame] = []
    i = 0
    while i + 2 <= len(value):
        op, ln = value[i], value[i + 1]
        if op not in OPCODES or i + 2 + ln > len(value):
            break
        body = value[i + 2:i + 2 + ln]
        sub = body[0] if ln >= 1 else None
        out.append(OuterFrame(opcode=op, sub_op=sub, body=body, raw=value[i:i + 2 + ln]))
        i += 2 + ln
    return out


def parse_inner_records(value: bytes) -> list[InnerRecord]:
    """Return zero or more inner records concatenated into one notification."""
    out: list[InnerRecord] = []
    i = 0
    while i + 2 <= len(value):
        t, ln = value[i], value[i + 1]
        body = value[i + 2:i + 2 + ln]
        if len(body) != ln or ln < 4:
            break
        ctr = body[0] | (body[1] << 8)
        sess = body[2] | (body[3] << 8)
        out.append(InnerRecord(type_byte=t, counter=ctr, session=sess, payload=body[4:]))
        i += 2 + ln
    return out


def looks_like_outer_frame(value: bytes) -> bool:
    """First-byte test: is this an outer frame stream or inner records?"""
    return bool(value) and value[0] in OPCODES
