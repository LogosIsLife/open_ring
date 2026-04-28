"""Offline replay: read a btsnoop HCI capture, emit JSONL records.

This is the reference implementation of the driver's decode pipeline against
real wire data, without needing a live ring. Same envelope format as the
live driver will produce.
"""
from __future__ import annotations

import struct
import sys
from collections.abc import Iterator
from pathlib import Path

from .decoders import canonical_type, decode
from .envelope import Record
from .framing import (
    OPCODES,
    looks_like_outer_frame,
    parse_inner_records,
    parse_outer_frames,
)


# btsnoop epoch is 0001-01-01; offset to Unix epoch in microseconds
BTSNOOP_EPOCH_OFFSET_US = 0x00DCDDB30F2F8000


def btsnoop_packets(path: str | Path) -> Iterator[tuple[float, bytes]]:
    """Yield (unix_t_seconds, packet_bytes) tuples from a btsnoop file."""
    with open(path, "rb") as f:
        header = f.read(16)
        if header[:8] != b"btsnoop\x00":
            raise ValueError(f"not a btsnoop file: {path}")
        while True:
            h = f.read(24)
            if len(h) < 24:
                break
            _orig, incl, _flags, _drops, ts_h, ts_l = struct.unpack(">IIIIii", h)
            ts_us = ((ts_h & 0xffffffff) << 32) | (ts_l & 0xffffffff)
            unix_t = (ts_us - BTSNOOP_EPOCH_OFFSET_US) / 1e6
            yield unix_t, f.read(incl)


def parse_att(pkt: bytes) -> tuple[int, int, bytes] | None:
    """Extract (att_op, att_handle, att_value) from an HCI ACL packet, or None.

    H4: [type:1=0x02 ACL][acl_handle:2 LE][acl_len:2 LE]
        [l2cap_len:2 LE][l2cap_cid:2 LE]
        [att_op:1][att_handle:2 LE][value...]
    """
    if len(pkt) < 12 or pkt[0] != 0x02:
        return None
    att_op = pkt[9]
    if att_op not in (0x12, 0x52, 0x1B):  # write_req / write_cmd / notify
        return None
    handle = pkt[10] | (pkt[11] << 8)
    return att_op, handle, pkt[12:]


def replay(
    path: str | Path,
    *,
    cmd_handle: int = 0x0015,
    notify_handle: int = 0x0012,
) -> Iterator[Record]:
    """Walk a btsnoop file and yield Records (envelope-shaped) for every
    decodable record / control event observed.
    """
    # The lib emits utc_time_ms for each parsed event; offline we have the
    # btsnoop arrival timestamp which is the BLE controller's view (close enough
    # — typically <100 ms drift from the on-wire ring time-corrected timestamp).
    for ts_seconds, pkt in btsnoop_packets(path):
        parsed = parse_att(pkt)
        if not parsed:
            continue
        att_op, handle, value = parsed
        utc_ms = int(ts_seconds * 1000)

        # Decide direction (only used for synthetic events; inner records are
        # always ring→phone)
        if att_op in (0x12, 0x52) and handle == cmd_handle:
            direction = "phone"
        elif att_op == 0x1B and handle == notify_handle:
            direction = "ring"
        else:
            continue

        if looks_like_outer_frame(value):
            for f in parse_outer_frames(value):
                rec = _outer_to_record(f, direction, utc_ms)
                if rec is not None:
                    yield rec
        else:
            # Inner record stream (always ring→phone in normal use)
            if direction != "ring":
                continue
            for r in parse_inner_records(value):
                yield Record(
                    t=utc_ms,
                    rt=None,                # ring_time isn't in the inner-record TLV
                    ctr=r.counter,
                    sess=r.session,
                    tag=f"0x{r.type_byte:02x}",
                    type=canonical_type(r.type_byte),
                    data=decode(r.type_byte, r.payload),
                )


def _outer_to_record(f, direction: str, utc_ms: int) -> Record | None:
    """Translate selected outer frames into synthetic envelope records.

    We only emit records for outer frames the driver actually exposes to
    consumers (battery, time-sync, handshake completion, etc.). Routine
    framing (subscribe acks, capability negotiation) is filtered out.
    """
    op = f.opcode

    # Battery response: 0d 06 <byte_a> <byte_b> <byte_c> <byte_d> <voltage:2 LE>
    if op == 0x0d and direction == "ring" and len(f.raw) == 8:
        voltage_mv = f.raw[6] | (f.raw[7] << 8)
        return Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_BATTERY", type="_BATTERY",
            data={
                "voltage_mv": voltage_mv,
                "state_bytes": list(f.raw[2:6]),
            },
        )

    # Time-sync request: 12 09 <token> <counter:3 LE> <const:5>
    if op == 0x12 and direction == "phone" and len(f.raw) == 11:
        token = f.raw[2]
        counter = f.raw[3] | (f.raw[4] << 8) | (f.raw[5] << 16)
        return Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_TIME_SYNC_REQ", type="_TIME_SYNC_REQ",
            data={"token": token, "time_counter": counter},
        )

    # Time-sync reply: 13 05 <ack_code> <time_echo:3 LE> 00
    if op == 0x13 and direction == "ring" and len(f.raw) == 7:
        ack = f.raw[2]
        echo = f.raw[3] | (f.raw[4] << 8) | (f.raw[5] << 16)
        return Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_TIME_SYNC_REPLY", type="_TIME_SYNC_REPLY",
            data={"ack_code": ack, "time_echo": echo},
        )

    # Handshake nonce: ring 2F 10 2C <nonce:15>
    if op == 0x2f and direction == "ring" and f.sub_op == 0x2c and len(f.raw) == 18:
        return Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_HANDSHAKE_NONCE", type="_HANDSHAKE_NONCE",
            data={"nonce_hex": f.raw[3:18].hex()},
        )

    # Handshake proof: phone 2F 11 2D <proof:16>
    if op == 0x2f and direction == "phone" and f.sub_op == 0x2d and len(f.raw) == 19:
        return Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_HANDSHAKE_PROOF", type="_HANDSHAKE_PROOF",
            data={"proof_hex": f.raw[3:19].hex()},
        )

    # Handshake status: ring 2F 02 2E <status:1>
    if op == 0x2f and direction == "ring" and f.sub_op == 0x2e and len(f.raw) == 4:
        status = f.raw[3]
        return Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_HANDSHAKE_OK" if status == 0 else "_HANDSHAKE_FAIL",
            type="_HANDSHAKE_OK" if status == 0 else "_HANDSHAKE_FAIL",
            data={"status": status},
        )

    # All other outer frames: silent (or could expose as _CONTROL_FRAME if needed)
    return None


def main_replay(argv: list[str] | None = None) -> int:
    """CLI: `python -m oura_ring.replay <btsnoop>` → JSONL on stdout."""
    import argparse
    ap = argparse.ArgumentParser(description="Replay an Oura btsnoop capture as JSONL.")
    ap.add_argument("btsnoop", help="Path to btsnoop_hci.log")
    ap.add_argument("--cmd-handle", type=lambda x: int(x, 0), default=0x0015)
    ap.add_argument("--notify-handle", type=lambda x: int(x, 0), default=0x0012)
    args = ap.parse_args(argv)

    out = sys.stdout
    for rec in replay(args.btsnoop, cmd_handle=args.cmd_handle, notify_handle=args.notify_handle):
        out.write(rec.to_json())
        out.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main_replay())
