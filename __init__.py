"""open_ring — pure-Python read-only driver for the Oura Ring 4 BLE protocol.

Public API:

    from oura_ring import Record, decode, replay
    from oura_ring.framing import parse_inner_records, parse_outer_frames

For now the live BLE transport is a TODO; offline replay against btsnoop logs
is the supported entry point:

    python -m oura_ring.cli sunday_evening.log
"""
from __future__ import annotations

from .decoders import canonical_type, decode
from .envelope import Record
from .framing import (
    OPCODES,
    OuterFrame,
    InnerRecord,
    parse_outer_frames,
    parse_inner_records,
    looks_like_outer_frame,
)
from .replay import replay

__all__ = [
    "Record",
    "decode",
    "canonical_type",
    "OPCODES",
    "OuterFrame",
    "InnerRecord",
    "parse_outer_frames",
    "parse_inner_records",
    "looks_like_outer_frame",
    "replay",
]

__version__ = "0.1.0"
