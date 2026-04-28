"""JSONL envelope for decoded records.

Each record on the wire produces one line of JSON of the form:

  {"t": <utc_time_ms>, "rt": <ring_time>, "ctr": <counter>, "sess": <session>,
   "tag": "0xNN", "type": "<canonical name>", "data": { ... }}

Synthetic driver-side events use the same envelope with `tag` and `type`
prefixed by underscore (e.g., `_HANDSHAKE_OK`, `_BATTERY`, `_TIME_SYNC`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Record:
    t: int                  # utc_time_ms — Unix epoch ms (time-sync corrected)
    rt: int | None          # ring_time — uint32 from TLV header (None for synthetic events)
    ctr: int | None         # per-type counter — uint16 from TLV header (None for synthetic)
    sess: int | None        # session_id — uint16 from TLV header (None for synthetic)
    tag: str                # wire byte hex string ("0x60") OR underscore-prefixed for synthetic
    type: str               # canonical name (API_* or _SYNTHETIC_*)
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        d = {"t": self.t, "tag": self.tag, "type": self.type}
        if self.rt is not None:   d["rt"] = self.rt
        if self.ctr is not None:  d["ctr"] = self.ctr
        if self.sess is not None: d["sess"] = self.sess
        d["data"] = self.data
        return json.dumps(d, separators=(",", ":"), allow_nan=False, default=_default)


def _default(o):
    """JSON encoder fallback for NaN floats and bytes."""
    if isinstance(o, float):
        # NaN and infinities → null (per envelope contract: "missing → null")
        return None
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    raise TypeError(f"Cannot serialize {type(o).__name__}")
