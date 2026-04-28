"""State-tracking models for the ring and the client/driver.

Two small dataclasses, each with an `apply(record)` method that consumes one
JSONL Record (synthetic or wire) and mutates internal state.

Design:
- The two states are independent and consume the same `Record` stream.
- Both are pure data + one method; no I/O, no threading.
- Parsing of `0x43 API_DEBUG_EVENT_IND` ASCII strings is the primary source of
  state-machine info (DHR, CVA, A:SA, EHR, charging, orientation, …).
- Wire-typed events (StateChangeInd, WearEvent, RingStartInd, _BATTERY,
  _HANDSHAKE_*, _TIME_SYNC_*) drive the rest.

Usage:
    ring = RingState()
    client = ClientState()
    for rec in replay("capture.log"):
        ring.apply(rec)
        client.apply(rec)
    print(ring.snapshot())
    print(client.snapshot())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any

from .enums import STATE_CHANGE
from .envelope import Record


# ----- regex parsers for ASCII debug strings --------------------------------
# These are the high-value formats; everything else goes into `last_debug_text`.

_DHR_STATE   = re.compile(r"^DHR_state:(\d+)$")
_DHR_MODE    = re.compile(r"^DHR_mode:(\d+)$")
_CVA_STATE   = re.compile(r"^CVA_state;(\d+)$")
_A_SA        = re.compile(r"^A:SA:(\d+),(\d+)>(\d+)$")
_EHR_STATE   = re.compile(r"^EHRst;(\d+);(\d+);(\d+)$")
_BATT_PCT    = re.compile(r"^batt:\s*(\d+)$")
_ORIENT      = re.compile(r"^orientation\s+(\d+)$")
_CHG_IND     = re.compile(r"^chg_ind;(\d+);(\d+)$")
_BLESTDA     = re.compile(r"^blestda;(\d+)$")
_O2MODE      = re.compile(r"^O2Mode;(\d+)$")


# ----- RingState ------------------------------------------------------------


@dataclass
class RingState:
    """Reflects what the ring believes its own state is.

    Updated from records flowing in. Not authoritative — the source of truth
    is the ring itself; we infer from observed wire signals.
    """

    # ---- BLE-link
    is_connected: bool = False
    last_seen_ms: int | None = None       # last time *any* record arrived

    # ---- Identity (from RingStartInd)
    firmware_version: str | None = None
    bootloader_version: str | None = None
    api_version: str | None = None
    ring_type: int | None = None
    serial: str | None = None

    # ---- Unified state-machine (StateChangeInd / WearEvent — same enum)
    state: int | None = None              # numeric StateChange value (0..30)
    state_name: str | None = None         # canonical name from enum
    state_text: str | None = None         # debug-info text accompanying transition
    state_changes_seen: int = 0

    # ---- Sub-state machines (from 0x43 debug strings)
    dhr_state: int | None = None          # 0,1,2,4 main + 5 retry
    dhr_mode: int | None = None
    dhr_state_changes: int = 0             # raw transitions (any → any)
    dhr_main_loop_count: int = 0           # full 0→1→4→2→0 traversals
    dhr_retry_count: int = 0               # branches into state 5
    dhr_history: list[int] = field(default_factory=list)   # last ~30 states
    dhr_state_counts: dict[int, int] = field(default_factory=dict)

    cva_state: int | None = None          # 1→2→3→4→5→1 (0 = idle/scan-not-in-progress)
    cva_revolutions: int = 0               # count of 5→1 transitions (= full revolutions)
    cva_history: list[int] = field(default_factory=list)
    cva_state_counts: dict[int, int] = field(default_factory=dict)
    # ↑ surfaces the original analysis's per-state tally (x8/x11/x11/x11/x9)

    sleep_active: tuple[int, int] | None = None   # last (x,y) from A:SA
    sleep_active_target: int | None = None         # the >z (next/target state from A:SA)
    sleep_active_transitions: int = 0
    sleep_active_pair_counts: dict[str, int] = field(default_factory=dict)
    # ↑ tally of how often each (x,y) pair is seen — surfaces the "1,1 ↔ 1,2 ping-pong"
    # pattern from the original analysis

    ehr_state: tuple[int, int, int] | None = None   # last (a,b,c) from EHRst

    orientation: int | None = None

    o2_mode: int | None = None            # SpO₂ feature on/off

    # ---- Battery / charging
    battery_pct: int | None = None        # 0..100 (from "batt:" debug or _BATTERY)
    battery_voltage_mv: int | None = None
    charging_state: int | None = None     # 0..N from chg_ind first arg
    charging_validity: int | None = None  # 0..N from chg_ind second arg

    # ---- Time sync
    last_time_sync_ack_unix_ms: int | None = None
    ring_time_counter_echo: int | None = None      # last ack from 0x13

    # ---- Records seen, for sanity / driver UX
    last_record_type: str | None = None
    record_count_by_type: dict[str, int] = field(default_factory=dict)

    # ---- Latest unparsed debug string (handy for ad-hoc display)
    last_debug_text: str | None = None

    # ---- Control-plane state: known parameter values
    # 4-byte struct per param. We update from _PARAM_READ_RESP and _PARAM_PUSH.
    # Keys are documented param IDs (0x02 DHR, 0x03 ActivityHR, 0x04 SpO2, etc.).
    params: dict[int, list[int]] = field(default_factory=dict)
    last_param_push_at_ms: int | None = None

    # ----- mutation -----

    def apply(self, rec: Record) -> None:
        self.last_seen_ms = rec.t
        self.is_connected = True       # any record means link is up *for this moment*
        self.last_record_type = rec.type
        self.record_count_by_type[rec.type] = self.record_count_by_type.get(rec.type, 0) + 1

        if rec.type == "_DISCONNECT":
            self.is_connected = False
            return
        if rec.type == "_BATTERY":
            self.battery_voltage_mv = rec.data.get("voltage_mv")
            return
        if rec.type == "_TIME_SYNC_REPLY":
            self.last_time_sync_ack_unix_ms = rec.t
            self.ring_time_counter_echo = rec.data.get("time_echo")
            return
        if rec.type in ("_PARAM_READ_RESP", "_PARAM_PUSH"):
            pid = rec.data.get("param_id")
            val = rec.data.get("value")
            if pid is not None and val is not None:
                self.params[pid] = list(val)
            if rec.type == "_PARAM_PUSH":
                self.last_param_push_at_ms = rec.t
            return

        if rec.type == "API_RING_START_IND":
            # Wire-extracted fields are limited; richer firmware/bootloader strings
            # arrive in DB-mirrored RingStartIndication rows on Android. Here we
            # only get what the wire payload carries directly.
            self.state = None     # ring just started; no state yet
            self.state_changes_seen += 1
            return

        if rec.type in ("API_STATE_CHANGE_IND", "API_WEAR_EVENT"):
            new = rec.data.get("state")
            if new is not None and new != self.state:
                self.state_changes_seen += 1
            self.state = new
            self.state_name = STATE_CHANGE.get(new) if new is not None else None
            self.state_text = rec.data.get("text") or None
            return

        if rec.type == "API_DEBUG_EVENT_IND":
            self._apply_debug(rec.data.get("text") or "")
            return

    def _apply_debug(self, text: str) -> None:
        self.last_debug_text = text

        m = _DHR_STATE.match(text)
        if m:
            n = int(m.group(1))
            prev = self.dhr_state
            if prev is not None and prev != n:
                self.dhr_state_changes += 1
                # Original analysis: main loop is 0→1→4→2→0; state 5 is a retry branch
                if prev == 2 and n == 0:
                    self.dhr_main_loop_count += 1
                if n == 5:
                    self.dhr_retry_count += 1
            self.dhr_state = n
            self.dhr_history.append(n)
            del self.dhr_history[:-30]
            self.dhr_state_counts[n] = self.dhr_state_counts.get(n, 0) + 1
            return

        m = _DHR_MODE.match(text)
        if m:
            self.dhr_mode = int(m.group(1))
            return

        m = _CVA_STATE.match(text)
        if m:
            n = int(m.group(1))
            # A full CVA revolution is specifically the 5→1 wrap (per the original
            # analysis: 1→2→3→4→5→1 is one revolution).
            if self.cva_state == 5 and n == 1:
                self.cva_revolutions += 1
            self.cva_state = n
            self.cva_history.append(n)
            del self.cva_history[:-30]
            self.cva_state_counts[n] = self.cva_state_counts.get(n, 0) + 1
            return

        m = _A_SA.match(text)
        if m:
            x, y, z = (int(g) for g in m.groups())
            new_pair = (x, y)
            if self.sleep_active is not None and new_pair != self.sleep_active:
                self.sleep_active_transitions += 1
            self.sleep_active = new_pair
            self.sleep_active_target = z
            key = f"{x},{y}"
            self.sleep_active_pair_counts[key] = self.sleep_active_pair_counts.get(key, 0) + 1
            return

        m = _EHR_STATE.match(text)
        if m:
            self.ehr_state = tuple(int(g) for g in m.groups())  # type: ignore[assignment]
            return

        m = _BATT_PCT.match(text)
        if m:
            self.battery_pct = int(m.group(1))
            return

        m = _ORIENT.match(text)
        if m:
            self.orientation = int(m.group(1))
            return

        m = _CHG_IND.match(text)
        if m:
            self.charging_state = int(m.group(1))
            self.charging_validity = int(m.group(2))
            return

        m = _O2MODE.match(text)
        if m:
            self.o2_mode = int(m.group(1))
            return

        # blestda etc. — leave for future expansion

    def snapshot(self) -> dict[str, Any]:
        d = asdict(self)
        # Trim history lists in snapshot for compactness
        d["dhr_history"] = self.dhr_history[-10:]
        d["cva_history"] = self.cva_history[-10:]
        return d


# ----- ClientState ----------------------------------------------------------


# Lifecycle phases the driver moves through. Names align with the connection
# sequence in spec § 4.
PHASE_DISCONNECTED   = "DISCONNECTED"
PHASE_CONNECTING     = "CONNECTING"
PHASE_HANDSHAKING    = "HANDSHAKING"
PHASE_SUBSCRIBED     = "SUBSCRIBED"
PHASE_STREAMING      = "STREAMING"


@dataclass
class ClientState:
    """Reflects what the driver is doing.

    Phase transitions:
      DISCONNECTED → CONNECTING → HANDSHAKING → SUBSCRIBED → STREAMING
                  ↑__________________________________________|
                       (on _DISCONNECT; auto-reconnect)
    """

    phase: str = PHASE_DISCONNECTED
    phase_changed_at_ms: int | None = None

    # Handshake telemetry
    handshake_count: int = 0
    last_handshake_at_ms: int | None = None
    last_nonce_hex: str | None = None
    last_proof_hex: str | None = None
    last_handshake_status: int | None = None

    # Time-sync telemetry
    time_sync_count: int = 0
    last_time_sync_sent_at_ms: int | None = None
    last_time_counter_sent: int | None = None
    last_time_sync_ack_at_ms: int | None = None

    # Stream stats
    records_seen: int = 0
    records_by_type: dict[str, int] = field(default_factory=dict)
    bytes_seen: int = 0           # if you also track raw byte counts (optional)
    sessions_seen: set[int] = field(default_factory=set)
    current_session: int | None = None

    # Disconnect telemetry
    disconnect_count: int = 0           # only counts explicit `_DISCONNECT` events (live mode)
    reconnect_count: int = 0            # counts every handshake AFTER the first
    last_disconnect_at_ms: int | None = None
    last_disconnect_reason: str | None = None

    # ----- Autonomous catch-up (data plane) -----
    # On every reconnect, the driver requests history with a delta-sync cursor.
    # We track per-sub-op cursors so consumers can verify "we've caught up".
    history_fetch_count: int = 0
    history_fetch_full_sync_count: int = 0    # cursor=0 (full re-sync)
    last_history_cursor_by_subop: dict[int, int] = field(default_factory=dict)

    # Per-record-type coverage: count + last (counter, session) seen.
    # Lets consumers detect when records are missed (counter gaps).
    coverage_by_type: dict[str, dict[str, int]] = field(default_factory=dict)
    # ↑ each value is {"count": int, "last_counter": int, "last_session": int}

    # ----- On-demand control plane -----
    # Every parameter read/write/push is counted. Consumers can use these to
    # verify control commands take effect (corresponding RingState.params update).
    param_reads_sent: int = 0
    param_writes_sent: int = 0
    param_pushes_received: int = 0
    last_param_command_at_ms: int | None = None
    # Per-param breakdown: param_id → {"reads": N, "writes_b0": N, "writes_b2": N, "pushes": N}
    per_param_activity: dict[int, dict[str, int]] = field(default_factory=dict)

    # ----- mutation -----

    def _set_phase(self, p: str, ts: int | None) -> None:
        if p != self.phase:
            self.phase = p
            self.phase_changed_at_ms = ts

    def apply(self, rec: Record) -> None:
        t = rec.t
        self.records_seen += 1
        self.records_by_type[rec.type] = self.records_by_type.get(rec.type, 0) + 1

        if rec.sess is not None:
            self.sessions_seen.add(rec.sess)
            self.current_session = rec.sess

        # Phase-driving synthetic events
        if rec.type == "_HANDSHAKE_NONCE":
            # Any nonce after the first one represents a fresh BLE session
            # (whether or not we observed an explicit disconnect).
            if self.handshake_count > 0:
                self.reconnect_count += 1
            self._set_phase(PHASE_HANDSHAKING, t)
            self.last_nonce_hex = rec.data.get("nonce_hex")
            return
        if rec.type == "_HANDSHAKE_PROOF":
            self.last_proof_hex = rec.data.get("proof_hex")
            return
        if rec.type == "_HANDSHAKE_OK":
            self.handshake_count += 1
            self.last_handshake_at_ms = t
            self.last_handshake_status = 0
            self._set_phase(PHASE_SUBSCRIBED, t)
            return
        if rec.type == "_HANDSHAKE_FAIL":
            self.last_handshake_status = rec.data.get("status")
            self._set_phase(PHASE_DISCONNECTED, t)
            return
        if rec.type == "_TIME_SYNC_REQ":
            self.last_time_sync_sent_at_ms = t
            self.last_time_counter_sent = rec.data.get("time_counter")
            return
        if rec.type == "_TIME_SYNC_REPLY":
            self.time_sync_count += 1
            self.last_time_sync_ack_at_ms = t
            return
        if rec.type == "_DISCONNECT":
            self.disconnect_count += 1
            self.last_disconnect_at_ms = t
            self.last_disconnect_reason = rec.data.get("reason")
            self._set_phase(PHASE_DISCONNECTED, t)
            self.current_session = None
            return

        # ---- Autonomous catch-up plane ----
        if rec.type == "_HISTORY_FETCH_REQ":
            self.history_fetch_count += 1
            if rec.data.get("is_full_sync"):
                self.history_fetch_full_sync_count += 1
            self.last_history_cursor_by_subop[rec.data["sub_op"]] = rec.data["cursor"]
            return
        if rec.type == "_HISTORY_FETCH_RESP":
            return  # already accounted for via the request

        # ---- Control plane ----
        if rec.type in ("_PARAM_READ", "_PARAM_WRITE_B0", "_PARAM_WRITE_B2", "_PARAM_PUSH",
                         "_PARAM_READ_RESP"):
            pid = rec.data.get("param_id")
            self.last_param_command_at_ms = t
            bucket = self.per_param_activity.setdefault(
                pid if pid is not None else -1,
                {"reads": 0, "writes_b0": 0, "writes_b2": 0, "pushes": 0},
            )
            if rec.type == "_PARAM_READ":
                self.param_reads_sent += 1
                bucket["reads"] += 1
            elif rec.type == "_PARAM_WRITE_B0":
                self.param_writes_sent += 1
                bucket["writes_b0"] += 1
            elif rec.type == "_PARAM_WRITE_B2":
                self.param_writes_sent += 1
                bucket["writes_b2"] += 1
            elif rec.type == "_PARAM_PUSH":
                self.param_pushes_received += 1
                bucket["pushes"] += 1
            return

        # ---- Inner records → STREAMING phase + per-type coverage ----
        if rec.tag.startswith("0x"):
            if self.phase != PHASE_STREAMING:
                self._set_phase(PHASE_STREAMING, t)
            cov = self.coverage_by_type.setdefault(
                rec.type, {"count": 0, "last_counter": -1, "last_session": -1},
            )
            cov["count"] += 1
            if rec.ctr is not None:
                cov["last_counter"] = rec.ctr
            if rec.sess is not None:
                cov["last_session"] = rec.sess

    def snapshot(self) -> dict[str, Any]:
        d = asdict(self)
        d["sessions_seen"] = sorted(self.sessions_seen)
        return d
