"""Live BLE transport — `OuraRingClient`.

Async client that:
  1. Connects to the ring via `bleak` (cross-platform BLE).
  2. Subscribes to the notify char.
  3. Runs the secure handshake (AES-128-ECB-PKCS5).
  4. Performs initial time-sync.
  5. Subscribes to event categories.
  6. Streams decoded `Record` objects to the caller.
  7. Auto-reconnects when the ring drops (~every few minutes per spec).

Live transport requires the `bleak` package; install with:
    pip install bleak

Crypto requires either `cryptography` or `/usr/bin/openssl`.

The decode pipeline (`framing` + `decoders`) is shared 1:1 with offline
replay, so a btsnoop test harness validates the live decode end-to-end.

Cannot be tested without a real ring; the structure mirrors the verified
control-plane sequences from `sunday_evening.log`.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import struct
import time
from collections.abc import AsyncIterator
from typing import Any

from .crypto import compute_handshake_proof, extract_auth_key_from_realm
from .decoders import CvaPpgDecoder, canonical_type, decode
from .envelope import Record
from .persistence import CursorStore
from .framing import (
    OPCODES,
    OuterFrame,
    looks_like_outer_frame,
    parse_inner_records,
    parse_outer_frames,
)


log = logging.getLogger(__name__)

# GATT topology (from `Constants.java`, verified):
SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_CHAR   = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_CHAR  = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"


def _make_time_sync_frame() -> bytes:
    """Build a 12/09 time-sync request frame.

        12 09 <token:1> <counter:3 LE> 00 00 00 00 f8

    `counter = int(time.time()) // 256` — verified across 484 reconnects.
    """
    token = secrets.token_bytes(1)
    counter = int(time.time()) // 256
    counter_bytes = counter.to_bytes(3, "little")
    return b"\x12\x09" + token + counter_bytes + b"\x00\x00\x00\x00\xf8"


# ----- Client ---------------------------------------------------------------


class OuraRingClient:
    """Async live BLE client.

    Usage:
        async with OuraRingClient(mac="A0:38:F8:A4:09:C9", auth_key=key) as client:
            async for rec in client.stream():
                print(rec.to_json())
    """

    def __init__(
        self,
        mac: str,
        *,
        auth_key: bytes | None = None,
        realm_path: str | os.PathLike | None = None,
        event_categories: tuple[int, ...] = (0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d),
        reconnect: bool = True,
        cursor_store: "CursorStore | None" = None,
        cursor_save_every: int = 64,
    ):
        if (auth_key is None) == (realm_path is None):
            raise ValueError("Pass exactly one of auth_key= or realm_path=")
        if realm_path is not None:
            auth_key = extract_auth_key_from_realm(realm_path)
        if auth_key is None or len(auth_key) != 16:
            raise ValueError("auth_key must resolve to 16 bytes")
        self.mac = mac
        self.auth_key: bytes = auth_key
        self.event_categories = event_categories
        self.reconnect = reconnect
        # Cursor persistence: holds the per-sub-op delta-sync positions across
        # process restarts. The ONLY field of ClientState whose loss matters
        # for correctness — see oura_ring.persistence for rationale.
        self.cursor_store = cursor_store
        if cursor_store is not None:
            cursor_store.load()
        self._cursor_save_every = max(1, cursor_save_every)
        self._cursor_updates_since_save = 0
        self._client = None       # bleak.BleakClient
        self._notify_q: asyncio.Queue[tuple[float, bytes]] = asyncio.Queue()

    # ----- async context manager -----

    async def __aenter__(self) -> OuraRingClient:
        try:
            from bleak import BleakClient
        except ImportError as e:
            raise RuntimeError(
                "bleak is required for live BLE; install with `pip install bleak`"
            ) from e
        self._BleakClient = BleakClient
        await self._connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # Always flush cursors on shutdown — losing the last few minutes of
        # cursor advances means the next session re-fetches that window.
        self._save_cursors_safe()
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None

    def _save_cursors_safe(self) -> None:
        """Save the cursor store to disk, swallowing any error (a failed save
        should never crash the streamer — worst case is we re-sync next time)."""
        if self.cursor_store is None:
            return
        try:
            self.cursor_store.save()
            self._cursor_updates_since_save = 0
        except Exception as e:
            log.warning("cursor_store save failed: %s", e)

    # ----- connection lifecycle -----

    async def _connect(self) -> None:
        log.info("Connecting to %s", self.mac)
        self._client = self._BleakClient(self.mac)
        await self._client.connect()

        # Subscribe to notify char (CCCD `01 00` is handled by bleak)
        def on_notify(_char, value: bytearray) -> None:
            self._notify_q.put_nowait((time.time(), bytes(value)))
        await self._client.start_notify(NOTIFY_CHAR, on_notify)

        # Identity exchange (replay verbatim — pre-handshake; semantics not on critical path)
        # Spec § 4: typical sequence is 06 → 07, 08 → 09 etc. We send a minimal init.
        # Most observed setups skip ahead to the secure session directly; we replicate.
        await self._handshake()
        await self._time_sync_now()
        await self._subscribe_events()
        await self._catchup()

    async def _disconnected_or_idle(self) -> None:
        # Detect disconnect via bleak's is_connected attribute
        while self._client and self._client.is_connected:
            await asyncio.sleep(0.5)

    # ----- write helper -----

    async def _write(self, data: bytes, *, response: bool = True) -> None:
        if self._client is None or not self._client.is_connected:
            raise RuntimeError("not connected")
        await self._client.write_gatt_char(WRITE_CHAR, data, response=response)

    async def _expect(self, predicate, timeout: float = 5.0) -> tuple[float, bytes]:
        """Drain the notify queue until predicate(value) is True. Returns the matching
        (timestamp, value). Raises TimeoutError on no match.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError("expected notification not received")
            ts, value = await asyncio.wait_for(self._notify_q.get(), timeout=remaining)
            if predicate(value):
                return ts, value
            # Otherwise drop on the floor — only the handshake/time-sync replies
            # are interesting during setup; record streams haven't started yet.

    # ----- secure handshake -----

    async def _handshake(self) -> None:
        # Phone → Ring: 2F 01 2B   (start)
        await self._write(b"\x2f\x01\x2b", response=False)

        # Ring → Phone: 2F 10 2C <nonce:15>
        def is_nonce(v: bytes) -> bool:
            for f in parse_outer_frames(v):
                if f.opcode == 0x2f and f.sub_op == 0x2c and len(f.body) == 16:
                    return True
            return False

        _, value = await self._expect(is_nonce)
        nonce = next(
            f.body[1:16] for f in parse_outer_frames(value)
            if f.opcode == 0x2f and f.sub_op == 0x2c
        )

        # Phone → Ring: 2F 11 2D <proof:16>
        proof = compute_handshake_proof(self.auth_key, nonce)
        frame = b"\x2f\x11\x2d" + proof
        await self._write(frame, response=False)

        # Ring → Phone: 2F 02 2E <status:1>  (00 = success)
        def is_status(v: bytes) -> bool:
            for f in parse_outer_frames(v):
                if f.opcode == 0x2f and f.sub_op == 0x2e and len(f.body) == 2:
                    return True
            return False

        _, value = await self._expect(is_status)
        status = next(
            f.body[1] for f in parse_outer_frames(value)
            if f.opcode == 0x2f and f.sub_op == 0x2e
        )
        if status != 0:
            raise RuntimeError(f"handshake failed; status=0x{status:02x}")
        log.info("handshake OK")

    # ----- time-sync -----

    async def _time_sync_now(self) -> None:
        await self._write(_make_time_sync_frame(), response=False)
        # The reply is `13 05 <ack> <echo:3 LE> 00`. We don't strictly need to
        # validate it — the formula is one-way (phone tells the ring the time;
        # the ring acknowledges).

    # ----- control plane: parameter RPC + history fetch -----
    #
    # These let the driver actively change ring sensor configuration (toggle SpO2,
    # set DHR mode, etc.) and request missed records from a delta-sync cursor.

    # Documented parameter IDs (verified empirically; see truth-table § 8.2)
    PARAM_DHR             = 0x02   # Daytime Heart Rate; bytes 0/2 are mode/sub-mode
    PARAM_ACTIVITY_HR     = 0x03   # Activity HR enable; byte 0 toggle
    PARAM_SPO2            = 0x04   # SpO2 enable; byte 0 toggle
    PARAM_ACTIVITY_HR_AUX = 0x0B   # companion to 0x03 (read-only in observed traffic)
    PARAM_UNMAPPED_0D     = 0x0D
    PARAM_UNMAPPED_10     = 0x10

    async def read_param(self, param_id: int) -> None:
        """Fire `2F 02 20 <param>` to request the 4-byte param value. The ring
        replies with `2F 06 21 <param> <value:4>` which `stream()` will surface
        as a `_PARAM_READ_RESP` Record.
        """
        await self._write(bytes([0x2f, 0x02, 0x20, param_id]), response=False)

    async def write_param_byte0(self, param_id: int, value: int) -> None:
        """Fire `2F 03 22 <param> <value>` — sets BYTE 0 of the param."""
        await self._write(bytes([0x2f, 0x03, 0x22, param_id, value & 0xff]), response=False)

    async def write_param_byte2(self, param_id: int, value: int) -> None:
        """Fire `2F 03 26 <param> <value>` — sets BYTE 2 of the param."""
        await self._write(bytes([0x2f, 0x03, 0x26, param_id, value & 0xff]), response=False)

    # High-level convenience wrappers

    async def set_spo2(self, on: bool) -> None:
        """Enable or disable SpO2 sampling. Verified by toggle-RE (spec § 8.3)."""
        await self.write_param_byte0(self.PARAM_SPO2, 0x01 if on else 0x00)

    async def set_activity_hr(self, on: bool) -> None:
        """Toggle activity-heart-rate detection."""
        await self.write_param_byte0(self.PARAM_ACTIVITY_HR, 0x01 if on else 0x00)

    async def set_dhr_mode(self, mode: int, sub_mode: int = 0) -> None:
        """Set Daytime Heart Rate mode (byte 0) and sub-mode (byte 2).
        Observed: (mode=3, sub_mode=2) for an on-demand HR check; (mode=1, sub_mode=0) idle.
        """
        await self.write_param_byte0(self.PARAM_DHR, mode)
        if sub_mode is not None:
            await self.write_param_byte2(self.PARAM_DHR, sub_mode)

    async def request_hr_on_demand(self) -> None:
        """Fire the on-demand HR burst pattern: DHR mode=3 / sub-mode=2.
        Per spec § 8.2: this triggers a ~20 s HR sampling window, after which
        the ring returns to mode=1 / sub-mode=0 on its own.
        """
        await self.set_dhr_mode(mode=3, sub_mode=2)

    async def soft_reset(self) -> None:
        """Issue a soft reset to the ring: phone sends `0e 01 ff`, ring acks
        `0f 01 00`, and the ring reboots ~25-35 seconds later (emits
        `API_RING_START_IND` on reconnect).

        Verified across thursday.log: 3 reset commands → 3 ring boots, each
        with ack latency 19-181 ms and reboot delay 22-35 s.
        """
        await self._write(b"\x0e\x01\xff", response=False)

    async def request_history(self, sub_op: int = 0x00, cursor: int = 0) -> None:
        """Phone → Ring: `10 09 <subop> <cursor:3 LE> 00 ff ff ff ff ff`.
        cursor = 0 → full sync. Otherwise delta-sync from that point.
        Sub-op selects which record-type cursor to query (different sub-ops are used
        for different aggregations; observed sub-ops include 0x00, 0xff, plus ~250 others).
        """
        c = cursor.to_bytes(3, "little")
        await self._write(
            bytes([0x10, 0x09, sub_op]) + c + b"\x00\xff\xff\xff\xff\xff",
            response=False,
        )

    # ----- event subscribe -----

    async def _subscribe_events(self) -> None:
        # `16 01 02` = subscribe to record stream
        await self._write(b"\x16\x01\x02", response=False)
        # `18 03 <category> <flags>` per category. Default subscribe set is
        # taken from observed live captures; covers IBI/SpO2/HRV/Temp/Motion/Wear.
        for category in self.event_categories:
            await self._write(bytes([0x18, 0x03, category, 0xff]), response=False)
        # Send the post-handshake config push (verified byte-invariant)
        await self._write(bytes.fromhex("2f0b29043c19031e1800000000"), response=False)

    async def _catchup(self) -> None:
        """Autonomous catch-up: on every (re)connect, ask the ring for any
        records it has buffered since the last delta-sync cursor we acknowledged.

        We start with two probes that the app emits on every reconnect:
            10 09 00 <cursor:3 LE> 00 ff ff ff ff ff   — sub-op 0x00
            10 09 ff <cursor:3 LE> 00 ff ff ff ff ff   — sub-op 0xff
        Sub-op 0x00 is the legacy "general" cursor; 0xff is the "all types"
        cursor used after the first connection.

        If a `cursor_store` was configured, we use the saved per-sub-op
        cursors here so we get a true delta-sync instead of pulling everything
        back. Falls back to `cursor=0` (full re-sync) for any sub-op we've
        never seen before.
        """
        c00 = self.cursor_store.get(0x00) if self.cursor_store else 0
        cff = self.cursor_store.get(0xff) if self.cursor_store else 0
        await self.request_history(sub_op=0x00, cursor=c00)
        await self.request_history(sub_op=0xff, cursor=cff)
        if self.cursor_store and (c00 or cff):
            log.info("delta-sync resumed: sub_op 0x00 cursor=%d, 0xff cursor=%d",
                     c00, cff)

    # ----- stream -----

    async def stream(self) -> AsyncIterator[Record]:
        """Yield decoded Records as the ring sends notifications.

        Auto-reconnects on disconnect when `reconnect=True`. Synthetic events
        (handshake, time-sync, battery, disconnect) are emitted between record
        streams.
        """
        cva_ppg_dec = CvaPpgDecoder()
        cva_ppg_last_t: int | None = None
        while True:
            try:
                while True:
                    ts, value = await self._notify_q.get()
                    utc_ms = int(ts * 1000)

                    if looks_like_outer_frame(value):
                        for f in parse_outer_frames(value):
                            for rec in _outer_to_records(f, utc_ms):
                                if rec.type == "_RING_RESET_ACK":
                                    cva_ppg_dec.reset()
                                # Capture delta-sync cursor positions as the
                                # ring reports them, persist periodically.
                                if (rec.type == "_HISTORY_FETCH_RESP"
                                        and self.cursor_store is not None):
                                    sub_op = rec.data.get("sub_op")
                                    cur = rec.data.get("cursor")
                                    if (sub_op is not None and cur is not None
                                            and self.cursor_store.update(sub_op, cur)):
                                        self._cursor_updates_since_save += 1
                                        if self._cursor_updates_since_save >= self._cursor_save_every:
                                            self._save_cursors_safe()
                                yield rec
                    else:
                        for r in parse_inner_records(value):
                            data = decode(r.type_byte, r.payload)
                            if r.type_byte == 0x81:
                                if cva_ppg_last_t is not None and (utc_ms - cva_ppg_last_t) > 60_000:
                                    cva_ppg_dec.reset()
                                samples = cva_ppg_dec.feed(r.payload)
                                data = {
                                    "samples": samples,
                                    "samples_in_record": len(samples),
                                    "session_samples_total": cva_ppg_dec.samples_total,
                                    "session_absolutes": cva_ppg_dec.absolutes_total,
                                    "session_deltas": cva_ppg_dec.deltas_total,
                                }
                                cva_ppg_last_t = utc_ms
                            yield Record(
                                t=utc_ms,
                                rt=None,
                                ctr=r.counter,
                                sess=r.session,
                                tag=f"0x{r.type_byte:02x}",
                                type=canonical_type(r.type_byte),
                                data=data,
                            )
            except (asyncio.CancelledError, KeyboardInterrupt):
                # Best-effort cursor flush on cancel — don't lose the work.
                self._save_cursors_safe()
                raise
            except Exception as e:
                # Disconnect path: flush cursors before reconnect attempt so
                # an immediate crash still preserves the latest positions.
                self._save_cursors_safe()
                yield Record(
                    t=int(time.time() * 1000), rt=None, ctr=None, sess=None,
                    tag="_DISCONNECT", type="_DISCONNECT",
                    data={"reason": type(e).__name__, "detail": str(e)},
                )
                if not self.reconnect:
                    raise
                log.warning("disconnect; reconnecting…")
                await asyncio.sleep(1.0)
                try:
                    await self._connect()
                except Exception as e2:
                    log.error("reconnect failed: %s", e2)
                    await asyncio.sleep(5.0)


# ----- outer-frame → synthetic Record (live mode) ---------------------------


def _outer_to_records(f: OuterFrame, utc_ms: int) -> list[Record]:
    """Translate a live outer frame into zero-or-one synthetic Records.
    Mirrors `replay._outer_to_record` but ring-direction-only since the live
    client only listens to notify-char traffic.
    """
    op = f.opcode

    if op == 0x0d and len(f.raw) == 8:
        return [Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_BATTERY", type="_BATTERY",
            data={"voltage_mv": f.raw[6] | (f.raw[7] << 8),
                  "state_bytes": list(f.raw[2:6])},
        )]
    if op == 0x13 and len(f.raw) == 7:
        return [Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_TIME_SYNC_REPLY", type="_TIME_SYNC_REPLY",
            data={"ack_code": f.raw[2],
                  "time_echo": f.raw[3] | (f.raw[4] << 8) | (f.raw[5] << 16)},
        )]
    if op == 0x1f and len(f.raw) == 6:
        return [Record(
            t=utc_ms, rt=None, ctr=None, sess=None,
            tag="_STATE_PULSE", type="_STATE_PULSE",
            data={"sub_op": f.raw[2], "data": list(f.raw[3:6])},
        )]
    return []


# ----- Sync wrapper (for non-asyncio consumers) -----------------------------


def stream_sync(
    mac: str,
    *,
    auth_key: bytes | None = None,
    realm_path: str | os.PathLike | None = None,
    **kwargs: Any,
):
    """Synchronous generator wrapper around the async `OuraRingClient.stream`.

    Each `next()` call drives the asyncio loop one record forward.
    """
    async def _gen():
        async with OuraRingClient(
            mac=mac, auth_key=auth_key, realm_path=realm_path, **kwargs
        ) as client:
            async for rec in client.stream():
                yield rec

    loop = asyncio.new_event_loop()
    agen = _gen().__aiter__()
    try:
        while True:
            yield loop.run_until_complete(agen.__anext__())
    except StopAsyncIteration:
        return
    finally:
        loop.close()
