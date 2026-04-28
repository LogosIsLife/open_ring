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
from .decoders import canonical_type, decode
from .envelope import Record
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
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None

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

    # ----- stream -----

    async def stream(self) -> AsyncIterator[Record]:
        """Yield decoded Records as the ring sends notifications.

        Auto-reconnects on disconnect when `reconnect=True`. Synthetic events
        (handshake, time-sync, battery, disconnect) are emitted between record
        streams.
        """
        while True:
            try:
                while True:
                    ts, value = await self._notify_q.get()
                    utc_ms = int(ts * 1000)

                    if looks_like_outer_frame(value):
                        for f in parse_outer_frames(value):
                            for rec in _outer_to_records(f, utc_ms):
                                yield rec
                    else:
                        for r in parse_inner_records(value):
                            yield Record(
                                t=utc_ms,
                                rt=None,
                                ctr=r.counter,
                                sess=r.session,
                                tag=f"0x{r.type_byte:02x}",
                                type=canonical_type(r.type_byte),
                                data=decode(r.type_byte, r.payload),
                            )
            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception as e:
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
