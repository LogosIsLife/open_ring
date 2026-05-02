"""CLI entry point.

Usage:
    python -m oura_ring.cli replay <btsnoop>
    python -m oura_ring.cli live --mac <MAC> --realm <path/to/assa-store.realm>
    python -m oura_ring.cli live --mac <MAC> --auth-key <hex>
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from .replay import main_replay


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="oura-stream")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("replay", help="Decode an offline btsnoop capture as JSONL.")
    rp.add_argument("btsnoop", help="Path to btsnoop_hci.log")
    rp.add_argument("--cmd-handle", type=lambda x: int(x, 0), default=0x0015)
    rp.add_argument("--notify-handle", type=lambda x: int(x, 0), default=0x0012)

    lv = sub.add_parser("live", help="Stream from a live ring via BLE (requires bleak).")
    lv.add_argument("--mac", required=True, help="Ring BLE MAC, e.g. A0:38:F8:A4:09:C9")
    src = lv.add_mutually_exclusive_group(required=True)
    src.add_argument("--auth-key", help="16-byte AES-128 auth_key as hex (32 chars)")
    src.add_argument("--realm", help="Path to assa-store.realm to extract auth_key from")
    lv.add_argument("--no-reconnect", action="store_true",
                    help="Stop on first disconnect instead of auto-reconnecting")
    lv.add_argument("--cursor-file",
                    help="Path to a JSON file storing the per-sub-op delta-sync "
                         "cursors. With this set, the next reconnect resumes "
                         "from the saved position instead of full re-sync. "
                         "Default: ~/.local/share/oura_ring/cursors.json. "
                         "Use --no-cursor-file to disable persistence.")
    lv.add_argument("--no-cursor-file", action="store_true",
                    help="Disable cursor persistence; every reconnect does a full re-sync.")

    args = ap.parse_args(argv)
    if args.cmd == "replay":
        return main_replay([args.btsnoop, "--cmd-handle", str(args.cmd_handle),
                            "--notify-handle", str(args.notify_handle)])
    if args.cmd == "live":
        return _run_live(args)
    return 1


def _run_live(args) -> int:
    from .persistence import CursorStore
    from .transport import OuraRingClient

    auth_key = bytes.fromhex(args.auth_key) if args.auth_key else None
    realm_path = args.realm

    cursor_store: CursorStore | None = None
    if not args.no_cursor_file:
        cursor_store = CursorStore(args.cursor_file) if args.cursor_file else CursorStore()

    async def _go():
        async with OuraRingClient(
            mac=args.mac, auth_key=auth_key, realm_path=realm_path,
            reconnect=not args.no_reconnect,
            cursor_store=cursor_store,
        ) as client:
            async for rec in client.stream():
                sys.stdout.write(rec.to_json())
                sys.stdout.write("\n")
                sys.stdout.flush()

    try:
        asyncio.run(_go())
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
