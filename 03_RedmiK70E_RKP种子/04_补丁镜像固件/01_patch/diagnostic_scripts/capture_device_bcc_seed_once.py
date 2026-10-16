#!/usr/bin/env python3
"""Permanently disabled historical K70E collector; archived for forensics."""
from __future__ import annotations
import sys
from pathlib import Path

LEGACY_ONLINE_ENTRYPOINT_DISABLED = True
EXIT_CODE = 78
REPLACEMENT_ENTRYPOINT = Path(__file__).resolve().with_name("rkp_sw_stock_log_once.py")

def main(argv: list[str] | None = None) -> int:
    del argv
    print(f"SAFE_ABORT_LEGACY_ENTRYPOINT_DISABLED: use {REPLACEMENT_ENTRYPOINT}", file=sys.stderr)
    return EXIT_CODE

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
