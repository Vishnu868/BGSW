"""Append-only audit trail (runs/<repo>/audit.jsonl): every stage, AI call, approval and change."""
from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path

from . import config


def operator() -> str:
    return config.get("OPERATOR") or getpass.getuser()


def log(path: Path, event: str, data: dict | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rec = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, "operator": operator(),
           **(data or {})}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")


def read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
