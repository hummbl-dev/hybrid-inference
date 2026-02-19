import hashlib
import json
import time
from pathlib import Path


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit_append(path: str, record: dict) -> None:
    payload = dict(record)
    payload["ts"] = time.time()
    line = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    target = Path(path)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
