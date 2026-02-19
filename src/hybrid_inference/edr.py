from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any


def canonicalize(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_json(data: Any) -> str:
    return hashlib.sha256(canonicalize(data)).hexdigest()


@dataclass(frozen=True)
class EDRFailure:
    type: str
    stage: str
    message: str


@dataclass(frozen=True)
class EDR:
    edr_version: str
    timestamp: str
    request_id: str
    contract_hash: str
    policy_version: str
    decision: dict[str, Any]
    decision_factors: list[str]
    constraints_applied: list[str]
    input_hash: str
    output_hash: str
    decision_core_hash: str
    edr_hash: str
    failure: dict[str, str] | None
    side_effects: str
    replay: dict[str, Any]


def build_edr(
    *,
    request_id: str,
    contract: dict[str, Any],
    decision: dict[str, Any],
    decision_factors: list[str],
    constraints_applied: list[str],
    input_payload: dict[str, Any],
    output_payload: dict[str, Any],
    failure: EDRFailure | None,
    side_effects: str = "none",
    replayable: bool = True,
    replay_pointer: str = "inline",
) -> EDR:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    contract_hash = hash_json(contract)
    input_hash = hash_json(input_payload)
    output_hash = hash_json(output_payload)
    failure_payload = asdict(failure) if failure else None

    decision_core = {
        "contract_hash": contract_hash,
        "policy_version": "1.0.0",
        "decision": decision,
        "decision_factors": decision_factors,
        "constraints_applied": constraints_applied,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "failure": failure_payload,
        "side_effects": side_effects,
        "replay": {"replayable": replayable, "required_inputs_pointer": replay_pointer},
    }
    decision_core_hash = hash_json(decision_core)

    edr_base = {
        "edr_version": "1.0.0",
        "timestamp": now,
        "request_id": request_id,
        "contract_hash": contract_hash,
        "policy_version": "1.0.0",
        "decision": decision,
        "decision_factors": decision_factors,
        "constraints_applied": constraints_applied,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "decision_core_hash": decision_core_hash,
        "failure": failure_payload,
        "side_effects": side_effects,
        "replay": {"replayable": replayable, "required_inputs_pointer": replay_pointer},
    }
    edr_hash = hash_json(edr_base)

    return EDR(**edr_base, edr_hash=edr_hash)


def edr_storage_path(root: str, decision_id: str, timestamp: str) -> Path:
    ts = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return Path(root) / f"{ts.year:04d}" / f"{ts.month:02d}" / f"{ts.day:02d}" / f"{decision_id}.json"


def persist_edr(root: str, edr: EDR) -> Path:
    decision_id = edr.decision_core_hash
    target = edr_storage_path(root, decision_id, edr.timestamp)
    target.parent.mkdir(parents=True, exist_ok=True)

    payload = asdict(edr)
    data = canonicalize(payload)
    tmp_target = target.with_suffix(".tmp")

    with tmp_target.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(tmp_target, target)
    return target
