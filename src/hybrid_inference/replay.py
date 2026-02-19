from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import datetime as dt
from enum import StrEnum
import json
import os
from pathlib import Path
from typing import Any

from src.hybrid_inference.edr import canonicalize, hash_json


class ReplayStatus(StrEnum):
    MATCH = "MATCH"
    DIVERGED = "DIVERGED"
    REFUSED = "REFUSED"
    ERROR = "ERROR"


class DivergenceReason(StrEnum):
    SIDE_EFFECTS_REFUSED = "SIDE_EFFECTS_REFUSED"
    SIDE_EFFECTS_NOT_ALLOWED = "SIDE_EFFECTS_NOT_ALLOWED"
    NETWORK_NOT_ALLOWED = "NETWORK_NOT_ALLOWED"
    REPLAY_NOT_REPLAYABLE = "REPLAY_NOT_REPLAYABLE"
    INPUT_POINTER_MISSING = "INPUT_POINTER_MISSING"
    INPUT_HASH_MISMATCH = "INPUT_HASH_MISMATCH"
    OUTPUT_HASH_MISMATCH = "OUTPUT_HASH_MISMATCH"
    DECISION_CORE_MISMATCH = "DECISION_CORE_MISMATCH"
    EDR_HASH_MISMATCH = "EDR_HASH_MISMATCH"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    PROVIDER_NOT_SUPPORTED = "PROVIDER_NOT_SUPPORTED"
    EXECUTION_ERROR = "EXECUTION_ERROR"


@dataclass(frozen=True)
class ReplayReport:
    replay_report_version: str
    timestamp: str
    source_edr_path: str
    decision_core_hash: str
    status: str
    reason_codes: list[str]
    checks: dict[str, bool]
    edr_hash_expected: str
    edr_hash_observed: str | None
    input_hash_expected: str
    input_hash_observed: str | None
    output_hash_expected: str
    output_hash_observed: str | None
    decision_core_hash_expected: str
    decision_core_hash_observed: str | None
    report_hash: str


class ReplayError(RuntimeError):
    def __init__(self, reason: DivergenceReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ReplayError(DivergenceReason.EXECUTION_ERROR, "JSON root must be an object")
    return loaded


def _resolve_inputs_pointer(edr_path: Path, pointer: str) -> Path:
    candidate = Path(pointer)
    if not candidate.is_absolute():
        candidate = (edr_path.parent / candidate).resolve()
    return candidate


def _load_required_inputs(edr_path: Path, edr: dict[str, Any]) -> dict[str, Any]:
    replay = edr.get("replay") or {}
    pointer = replay.get("required_inputs_pointer")
    if not isinstance(pointer, str) or not pointer:
        raise ReplayError(DivergenceReason.INPUT_POINTER_MISSING, "missing replay.required_inputs_pointer")
    if pointer == "inline":
        raise ReplayError(DivergenceReason.INPUT_POINTER_MISSING, "inline replay inputs are not available in EDR v1.0.0")

    pointer_path = _resolve_inputs_pointer(edr_path, pointer)
    if not pointer_path.exists():
        raise ReplayError(DivergenceReason.INPUT_POINTER_MISSING, f"required replay input file not found: {pointer_path}")
    return _load_json(pointer_path)


def _deterministic_stub_output(
    decision: dict[str, Any],
    input_payload: dict[str, Any],
    runtime_environment: str,
) -> dict[str, Any]:
    seed = {
        "model": decision.get("model", ""),
        "input_payload": input_payload,
        "runtime_environment": runtime_environment,
    }
    replay_id = hash_json(seed)[:16]
    return {
        "id": f"replay_{replay_id}",
        "object": "chat.completion",
        "model": decision.get("model", ""),
        "choices_count": 1,
        "first_choice_finish_reason": "stop",
    }


def _execute_replay(
    edr: dict[str, Any],
    input_payload: dict[str, Any],
    runtime_environment: str,
) -> dict[str, Any]:
    decision = edr.get("decision") or {}
    provider = decision.get("provider")
    if provider in {"local", "local_stub"}:
        return _deterministic_stub_output(decision, input_payload, runtime_environment)
    raise ReplayError(DivergenceReason.PROVIDER_NOT_SUPPORTED, f"provider {provider!r} is not supported for offline replay")


def _is_networked_replay(decision: dict[str, Any]) -> bool:
    provider = str(decision.get("provider", ""))
    protocol = str(decision.get("protocol", "")).lower()
    if provider in {"local", "local_stub"}:
        return False
    if protocol in {"http", "https"}:
        return True
    if provider in {"openai", "anthropic", "remote", "api"}:
        return True
    return False


def _recompute_hashes(edr: dict[str, Any], input_payload: dict[str, Any], output_payload: dict[str, Any]) -> dict[str, str]:
    input_hash = hash_json(input_payload)
    output_hash = hash_json(output_payload)

    decision_core = {
        "contract_hash": edr.get("contract_hash"),
        "policy_version": edr.get("policy_version"),
        "decision": edr.get("decision"),
        "decision_factors": edr.get("decision_factors"),
        "constraints_applied": edr.get("constraints_applied"),
        "input_hash": input_hash,
        "output_hash": output_hash,
        "failure": edr.get("failure"),
        "side_effects": edr.get("side_effects"),
        "replay": edr.get("replay"),
    }
    decision_core_hash = hash_json(decision_core)

    edr_base = {
        "edr_version": edr.get("edr_version"),
        "timestamp": edr.get("timestamp"),
        "request_id": edr.get("request_id"),
        "contract_hash": edr.get("contract_hash"),
        "policy_version": edr.get("policy_version"),
        "decision": edr.get("decision"),
        "decision_factors": edr.get("decision_factors"),
        "constraints_applied": edr.get("constraints_applied"),
        "input_hash": input_hash,
        "output_hash": output_hash,
        "decision_core_hash": decision_core_hash,
        "failure": edr.get("failure"),
        "side_effects": edr.get("side_effects"),
        "replay": edr.get("replay"),
    }
    edr_hash = hash_json(edr_base)

    return {
        "input_hash": input_hash,
        "output_hash": output_hash,
        "decision_core_hash": decision_core_hash,
        "edr_hash": edr_hash,
    }


def replay_storage_path(root: str, decision_id: str, timestamp: str) -> Path:
    ts = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return Path(root) / f"{ts.year:04d}" / f"{ts.month:02d}" / f"{ts.day:02d}" / f"{decision_id}.json"


def persist_replay_report(root: str, report: ReplayReport) -> Path:
    target = replay_storage_path(root, report.decision_core_hash, report.timestamp)
    target.parent.mkdir(parents=True, exist_ok=True)

    tmp_target = target.with_suffix(".tmp")
    with tmp_target.open("wb") as handle:
        handle.write(canonicalize(asdict(report)))
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(tmp_target, target)
    return target


def _report_with_hash(payload: dict[str, Any]) -> ReplayReport:
    report_hash = hash_json(payload)
    return ReplayReport(**payload, report_hash=report_hash)


def replay_edr(
    edr_path: str,
    *,
    output_root: str = "./artifacts/replay",
    allow_side_effects: bool = False,
    allow_network: bool = False,
    runtime_environment: str = "default",
) -> tuple[ReplayReport, Path]:
    source_path = Path(edr_path).resolve()
    edr = _load_json(source_path)

    reason_codes: list[str] = []
    checks = {
        "input_hash_match": False,
        "output_hash_match": False,
        "decision_core_hash_match": False,
        "edr_hash_match": False,
    }
    observed_input_hash: str | None = None
    observed_output_hash: str | None = None
    observed_decision_core_hash: str | None = None
    observed_edr_hash: str | None = None

    try:
        if edr.get("side_effects") != "none" and not allow_side_effects:
            raise ReplayError(
                DivergenceReason.SIDE_EFFECTS_NOT_ALLOWED,
                "side-effectful replay refused; use --allow-side-effects",
            )

        replay_info = edr.get("replay") or {}
        if replay_info.get("replayable") is not True:
            raise ReplayError(DivergenceReason.REPLAY_NOT_REPLAYABLE, "EDR marked as non-replayable")

        required_inputs = _load_required_inputs(source_path, edr)
        input_payload = required_inputs.get("input_payload")
        if not isinstance(input_payload, dict):
            raise ReplayError(DivergenceReason.INPUT_POINTER_MISSING, "required input_payload object not present")

        expected_env = required_inputs.get("runtime_environment")
        environment_mismatch = expected_env is not None and expected_env != runtime_environment
        if _is_networked_replay(edr.get("decision") or {}) and not allow_network:
            raise ReplayError(
                DivergenceReason.NETWORK_NOT_ALLOWED,
                "networked replay refused; use --allow-network",
            )

        output_payload = _execute_replay(edr, input_payload, runtime_environment)
        recomputed = _recompute_hashes(edr, input_payload, output_payload)
        observed_input_hash = recomputed["input_hash"]
        observed_output_hash = recomputed["output_hash"]
        observed_decision_core_hash = recomputed["decision_core_hash"]
        observed_edr_hash = recomputed["edr_hash"]

        checks["input_hash_match"] = recomputed["input_hash"] == edr.get("input_hash")
        checks["output_hash_match"] = recomputed["output_hash"] == edr.get("output_hash")
        checks["decision_core_hash_match"] = recomputed["decision_core_hash"] == edr.get("decision_core_hash")
        checks["edr_hash_match"] = recomputed["edr_hash"] == edr.get("edr_hash")

        if not checks["input_hash_match"]:
            reason_codes.append(DivergenceReason.INPUT_HASH_MISMATCH.value)
        if not checks["output_hash_match"]:
            reason_codes.append(DivergenceReason.OUTPUT_HASH_MISMATCH.value)
            if environment_mismatch:
                reason_codes.append(DivergenceReason.ENVIRONMENT_MISMATCH.value)
        elif not checks["decision_core_hash_match"]:
            # Output matched, so this indicates non-output decision core drift
            # (e.g., decision_factors/constraints/failure/replay fields).
            reason_codes.append(DivergenceReason.DECISION_CORE_MISMATCH.value)
        if not checks["edr_hash_match"]:
            reason_codes.append(DivergenceReason.EDR_HASH_MISMATCH.value)

        status = ReplayStatus.MATCH if not reason_codes else ReplayStatus.DIVERGED

    except ReplayError as exc:
        reason_codes.append(exc.reason.value)
        refusal_reasons = {
            DivergenceReason.SIDE_EFFECTS_NOT_ALLOWED,
            DivergenceReason.NETWORK_NOT_ALLOWED,
        }
        status = ReplayStatus.REFUSED if exc.reason in refusal_reasons else ReplayStatus.ERROR
    except Exception:  # pragma: no cover
        reason_codes.append(DivergenceReason.EXECUTION_ERROR.value)
        status = ReplayStatus.ERROR
    report_payload: dict[str, Any] = {
        "replay_report_version": "1.0.0",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_edr_path": str(source_path),
        "decision_core_hash": str(edr.get("decision_core_hash", "")),
        "status": status.value,
        "reason_codes": reason_codes,
        "checks": checks,
        "edr_hash_expected": str(edr.get("edr_hash", "")),
        "edr_hash_observed": observed_edr_hash,
        "input_hash_expected": str(edr.get("input_hash", "")),
        "input_hash_observed": observed_input_hash,
        "output_hash_expected": str(edr.get("output_hash", "")),
        "output_hash_observed": observed_output_hash,
        "decision_core_hash_expected": str(edr.get("decision_core_hash", "")),
        "decision_core_hash_observed": observed_decision_core_hash,
    }
    report = _report_with_hash(report_payload)
    report_path = persist_replay_report(output_root, report)
    return report, report_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay and verify an EDR artifact offline")
    parser.add_argument("edr_json", help="Path to EDR JSON artifact")
    parser.add_argument("--allow-side-effects", action="store_true", help="Allow replays where side_effects is not none")
    parser.add_argument("--allow-network", action="store_true", help="Allow replay execution paths that require network")
    parser.add_argument("--output-root", default="./artifacts/replay", help="Replay report output root")
    parser.add_argument(
        "--runtime-environment",
        default="default",
        help="Runtime environment label used to validate deterministic replay context",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report, report_path = replay_edr(
        args.edr_json,
        output_root=args.output_root,
        allow_side_effects=args.allow_side_effects,
        allow_network=args.allow_network,
        runtime_environment=args.runtime_environment,
    )
    print(json.dumps({"status": report.status, "reason_codes": report.reason_codes, "report_path": str(report_path)}))
    if report.status == ReplayStatus.MATCH.value:
        return 0
    if report.status == ReplayStatus.REFUSED.value:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
