from __future__ import annotations

from pathlib import Path
from typing import Any

from src.hybrid_inference.edr import EDRFailure, build_edr, persist_edr


def emit_edr(*, edr_root: str, request_id: str, contract: dict[str, Any], decision: dict[str, Any],
             decision_factors: list[str], constraints_applied: list[str], input_payload: dict[str, Any],
             output_payload: dict[str, Any], failure: EDRFailure | None, side_effects: str = "none") -> Path:
    edr = build_edr(
        request_id=request_id,
        contract=contract,
        decision=decision,
        decision_factors=decision_factors,
        constraints_applied=constraints_applied,
        input_payload=input_payload,
        output_payload=output_payload,
        failure=failure,
        side_effects=side_effects,
    )
    return persist_edr(edr_root, edr)
