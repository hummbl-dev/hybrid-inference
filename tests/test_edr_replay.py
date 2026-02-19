from pathlib import Path

from src.hybrid_inference.edr import build_edr, canonicalize
from src.hybrid_inference.replay import ReplayStatus, replay_edr


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonicalize(payload))
    return path


def _build_replay_fixture(tmp_path: Path, *, side_effects: str = "none") -> Path:
    inputs_path = _write_json(
        tmp_path / "inputs" / "required_inputs.json",
        {
            "runtime_environment": "ci-stub",
            "input_payload": {
                "messages_sha256": "abc123",
                "stream": False,
                "model": "qwen3:8b",
            },
        },
    )

    decision = {
        "provider": "local",
        "model": "qwen3:8b",
        "protocol": "http",
        "path": "/v1/chat/completions",
    }
    output_payload = {
        "id": "replay_30930a7004081a5f",
        "object": "chat.completion",
        "model": "qwen3:8b",
        "choices_count": 1,
        "first_choice_finish_reason": "stop",
    }

    edr = build_edr(
        request_id="req-replay-1",
        contract={"classification": "INTERNAL", "latency": "interactive"},
        decision=decision,
        decision_factors=["LOCAL_OK_ROUTER"],
        constraints_applied=["max_swap_bytes=0", "max_mem_percent=92.0"],
        input_payload={"messages_sha256": "abc123", "stream": False, "model": "qwen3:8b"},
        output_payload=output_payload,
        failure=None,
        side_effects=side_effects,
        replay_pointer=str(inputs_path),
    )

    edr_path = tmp_path / "edr" / "sample_edr.json"
    _write_json(edr_path, edr.__dict__)
    return edr_path


def test_replay_match_with_deterministic_stub(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)

    report, report_path = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.MATCH.value
    assert report.reason_codes == []
    assert report.checks["input_hash_match"] is True
    assert report.checks["output_hash_match"] is True
    assert report.checks["decision_core_hash_match"] is True
    assert report.checks["edr_hash_match"] is True
    assert report_path.exists()


def test_replay_refuses_side_effects_by_default(tmp_path):
    edr_path = _build_replay_fixture(tmp_path, side_effects="external")

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.REFUSED.value
    assert "SIDE_EFFECTS_REFUSED" in report.reason_codes


def test_replay_diverges_on_environment_mismatch(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="different-env",
    )

    assert report.status == ReplayStatus.DIVERGED.value
    assert "ENVIRONMENT_MISMATCH" in report.reason_codes
    assert report.checks["input_hash_match"] is True
    assert report.checks["output_hash_match"] is False
