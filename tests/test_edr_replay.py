import hashlib
import json
from pathlib import Path

from jsonschema import validate

from src.hybrid_inference.edr import build_edr, canonicalize, hash_json
from src.hybrid_inference.replay import ReplayStatus, replay_edr

EXPECTED_REPLAY_REASON_CODES_BY_STATUS = {
    ReplayStatus.REFUSED.value: {
        "SIDE_EFFECTS_NOT_ALLOWED",
        "NETWORK_NOT_ALLOWED",
    },
    ReplayStatus.ERROR.value: {
        "REPLAY_NOT_REPLAYABLE",
        "INPUT_POINTER_MISSING",
        "PROVIDER_NOT_SUPPORTED",
        "EXECUTION_ERROR",
    },
    ReplayStatus.DIVERGED.value: {
        "INPUT_HASH_MISMATCH",
        "OUTPUT_HASH_MISMATCH",
        "DECISION_CORE_MISMATCH",
        "EDR_HASH_MISMATCH",
        "ENVIRONMENT_MISMATCH",
    },
}


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


def _build_network_replay_fixture(tmp_path: Path) -> Path:
    inputs_path = _write_json(
        tmp_path / "inputs" / "required_inputs_network.json",
        {
            "runtime_environment": "ci-stub",
            "input_payload": {
                "messages_sha256": "network-abc123",
                "stream": False,
                "model": "gpt-4.1-mini",
            },
        },
    )
    edr = build_edr(
        request_id="req-replay-network-1",
        contract={"classification": "INTERNAL", "latency": "interactive"},
        decision={
            "provider": "openai",
            "model": "gpt-4.1-mini",
            "protocol": "https",
            "path": "/v1/chat/completions",
        },
        decision_factors=["REMOTE_PROVIDER_ALLOWED"],
        constraints_applied=["max_swap_bytes=0", "max_mem_percent=92.0"],
        input_payload={"messages_sha256": "network-abc123", "stream": False, "model": "gpt-4.1-mini"},
        output_payload={"id": "remote_1", "object": "chat.completion"},
        failure=None,
        side_effects="none",
        replay_pointer=str(inputs_path),
    )
    edr_path = tmp_path / "edr" / "sample_network_edr.json"
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
    report_payload = report.__dict__.copy()
    observed_report_hash = report_payload.pop("report_hash")
    assert observed_report_hash == hash_json(report_payload)
    assert report_path.exists()


def test_replay_refuses_side_effects_without_flag(tmp_path):
    edr_path = _build_replay_fixture(tmp_path, side_effects="external")

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.REFUSED.value
    assert "SIDE_EFFECTS_NOT_ALLOWED" in report.reason_codes


def test_replay_refuses_network_without_flag(tmp_path):
    edr_path = _build_network_replay_fixture(tmp_path)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.REFUSED.value
    assert "NETWORK_NOT_ALLOWED" in report.reason_codes


def test_replay_errors_when_edr_marked_non_replayable(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["replay"]["replayable"] = False
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.ERROR.value
    assert "REPLAY_NOT_REPLAYABLE" in report.reason_codes


def test_replay_errors_when_required_inputs_pointer_missing(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["replay"]["required_inputs_pointer"] = ""
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.ERROR.value
    assert "INPUT_POINTER_MISSING" in report.reason_codes


def test_replay_errors_when_required_inputs_pointer_whitespace_only(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["replay"]["required_inputs_pointer"] = "   "
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.ERROR.value
    assert "INPUT_POINTER_MISSING" in report.reason_codes


def test_replay_errors_when_required_inputs_pointer_inline_with_padding(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["replay"]["required_inputs_pointer"] = " inline "
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.ERROR.value
    assert "INPUT_POINTER_MISSING" in report.reason_codes


def test_replay_errors_when_provider_unsupported_even_if_network_allowed(tmp_path):
    edr_path = _build_network_replay_fixture(tmp_path)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
        allow_network=True,
    )

    assert report.status == ReplayStatus.ERROR.value
    assert "PROVIDER_NOT_SUPPORTED" in report.reason_codes


def test_replay_diverges_on_input_hash_mismatch(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["input_hash"] = "0" * 64
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.DIVERGED.value
    assert report.reason_codes == ["INPUT_HASH_MISMATCH"]


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


def test_replay_diverges_on_edr_hash_mismatch(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["edr_hash"] = "f" * 64
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.DIVERGED.value
    assert report.reason_codes == ["EDR_HASH_MISMATCH"]


def test_replay_diverges_when_decision_core_mismatch_with_matching_output_hash(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    edr_payload = json.loads(edr_path.read_text())
    edr_payload["decision_factors"] = ["TAMPERED_FACTOR"]
    _write_json(edr_path, edr_payload)

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.DIVERGED.value
    assert report.checks["output_hash_match"] is True
    assert report.checks["decision_core_hash_match"] is False
    assert "DECISION_CORE_MISMATCH" in report.reason_codes


def test_replay_errors_on_non_object_json_root(tmp_path):
    edr_path = tmp_path / "edr" / "malformed_root.json"
    _write_json(edr_path, {"placeholder": True})
    edr_path.write_text("[1,2,3]", encoding="utf-8")

    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    assert report.status == ReplayStatus.ERROR.value
    assert report.reason_codes == ["EXECUTION_ERROR"]


def test_replay_reason_code_contract_lock():
    assert EXPECTED_REPLAY_REASON_CODES_BY_STATUS == {
        "REFUSED": {"SIDE_EFFECTS_NOT_ALLOWED", "NETWORK_NOT_ALLOWED"},
        "ERROR": {"REPLAY_NOT_REPLAYABLE", "INPUT_POINTER_MISSING", "PROVIDER_NOT_SUPPORTED", "EXECUTION_ERROR"},
        "DIVERGED": {
            "INPUT_HASH_MISMATCH",
            "OUTPUT_HASH_MISMATCH",
            "DECISION_CORE_MISMATCH",
            "EDR_HASH_MISMATCH",
            "ENVIRONMENT_MISMATCH",
        },
    }


def test_replay_reason_codes_emitted_are_within_contract(tmp_path):
    observed: dict[str, set[str]] = {
        ReplayStatus.REFUSED.value: set(),
        ReplayStatus.ERROR.value: set(),
        ReplayStatus.DIVERGED.value: set(),
    }

    scenarios = []

    side_effects = _build_replay_fixture(tmp_path / "side_effects", side_effects="external")
    scenarios.append(
        replay_edr(
            str(side_effects),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    network = _build_network_replay_fixture(tmp_path / "network")
    scenarios.append(
        replay_edr(
            str(network),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    non_replayable = _build_replay_fixture(tmp_path / "non_replayable")
    non_replayable_payload = json.loads(non_replayable.read_text())
    non_replayable_payload["replay"]["replayable"] = False
    _write_json(non_replayable, non_replayable_payload)
    scenarios.append(
        replay_edr(
            str(non_replayable),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    missing_pointer = _build_replay_fixture(tmp_path / "missing_pointer")
    missing_pointer_payload = json.loads(missing_pointer.read_text())
    missing_pointer_payload["replay"]["required_inputs_pointer"] = ""
    _write_json(missing_pointer, missing_pointer_payload)
    scenarios.append(
        replay_edr(
            str(missing_pointer),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    provider_unsupported = _build_network_replay_fixture(tmp_path / "provider_unsupported")
    scenarios.append(
        replay_edr(
            str(provider_unsupported),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
            allow_network=True,
        )[0]
    )

    env_mismatch = _build_replay_fixture(tmp_path / "env_mismatch")
    scenarios.append(
        replay_edr(
            str(env_mismatch),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="different-env",
        )[0]
    )

    input_hash_mismatch = _build_replay_fixture(tmp_path / "input_hash")
    input_hash_payload = json.loads(input_hash_mismatch.read_text())
    input_hash_payload["input_hash"] = "0" * 64
    _write_json(input_hash_mismatch, input_hash_payload)
    scenarios.append(
        replay_edr(
            str(input_hash_mismatch),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    decision_core_mismatch = _build_replay_fixture(tmp_path / "decision_core")
    decision_core_payload = json.loads(decision_core_mismatch.read_text())
    decision_core_payload["decision_factors"] = ["TAMPERED_FACTOR"]
    _write_json(decision_core_mismatch, decision_core_payload)
    scenarios.append(
        replay_edr(
            str(decision_core_mismatch),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    edr_hash_mismatch = _build_replay_fixture(tmp_path / "edr_hash")
    edr_hash_payload = json.loads(edr_hash_mismatch.read_text())
    edr_hash_payload["edr_hash"] = "f" * 64
    _write_json(edr_hash_mismatch, edr_hash_payload)
    scenarios.append(
        replay_edr(
            str(edr_hash_mismatch),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    malformed_root = tmp_path / "edr" / "malformed_root_contract.json"
    malformed_root.parent.mkdir(parents=True, exist_ok=True)
    malformed_root.write_text("[1,2,3]", encoding="utf-8")
    scenarios.append(
        replay_edr(
            str(malformed_root),
            output_root=str(tmp_path / "artifacts" / "replay"),
            runtime_environment="ci-stub",
        )[0]
    )

    for report in scenarios:
        if report.status in observed:
            observed[report.status].update(report.reason_codes)
            assert set(report.reason_codes).issubset(EXPECTED_REPLAY_REASON_CODES_BY_STATUS[report.status])

    for status, expected_codes in EXPECTED_REPLAY_REASON_CODES_BY_STATUS.items():
        assert observed[status] == expected_codes


def test_replay_report_validates_against_schema(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    report, _ = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )

    schema = json.loads(Path("schemas/replay/REPLAY_REPORT_v1.0.0.json").read_text())
    validate(instance=report.__dict__, schema=schema)


def test_replay_report_schema_v1_0_0_is_immutable_hash_pinned():
    schema_bytes = Path("schemas/replay/REPLAY_REPORT_v1.0.0.json").read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == "84362e7b44c4528048fb66625dc886c5548730ef4c5ff53273d26d89aeedd3b8"


def test_replay_report_persist_is_atomic_and_no_tmp_left(tmp_path):
    edr_path = _build_replay_fixture(tmp_path)
    report, report_path = replay_edr(
        str(edr_path),
        output_root=str(tmp_path / "artifacts" / "replay"),
        runtime_environment="ci-stub",
    )
    assert report.status == ReplayStatus.MATCH.value
    assert report_path.exists()
    assert list((tmp_path / "artifacts" / "replay").rglob("*.tmp")) == []
