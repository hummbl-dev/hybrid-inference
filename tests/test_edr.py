import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient
from jsonschema import validate

from src.hybrid_inference.edr import EDRFailure, build_edr, persist_edr
from src.router import main
from src.router.health.local_health import Health


def _latest_edr_file(root: Path) -> Path:
    files = sorted(root.rglob("*.json"))
    assert files, "no edr artifacts found"
    return files[-1]


def test_edr_emitted_on_success(monkeypatch, tmp_path):
    async def fake_ollama_chat(base_url, model, messages, stream=False):
        return {"message": {"content": "ok"}}

    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", fake_ollama_chat)

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive"},
        },
    )
    assert response.status_code == 200

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"] is None
    assert edr["decision"]["provider"] == "local"


def test_edr_emitted_on_policy_reject(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    def unhealthy(*args, **kwargs):
        return Health(False, "forced-unhealthy")

    monkeypatch.setattr(main, "check_local_health", unhealthy)

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "reject me"}],
            "routing_contract": {
                "classification": "SENSITIVE",
                "latency": "interactive",
                "provider_allowlist": ["local"],
            },
        },
    )
    assert response.status_code == 503

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "policy_reject"


def test_edr_emitted_on_provider_failure(monkeypatch, tmp_path):
    async def broken_ollama_chat(base_url, model, messages, stream=False):
        raise RuntimeError("provider down")

    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", broken_ollama_chat)

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive"},
        },
    )
    assert response.status_code == 502

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "provider_failure"


def test_edr_emitted_on_uncaught_exception(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    def explode(*args, **kwargs):
        raise RuntimeError("health stack exploded")

    monkeypatch.setattr(main, "check_local_health", explode)

    client = TestClient(main.app, raise_server_exceptions=False)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "boom"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive"},
        },
    )
    assert response.status_code == 500

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "uncaught_exception"


def test_decision_core_hash_is_stable_across_timestamps():
    kwargs = {
        "request_id": "req-1",
        "contract": {"classification": "INTERNAL", "latency": "interactive"},
        "decision": {"provider": "local", "model": "qwen3:8b", "protocol": "http", "path": "/v1/chat/completions"},
        "decision_factors": ["LOCAL_OK_ROUTER"],
        "constraints_applied": ["max_swap_bytes=0"],
        "input_payload": {"messages_sha256": "abc", "stream": False},
        "output_payload": {"result": "ok"},
        "failure": None,
    }
    first = build_edr(**kwargs)
    second = build_edr(**kwargs)
    assert first.timestamp != second.timestamp
    assert first.decision_core_hash == second.decision_core_hash


def test_edr_persist_is_atomic_and_no_tmp_left(tmp_path):
    edr = build_edr(
        request_id="req-2",
        contract={"classification": "INTERNAL", "latency": "interactive"},
        decision={"provider": "local", "model": "qwen3:8b", "protocol": "http", "path": "/v1/chat/completions"},
        decision_factors=["LOCAL_OK_ROUTER"],
        constraints_applied=[],
        input_payload={"messages_sha256": "abc"},
        output_payload={"result": "ok"},
        failure=EDRFailure(type="none", stage="none", message="none"),
    )
    target = persist_edr(str(tmp_path / "edr"), edr)
    assert target.exists()
    assert list((tmp_path / "edr").rglob("*.tmp")) == []


def test_edr_validates_against_schema(monkeypatch, tmp_path):
    async def fake_ollama_chat(base_url, model, messages, stream=False):
        return {"message": {"content": "ok"}}

    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", fake_ollama_chat)

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "validate"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive"},
        },
    )
    assert response.status_code == 200

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    schema = json.loads(Path("schemas/edr/EDR_v1.0.0.json").read_text())
    validate(instance=edr, schema=schema)


def test_schema_v1_0_0_is_immutable_hash_pinned():
    schema_bytes = Path("schemas/edr/EDR_v1.0.0.json").read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == "2228890cb38c4d89a2a4ab46ba1b1430c2066f8c74548b8beb95e298f87ad45a"
