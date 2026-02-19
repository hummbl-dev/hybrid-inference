import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.router import main
from src.router.authority import LEASE_REGISTRY
from src.router.health.local_health import Health


def _latest_edr_file(root: Path) -> Path:
    files = sorted(root.rglob("*.json"))
    assert files, "no edr artifacts found"
    return files[-1]


def test_authority_required_missing_rejected_and_edr_logged(monkeypatch, tmp_path):
    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
        },
    )
    assert response.status_code == 403
    assert "AUTHORITY_MISSING" in response.json()["detail"]["reason_codes"]

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "authority_violation"
    assert edr["decision_factors"] == ["AUTHORITY_MISSING"]


def test_authority_scope_denied_rejected(monkeypatch, tmp_path):
    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
            "authority": {
                "issued_by": "ops",
                "scope": "metrics:read",
                "ttl": 60,
                "lease_id": "lease-a",
            },
        },
    )
    assert response.status_code == 403
    assert "AUTHORITY_SCOPE_DENIED" in response.json()["detail"]["reason_codes"]


def test_authority_lease_replay_rejected(monkeypatch, tmp_path):
    async def fake_ollama_chat(base_url, model, messages, stream=False):
        return {"message": {"content": "ok"}}

    def healthy(*args, **kwargs):
        return Health(True, "ok")

    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", fake_ollama_chat)
    monkeypatch.setattr(main, "check_local_health", healthy)

    payload = {
        "messages": [{"role": "user", "content": "hello"}],
        "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
        "authority": {
            "issued_by": "ops",
            "scope": "chat:completions",
            "ttl": 60,
            "lease_id": "lease-1",
        },
    }

    client = TestClient(main.app)
    first = client.post("/v1/chat/completions", json=payload)
    assert first.status_code == 200

    second = client.post("/v1/chat/completions", json=payload)
    assert second.status_code == 403
    assert "LEASE_REPLAY" in second.json()["detail"]["reason_codes"]


def test_authority_lease_id_whitespace_canonicalization_blocks_replay_bypass(monkeypatch, tmp_path):
    async def fake_ollama_chat(base_url, model, messages, stream=False):
        return {"message": {"content": "ok"}}

    def healthy(*args, **kwargs):
        return Health(True, "ok")

    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", fake_ollama_chat)
    monkeypatch.setattr(main, "check_local_health", healthy)

    client = TestClient(main.app)

    with_whitespace = {
        "messages": [{"role": "user", "content": "hello"}],
        "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
        "authority": {
            "issued_by": "ops",
            "scope": "chat:completions",
            "ttl": 60,
            "lease_id": " lease-1 ",
        },
    }
    canonicalized = {
        "messages": [{"role": "user", "content": "hello"}],
        "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
        "authority": {
            "issued_by": "ops",
            "scope": "chat:completions",
            "ttl": 60,
            "lease_id": "lease-1",
        },
    }

    first = client.post("/v1/chat/completions", json=with_whitespace)
    assert first.status_code == 200

    second = client.post("/v1/chat/completions", json=canonicalized)
    assert second.status_code == 403
    assert "LEASE_REPLAY" in second.json()["detail"]["reason_codes"]


def test_authority_scope_invalid_type_rejected_and_edr_logged(monkeypatch, tmp_path):
    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
            "authority": {
                "issued_by": "ops",
                "scope": {"chat": "completions"},
                "ttl": 60,
                "lease_id": "lease-invalid-scope",
            },
        },
    )
    assert response.status_code == 403
    assert "AUTHORITY_SCOPE_INVALID" in response.json()["detail"]["reason_codes"]

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "authority_violation"
    assert edr["decision_factors"] == ["AUTHORITY_SCOPE_INVALID"]


def test_authority_non_object_rejected_and_edr_logged(monkeypatch, tmp_path):
    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
            "authority": "ops-issued-token",
        },
    )
    assert response.status_code == 403
    assert "AUTHORITY_INVALID" in response.json()["detail"]["reason_codes"]

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "authority_violation"
    assert edr["decision_factors"] == ["AUTHORITY_INVALID"]


def test_authority_missing_lease_id_rejected_and_edr_logged(monkeypatch, tmp_path):
    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
            "authority": {
                "issued_by": "ops",
                "scope": "chat:completions",
                "ttl": 60,
            },
        },
    )
    assert response.status_code == 403
    assert "AUTHORITY_LEASE_INVALID" in response.json()["detail"]["reason_codes"]

    edr = json.loads(_latest_edr_file(tmp_path / "edr").read_text())
    assert edr["failure"]["type"] == "authority_violation"
    assert edr["decision_factors"] == ["AUTHORITY_LEASE_INVALID"]


def test_authority_scope_list_allows_request(monkeypatch, tmp_path):
    async def fake_ollama_chat(base_url, model, messages, stream=False):
        return {"message": {"content": "ok"}}

    def healthy(*args, **kwargs):
        return Health(True, "ok")

    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", fake_ollama_chat)
    monkeypatch.setattr(main, "check_local_health", healthy)

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
            "authority": {
                "issued_by": "ops",
                "scope": ["metrics:read", "chat:completions"],
                "ttl": 60,
                "lease_id": "lease-list-scope",
            },
        },
    )
    assert response.status_code == 200


def test_authority_wildcard_scope_allows_request(monkeypatch, tmp_path):
    async def fake_ollama_chat(base_url, model, messages, stream=False):
        return {"message": {"content": "ok"}}

    def healthy(*args, **kwargs):
        return Health(True, "ok")

    LEASE_REGISTRY.clear()
    monkeypatch.setattr(main.settings, "edr_root_path", str(tmp_path / "edr"))
    monkeypatch.setattr(main, "ollama_chat", fake_ollama_chat)
    monkeypatch.setattr(main, "check_local_health", healthy)

    client = TestClient(main.app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "routing_contract": {"classification": "INTERNAL", "latency": "interactive", "authority_required": True},
            "authority": {
                "issued_by": "ops",
                "scope": "*",
                "ttl": 60,
                "lease_id": "lease-wildcard-scope",
            },
        },
    )
    assert response.status_code == 200
