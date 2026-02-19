from src.router.policy.engine import decide


def test_sensitive_routes_local_deep_when_healthy():
    decision = decide(
        {"classification": "SENSITIVE", "latency": "interactive", "provider_allowlist": ["local"]},
        local_ok=True,
        router_model="qwen3:8b",
        deep_model="qwen3:32b",
    )
    assert decision.provider == "local"
    assert decision.model == "qwen3:32b"


def test_falls_back_to_openai_when_local_unhealthy():
    decision = decide(
        {"classification": "INTERNAL", "latency": "interactive", "provider_allowlist": ["openai"]},
        local_ok=False,
        router_model="qwen3:8b",
        deep_model="qwen3:32b",
    )
    assert decision.provider == "openai"
    assert decision.degraded is True
