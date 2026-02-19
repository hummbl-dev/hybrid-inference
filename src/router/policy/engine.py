from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    provider: str
    model: str
    reason_codes: list[str]
    degraded: bool = False


def decide(contract: dict, local_ok: bool, router_model: str, deep_model: str) -> Decision:
    classification = contract.get("classification", "INTERNAL")
    latency = contract.get("latency", "interactive")
    allow = contract.get("provider_allowlist") or ["local", "anthropic", "openai"]

    if classification in ("SECRET", "SENSITIVE") and "local" in allow:
        if not local_ok:
            return Decision("reject", "", ["LOCAL_UNHEALTHY_FOR_SENSITIVE"])
        return Decision("local", deep_model, ["SENSITIVE_LOCAL"])

    if "local" in allow and local_ok:
        preferences = contract.get("model_preferences") or []
        if deep_model in preferences or latency == "batch":
            return Decision("local", deep_model, ["LOCAL_OK_DEEP"])
        return Decision("local", router_model, ["LOCAL_OK_ROUTER"])

    for provider in allow:
        if provider in ("anthropic", "openai"):
            fallback_model = (contract.get("model_preferences") or ["default"])[0]
            return Decision(provider, fallback_model, [f"FALLBACK_{provider.upper()}"], degraded=True)

    return Decision("reject", "", ["NO_PROVIDER_AVAILABLE"])
