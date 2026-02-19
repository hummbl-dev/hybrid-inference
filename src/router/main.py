from typing import Any
import json
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from src.hybrid_inference.edr import EDRFailure
from src.hybrid_inference.middleware.edr_emitter import emit_edr
from .audit.log import audit_append, sha256_hex
from .authority import AuthorityError, validate_authority
from .health.local_health import check_local_health
from .policy.engine import decide
from .providers.ollama import ollama_chat
from .queue.heavy_slot import HeavySlot
from .settings import settings

app = FastAPI(title="hybrid-inference", version="0.2.2")
heavy = HeavySlot(settings.heavy_slot_concurrency)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if request.url.path == "/v1/chat/completions":
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        body = b""
        parsed: dict[str, Any] = {}
        try:
            body = await request.body()
            parsed = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            parsed = {}

        contract = parsed.get("routing_contract") or {"classification": "INTERNAL", "latency": "interactive"}
        try:
            emit_edr(
                edr_root=settings.edr_root_path,
                request_id=request_id,
                contract=contract,
                decision={"provider": "unknown", "model": "", "protocol": "http", "path": request.url.path},
                decision_factors=["UNCAUGHT_EXCEPTION"],
                constraints_applied=[],
                input_payload={"body_sha256": sha256_hex(body)},
                output_payload={"error": "uncaught_exception", "exception": exc.__class__.__name__},
                failure=EDRFailure(type="uncaught_exception", stage="framework", message=str(exc)),
            )
        except Exception:
            pass
    return JSONResponse(status_code=500, content={"detail": "INTERNAL_SERVER_ERROR"})


class ChatReq(BaseModel):
    model: str | None = None
    messages: list[dict[str, Any]] = Field(default_factory=list)
    stream: bool = False
    routing_contract: dict[str, Any] | None = None
    authority: Any | None = None


class AuthorityPayload(BaseModel):
    issued_by: str
    scope: str | list[str]
    ttl: int
    lease_id: str


def _authority_error_code_from_validation(exc: ValidationError) -> str:
    if not exc.errors():
        return "AUTHORITY_INVALID"

    field = exc.errors()[0].get("loc", (None,))[0]
    if field == "issued_by":
        return "AUTHORITY_ISSUER_INVALID"
    if field == "scope":
        return "AUTHORITY_SCOPE_INVALID"
    if field == "ttl":
        return "AUTHORITY_TTL_INVALID"
    if field == "lease_id":
        return "AUTHORITY_LEASE_INVALID"
    return "AUTHORITY_INVALID"


def _normalized_authority_or_raise(authority: Any) -> dict[str, Any] | None:
    if authority is None:
        return None
    if not isinstance(authority, dict):
        raise AuthorityError(code="AUTHORITY_INVALID", message="authority block must be an object")

    try:
        normalized = AuthorityPayload.model_validate(authority)
    except ValidationError as exc:
        code = _authority_error_code_from_validation(exc)
        raise AuthorityError(code=code, message="authority payload failed typed validation") from exc

    return normalized.model_dump()


@app.get("/health")
def health() -> dict[str, Any]:
    current = check_local_health(settings.max_swap_bytes, settings.max_mem_percent)
    return {"ok": current.ok, "reason": current.reason}


@app.post("/v1/chat/completions")
async def chat(req: ChatReq, request: Request) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    contract = req.routing_contract or {"classification": "INTERNAL", "latency": "interactive"}
    msg_bytes = str(req.messages).encode("utf-8")
    input_payload = {"messages_sha256": sha256_hex(msg_bytes), "stream": req.stream, "model": req.model}
    authority_required = bool(contract.get("authority_required", False))
    constraints_applied = [
        f"max_swap_bytes={settings.max_swap_bytes}",
        f"max_mem_percent={settings.max_mem_percent}",
        f"authority_required={authority_required}",
    ]

    try:
        normalized_authority = _normalized_authority_or_raise(req.authority)
        validate_authority(
            normalized_authority,
            required_scope="chat:completions",
            authority_required=authority_required,
        )
    except AuthorityError as exc:
        output_payload = {"error": "authority_violation", "reason_code": exc.code}
        emit_edr(
            edr_root=settings.edr_root_path,
            request_id=request_id,
            contract=contract,
            decision={"provider": "reject", "model": "", "protocol": "http", "path": "/v1/chat/completions"},
            decision_factors=[exc.code],
            constraints_applied=constraints_applied,
            input_payload=input_payload,
            output_payload=output_payload,
            failure=EDRFailure(type="authority_violation", stage="authority", message=exc.message),
        )
        raise HTTPException(status_code=403, detail={"request_id": request_id, "reason_codes": [exc.code]})

    current = check_local_health(settings.max_swap_bytes, settings.max_mem_percent)
    decision = decide(contract, current.ok, settings.ollama_router_model, settings.ollama_deep_model)
    decision_payload = {
        "provider": decision.provider,
        "model": decision.model,
        "protocol": "http",
        "path": "/v1/chat/completions",
    }

    audit_append(
        settings.audit_log_path,
        {
            "request_id": request_id,
            "remote": request.client.host if request.client else None,
            "contract": contract,
            "provider": decision.provider,
            "model": decision.model,
            "reason_codes": decision.reason_codes,
            "degraded": decision.degraded,
            "messages_sha256": sha256_hex(msg_bytes),
            "local_health_ok": current.ok,
            "local_health_reason": current.reason,
            "authority_present": req.authority is not None,
            "authority_required": authority_required,
        },
    )

    if decision.provider == "reject":
        output_payload = {"error": "policy_reject", "reason_codes": decision.reason_codes}
        emit_edr(
            edr_root=settings.edr_root_path,
            request_id=request_id,
            contract=contract,
            decision=decision_payload,
            decision_factors=decision.reason_codes,
            constraints_applied=constraints_applied,
            input_payload=input_payload,
            output_payload=output_payload,
            failure=EDRFailure(type="policy_reject", stage="policy", message="request rejected by policy"),
        )
        raise HTTPException(status_code=503, detail={"request_id": request_id, "reason_codes": decision.reason_codes})

    if decision.provider != "local":
        output_payload = {"error": "provider_not_implemented", "provider": decision.provider}
        emit_edr(
            edr_root=settings.edr_root_path,
            request_id=request_id,
            contract=contract,
            decision=decision_payload,
            decision_factors=decision.reason_codes,
            constraints_applied=constraints_applied,
            input_payload=input_payload,
            output_payload=output_payload,
            failure=EDRFailure(type="provider_error", stage="dispatch", message="API provider not implemented"),
            side_effects="external",
        )
        raise HTTPException(
            status_code=501,
            detail={"request_id": request_id, "provider": decision.provider, "reason": "API_PROVIDER_NOT_IMPLEMENTED"},
        )

    try:
        if decision.model == settings.ollama_deep_model:
            async with heavy:
                output = await ollama_chat(settings.ollama_base_url, decision.model, req.messages, stream=False)
        else:
            output = await ollama_chat(settings.ollama_base_url, decision.model, req.messages, stream=False)

        content = output.get("message", {}).get("content", "")
        response = {
            "id": f"chatcmpl_{request_id}",
            "object": "chat.completion",
            "model": decision.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }
        emit_edr(
            edr_root=settings.edr_root_path,
            request_id=request_id,
            contract=contract,
            decision=decision_payload,
            decision_factors=decision.reason_codes,
            constraints_applied=constraints_applied,
            input_payload=input_payload,
            output_payload={
                "id": response["id"],
                "object": response["object"],
                "model": response["model"],
                "choices_count": len(response["choices"]),
                "first_choice_finish_reason": response["choices"][0]["finish_reason"],
            },
            failure=None,
        )
        return response
    except Exception as exc:
        output_payload = {"error": "provider_failure", "exception": exc.__class__.__name__}
        emit_edr(
            edr_root=settings.edr_root_path,
            request_id=request_id,
            contract=contract,
            decision=decision_payload,
            decision_factors=decision.reason_codes,
            constraints_applied=constraints_applied,
            input_payload=input_payload,
            output_payload=output_payload,
            failure=EDRFailure(type="provider_failure", stage="provider", message=str(exc)),
        )
        raise HTTPException(status_code=502, detail={"request_id": request_id, "reason": "LOCAL_PROVIDER_FAILURE"}) from exc
