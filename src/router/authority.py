from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any


@dataclass(frozen=True)
class AuthorityError(Exception):
    code: str
    message: str


class LeaseRegistry:
    def __init__(self) -> None:
        self._expires_at: dict[str, float] = {}

    def clear(self) -> None:
        self._expires_at.clear()

    def check_and_reserve(self, lease_id: str, ttl_seconds: int, now_epoch: float | None = None) -> bool:
        now = now_epoch if now_epoch is not None else time.time()
        self._expires_at = {k: exp for k, exp in self._expires_at.items() if exp > now}
        if lease_id in self._expires_at:
            return False
        self._expires_at[lease_id] = now + ttl_seconds
        return True


LEASE_REGISTRY = LeaseRegistry()


def _parse_scope(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    raise AuthorityError(code="AUTHORITY_SCOPE_INVALID", message="authority.scope must be a string or list of strings")


def validate_authority(
    authority: dict[str, Any] | None,
    *,
    required_scope: str,
    authority_required: bool,
    lease_registry: LeaseRegistry | None = None,
    now_epoch: float | None = None,
) -> None:
    if authority is None:
        if authority_required:
            raise AuthorityError(code="AUTHORITY_MISSING", message="authority block is required")
        return

    if not isinstance(authority, dict):
        raise AuthorityError(code="AUTHORITY_INVALID", message="authority block must be an object")

    issued_by = authority.get("issued_by")
    if not isinstance(issued_by, str) or not issued_by.strip():
        raise AuthorityError(code="AUTHORITY_ISSUER_INVALID", message="authority.issued_by must be a non-empty string")

    ttl = authority.get("ttl")
    if not isinstance(ttl, int) or ttl <= 0:
        raise AuthorityError(code="AUTHORITY_TTL_INVALID", message="authority.ttl must be a positive integer")

    lease_id = authority.get("lease_id")
    if not isinstance(lease_id, str) or not lease_id.strip():
        raise AuthorityError(code="AUTHORITY_LEASE_INVALID", message="authority.lease_id must be a non-empty string")

    scopes = _parse_scope(authority.get("scope"))
    if required_scope not in scopes and "*" not in scopes:
        raise AuthorityError(code="AUTHORITY_SCOPE_DENIED", message=f"required scope {required_scope!r} not granted")

    registry = lease_registry or LEASE_REGISTRY
    if not registry.check_and_reserve(lease_id.strip(), ttl, now_epoch=now_epoch):
        raise AuthorityError(code="LEASE_REPLAY", message="lease_id has already been used and is still active")
