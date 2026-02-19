# hybrid-inference

Policy-driven hybrid inference router for local-first (Ollama) with Anthropic/OpenAI fallback paths.

## v0.2.2 goals
- Deterministic routing contract.
- Local health gating.
- Single heavy local inference slot.
- EDR (Execution Decision Record) artifact emission on every request path.
- Uncaught exception EDR fallback and atomic EDR persistence.

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn src.router.main:app --host 127.0.0.1 --port 8088
```

## EDR artifacts
Each request writes a schema-validated EDR artifact to:

`artifacts/edr/YYYY/MM/DD/<decision_core_hash>.json`

Schema `EDR_v1.0.0` is hash-pinned in tests to enforce immutability.

## Governance
CAES: `governance/CAES_SPEC.md` (v1.0.0, hash-pinned).

## EDR replay
Replay and verify an EDR artifact offline:

```bash
scripts/edr-replay artifacts/edr/YYYY/MM/DD/<decision_core_hash>.json
```

Safety defaults:
- Refuses replay when `side_effects != "none"` unless `--allow-side-effects`.
- Refuses replay for networked providers unless `--allow-network`.
- Uses deterministic local replay only (no external provider calls).
- Writes replay reports to `artifacts/replay/YYYY/MM/DD/<decision_core_hash>.json`.
- Replay report schema is pinned at `schemas/replay/REPLAY_REPORT_v1.0.0.json`.
- CI runs adversarial replay invariant gates (`tests/test_edr_replay.py`) before full suite.

## Authority + lease boundary
`/v1/chat/completions` accepts optional `authority`:

```json
{
  "issued_by": "ops",
  "scope": "chat:completions",
  "ttl": 60,
  "lease_id": "lease-123"
}
```

When `routing_contract.authority_required` is `true`, missing/invalid authority is rejected at router boundary (`403`) and emitted as EDR failure type `authority_violation`.

CI runs authority adversarial invariant gates (`tests/test_authority.py`) to guard replay-safe lease handling and strict authority validation failures.
