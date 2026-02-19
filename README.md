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
