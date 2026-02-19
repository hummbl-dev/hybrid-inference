# Architecture

`src/router/main.py` exposes an OpenAI-compatible `POST /v1/chat/completions` endpoint.

Core flow:
1. Parse request + optional routing contract.
2. Health-check local host constraints.
3. Run deterministic policy decision.
4. Audit metadata (hashes, no raw prompt body).
5. Dispatch to provider (Ollama implemented, API providers pending).
6. Emit EDR artifact for every path (success/failure/reject).

EDR modules:
- `src/hybrid_inference/edr.py`: canonicalization + hashes + EDR object construction.
- `src/hybrid_inference/middleware/edr_emitter.py`: deterministic persistence to artifacts.
