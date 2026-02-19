# Changelog

## 0.2.2
- Added GitHub Actions CI workflow for push/pull request validation.
- CI now runs dependency install, EDR schema hash pin validation, and `pytest -q` across Python 3.11 and 3.12.

## 0.2.1
- Added top-level uncaught exception EDR emission middleware for `/v1/chat/completions`.
- Added atomic EDR artifact persistence (write + fsync + rename) to prevent partial files.
- Hardened EDR payloads to avoid raw prompt/response persistence by default.
- Added tests for uncaught exception emission, decision hash stability, atomic writes, and schema hash pinning.

## 0.2.0
- Added EDR v1.0 schema at `schemas/edr/EDR_v1.0.0.json`.
- Added deterministic canonicalization and hashing utilities for EDR.
- Added always-on EDR emission for success, policy reject, and provider failure paths.
- Added EDR middleware emitter module and storage path conventions.
- Added tests for EDR emission and schema validation.

## 0.1.0
- Initial repository scaffolding.
- Added FastAPI router skeleton with policy/health/queue/audit modules.
- Added routing contract schema and example contracts.
- Added node receipt script and basic tests.
