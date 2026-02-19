# PR10 Team Launch

## Objective
Enforce authority and replay contracts with typed boundary validation and deterministic CI bootstrap so invariant gates are mandatory and reproducible.

## Goal
Ship hardening that makes PR9 safety invariants unavoidable in production paths and consistently verifiable in local + CI execution.

## Necessary
- Introduce strict typed authority validation at router boundary (no loose dict acceptance paths).
- Add replay reason-code contract tests to lock stable refusal/error taxonomy.
- Add deterministic test bootstrap path so `pytest -q` runs with pinned deps in CI and documented local flow.
- Add one end-to-end integration test covering authority rejection plus replay refusal expectations.

## Out Of Scope
- Adding new external providers or changing routing policy decisions.
- Modifying schema versions unless explicitly required by contract change.
- Broad router refactors unrelated to authority/replay safety.

## Core Team

### 1) Release Integrator (Lead)
- Own scope lock, sequencing, and merge criteria.
- Ensure no schema drift and no unrelated file churn.

### 2) Boundary Validation Owner
- Implement typed request models for authority boundary inputs.
- Preserve existing refusal semantics and status codes.

### 3) Replay Contract Owner
- Codify stable replay reason-code contract tests.
- Guard against taxonomy drift and silent behavior changes.

### 4) CI Bootstrap Owner
- Make dependency bootstrap deterministic and repeatable.
- Keep local/CI test invocation parity.

### 5) Adversarial Integration Owner
- Add E2E-style test path spanning authority + replay refusal behavior.
- Ensure artifacts and reason codes remain deterministic.

## Execution Order
1. Lock exact PR10 scope and acceptance matrix.
2. Implement typed authority boundary validation.
3. Add replay reason-code contract tests.
4. Implement deterministic CI/local bootstrap updates.
5. Add integrated adversarial flow test.
6. Run full suite and merge gate checks.

## Test Matrix
| Area | Invariant | Gate |
|---|---|---|
| Authority boundary | Invalid authority payload shapes cannot bypass typed validation | `tests/test_authority.py` |
| Replay taxonomy | Refusal/error reason codes remain stable | `tests/test_edr_replay.py` |
| Integrated behavior | Authority + replay safety holds in one adversarial path | `tests/test_*integration*.py` |
| CI reproducibility | Full suite runnable with deterministic deps | `.github/workflows/ci.yml` + local bootstrap doc |

## Merge Gate (Hard)
- CI 3.11 and 3.12 green.
- Full `pytest -q` green in a documented local bootstrap environment.
- `git diff --name-only | rg '^schemas/' || true` is empty unless contract bump is intentional.
- No security policy regressions in authority/replay refusal paths.
