# PR8 Team Launch

## Mission
Deliver PR8 with strict scope control, schema/governance integrity, runtime safety, and adversarial test coverage.

## Goal
Add explicit CI invariant adversarial gates that prove authority-boundary safety and replay safety remain intact across future changes.

## Necessary
- Add authority adversarial tests for:
  - lease replay denial,
  - lease ID whitespace canonicalization (bypass resistance),
  - invalid scope type rejection with EDR failure evidence.
- Add replay adversarial tests for:
  - non-replayable EDR rejection,
  - missing replay input pointer rejection,
  - unsupported provider error when network is explicitly allowed.
- Wire CI to run `tests/test_edr_replay.py` and `tests/test_authority.py` as dedicated invariant gates before full `pytest -q`.
- Document these dedicated invariant gates in `README.md`.

## Out Of Scope
- Changing runtime policy or authority semantics.
- Modifying replay report schema versions or schema pins.
- Expanding provider implementations for offline replay.
- Refactoring router internals unrelated to authority/replay invariants.

## Test Matrix
| Area | Invariant | Test |
|---|---|---|
| Authority | Missing authority when required is rejected with `403` and EDR authority violation | `tests/test_authority.py::test_authority_required_missing_rejected_and_edr_logged` |
| Authority | Lease replay is denied | `tests/test_authority.py::test_authority_lease_replay_rejected` |
| Authority | Lease ID canonicalization prevents whitespace replay bypass | `tests/test_authority.py::test_authority_lease_id_whitespace_canonicalization_blocks_replay_bypass` |
| Authority | Invalid scope type is rejected and emitted to EDR | `tests/test_authority.py::test_authority_scope_invalid_type_rejected_and_edr_logged` |
| Replay | Non-replayable artifacts error out | `tests/test_edr_replay.py::test_replay_errors_when_edr_marked_non_replayable` |
| Replay | Missing required inputs pointer errors out | `tests/test_edr_replay.py::test_replay_errors_when_required_inputs_pointer_missing` |
| Replay | Networkless safety refusal remains enforced by default | `tests/test_edr_replay.py::test_replay_refuses_network_without_flag` |
| Replay | Unsupported provider still errors even when network allowed | `tests/test_edr_replay.py::test_replay_errors_when_provider_unsupported_even_if_network_allowed` |

## Core Team

### 1) Release-Integrator (Lead)
- Owns PR8 scope lock and acceptance criteria.
- Runs merge gate checks (CI green, branch clean, no schema drift).
- Owns cross-agent sequencing and final cut/no-cut decision.

### 2) Schema-Governance Agent
- Handles schema changes, versioning, and hash pin policy.
- Adds/updates CI hash verification steps where required.
- Ensures older schema versions remain immutable.

### 3) Runtime-Guard Agent
- Implements runtime/boundary behavior changes.
- Preserves stable status semantics and backward-compatible defaults.
- Rejects unsafe operations by default where applicable.

### 4) Adversarial-Test Agent
- Builds red-path tests before merge.
- Covers malformed payloads, replay/reuse edge cases, and regression checks.
- Verifies no behavior drift in existing EDR/replay/authority flows.

## Optional Sub-Agent

### Docs-Operator (on-demand)
- Updates README/docs/runbook deltas only for changed behavior.
- Keeps docs concise and operator-focused.

## Execution Order
1. Release-Integrator publishes PR8 scope + non-goals.
2. Runtime-Guard and Schema-Governance work in parallel.
3. Adversarial-Test codifies failure matrix and gates.
4. Docs-Operator updates minimal docs.
5. Release-Integrator runs merge gate and ships.

## Merge Gate (Hard)
- CI 3.11 and 3.12 green.
- No unpinned schema changes.
- No unrelated file churn.
- All refusal/error paths produce deterministic artifacts.
- `main` clean and rebased before merge.

## Kickoff Checklist
- [ ] PR8 objective sentence approved.
- [ ] Non-goals declared.
- [ ] File/path blast radius listed.
- [ ] Test matrix declared.
- [ ] Merge criteria declared.

## Request Needed To Start Build
Provide PR8 objective in one line:
- `Goal:`
- `Necessary:`
- `Out of scope:`
