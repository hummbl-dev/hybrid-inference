# PR8 Team Launch

## Mission
Deliver PR8 with strict scope control, schema/governance integrity, runtime safety, and adversarial test coverage.

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
