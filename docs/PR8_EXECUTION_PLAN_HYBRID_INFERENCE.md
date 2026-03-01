# PR8 Execution Plan (Hybrid Inference)

## Scope Lock
- PR8 execution is limited to `/Users/others/PROJECTS/hybrid-inference`.
- Released schemas/contracts remain immutable in place.
- Existing authority, replay, and EDR semantics are preserved.
- Runtime safety remains deny-by-default with fail-closed handling.
- No secrets or network-dependent test requirements introduced.

## Acceptance Criteria
- Planning artifact exists with scope lock, acceptance criteria, merge gates, and rollback notes.
- Runtime guard changes (if any) are backward compatible by default and fail closed.
- Adversarial tests cover malformed payloads and replay edge cases.
- Local validation is runnable and green without requiring remote CI calls.

## Merge Gates
- `bash scripts/run_ci_local_gates.sh` passes locally.
- No schema drift: hash-pinned schema checks continue to pass.
- Adversarial replay and authority tests pass.
- Diff only includes PR8-scoped files.

## Local Validation Commands
```bash
bash scripts/run_ci_local_gates.sh
```

## Rollback Notes
- Revert PR8 commit(s) with `git revert <sha>` if post-merge issues are found.
- Re-run `bash scripts/run_ci_local_gates.sh` after rollback to confirm baseline integrity.
- If only tests/docs regress, revert those files first and keep runtime guard fixes isolated.
