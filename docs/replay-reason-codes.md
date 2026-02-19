# Replay Reason Codes

This document defines the replay reason-code contract enforced by CI.

## REFUSED

### `SIDE_EFFECTS_NOT_ALLOWED`
- Meaning: replay was blocked because the source EDR declares side effects and `--allow-side-effects` was not provided.
- Operator action: rerun only if side effects are explicitly approved.

### `NETWORK_NOT_ALLOWED`
- Meaning: replay was blocked because replay would use a networked provider and `--allow-network` was not provided.
- Operator action: rerun only if network access is explicitly approved.

## ERROR

### `REPLAY_NOT_REPLAYABLE`
- Meaning: EDR is marked non-replayable.
- Operator action: treat as terminal; use original EDR artifact for analysis.

### `INPUT_POINTER_MISSING`
- Meaning: required replay input pointer is missing/invalid/unreadable.
- Operator action: recover or reconstruct required input artifact before retry.

### `PROVIDER_NOT_SUPPORTED`
- Meaning: replay path selected a provider unsupported by offline replay engine.
- Operator action: use supported local provider replay flow or add support in a future scoped change.

### `EXECUTION_ERROR`
- Meaning: replay encountered execution/parsing failure (for example malformed EDR JSON root).
- Operator action: inspect source EDR validity and replay runtime logs.

## DIVERGED

### `INPUT_HASH_MISMATCH`
- Meaning: replay recomputed input hash differs from EDR input hash.
- Operator action: treat as integrity drift; validate source artifacts.

### `OUTPUT_HASH_MISMATCH`
- Meaning: replay output hash differs from EDR output hash.
- Operator action: investigate environmental/runtime differences.

### `DECISION_CORE_MISMATCH`
- Meaning: output matched but decision core fields drifted.
- Operator action: inspect decision factors/constraints/failure/replay fields for tamper or regression.

### `EDR_HASH_MISMATCH`
- Meaning: recomputed EDR hash differs from recorded EDR hash.
- Operator action: treat as EDR integrity failure and escalate.

### `ENVIRONMENT_MISMATCH`
- Meaning: replay runtime environment differs from recorded required environment.
- Operator action: rerun with matching environment label where possible.
