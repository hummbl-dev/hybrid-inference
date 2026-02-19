#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv}"
PYTEST_BIN="${VENV_DIR}/bin/pytest"

if [[ ! -x "${PYTEST_BIN}" ]]; then
  echo "missing ${PYTEST_BIN}; run scripts/bootstrap_test_env.sh first" >&2
  exit 1
fi

expected_edr="2228890cb38c4d89a2a4ab46ba1b1430c2066f8c74548b8beb95e298f87ad45a"
actual_edr="$(sha256sum schemas/edr/EDR_v1.0.0.json | awk '{print $1}')"
test "${actual_edr}" = "${expected_edr}"

sha256sum -c governance/CAES_CANONICAL.sha256

expected_replay="84362e7b44c4528048fb66625dc886c5548730ef4c5ff53273d26d89aeedd3b8"
actual_replay="$(sha256sum schemas/replay/REPLAY_REPORT_v1.0.0.json | awk '{print $1}')"
test "${actual_replay}" = "${expected_replay}"

"${PYTEST_BIN}" -q tests/test_edr_replay.py
"${PYTEST_BIN}" -q tests/test_authority.py
"${PYTEST_BIN}" -q
