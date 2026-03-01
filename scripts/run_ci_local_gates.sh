#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv}"
PYTEST_BIN="${VENV_DIR}/bin/pytest"

if [[ ! -x "${PYTEST_BIN}" ]]; then
  echo "missing ${PYTEST_BIN}; run scripts/bootstrap_test_env.sh first" >&2
  exit 1
fi

hash_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
    return
  fi
  shasum -a 256 "${path}" | awk '{print $1}'
}

expected_edr="2228890cb38c4d89a2a4ab46ba1b1430c2066f8c74548b8beb95e298f87ad45a"
actual_edr="$(hash_file schemas/edr/EDR_v1.0.0.json)"
test "${actual_edr}" = "${expected_edr}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c governance/CAES_CANONICAL.sha256
else
  shasum -a 256 -c governance/CAES_CANONICAL.sha256
fi

expected_replay="84362e7b44c4528048fb66625dc886c5548730ef4c5ff53273d26d89aeedd3b8"
actual_replay="$(hash_file schemas/replay/REPLAY_REPORT_v1.0.0.json)"
test "${actual_replay}" = "${expected_replay}"

"${PYTEST_BIN}" -q tests/test_edr_replay.py
"${PYTEST_BIN}" -q tests/test_authority.py
"${PYTEST_BIN}" -q
