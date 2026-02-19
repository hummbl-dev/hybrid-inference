#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"
PIP_VERSION="${PIP_VERSION:-24.3.1}"

"${PYTHON_BIN}" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade "pip==${PIP_VERSION}"
"${VENV_DIR}/bin/pip" install -r requirements.txt

echo "bootstrap complete: venv=${VENV_DIR} python=$("${VENV_DIR}/bin/python" --version)"
