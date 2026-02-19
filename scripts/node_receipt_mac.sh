#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-NODE_RECEIPT.md}"
{
  echo "# NODE RECEIPT"
  echo
  echo "## System"
  sw_vers || true
  echo
  echo "## Hardware"
  system_profiler SPHardwareDataType | sed -n '1,60p' || true
  echo
  echo "## Ollama"
  command -v ollama && ollama --version || echo "ollama: not found"
  echo
  echo "### Models"
  ollama list || true
  echo
  echo "### Show: qwen3:8b"
  ollama show qwen3:8b || true
  echo
  echo "### Show: qwen3:32b"
  ollama show qwen3:32b || true
  echo
  echo "## Storage"
  df -h / || true
  echo
  echo "## Memory"
  vm_stat | head -n 30 || true
  echo
  echo "## Swap"
  sysctl vm.swapusage || true
  echo
  echo "## Network"
  scutil --get HostName 2>/dev/null || true
  ipconfig getifaddr en0 2>/dev/null || true
  ipconfig getifaddr en1 2>/dev/null || true
  echo
  echo "## SSH Fingerprints"
  for key in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$key" ] && ssh-keygen -lf "$key"
  done
} > "$OUT"

echo "Wrote $OUT"
