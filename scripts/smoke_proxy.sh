#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${ROOT_DIR}/logs/smoke.jsonl"

echo "[smoke] running Go-based integration probe"
GOFLAGS="" go run "$ROOT_DIR/cmd/smokecheck" --addr 127.0.0.1:18080 --log-file "$LOG_FILE"

echo "[smoke] completed; log entries written to $LOG_FILE"
