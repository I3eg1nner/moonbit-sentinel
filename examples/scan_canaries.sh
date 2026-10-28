#!/usr/bin/env bash
# Minimal end-to-end example: build the auditor and scan the bundled
# canary fixtures — no network access required.
set -euo pipefail
cd "$(dirname "$0")/.."

moon build --target native --release
ENGINE=$(find _build/native/release -type f -executable | head -1)

echo "== malicious canary (expect Malicious, exit 1) =="
"$ENGINE" scan canaries/typo_malicious --explain || true

echo
echo "== benign canary (expect Clean, exit 0) =="
"$ENGINE" scan canaries/benign_http
