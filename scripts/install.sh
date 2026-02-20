#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
PROFILE_HINT="${PROFILE_HINT:-$HOME/.profile}"

echo "[+] Building bsuppla (release)"
(cd "$ROOT_DIR/bsuppla" && cargo build --release)

mkdir -p "$BIN_DIR"
cp "$ROOT_DIR/bsuppla/target/release/bsuppla" "$BIN_DIR/bsuppla"

echo "[+] Installed to $BIN_DIR/bsuppla"

if ! command -v bsuppla >/dev/null 2>&1; then
  echo "[!] $BIN_DIR is not on PATH."
  echo "    Add this line to your shell profile (e.g. $PROFILE_HINT):"
  echo "    export PATH=\"$BIN_DIR:\$PATH\""
fi
