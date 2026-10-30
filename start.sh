#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${1:-eth0}"
BIN="./target/release/aegis"
EBPF_BIN="./target/bpfel-unknown-none/release/aegis"

echo "[NYX] Initializing Apex Predator Shield on ${INTERFACE}..."

if [[ -x "${BIN}" && -f "${EBPF_BIN}" && \
      "${BIN}" -nt "aegis/src/main.rs" && \
      "${BIN}" -nt "aegis-ebpf/src/main.rs" && \
      "${BIN}" -nt "aegis-common/src/lib.rs" ]]; then
    echo "[+] Up-to-date release binary verified. Launching..."
    exec sudo "${BIN}" "${INTERFACE}"
else
    echo "[+] Source changes or missing artifacts detected. Compiling via make..."
    make build
    exec sudo "${BIN}" "${INTERFACE}"
fi
