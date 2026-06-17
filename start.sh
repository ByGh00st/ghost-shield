#!/bin/bash
INTERFACE=${1:-eth0}
echo "[NYX] Initializing Apex Predator Shield on $INTERFACE..."
if [ -f "./target/release/aegis" ]; then
    echo "[+] Found existing release binary. Bypassing compilation build phase..."
    sudo ./target/release/aegis $INTERFACE
else
    make run INTERFACE=$INTERFACE
fi
