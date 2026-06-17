#!/bin/bash
INTERFACE=${1:-eth0}
echo "[NYX] Initializing Apex Predator Shield on $INTERFACE..."
make run INTERFACE=$INTERFACE
