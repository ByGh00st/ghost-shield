INTERFACE ?= eth0
TARGET_IP ?= 127.0.0.1
PROTO ?= udp

.PHONY: all build build-ebpf build-user run test clean

all: build

build-ebpf:
	@echo "[+] Building eBPF Core (Apex Ring 0)..."
	cargo +nightly build -p aegis-ebpf --target bpfel-unknown-none -Z build-std=core --release

build-user: build-ebpf
	@echo "[+] Building Apex Control Plane (Ring 3)..."
	cargo build -p aegis --release

build: build-user

run: build
	@echo "[!] Attaching Hydra Apex on $(INTERFACE)..."
	sudo ./target/release/aegis $(INTERFACE)

test:
	@echo "[!] Starting Simulated Flood Test against $(TARGET_IP) ($(PROTO))..."
	python3 test_flood.py $(TARGET_IP) $(PROTO)

clean:
	cargo clean
