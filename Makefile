all: build

build:
	@echo "[+] Building eBPF Core (Apex)..."
	cargo build -p aegis-ebpf --target bpfel-unknown-none --release
	@echo "[+] Building Apex Loader..."
	cargo build -p aegis --release

run: build
	@echo "[!] Starting Hydra on $(INTERFACE)..."
	sudo ./target/release/aegis $(INTERFACE)

test:
	@echo "[!] Starting Simulated Flood Test..."
	python3 test_flood.py $(TARGET_IP)

clean:
	cargo clean
