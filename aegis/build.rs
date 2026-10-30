use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// 64-byte sentinel written to `OUT_DIR/aegis-ebpf.bin` when host `cargo check` runs
/// before the `bpfel-unknown-none` kernel artifact has been built.
/// Begins with `aegis_common::DUMMY_EBPF_MAGIC` (`b"NYX_DUMMY_EBPF00"`).
const DUMMY_EBPF_PAYLOAD: &[u8; 64] =
    b"NYX_DUMMY_EBPF00_PLACEHOLDER_BUILD_KERNEL_VIA_MAKE_BUILD_FIRST!!";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../aegis-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../aegis-common/src/lib.rs");

    let target_root = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("../target").to_path_buf());

    let compiled_ebpf = target_root
        .join("bpfel-unknown-none")
        .join("release")
        .join("aegis");

    println!("cargo:rerun-if-changed={}", compiled_ebpf.display());

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set by Cargo"));
    let staged_ebpf = out_dir.join("aegis-ebpf.bin");

    let valid_elf = fs::read(&compiled_ebpf)
        .ok()
        .filter(|bytes| bytes.len() > 64 && bytes.starts_with(b"\x7fELF"));

    match valid_elf {
        Some(elf_bytes) => {
            fs::write(&staged_ebpf, elf_bytes)
                .expect("Failed to stage compiled eBPF ELF into OUT_DIR");
        }
        None => {
            fs::write(&staged_ebpf, DUMMY_EBPF_PAYLOAD)
                .expect("Failed to write placeholder eBPF payload into OUT_DIR");
        }
    }
}
