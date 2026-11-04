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

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));
    let workspace_root = manifest_dir.parent().unwrap_or(&manifest_dir).to_path_buf();

    let mut candidate_roots = Vec::new();
    if let Some(target_dir_var) = env::var_os("CARGO_TARGET_DIR") {
        let p = PathBuf::from(target_dir_var);
        if p.is_relative() {
            candidate_roots.push(workspace_root.join(&p));
            candidate_roots.push(manifest_dir.join(&p));
        } else {
            candidate_roots.push(p);
        }
    }
    candidate_roots.push(workspace_root.join("target"));
    candidate_roots.push(manifest_dir.join("../target"));
    candidate_roots.push(PathBuf::from("../target"));
    candidate_roots.push(PathBuf::from("target"));

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set by Cargo"));
    let staged_ebpf = out_dir.join("aegis-ebpf.bin");

    let mut found_elf = None;
    for root in &candidate_roots {
        let candidate_path = root
            .join("bpfel-unknown-none")
            .join("release")
            .join("aegis");

        println!("cargo:rerun-if-changed={}", candidate_path.display());
        if let Ok(bytes) = fs::read(&candidate_path) {
            if bytes.len() > 64 && bytes.starts_with(b"\x7fELF") {
                println!(
                    "cargo:warning=[aegis/build.rs] Staging valid eBPF kernel ELF ({} bytes) from {}",
                    bytes.len(),
                    candidate_path.display()
                );
                found_elf = Some(bytes);
                break;
            }
        }
    }

    match found_elf {
        Some(elf_bytes) => {
            fs::write(&staged_ebpf, elf_bytes)
                .expect("Failed to stage compiled eBPF ELF into OUT_DIR");
        }
        None => {
            println!(
                "cargo:warning=[aegis/build.rs] eBPF artifact not found in candidates: {:?}. Writing dummy placeholder.",
                candidate_roots
            );
            fs::write(&staged_ebpf, DUMMY_EBPF_PAYLOAD)
                .expect("Failed to write placeholder eBPF payload into OUT_DIR");
        }
    }
}
