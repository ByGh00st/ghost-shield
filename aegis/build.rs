use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Ensure that target directory and dummy file exist so include_bytes! doesn't fail cargo check/build.
    let out_dir = Path::new("../target/bpfel-unknown-none/release");
    if !out_dir.exists() {
        let _ = fs::create_dir_all(out_dir);
    }
    let aegis_bpf = out_dir.join("aegis");
    if !aegis_bpf.exists() {
        let _ = fs::write(aegis_bpf, &[0u8; 64]);
    }
}
