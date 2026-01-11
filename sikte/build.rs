use std::{env, ffi::OsStr, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/sikte.bpf.c";
const HEADER: &str = "src/bpf/sikte.h";

fn main() {
    // Output skeleton to source tree (following libbpf-rs examples)
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("sikte.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    // Generate Rust skeleton from C eBPF programs
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .expect("Failed to build and generate skeleton");

    // Trigger rebuild if source files change
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={HEADER}");
}
