use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    let out_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));

    // Generate Rust skeleton from C eBPF programs
    SkeletonBuilder::new()
        .source("ebpf-src/raw_trace_points.bpf.c")
        .clang_args([
            "-Iebpf-src/vmlinux",
            "-Iebpf-src",
            "-D__TARGET_ARCH_x86", // Architecture-specific define
            "-g",                  // Debug info for BTF
        ])
        .build_and_generate(&mut out_path.join("sikte.skel.rs"))
        .expect("Failed to build and generate skeleton");

    // Trigger rebuild if source files change
    println!("cargo:rerun-if-changed=ebpf-src/raw_trace_points.bpf.c");
    println!("cargo:rerun-if-changed=ebpf-src/raw_trace_points.h");
    println!("cargo:rerun-if-changed=ebpf-src/vmlinux/vmlinux.h");
}
