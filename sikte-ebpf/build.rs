fn main() {
    // Trigger rebuild if C source files change
    // The actual compilation is handled by sikte/build.rs using libbpf-cargo
    println!("cargo:rerun-if-changed=src/raw_trace_points.bpf.c");
    println!("cargo:rerun-if-changed=src/raw_trace_points.h");
    println!("cargo:rerun-if-changed=src/vmlinux/vmlinux.h");
}
