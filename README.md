# sikte

An eBPF-based syscall tracer with CO-RE (Compile Once, Run Everywhere) support.

## Prerequisites

1. **Rust toolchains**:
   - Stable: `rustup toolchain install stable`
   - Nightly: `rustup toolchain install nightly --component rust-src`

2. **eBPF development tools**:
   - clang/LLVM for compiling C eBPF programs
   - bpftool for generating vmlinux.h: `apt-get install linux-tools-generic` (or equivalent)
   - libbpf development headers: `apt-get install libbpf-dev`

3. **Kernel requirements**:
   - Linux kernel 5.8+ with BTF enabled
   - Verify BTF is available: `ls /sys/kernel/btf/vmlinux`
   - CONFIG_DEBUG_INFO_BTF=y in kernel config

## Build & Run

Build the project:

```shell
cargo build --release
```

Run with root privileges (required for eBPF):

```shell
sudo ./target/release/sikte record --syscalls --command ls
```

Or use cargo directly:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- record --syscalls --command ls
```

## CO-RE Support

This project uses libbpf-rs and CO-RE, which means:
- A single compiled binary works across different kernel versions (5.8+)
- Automatic field offset relocations based on kernel BTF
- No need to recompile for different kernel configurations

The vmlinux.h header is generated from your system's BTF at build time, capturing all kernel type definitions for CO-RE relocations.

## Development

Cargo build scripts automatically:
1. Compile C eBPF programs using clang
2. Generate Rust skeleton bindings via libbpf-cargo
3. Embed eBPF bytecode in the final binary

## License

All code is distributed under the terms of the [GNU General Public License,
Version 2].

[GNU General Public License, Version 2]: LICENSE
