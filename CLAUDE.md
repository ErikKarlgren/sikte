# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Sikte** is an eBPF-based performance tracer for Linux with CO-RE (Compile Once, Run Everywhere) support. It captures system calls from running processes, calculates timing information, and provides detailed execution analysis. The tool can either trace specific PIDs or execute commands and trace their syscalls.

## Build & Run Commands

### Development (main commands)
You will use the following command all the time for ensuring everything compiles, checking linter issues, ...
```bash
# Format, then run check and clippy
just
```

### Standard Build
```bash
# For actually building the binary
just build
# For actually building the binary in release mode
just build-release
```

### Running (requires root)
```bash
# Run with default logging (info level)
just run [args]

# Run with custom log level
just run-log debug [args]
```

### Testing
```bash
# Run all tests
just test
# Debug specific test with rust-gdb
just dbg-test [args]
```

### System Verification
```bash
# Verify kernel eBPF support and capabilities
just check-system
```

## Prerequisites

- **Rust toolchains**:
  - Stable: `rustup toolchain install stable`
  - Nightly: `rustup toolchain install nightly --component rust-src`

- **eBPF development tools**:
  - clang/LLVM for compiling C eBPF programs
  - bpftool: `apt-get install linux-tools-generic`
  - libbpf development headers: `apt-get install libbpf-dev`

- **Kernel requirements**:
  - Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
  - CONFIG_DEBUG_INFO_BTF=y
  - Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities

## Project Architecture

This is a single-crate project with a workspace structure (ready for future expansion to multiple crates like a GUI).

### sikte (Main Crate)
Main binary that orchestrates eBPF program loading, data collection, and event handling using libbpf-rs.

**Rust modules (sikte/src/):**
- `cli/`: Command-line argument parsing (uses clap)
- `common/`: C-compatible types shared between kernel and userspace
  - `constants/`: Program names and attachment point constants
  - `generic_types.rs`: Generic types for eBPF maps
  - `generated_types.rs`: Generated SyscallData, SyscallState types from C skeleton
- `ebpf/`: eBPF program lifecycle management (skeleton-based loading, attaching, maps)
  - `sikte_ebpf.rs`: Skeleton-based loader with CO-RE support
  - `map_types.rs`: Wrappers for libbpf-rs maps
  - `error.rs`: libbpf-rs error handling
- `events.rs`: EventBus implementation (tokio broadcast channel)
- `publishers/`: Extract data from kernel (ring buffers → events)
  - `syscalls/`: SyscallPublisher uses RingBufferBuilder with callbacks
- `subscribers/`: Consume events (ShellSubscriber for stdout)
- `syscall_table/`: Maps syscall IDs to names (x86_64 only)

**C eBPF programs (sikte/src/bpf/):**
C eBPF programs that run in kernel space, attached to raw tracepoints.

**Files:**
- `sikte.bpf.c`: C eBPF programs with CO-RE support
- `sikte.h`: C header with shared type definitions (includes vmlinux.h)

**Programs:**
- `sikte_raw_trace_point_at_enter`: Captures syscall entry (sys_enter tracepoint)
- `sikte_raw_trace_point_at_exit`: Captures syscall exit (sys_exit tracepoint)

**Maps:**
- `SYSCALL_EVENTS`: Ring buffer (1MB) for kernel→userspace event passing
- `PID_ALLOW_LIST`: HashMap (1024 entries) for PID filtering in kernel

## Data Flow

```
Kernel Space:
  sys_enter/sys_exit raw tracepoints
         ↓
  eBPF Programs (filter by PID_ALLOW_LIST)
         ↓
  SYSCALL_EVENTS ring buffer

Userspace:
  RingBufferBuilder callback (polls ring buffer)
         ↓
  EventBus (tokio broadcast channel)
         ↓
  ShellSubscriber (pairs enter/exit, calculates duration, prints)
```

## CO-RE Support

This project uses libbpf-rs and CO-RE for kernel portability:

**Key benefits:**
- Single binary works across kernel versions 5.8+
- Automatic field offset relocations based on kernel BTF
- No recompilation needed for different kernel configs

**How it works:**
1. Build time: `bpftool` generates vmlinux.h from `/sys/kernel/btf/vmlinux`
2. Compile time: clang compiles C eBPF with BTF debug info
3. Load time: libbpf applies CO-RE relocations for running kernel
4. Runtime: eBPF programs adapt to kernel-specific structure layouts

## Build System

The build process uses libbpf-cargo:

1. **sikte/build.rs**: Uses `SkeletonBuilder` to:
   - Compile C eBPF programs with clang
   - Generate Rust skeleton bindings
   - Output `OUT_DIR/sikte.skel.rs`

2. **Skeleton-based loading**:
   - Generated skeleton provides type-safe map and program access
   - `SikteSkel::open()` parses eBPF object
   - `.load()` applies CO-RE relocations and loads into kernel
   - `.attach()` attaches all programs to tracepoints

## Key Architectural Patterns

### Publisher-Subscriber Pattern
The project uses a multi-publisher, multi-consumer architecture:
- **Publishers** (EventPublisher trait): Read from eBPF ring buffers via callbacks
- **EventBus**: Tokio broadcast channel (capacity: 1024 events)
- **Subscribers** (EventSubscriber trait): Consume events from EventBus

### Ring Buffer Callbacks (libbpf-rs pattern)
- `RingBufferBuilder` registers callbacks for each ring buffer
- Callback invoked for each event, deserializes `SyscallData`
- `poll()` called in blocking task via `tokio::task::block_in_place`

### PID Filtering
- User provides PIDs via CLI (`--pid`) or launches a command (`--command`)
- Userspace populates `PID_ALLOW_LIST` eBPF map
- Kernel-space eBPF programs check this map before submitting events

### C-Compatible Data Structures
- Rust enums with data don't match C tagged unions
- `SyscallState` uses explicit `tag` field + `union` for C compatibility
- Helper methods provide safe access: `syscall_id()`, `syscall_ret()`

## Adding New Features

### Adding a New Subscriber
1. Implement the `EventSubscriber` trait in `sikte/src/subscribers/`
2. Implement `read_syscall(&mut self, syscall_data: &SyscallData)`
3. Register subscriber in `main.rs` via `event_bus.add_subscriber()`

### Adding a New eBPF Program
1. Add program to `sikte/src/bpf/sikte.bpf.c`
2. Define any new maps with proper SEC(".maps") annotations
3. If sharing data with userspace, add types to `sikte/src/common/` and `sikte/src/bpf/sikte.h`
4. Create a publisher in `sikte/src/publishers/` using `RingBufferBuilder`
5. Update `sikte/src/ebpf/sikte_ebpf.rs` to expose new maps

### Syscall Name Resolution
Currently only x86_64 is supported. To add another architecture:
1. Obtain syscall table from Linux kernel source
2. Generate const array in `sikte/src/syscall_table/`
3. Use conditional compilation (`#[cfg(target_arch = "...")]`)

## Important Implementation Notes

- All shared types must be C-compatible with `#[repr(C)]` and explicit alignment
- Use `bytemuck::CheckedBitPattern` for safe zero-copy deserialization
- Ring buffer can drop events if userspace consumer is slow (logged as warnings)
- Pattern matching uses `state.tag == SyscallStateTag::AT_ENTER` (not Rust enum variants)
- Helper methods provide safe access: `state.syscall_id()`, `state.syscall_ret()`
- The generated skeleton is located at `OUT_DIR/sikte.skel.rs`

## Licensing

This project uses **dual licensing** due to Linux kernel compatibility requirements:

- **Userspace Rust code** (`sikte/src/`, excluding `sikte/src/bpf/`): **AGPL-3.0-or-later**
  - The main binary and all Rust modules are licensed under AGPL-3.0-or-later
  - Cargo.toml reflects this license for the Rust crate

- **Kernel-space eBPF code** (`sikte/src/bpf/*.c`, `sikte/src/bpf/*.h`): **GPL-2.0-or-later**
  - eBPF programs must be GPL-compatible to load into the Linux kernel
  - AGPL-3.0 is NOT compatible with Linux's GPL-2.0-only license
  - Each C file has an SPDX header indicating GPL-2.0-or-later
  - The LICENSE string in the eBPF program is set to "GPL" for kernel verifier compatibility

**When adding new eBPF code**: Always use `// SPDX-License-Identifier: GPL-2.0-or-later` at the top of C files in `sikte/src/bpf/`.
**When adding new userspace code**: Always use `// SPDX-License-Identifier: AGPL-3.0-or-later` at the top of all other source code files

## Current Development Status

**Focus**: Syscall tracing with CO-RE support

**Completed**:
- Syscall enter/exit tracing with CO-RE relocations
- PID-based filtering
- Duration calculation between syscall pairs
- Command execution tracing
- Shell output subscriber
- Architecture support for x86_64

**Future work** (see TASKS.md):
- Syscall argument extraction (requires specific tracepoints)
- Multiple output backends (database, metrics)
- Support for additional architectures (ARM)
- Process fork tracking (sched_process_fork tracepoint)

## Debugging

- Use `RUST_LOG=debug` for verbose logging
- Ring buffer drops are logged when buffer fills
- Check kernel eBPF support: `just check-system`
- Verify BTF: `ls -lh /sys/kernel/btf/vmlinux`
- View loaded eBPF programs: `sudo bpftool prog list`
- Check for BPF verifier errors: `dmesg | tail`
