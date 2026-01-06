# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Sikte** is an eBPF-based syscall tracer for Linux with CO-RE (Compile Once, Run Everywhere) support. It captures system calls from running processes, calculates timing information, and provides detailed execution analysis. The tool can either trace specific PIDs or execute commands and trace their syscalls.

## Build & Run Commands

### Standard Build
```bash
cargo build          # Debug build
cargo build --release  # Release build
cargo check && cargo clippy  # Check + lint
```

### Running (requires root)
```bash
# Run with default logging (info level)
just run [args]

# Run with custom log level
just run-log debug [args]

# Or use cargo directly
RUST_BACKTRACE=1 RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- record --syscalls --command ls
```

### Testing
```bash
just test            # Run all tests
just dbg-test [args] # Debug specific test with rust-gdb
```

### Development
```bash
just check           # Run clippy
just fix             # Auto-fix clippy warnings, format, and commit
```

### System Verification
```bash
just check-system    # Verify kernel eBPF support and capabilities
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
  - `raw_tracepoints/syscalls.rs`: SyscallData, SyscallState, SyscallStateTag types
- `ebpf/`: eBPF program lifecycle management (skeleton-based loading, attaching, maps)
  - `sikte_ebpf.rs`: Skeleton-based loader with CO-RE support
  - `map_types.rs`: Wrappers for libbpf-rs maps
  - `error.rs`: libbpf-rs error handling
- `events.rs`: EventBus implementation (tokio broadcast channel)
- `publishers/`: Extract data from kernel (ring buffers → events)
  - `syscalls/`: SyscallPublisher uses RingBufferBuilder with callbacks
- `subscribers/`: Consume events (ShellSubscriber for stdout)
- `syscall_table/`: Maps syscall IDs to names (x86_64 only)

**C eBPF programs (sikte/ebpf-src/):**
C eBPF programs that run in kernel space, attached to raw tracepoints.

**Files:**
- `raw_trace_points.bpf.c`: C eBPF programs with CO-RE support
- `raw_trace_points.h`: C header with shared type definitions (includes vmlinux.h)
- `vmlinux/vmlinux.h`: Generated kernel type definitions for CO-RE

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

The build process uses libbpf-cargo instead of aya-build:

1. **sikte/build.rs**: Uses `SkeletonBuilder` to:
   - Compile C eBPF programs with clang
   - Generate Rust skeleton bindings
   - Output `OUT_DIR/sikte.skel.rs`

2. **Skeleton-based loading**:
   - Generated skeleton provides type-safe map and program access
   - `RawTracePointsSkel::open()` parses eBPF object
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
1. Add program to `sikte/ebpf-src/raw_trace_points.bpf.c`
2. Define any new maps with proper SEC(".maps") annotations
3. If sharing data with userspace, add types to `sikte/src/common/` and `sikte/ebpf-src/raw_trace_points.h`
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
- Inspect CO-RE relocations: `llvm-objdump -d sikte/ebpf-src/*.o`
