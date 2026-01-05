# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Sikte** is an eBPF-based syscall and performance event tracer for Linux. It captures system calls from running processes, calculates timing information, and provides detailed execution analysis. The tool can either trace specific PIDs or execute commands and trace their syscalls.

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
RUST_BACKTRACE=1 RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- [args]
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

- Rust stable + nightly toolchains
  - `rustup toolchain install stable`
  - `rustup toolchain install nightly --component rust-src`
- **bpf-linker**: `cargo install bpf-linker` (`--no-default-features` on macOS)
- Linux kernel 5.8+ with eBPF support (CONFIG_BPF_SYSCALL=y)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities

For cross-compilation (macOS):
- LLVM: `brew install llvm`
- musl toolchain: `brew install filosottile/musl-cross/musl-cross`
- Target: `rustup target add x86_64-unknown-linux-musl`

## Workspace Architecture

This is a Cargo workspace with three crates:

### sikte (Userspace Application)
Main binary that orchestrates eBPF program loading, data collection, and event handling.

**Key modules:**
- `cli/`: Command-line argument parsing (uses clap)
- `ebpf/`: eBPF program lifecycle management (loading, attaching, maps)
- `events.rs`: EventBus implementation (tokio broadcast channel)
- `publishers/`: Extract data from kernel (ring buffers → events)
  - `syscalls/`: SyscallPublisher reads from SYSCALL_EVENTS ring buffer
  - `perf_events/`: Framework for CPU sampling (stub)
- `subscribers/`: Consume events (currently only ShellSubscriber for stdout)
- `syscall_table/`: Maps syscall IDs to names (x86_64 only)

### sikte-common (Shared Types)
`no_std` compatible crate with types shared between kernel and userspace.

**Key types:**
- `SyscallData`: Represents a syscall event (timestamp, PID, state)
- `SyscallState`: Either `AtEnter{syscall_id}` or `AtExit{syscall_ret}`
- Constants for program names and attachment points

### sikte-ebpf (eBPF Kernel Programs)
eBPF programs that run in kernel space, attached to tracepoints.

**Programs:**
- `sikte_raw_trace_point_at_enter`: Captures syscall entry (sys_enter tracepoint)
- `sikte_raw_trace_point_at_exit`: Captures syscall exit (sys_exit tracepoint)
- `sikte_perf_events`: CPU clock sampling (framework)
- `sikte_trace_points`: Placeholder for future trace points

**Maps:**
- `SYSCALL_EVENTS`: Ring buffer (1MB) for kernel→userspace event passing
- `PID_ALLOW_LIST`: HashMap (1024 entries) for PID filtering in kernel

## Data Flow

```
Kernel Space:
  sys_enter/sys_exit tracepoints
         ↓
  eBPF Programs (filter by PID_ALLOW_LIST)
         ↓
  SYSCALL_EVENTS ring buffer

Userspace:
  SyscallPublisher (polls ring buffer)
         ↓
  EventBus (tokio broadcast channel)
         ↓
  ShellSubscriber (pairs enter/exit, calculates duration, prints)
```

## Build System

The eBPF build process uses Cargo build scripts:

1. **sikte-ebpf/build.rs**: Tracks bpf-linker binary changes
2. **sikte/build.rs**: Invokes `aya_build::build_ebpf()` to compile eBPF programs
3. Compiled eBPF bytecode is included in the binary at compile time

The build requires `bpf-linker` to be in PATH. eBPF programs target the `bpf` architecture and are compiled separately from userspace code.

## Key Architectural Patterns

### Publisher-Subscriber Pattern
The project uses a multi-publisher, multi-consumer architecture:
- **Publishers** (EventPublisher trait): Read from eBPF ring buffers, send to EventBus
- **EventBus**: Tokio broadcast channel (capacity: 1024 events)
- **Subscribers** (EventSubscriber trait): Consume events from EventBus

This design allows adding new data sources (publishers) and consumers (subscribers) independently.

### eBPF Program Lifecycle
1. **Load**: `SikteEbpf::load()` loads compiled eBPF bytes into kernel
2. **Attach**: Programs attach to specific kernel tracepoints (sys_enter, sys_exit)
3. **Runtime**: Kernel triggers programs on syscall events, data flows through ring buffers
4. **Cleanup**: Programs auto-detach on drop

### PID Filtering
- User provides PIDs via CLI (`--pid`) or launches a command (`--command`)
- Userspace populates `PID_ALLOW_LIST` eBPF map
- Kernel-space eBPF programs check this map before submitting events
- This avoids overwhelming userspace with irrelevant syscalls

## Adding New Features

### Adding a New Subscriber
1. Implement the `EventSubscriber` trait in `sikte/src/subscribers/`
2. Implement `read_syscall(&mut self, syscall_data: &SyscallData)`
3. Register subscriber in `main.rs` via `event_bus.add_subscriber()`

### Adding a New eBPF Program
1. Add program to `sikte-ebpf/src/` (use `#[raw_tracepoint]` or similar macro)
2. Define any new maps with `#[map]` attribute
3. If sharing data with userspace, add types to `sikte-common`
4. Create a publisher in `sikte/src/publishers/` to read from new ring buffer
5. Update `sikte/src/ebpf/programs.rs` to load and attach the program

### Syscall Name Resolution
Currently only x86_64 is supported. To add another architecture:
1. Obtain syscall table from Linux kernel source (e.g., `arch/arm64/include/asm/unistd.h`)
2. Generate const array in `sikte/src/syscall_table/`
3. Use conditional compilation (`#[cfg(target_arch = "...")]`)

## Important Implementation Notes

- All eBPF-related types must be `#[repr(C)]` with explicit alignment
- Use `bytemuck` for safe zero-copy deserialization from ring buffers
- Ring buffer can drop events if userspace consumer is slow (logged as warnings)
- The EventBus uses tokio's broadcast channel; lagging subscribers are detected but don't block publishers
- ShellSubscriber pairs enter/exit events by thread ID to calculate syscall duration
- Requires `bump_memlock_rlimit()` for kernels pre-5.11 (memory accounting)

## Current Development Status

**Active branch**: `feat/switch_to_libbpf-rs` (migrating from aya to libbpf-rs)

**Completed**:
- Syscall enter/exit tracing with timing
- PID-based filtering
- Command execution tracing
- Shell output subscriber

**Future work** (see TASKS.md):
- Syscall argument extraction (requires specific tracepoints)
- Multiple output backends (database, metrics)
- Architecture support beyond x86_64
- Process fork tracking (sched_process_fork tracepoint)

## Cross-Compilation

Example for x86_64 musl target (from macOS):
```bash
CC=x86_64-linux-musl-gcc cargo build --package sikte --release \
  --target=x86_64-unknown-linux-musl \
  --config=target.x86_64-unknown-linux-musl.linker=\"x86_64-linux-musl-gcc\"
```

Binary will be at `target/x86_64-unknown-linux-musl/release/sikte`.

## Debugging

- Use `RUST_LOG=debug` for verbose logging
- Ring buffer drops are logged when buffer fills
- Check kernel eBPF support: `just check-system`
- Verify bpftool: `sudo bpftool prog list` (shows loaded eBPF programs)
- For kernel issues: `dmesg | tail` shows BPF verifier errors
