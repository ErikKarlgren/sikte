# Sikte eBPF

## Where to check tracepoints definitions

**Always check the kernel's source code.**

For example, for syscall tracepoints check the following:
- [Syscall tracepoints definitions for `sys_enter` and `sys_exit`](https://elixir.bootlin.com/linux/v6.16/source/include/trace/events/syscalls.h)

As you'll notice, both `sys_enter` and `sys_exit` have as a first argument the current register state, while the second isn't the same. For `sys_enter` it's the syscall id, and for `sys_exit` it's the return code.
