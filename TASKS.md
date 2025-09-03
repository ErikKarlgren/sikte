# Tasks
- [x] Make cli accept mandatory PID
- [x] Make ebpf program always filter by PID
- [x] Show syscalls (sys enter and exit) for PIDs given
- [x] Execute commands and track their syscalls
- [x] Map syscall IDs to their names (userspace?)
- [x] Calculate time spent per syscall
- [x] Print time spent per syscall
- [ ] Add a syscall filter using array. Should work for x64, arm, ...
- [ ] Fix ctrl-c bug: if command has finished, i shouldn't need to press ctrl-c
- [ ] Refactor sikte to make my life easier (make more modules)


- [-] Make command not start immediately so as to ensure we're tracking all of its syscalls and not lose some information at the beginning (it can send a sigstop signal to self)
  - I tried creating the structs PasuableCommand and PausedCommand, but working with fork() and exec() was getting crazy, and the results brittle
  - I'll use an eBPF trace point for sched_process_fork, which seems to be far more reliable

## Trace points
- [ ] Add trace point to sched_process_fork for detecting when a command is launched
  - Take a look at this: https://www.nccgroup.com/research-blog/some-musings-on-common-ebpf-linux-tracing-bugs/
- [ ] Add normal trace points for every syscall (or at least the most interesting ones)
  - Would make my life much easier for showing syscall args
  - With this you can print all the syscall trace points for your kernel version: `sudo bpftrace -l 'tracepoint:syscalls:*'`
  - Using aya-tool i can supposedly generate the required bindings automatically
