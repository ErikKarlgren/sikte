use std::collections::HashMap;

use libc::pid_t;
use sikte_common::raw_tracepoints::syscalls::{SyscallData, SyscallState};

use super::EventSubscriber;
use crate::publishers::syscalls::to_syscall_name;

/// Event Subscriber that writes to stdout
pub struct ShellSubscriber {
    /// Match a thread to its last registered sys_enter event
    thr_to_last_sys_enter: HashMap<pid_t, SyscallData>,
    /// Total time spent on syscalls in us
    total_syscalls_time: f64,
}

impl ShellSubscriber {
    pub fn new() -> ShellSubscriber {
        ShellSubscriber {
            thr_to_last_sys_enter: HashMap::new(),
            total_syscalls_time: 0f64,
        }
    }
}

impl ShellSubscriber {
    fn show_summary(&self) {
        println!("Spent time on syscalls: {:.2} us", self.total_syscalls_time);
    }
}

impl EventSubscriber for ShellSubscriber {
    fn get_name(&self) -> &'static str {
        "Shell"
    }

    fn read_syscall(&mut self, syscall_data: &SyscallData) {
        let SyscallData {
            timestamp,
            state,
            // convert from kernel tgid/pid notation -> userspace pid/tid
            tgid: pid,
            pid: tid,
        } = *syscall_data;

        match state {
            SyscallState::AtEnter { .. } => {
                self.thr_to_last_sys_enter.insert(tid, *syscall_data);
            }
            SyscallState::AtExit { .. } => match self.thr_to_last_sys_enter.remove(&tid) {
                Some(last_data) => {
                    if let SyscallState::AtEnter { syscall_id } = last_data.state {
                        let syscall_name = to_syscall_name(syscall_id).unwrap_or("UNKNOWN");
                        let time_ns = timestamp - last_data.timestamp;
                        let time_us = time_ns as f64 / 1000f64;
                        println!("({pid}/{tid}) {syscall_name} (took {time_us} us)");
                        self.total_syscalls_time += time_us;
                    } else {
                        unreachable!(
                            "only SyscallState::AtEnter can be stored in self.thr_to_last_sys_enter"
                        );
                    }
                }
                None => {
                    println!("({pid}/{tid}) ??? (took ??? us)");
                }
            },
        }
    }
}

impl Drop for ShellSubscriber {
    fn drop(&mut self) {
        self.show_summary();
    }
}
