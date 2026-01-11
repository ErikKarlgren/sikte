use std::collections::HashMap;

use super::EventSubscriber;
use crate::{
    common::generated_types::{SyscallData, SyscallStateExt, syscall_state_tag},
    publishers::syscalls::SyscallID,
};
use libc::pid_t;
use log::trace;

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
        println!("Spent time on syscalls: {} us", self.total_syscalls_time);
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

        match state.tag {
            syscall_state_tag::AT_ENTER => {
                trace!("sys_enter: pid {pid}, tid {tid}");
                self.thr_to_last_sys_enter.insert(tid, *syscall_data);
            }
            syscall_state_tag::AT_EXIT => {
                trace!("sys_exit: pid {pid}, tid {tid}");
                match self.thr_to_last_sys_enter.remove(&tid) {
                    Some(last_data) => {
                        if last_data.state.tag == syscall_state_tag::AT_ENTER {
                            let syscall_id = last_data.state.syscall_id().unwrap();
                            let syscall_name = SyscallID::try_from(syscall_id)
                                .map(|id| id.as_str())
                                .unwrap_or("???");
                            let time_ns = timestamp - last_data.timestamp;
                            let time_us = time_ns as f64 / 1000f64;
                            println!("({pid}/{tid}) {syscall_name} (took {time_us} us)");
                            self.total_syscalls_time += time_us;
                        } else {
                            unreachable!(
                                "only syscall_state_tag::AT_ENTER can be stored in self.thr_to_last_sys_enter"
                            );
                        }
                    }
                    None => {
                        println!("({pid}/{tid}) ??? (took ??? us)");
                    }
                }
            }
            _ => {
                // Unknown state tag
            }
        }
    }
}

impl Drop for ShellSubscriber {
    fn drop(&mut self) {
        self.show_summary();
    }
}
