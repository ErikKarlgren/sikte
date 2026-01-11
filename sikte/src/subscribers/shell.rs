// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;

use libc::pid_t;
use log::{trace, warn};

use super::EventSubscriber;
use crate::{
    common::generated_types::{SyscallData, SyscallStateExt, syscall_state_tag},
    publishers::syscalls::SyscallID,
};

/// Event Subscriber that writes to stdout
pub struct ShellSubscriber {
    /// Match a thread to its last registered sys_enter event
    thr_to_last_sys_enter: HashMap<pid_t, SyscallData>,
    /// Total time spent on syscalls in us
    total_syscalls_time: f64,
}

impl Default for ShellSubscriber {
    fn default() -> Self {
        Self::new()
    }
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

        match state.tag {
            syscall_state_tag::AT_ENTER => {
                trace!("sys_enter: pid {pid}, tid {tid}");
                self.thr_to_last_sys_enter.insert(tid, *syscall_data);
            }
            syscall_state_tag::AT_EXIT => {
                trace!("sys_exit: pid {pid}, tid {tid}");

                match self.thr_to_last_sys_enter.remove(&tid) {
                    Some(last_data) => match last_data.state.syscall_id() {
                        Some(syscall_id) => {
                            let syscall_name = SyscallID::try_from(syscall_id)
                                .map(|id| id.as_str())
                                .unwrap_or("???");
                            let time_ns = timestamp.saturating_sub(last_data.timestamp);
                            let time_us = time_ns as f64 / 1000f64;
                            println!("({pid}/{tid}) {syscall_name} (took {time_us:.2} us)");
                            self.total_syscalls_time += time_us;
                        }
                        None => warn!("Unexpected non-AT_ENTER stored for tid {tid}"),
                    },
                    None => println!("({pid}/{tid}) ??? (took ??? us)"),
                }
            }
            _ => trace!(
                "Unknown syscall state tag {} for pid {pid}, tid {tid}",
                state.tag
            ),
        }
    }
}

impl Drop for ShellSubscriber {
    fn drop(&mut self) {
        self.show_summary();
    }
}
