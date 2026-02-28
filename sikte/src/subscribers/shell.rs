// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{collections::HashMap, time::Instant};

use colored::Colorize;
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
    /// Total count of syscalls made
    total_syscalls_count: usize,
    /// When did we start tracking ebpf events
    begin: Instant,
    /// Whether to print all syscalls found
    print_all_syscalls: bool,
}

impl Default for ShellSubscriber {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ShellSubscriber {
    pub fn new(print_all_syscalls: bool) -> ShellSubscriber {
        ShellSubscriber {
            thr_to_last_sys_enter: HashMap::new(),
            total_syscalls_time: 0f64,
            total_syscalls_count: 0,
            begin: Instant::now(),
            print_all_syscalls,
        }
    }
}

impl ShellSubscriber {
    fn show_summary(&self) {
        let elapsed_time = self.begin.elapsed().as_micros();
        let percentage_syscalls = if elapsed_time > 0 {
            self.total_syscalls_time / (elapsed_time as f64) * 100f64
        } else {
            0f64
        };

        println!("Total syscalls made: {}", self.total_syscalls_count);
        println!("Spent time on syscalls: {:.2} us", self.total_syscalls_time);
        println!("Total analysis time: {elapsed_time} us");
        println!(
            "{:.2}% of the time was spent on syscalls",
            percentage_syscalls
        );
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
                self.total_syscalls_count += 1;

                match self.thr_to_last_sys_enter.remove(&tid) {
                    Some(last_data) => match last_data.state.syscall_id() {
                        Some(syscall_id) => {
                            let syscall_name = SyscallID::try_from(syscall_id)
                                .map(|id| id.as_str())
                                .unwrap_or("???");
                            let time_ns = timestamp.saturating_sub(last_data.timestamp);
                            let time_us = time_ns as f64 / 1000f64;

                            if self.print_all_syscalls {
                                let to_print =
                                    format!("({pid}/{tid}) {syscall_name} (took {time_us:.2} us)");
                                println!("{}", to_print.dimmed());
                            }
                            self.total_syscalls_time += time_us;
                        }
                        None => warn!("Unexpected non-AT_ENTER stored for tid {tid}"),
                    },
                    None => {
                        if self.print_all_syscalls {
                            let to_print = format!("({pid}/{tid}) ??? (took ??? us)");
                            println!("{}", to_print.dimmed());
                        }
                    }
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
