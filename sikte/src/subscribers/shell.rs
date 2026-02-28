// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{collections::HashMap, time::Instant};

use colored::Colorize;
use libc::pid_t;
use log::{trace, warn};

use super::EventSubscriber;
use crate::{
    common::generated_types::{SyscallData, SyscallStateExt, syscall_state_tag},
    publishers::syscalls::{MAX_NUM_SYSCALLS, SyscallID},
};

/// Event Subscriber that writes to stdout
#[derive(Debug)]
pub struct ShellSubscriber {
    /// Match a thread to its last registered sys_enter event
    thr_to_last_sys_enter: HashMap<pid_t, SyscallData>,
    /// Statistics related to syscalls
    syscall_stats: [SyscallStats; MAX_NUM_SYSCALLS],
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

#[derive(Debug, Copy, Clone, Default)]
struct SyscallStats {
    /// Number of times this syscall has been called
    number_of_calls: u32,
    /// Total wall clock time spent by this syscall (microseconds). It counts both running and
    /// idle time.
    total_wall_clock_us: f64,
}

impl ShellSubscriber {
    pub fn new(print_all_syscalls: bool) -> ShellSubscriber {
        ShellSubscriber {
            thr_to_last_sys_enter: HashMap::new(),
            syscall_stats: [Default::default(); MAX_NUM_SYSCALLS],
            begin: Instant::now(),
            print_all_syscalls,
        }
    }
}

impl ShellSubscriber {
    fn show_summary(&self) {
        let elapsed_time = self.begin.elapsed().as_micros();

        let mut total_syscalls_time = 0f64;
        let mut total_syscalls_count = 0u32;
        for stat in self.syscall_stats.iter() {
            total_syscalls_time += stat.total_wall_clock_us;
            total_syscalls_count += stat.number_of_calls;
        }

        let percentage_syscalls = if elapsed_time > 0 {
            total_syscalls_time / (elapsed_time as f64) * 100f64
        } else {
            0f64
        };

        println!("Total syscalls made: {}", total_syscalls_count);
        println!("Spent time on syscalls: {:.2} us", total_syscalls_time);
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

                match self.thr_to_last_sys_enter.remove(&tid) {
                    Some(last_data) => match last_data.state.syscall_id() {
                        Some(syscall_id) => {
                            self.syscall_stats[syscall_id as usize].number_of_calls += 1;

                            let time_ns = timestamp.saturating_sub(last_data.timestamp);
                            let time_us = time_ns as f64 / 1000f64;
                            self.syscall_stats[syscall_id as usize].total_wall_clock_us += time_us;

                            if self.print_all_syscalls {
                                let syscall_name = SyscallID::try_from(syscall_id)
                                    .map(|id| id.as_str())
                                    .unwrap_or("???");

                                let to_print =
                                    format!("({pid}/{tid}) {syscall_name} (took {time_us:.2} us)");
                                println!("{}", to_print.dimmed());
                            }
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
