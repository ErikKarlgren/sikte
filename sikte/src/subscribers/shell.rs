// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{cmp::Ordering, collections::HashMap, time::Instant};

use colored::Colorize;
use itertools::Itertools;
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

        let syscalls_time_percentage = if elapsed_time > 0 {
            total_syscalls_time / (elapsed_time as f64) * 100f64
        } else {
            0f64
        };

        const N: usize = 5;
        let syscall_count_stats = self.syscall_count_stats_as_str(N);
        let syscall_time_stats = self.syscall_time_stats_as_str(N);

        self.print_summary(
            elapsed_time,
            total_syscalls_time,
            total_syscalls_count,
            syscalls_time_percentage,
            N,
            &syscall_count_stats,
            &syscall_time_stats,
        );
    }

    fn syscall_count_stats_as_str(&self, max_syscalls: usize) -> String {
        let mut most_called: [(i64, u32); MAX_NUM_SYSCALLS] = self
            .syscall_stats
            .iter()
            .enumerate()
            .map(|(id, stat)| (id as i64, stat.number_of_calls))
            .collect_array()
            .unwrap();
        most_called.sort_by_key(|(_, num_calls)| *num_calls);

        let most_called: String = most_called
            .into_iter()
            .rev()
            .take_while(|(_, num_calls)| *num_calls > 0)
            .take(max_syscalls)
            .map(|(id, num_calls)| {
                format!(
                    "- {} was called {} times\n",
                    SyscallID::try_from(id)
                        .map_or("???", |id| id.as_str())
                        .blue(),
                    num_calls.to_string().blue()
                )
            })
            .collect::<String>();
        most_called
    }

    fn syscall_time_stats_as_str(&self, max_syscalls: usize) -> String {
        let mut most_time: [(i64, f64); MAX_NUM_SYSCALLS] = self
            .syscall_stats
            .iter()
            .enumerate()
            .map(|(id, stat)| (id as i64, stat.total_wall_clock_us))
            .collect_array()
            .unwrap();
        most_time.sort_by(|(_, time_a), (_, time_b)| {
            time_a.partial_cmp(time_b).unwrap_or_else(|| {
                if time_a.is_nan() && time_b.is_nan() {
                    Ordering::Equal
                } else if time_b.is_nan() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            })
        });

        let most_called: String = most_time
            .into_iter()
            .rev()
            .take_while(|(_, time)| *time > 0f64)
            .take(max_syscalls)
            .map(|(id, time)| {
                format!(
                    "- Total time for {} is {}\n",
                    SyscallID::try_from(id)
                        .map_or("???", |id| id.as_str())
                        .blue(),
                    format!("{:.2} us", time).to_string().blue()
                )
            })
            .collect::<String>();
        most_called
    }

    fn print_summary(
        &self,
        elapsed_time: u128,
        total_syscalls_time: f64,
        total_syscalls_count: u32,
        syscalls_time_percentage: f64,
        max_syscalls: usize,
        syscall_count_stats: &str,
        syscall_time_stats: &str,
    ) {
        println!(
            r#"
{}
- Total syscalls made: {}
- Spent time on syscalls: {}
- Total analysis time: {}
- {} of the time was spent on syscalls
            "#,
            "📄 Summary".bright_yellow().bold(),
            total_syscalls_count.to_string().blue(),
            format!("{:.2} us", total_syscalls_time).blue(),
            format!("{:.2} us", elapsed_time).blue(),
            format!("{:.2}%", syscalls_time_percentage).blue(),
        );
        println!(
            r#"
{}
{}

{}
{}
            "#,
            format!("1️⃣ Top {max_syscalls} most frequent syscalls")
                .bright_yellow()
                .bold(),
            syscall_count_stats,
            format!("⏳ Top {max_syscalls} most time-consuming syscalls")
                .bright_yellow()
                .bold(),
            syscall_time_stats,
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
