use std::collections::HashMap;

use libc::pid_t;
use sikte_common::raw_tracepoints::syscalls::{SyscallData, SyscallState};

use super::EventSubscriber;
use crate::publishers::syscalls::to_syscall_name;

/// Event Subscriber that writes to stdout
pub struct ShellSubscriber {
    /// Match a thread to its last registered sys_enter event
    thr_to_last_sys_enter: HashMap<pid_t, SyscallData>,
}

impl ShellSubscriber {
    pub fn new() -> ShellSubscriber {
        ShellSubscriber {
            thr_to_last_sys_enter: HashMap::new(),
        }
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
            SyscallState::AtEnter { syscall_id } => {
                let syscall_name = to_syscall_name(syscall_id).unwrap_or("UNKNOWN");
                println!("({pid}/{tid}) Start \"{syscall_name}\"");

                self.thr_to_last_sys_enter.insert(tid, *syscall_data);
            }
            SyscallState::AtExit { .. } => match self.thr_to_last_sys_enter.remove(&tid) {
                Some(last_data) => {
                    let time = timestamp - last_data.timestamp;
                    println!("({pid}/{tid}) Finished in {time} ns");
                }
                None => {
                    println!("({pid}/{tid}) Finished in ??? ns");
                }
            },
        }
    }
}
