use std::{
    borrow::Borrow,
    cmp,
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::anyhow;
use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::RawTracePoint,
};
use bytemuck::checked;
use itertools::Itertools;
use libc::pid_t;
use log::info;
use sikte_common::raw_tracepoints::syscalls::{NUM_ALLOWED_PIDS, PidT, SyscallData, SyscallState};
use tokio::{
    io::{Interest, unix::AsyncFd},
    process::Command,
    task::yield_now,
};

use crate::{
    cli::args::{Target, TargetArgs},
    ebpf::SikteEbpf,
    publishers::syscalls::table::to_syscall_name,
};

pub async fn syscalls(
    mut ebpf: SikteEbpf,
    interrupted: Arc<AtomicBool>,
    target: TargetArgs,
) -> anyhow::Result<SikteEbpf> {
    let syscalls_ring_buf = ebpf.take_syscalls_ringbuf();
    let mut pid_allow_list = ebpf.pid_allow_list_mut();

    tokio::spawn(read_syscall_data(syscalls_ring_buf.0, interrupted.clone()));

    match target.to_target() {
        Target::Pid(pids) => {
            for pid in &pids {
                pid_allow_list.insert(*pid)?
            }

            info!(
                "Tracing syscalls for the following PIDs: {}",
                pids.iter()
                    .map(|pid| pid.to_string())
                    .intersperse(", ".to_string())
                    .collect::<String>()
            );
        }
        Target::Command(command_args) => {
            if command_args.is_empty() {
                return Err(anyhow!("Command is empty"));
            }

            let program = &command_args[0];
            let args = &command_args[1..];

            info!("Running program: {command_args:?}");
            let mut child = Command::new(program).args(args).spawn()?;
            let pid = child.id().expect("program shouldn't have stopped yet");
            pid_allow_list.insert(pid as pid_t)?;

            child.wait().await?;
        }
    }

    Ok(ebpf)
}

async fn read_syscall_data<T: Borrow<MapData>>(
    ring_buf: RingBuf<T>,
    interrupted: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;
    let mut num_events = 0u64;
    const MAX_EVENTS_BATCH_SIZE: u64 = 1000;

    let mut thr_to_last_syscall: HashMap<pid_t, SyscallData> = HashMap::new();

    while !interrupted.load(Ordering::Acquire) {
        info!("reading...");
        let mut guard = async_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        while let Some(item) = ring_buf.next() {
            num_events += 1;

            let raw_data: &[u8] = &item;
            let syscall_data = checked::try_from_bytes::<SyscallData>(raw_data).map_err(|err| {
                anyhow!(format!("Could not parse SyscallData: {}", err.to_string()))
            })?;

            let SyscallData {
                timestamp,
                state,
                // convert from kernel tgid/pid notation -> userspace pid/tid
                tgid: _pid,
                pid: tid,
            } = *syscall_data;

            match state {
                SyscallState::AtEnter { syscall_id } => {
                    let syscall_name = to_syscall_name(syscall_id).unwrap_or("UNKNOWN");
                    info!("{timestamp} ns | TID {tid} | Start \"{syscall_name}\"");

                    thr_to_last_syscall.insert(tid, *syscall_data);
                }
                SyscallState::AtExit { .. } => match thr_to_last_syscall.remove(&tid) {
                    Some(last_data) => {
                        let time = timestamp - last_data.timestamp;
                        info!("{timestamp} ns | TID {tid} | Finished in {time} ns");
                    }
                    None => {
                        info!("BUG: previous 'at enter' data not found for syscall");
                    }
                },
            }

            if num_events % MAX_EVENTS_BATCH_SIZE == 0 {
                yield_now().await;
                if interrupted.load(Ordering::Acquire) {
                    return Ok(());
                }
            }
        }
        info!("no more messages");
        guard.clear_ready();
        yield_now().await;
    }

    Ok(())
}
