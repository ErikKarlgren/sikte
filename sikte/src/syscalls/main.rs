use anyhow::anyhow;
use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::{PerfEvent, RawTracePoint, TracePoint, perf_event},
    util::online_cpus,
};
use bytemuck::checked;
use clap::{Parser, Subcommand};
use itertools::Itertools;
use log::{debug, info, warn};
use sikte_common::raw_tracepoints::syscalls::{NUM_ALLOWED_PIDS, SyscallData, SyscallState, pid_t};
use std::{
    borrow::Borrow,
    cmp,
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    process::Command,
    task::yield_now,
};

use crate::{
    cli::args::SyscallsAction,
    programs::{get_raw_tp_sys_enter_program, get_raw_tp_sys_exit_program},
    syscalls::table::to_syscall_name,
};

pub async fn syscalls(
    mut ebpf: Ebpf,
    interrupted: Arc<AtomicBool>,
    action: SyscallsAction,
) -> anyhow::Result<Ebpf> {
    let program_syscalls_enter: &mut RawTracePoint = get_raw_tp_sys_enter_program(&mut ebpf);
    program_syscalls_enter.load()?;
    info!("Attaching raw tracepoint to sys_enter...");
    program_syscalls_enter.attach("sys_enter")?;

    let program_syscalls_exit: &mut RawTracePoint = get_raw_tp_sys_exit_program(&mut ebpf);
    program_syscalls_exit.load()?;
    info!("Attaching raw tracepoint to sys_exit...");
    program_syscalls_exit.attach("sys_exit")?;

    let mut pid_allow_list: Array<_, pid_t> =
        Array::try_from(ebpf.take_map("PID_ALLOW_LIST").expect("map exists"))
            .expect("map is of chosen type");

    let syscalls_ring_buf = RingBuf::try_from(ebpf.take_map("SYSCALL_EVENTS").expect("map exists"))
        .expect("map is of chosen type");
    tokio::spawn(read_syscall_data(syscalls_ring_buf, interrupted.clone()));

    match action {
        SyscallsAction::Follow { pids } => {
            let max_pids = cmp::min(
                NUM_ALLOWED_PIDS,
                cmp::min(pids.len(), u32::MAX as usize) as u32,
            );

            for i in 0..max_pids {
                pid_allow_list.set(i, pids[i as usize], 0)?;
            }

            info!(
                "Tracing syscalls for the following PIDs: {}",
                pids.iter()
                    .map(|pid| pid.to_string())
                    .intersperse(", ".to_string())
                    .collect::<String>()
            );
        }
        SyscallsAction::Run { command_args } => {
            if command_args.is_empty() {
                return Err(anyhow!("Command is empty"));
            }

            let program = &command_args[0];
            let args = &command_args[1..];

            info!("Running program: {command_args:?}");
            let mut child = Command::new(program).args(args).spawn()?;
            let pid = child.id().expect("program shouldn't have stopped yet");
            pid_allow_list.set(0, pid as pid_t, 0)?;

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

    let mut thr_to_last_syscall: HashMap<u32, SyscallData> = HashMap::new();

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
