mod programs;

use anyhow::anyhow;
use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::{PerfEvent, RawTracePoint, TracePoint, perf_event},
    util::online_cpus,
};
use clap::{Parser, Subcommand};
use itertools::Itertools;
use log::{debug, error, info, warn};
use programs::{
    get_perf_events_program, get_raw_tp_sys_enter_program, get_raw_tp_sys_exit_program,
    get_tracepoints_program, load_ebpf_object,
};
use sikte_common::raw_tracepoints::syscalls::{NUM_ALLOWED_PIDS, pid_t};
use std::{
    borrow::Borrow,
    cmp,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    process::Command,
    signal,
    task::yield_now,
};

#[derive(Subcommand, Debug, Clone)]
enum SyscallsAction {
    /// Trace a list of PIDs
    Follow { pids: Vec<pid_t> },
    /// Run and trace a command
    Run { command_args: Vec<String> },
}

#[derive(Subcommand, Debug, Clone)]
enum CliAction {
    /// Trace syscalls using raw tracepoints
    Syscalls {
        #[command(subcommand)]
        action: SyscallsAction,
    },
    /// Perf events (to be done)
    PerfEvents,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct CliArgs {
    #[command(subcommand)]
    action: CliAction,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = CliArgs::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = load_ebpf_object()?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let interrupted = Arc::new(AtomicBool::new(false));

    _ = match cli.action {
        CliAction::Syscalls { action } => syscalls(ebpf, interrupted.clone(), action).await?,
        CliAction::PerfEvents => perf_events(ebpf)?,
    };

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    interrupted.store(true, Ordering::Release);
    println!("Exiting...");

    Ok(())
}

async fn syscalls(
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

    while !interrupted.load(Ordering::Acquire) {
        info!("reading...");
        let mut guard = async_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        while let Some(item) = ring_buf.next() {
            num_events += 1;
            info!("{item:?}");

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

fn perf_events(mut ebpf: Ebpf) -> anyhow::Result<Ebpf> {
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let perf_event_program: &mut PerfEvent = get_perf_events_program(&mut ebpf);
    perf_event_program.load()?;

    for cpu in online_cpus().map_err(|(_, error)| error)? {
        perf_event_program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }

    let program: &mut TracePoint = get_tracepoints_program(&mut ebpf);
    program.load()?;
    program.attach("syscalls", "sys_enter_read")?;

    Ok(ebpf)
}
