mod programs;
use std::{
    borrow::Borrow,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::sleep,
};

use aya::{
    maps::{MapData, RingBuf, ring_buf},
    programs::{RawTracePoint, TracePoint},
};
use log::{info, trace};
use programs::{
    get_raw_tp_sys_enter_program, get_raw_tp_sys_exit_program, get_tracepoints_program,
    load_ebpf_object,
};

#[rustfmt::skip]
use log::{debug, warn};
use sikte_common::SyscallData;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
    task::yield_now,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    // // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // // on clock ticks.
    // let perf_event_program: &mut PerfEvent = get_perf_events_program(&mut ebpf);
    // perf_event_program.load()?;
    //
    // for cpu in online_cpus().map_err(|(_, error)| error)? {
    //     perf_event_program.attach(
    //         perf_event::PerfTypeId::Software,
    //         perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
    //         perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
    //         perf_event::SamplePolicy::Frequency(1),
    //         true,
    //     )?;
    // }

    // let program: &mut TracePoint = get_tracepoints_program(&mut ebpf);
    // program.load()?;
    // program.attach("syscalls", "sys_enter_read")?;

    let program_syscalls_enter: &mut RawTracePoint = get_raw_tp_sys_enter_program(&mut ebpf);
    program_syscalls_enter.load()?;
    info!("Attaching raw tracepoint to sys_enter...");
    program_syscalls_enter.attach("sys_enter")?;

    let program_syscalls_exit: &mut RawTracePoint = get_raw_tp_sys_exit_program(&mut ebpf);
    program_syscalls_exit.load()?;
    info!("Attaching raw tracepoint to sys_exit...");
    program_syscalls_exit.attach("sys_exit")?;

    let interrupted = Arc::new(AtomicBool::new(false));

    let syscalls_ring_buf = RingBuf::try_from(ebpf.take_map("SYSCALL_EVENTS").expect("map exists"))
        .expect("map is of chosen type");
    tokio::spawn(read_syscall_data(syscalls_ring_buf, interrupted.clone()));

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    interrupted.store(true, Ordering::Release);
    println!("Exiting...");

    Ok(())
}

async fn read_syscall_data<T: Borrow<MapData>>(
    ring_buf: RingBuf<T>,
    interrupted: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;
    let mut num_events = 0u64;
    const MAX_EVENTS_BATCH_SIZE: u64 = 100_000;

    while !interrupted.load(Ordering::Acquire) {
        let mut guard = async_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        while let Some(item) = ring_buf.next() {
            num_events += 1;
            debug!("{item:?}");

            if num_events % MAX_EVENTS_BATCH_SIZE == 0 {
                yield_now().await;
                if interrupted.load(Ordering::Acquire) {
                    return Ok(());
                }
            }
        }
        debug!("no more messages");
        guard.clear_ready();
        yield_now().await;
    }

    Ok(())
}
