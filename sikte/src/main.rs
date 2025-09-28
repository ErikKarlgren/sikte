mod cli;
mod ebpf;
mod events;
mod publishers;
mod subscribers;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use clap::{CommandFactory, Parser};
use cli::args::*;
use ebpf::SikteEbpf;
use events::EventBus;
use log::{debug, info, warn};
use publishers::syscalls::{self, Requirements, SyscallPublisher};
use subscribers::ShellSubscriber;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    if let Commands::Record(RecordArgs {
        options:
            TracingOptions {
                syscalls: false,
                perf_events: false,
            },
        ..
    }) = args.command
    {
        Cli::command()
            .error(
                clap::error::ErrorKind::TooFewValues,
                "You need to set what to trace!",
            )
            .exit();
    }

    env_logger::init();
    bump_memlock_rlimit();

    let mut ebpf = SikteEbpf::load()?;
    if let Err(e) = ebpf.init_logger() {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let interrupted = Arc::new(AtomicBool::new(false));

    let mut event_bus = EventBus::new();
    event_bus.spawn_subscription(ShellSubscriber::new());

    match args.command {
        Commands::Record(RecordArgs { target, options }) => {
            if options.syscalls {
                let sys_enter = ebpf.attach_sys_enter_program()?;
                let sys_exit = ebpf.attach_sys_exit_program()?;
                let requirements = syscalls::Requirements::new(sys_enter, sys_exit);

                // TODO: setup according to target
                let mut pid_allow_list = ebpf.pid_allow_list_mut();

                let ring_buf = ebpf.take_syscalls_ringbuf();
                let publisher = SyscallPublisher::new(requirements, ring_buf, interrupted.clone())?;
                event_bus.spawn_publishment(publisher);
            }
            if options.perf_events {
                // TODO:: work on perf_events
                // perf_events(ebpf)?;
            }
        }
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    interrupted.store(true, Ordering::Release);
    println!("Exiting...");

    // tokio::spawn(async move {
    //     let ctrl_c = signal::ctrl_c();
    //     ctrl_c.await.expect("failed to listen for event");
    //     interrupted.store(true, Ordering::Release);
    // });

    Ok(())
}

/// Bump the memlock rlimit. This is needed for older kernels that don't use the
/// new memcg based accounting, see https://lwn.net/Articles/837122/
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}
