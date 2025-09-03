mod cli;
mod perf_events;
mod programs;
mod syscalls;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use clap::{CommandFactory, Parser};
use cli::args::*;
use log::{Record, debug, warn};
use programs::load_ebpf_object;
use tokio::signal;

use crate::{perf_events::main::perf_events, syscalls::main::syscalls};

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

    match args.command {
        Commands::Record(RecordArgs { target, options }) => {
            if options.syscalls {
                syscalls(ebpf, interrupted.clone(), target).await?;
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
