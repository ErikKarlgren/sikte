mod cli;
mod ebpf;
mod events;
mod publishers;
mod subscribers;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::anyhow;
use cli::args::*;
use ebpf::SikteEbpf;
use events::EventBus;
use itertools::Itertools;
use libc::pid_t;
use log::{debug, info};
use publishers::syscalls::{self, SyscallPublisher};
use subscribers::ShellSubscriber;
use tokio::{process::Command, signal};

use crate::ebpf::map_types::{PidAllowList, SyscallRingBuf};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse_args();
    env_logger::init();
    bump_memlock_rlimit();

    let mut ebpf = SikteEbpf::load()?;

    let interrupted = Arc::new(AtomicBool::new(false));

    let mut event_bus = EventBus::new();
    event_bus.spawn_subscription(ShellSubscriber::new());

    match args.command {
        Commands::Record(RecordArgs { target, options }) => {
            if options.syscalls {
                let sys_enter = ebpf.attach_sys_enter_program()?;
                let sys_exit = ebpf.attach_sys_exit_program()?;
                let requirements = syscalls::Requirements::new(sys_enter, sys_exit);

                let pid_allow_list = PidAllowList::new(ebpf.pid_allow_list_map());
                add_pids_to_allowlist(target, &pid_allow_list).await?;

                let ring_buf = SyscallRingBuf::new(ebpf.syscall_events_map());
                let tx = event_bus.tx();
                let publisher =
                    SyscallPublisher::new(requirements, ring_buf, interrupted.clone(), tx)?;
                event_bus.spawn_publishment(publisher);
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

async fn add_pids_to_allowlist(
    target: TargetArgs,
    pid_allow_list: &PidAllowList<'_>,
) -> anyhow::Result<()> {
    match target.to_target() {
        Target::Pid(pids) => {
            for pid in &pids {
                pid_allow_list.insert(*pid)?
            }

            info!(
                "Tracing the following PIDs: {}",
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
    Ok(())
}
