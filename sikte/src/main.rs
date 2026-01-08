use anyhow::anyhow;
use itertools::Itertools;
use libc::pid_t;
use log::{debug, info};
use sikte::{
    cli::args::{Cli, Commands, RecordArgs, Target, TargetArgs},
    ebpf::{
        SikteEbpf,
        map_types::{PidAllowList, SyscallRingBuf},
    },
    events::EventBus,
    memlock_rlimit::bump_memlock_rlimit,
    publishers::syscalls::{self, SyscallPublisher},
    subscribers::ShellSubscriber,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{process::Command, signal};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse_args();
    env_logger::init();
    bump_memlock_rlimit();

    let mut ebpf = SikteEbpf::load()?;

    let interrupted = Arc::new(AtomicBool::new(false));

    let mut event_bus = EventBus::new();
    event_bus.spawn_subscription(ShellSubscriber::new());

    let child_process = match args.command {
        Commands::Record(RecordArgs { target }) => {
            let sys_enter = ebpf.attach_sys_enter_program()?;
            let sys_exit = ebpf.attach_sys_exit_program()?;
            let requirements = syscalls::Requirements::new(sys_enter, sys_exit);

            let pid_allow_list = PidAllowList::new(ebpf.pid_allow_list_map());
            let child_process = add_pids_to_allowlist(target, &pid_allow_list).await?;

            let ring_buf = SyscallRingBuf::new(ebpf.syscall_events_map());
            let tx = event_bus.tx();
            let publisher = SyscallPublisher::new(requirements, ring_buf, interrupted.clone(), tx)?;
            event_bus.spawn_publishment(publisher);

            child_process
        }
    };

    // Wait for either Ctrl-C or child process completion
    println!("Waiting for Ctrl-C...");

    if let Some(mut child) = child_process {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Received Ctrl-C, exiting...");
            }
            result = child.wait() => {
                match result {
                    Ok(status) => println!("Traced process exited with status: {}", status),
                    Err(e) => eprintln!("Error waiting for child process: {}", e),
                }
            }
        }
    } else {
        signal::ctrl_c().await?;
        println!("Received Ctrl-C, exiting...");
    }

    interrupted.store(true, Ordering::Release);

    Ok(())
}

#[allow(unstable_name_collisions)]
async fn add_pids_to_allowlist(
    target: TargetArgs,
    pid_allow_list: &PidAllowList<'_>,
) -> anyhow::Result<Option<tokio::process::Child>> {
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
            Ok(None)
        }
        Target::Command(command_args) => {
            if command_args.is_empty() {
                return Err(anyhow!("Command is empty"));
            }

            let program = &command_args[0];
            let args = &command_args[1..];

            info!("Running program: {command_args:?}");
            let child = Command::new(program).args(args).spawn()?;
            let pid = child.id().expect("program shouldn't have stopped yet");
            pid_allow_list.insert(pid as pid_t)?;

            Ok(Some(child))
        }
    }
}
