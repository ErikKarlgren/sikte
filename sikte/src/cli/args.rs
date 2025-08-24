use clap::{Parser, Subcommand, command};
use sikte_common::raw_tracepoints::syscalls::pid_t;

#[derive(Subcommand, Debug, Clone)]
pub enum SyscallsAction {
    /// Trace a list of PIDs
    Follow { pids: Vec<pid_t> },
    /// Run and trace a command
    Run { command_args: Vec<String> },
}

#[derive(Subcommand, Debug, Clone)]
pub enum CliAction {
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
pub struct CliArgs {
    #[command(subcommand)]
    pub action: CliAction,
}
