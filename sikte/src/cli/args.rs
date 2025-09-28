use clap::{Args, CommandFactory, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "sikte")]
#[command(about = "A tracing tool for syscalls and perf events")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Parse args and do some checks
    pub fn parse_args() -> Self {
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
        args
    }
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Record traces from processes
    Record(RecordArgs),
}

#[derive(Debug, Args)]
pub struct RecordArgs {
    #[command(flatten)]
    pub target: TargetArgs,

    #[command(flatten)]
    pub options: TracingOptions,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct TargetArgs {
    /// Process IDs to trace (comma-separated)
    #[arg(long, value_delimiter = ',', num_args = 1.., group = "target")]
    pub pid: Option<Vec<i32>>,

    /// Command to execute and trace
    #[arg(long, num_args = 1.., group = "target")]
    pub command: Option<Vec<String>>,
}

impl TargetArgs {
    /// Convert to a more ergonomic enum representation
    pub fn to_target(&self) -> Target {
        match (&self.pid, &self.command) {
            (Some(pids), None) => Target::Pid(pids.clone()),
            (None, Some(cmd)) => Target::Command(cmd.clone()),
            _ => unreachable!("clap ensures exactly one target is provided"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Target {
    Pid(Vec<i32>),
    Command(Vec<String>),
}

#[derive(Debug, Args)]
pub struct TracingOptions {
    /// Trace syscalls
    #[arg(long)]
    pub syscalls: bool,

    /// Trace perf events
    #[arg(long)]
    pub perf_events: bool,
}
