use aya_ebpf::{macros::map, maps::HashMap};
use sikte_common::{
    generic_types::Unused,
    raw_tracepoints::syscalls::{NUM_ALLOWED_PIDS, PidT},
};

#[map]
/// PID or TGID allowlist. No processes outside this map will be considered
pub static PID_ALLOW_LIST: HashMap<PidT, Unused> = HashMap::with_max_entries(NUM_ALLOWED_PIDS, 0);
