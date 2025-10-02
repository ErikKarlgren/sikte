use aya_ebpf::{bindings::BPF_F_NO_PREALLOC, macros::map, maps::HashMap};
use sikte_common::{
    generic_types::Unused,
    raw_tracepoints::syscalls::{NUM_ALLOWED_PIDS, PidT},
};

#[map]
/// PID or TGID allowlist. No processes outside this map will be considered. It uses
/// `BPF_F_NO_PREALLOC` to ensure the atomicity of insert() and remove(), and to eliminate the risk
/// of having a removed element from the map get aliased by another element
pub static PID_ALLOW_LIST: HashMap<PidT, Unused> =
    HashMap::with_max_entries(NUM_ALLOWED_PIDS, BPF_F_NO_PREALLOC);

/// Check if TGID is in allowlist. This operation is safe because `PID_ALLOW_LIST` is created with
/// `BPF_F_NO_PREALLOC`, so
pub fn is_tgid_in_allowlist(tgid: PidT) -> bool {
    unsafe { PID_ALLOW_LIST.get(&tgid).is_some() }
}
