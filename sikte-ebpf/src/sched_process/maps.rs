use aya_ebpf::{macros::map, maps::RingBuf};
use sikte_common::sched_process_fork::MAX_SCHED_PROCESS_EVENTS;

#[map]
/// Ringbuf for sending new fork events to userspace
pub static SCHED_PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_SCHED_PROCESS_EVENTS, 0);
