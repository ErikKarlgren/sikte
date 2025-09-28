use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sikte_common::{
    raw_tracepoints::syscalls::PidT,
    sched_process_fork::{MAX_SCHED_PROCESS_FORK_EVENTS, SchedProcessForkData},
};

use crate::common::{is_tgid_in_allowlist, submit_or_else};

/*
name: sched_process_fork
ID: 302
format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:__data_loc char[] parent_comm;	offset:8;	size:4;	signed:0;
    field:pid_t parent_pid;	offset:12;	size:4;	signed:1;
    field:__data_loc char[] child_comm;	offset:16;	size:4;	signed:0;
    field:pid_t child_pid;	offset:20;	size:4;	signed:1;

print fmt: "comm=%s pid=%d child_comm=%s child_pid=%d", __get_str(parent_comm), REC->parent_pid, __get_str(child_comm), REC->child_pid
*/

struct SchedProcessFork {
    parent_pid: PidT,
    child_pid: PidT,
}

#[map]
static SCHED_PROCESS_FORK_EVENTS: RingBuf =
    RingBuf::with_byte_size(MAX_SCHED_PROCESS_FORK_EVENTS, 0);

// TODO: add a system to signal from sikte that we want to track its next forked child

// TODO: modify the pid allow list, but only if configured this way from userspace (might be
// default behaviour? or not to avoid unwanted noise by default?)

#[tracepoint]
pub fn sikte_sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, u32> {
    let event = ctx.as_ptr() as *const SchedProcessFork;

    let parent_pid = unsafe { (*event).parent_pid };
    if !is_tgid_in_allowlist(parent_pid) {
        return Ok(0);
    }

    let child_pid = unsafe { (*event).child_pid };
    let data = SchedProcessForkData {
        parent_pid,
        child_pid,
    };

    submit_or_else(&SCHED_PROCESS_FORK_EVENTS, data, || {
        warn!(
            &ctx,
            "Dropped sched_process_fork data where parent pid is {} and child pid {}",
            parent_pid,
            child_pid
        );
    })
}
