use aya_ebpf::{EbpfContext, helpers::bpf_get_smp_processor_id, programs::PerfEventContext};
use aya_log_ebpf::info;

pub fn try_perf_events(ctx: PerfEventContext) -> Result<u32, u32> {
    let cpu = unsafe { bpf_get_smp_processor_id() };

    match ctx.pid() {
        0 => info!(
            &ctx,
            "perf_event 'perftest' triggered on CPU {}, running a kernel task", cpu
        ),
        pid => info!(
            &ctx,
            "perf_event 'perftest' triggered on CPU {}, running PID {}", cpu, pid
        ),
    }

    Ok(0)
}
