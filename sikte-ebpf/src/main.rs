#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, helpers::bpf_get_smp_processor_id, macros::perf_event, programs::PerfEventContext,
};
use aya_log_ebpf::info;

#[perf_event]
pub fn sikte(ctx: PerfEventContext) -> u32 {
    match try_sikte(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sikte(ctx: PerfEventContext) -> Result<u32, u32> {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
