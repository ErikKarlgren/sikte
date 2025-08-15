#![no_std]
#![no_main]

mod perf_events;
mod trace_points;

use aya_ebpf::{
    macros::{perf_event, tracepoint},
    programs::{PerfEventContext, TracePointContext},
};
use perf_events::try_perf_events;
use trace_points::try_tracepoints;

#[perf_event]
pub fn sikte_perf_events(ctx: PerfEventContext) -> u32 {
    match try_perf_events(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sikte_trace_points(ctx: TracePointContext) -> u32 {
    match try_tracepoints(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    use aya_ebpf::macros::tracepoint;

    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
