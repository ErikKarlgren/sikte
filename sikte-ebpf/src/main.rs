#![no_std]
#![no_main]

mod common;
mod perf_events;
mod raw_trace_points;
mod sched_process_fork;
mod trace_points;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
