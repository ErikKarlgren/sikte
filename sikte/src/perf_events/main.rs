use aya::{
    Ebpf,
    programs::{PerfEvent, TracePoint, perf_event},
    util::online_cpus,
};

use crate::programs::{get_perf_events_program, get_tracepoints_program};

pub fn perf_events(mut ebpf: Ebpf) -> anyhow::Result<Ebpf> {
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let perf_event_program: &mut PerfEvent = get_perf_events_program(&mut ebpf);
    perf_event_program.load()?;

    for cpu in online_cpus().map_err(|(_, error)| error)? {
        perf_event_program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }

    let program: &mut TracePoint = get_tracepoints_program(&mut ebpf);
    program.load()?;
    program.attach("syscalls", "sys_enter_read")?;

    Ok(ebpf)
}
