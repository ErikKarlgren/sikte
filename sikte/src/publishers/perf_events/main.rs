use aya::{programs::perf_event, util::online_cpus};

use crate::ebpf::SikteEbpf;

pub fn perf_events(mut ebpf: SikteEbpf) -> anyhow::Result<SikteEbpf> {
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let perf_event_program = ebpf.load_perf_events_program()?;

    for cpu in online_cpus().map_err(|(_, error)| error)? {
        perf_event_program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }

    Ok(ebpf)
}
