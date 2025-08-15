use aya::{
    Ebpf,
    programs::{PerfEvent, Program, TracePoint},
};

pub fn load_ebpf_object() -> anyhow::Result<Ebpf> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sikte"
    )))?;
    Ok(ebpf)
}

// NOTE: all the "program names" are actually the names of the main functions in
// `sikte-ebpf/src/main.rs`

pub fn get_perf_events_program(ebpf: &mut Ebpf) -> &mut PerfEvent {
    let name = "sikte_perf_events";
    let program = ebpf.program_mut(name).expect("program exists");
    program.try_into().expect("program is PerfEvent")
}

pub fn get_tracepoints_program(ebpf: &mut Ebpf) -> &mut TracePoint {
    let name = "sikte_trace_points";
    let program = ebpf.program_mut(name).expect("program exists");
    program.try_into().expect("program is TracePoint")
}
