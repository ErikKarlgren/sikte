use std::fmt::Debug;

use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::{PerfEvent, Program, ProgramError, RawTracePoint, TracePoint},
};
use aya_log::EbpfLogger;
use libc::pid_t;
use log::debug;

pub struct SikteEbpf {
    ebpf: Ebpf,
}

impl SikteEbpf {
    /// Load eBPF binary
    pub fn load() -> Result<SikteEbpf, aya::EbpfError> {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/sikte"
        )))?;
        Ok(SikteEbpf { ebpf })
    }

    /// Init logger for eBPF programs
    pub fn init_logger(&mut self) -> Result<EbpfLogger, aya_log::Error> {
        aya_log::EbpfLogger::init(&mut self.ebpf)
    }

    /// Load perf events program. The user chooses what to attach it to.
    pub fn load_perf_events_program(&mut self) -> Result<&mut PerfEvent, ProgramError> {
        let program = self.get_program::<PerfEvent>("sikte_perf_events");
        debug!("Loading perf events program");
        program.load()?;
        Ok(program)
    }

    /// Load trace points program. The user chooses what to attach it to.
    pub fn load_tracepoints_program(&mut self) -> Result<&mut TracePoint, ProgramError> {
        let program = self.get_program::<TracePoint>("sikte_trace_points");
        debug!("Loading trace points program");
        program.load()?;
        Ok(program)
    }

    /// Load raw tracepoints program for sys_enter
    pub fn load_sys_enter_program(&mut self) -> Result<&mut RawTracePoint, ProgramError> {
        let program = self.get_program::<RawTracePoint>("sikte_raw_trace_point_at_enter");
        debug!("Loading sys_enter program");
        program.load()?;
        Ok(program)
    }

    /// Load raw tracepoints program for sys_exit
    pub fn load_sys_exit_program(&mut self) -> Result<&mut RawTracePoint, ProgramError> {
        let program = self.get_program::<RawTracePoint>("sikte_raw_trace_point_at_exit");
        debug!("Loading sys_exit program");
        program.load()?;
        Ok(program)
    }

    /// Retrieves an eBPF program by its name
    fn get_program<'ebpf, T>(&'ebpf mut self, name: &str) -> &'ebpf mut T
    where
        &'ebpf mut T: TryFrom<&'ebpf mut Program>,
        <&'ebpf mut T as TryFrom<&'ebpf mut Program>>::Error: Debug,
    {
        debug!("Retrieving program {name}");
        let program = self.ebpf.program_mut(name).expect("program exists");
        program.try_into().expect("program can be converted to T")
    }

    /// Take the syscalls ring buffer
    pub fn syscalls_ringbuf<'ebpf>(&'ebpf mut self) -> RingBuf<&'ebpf MapData> {
        RingBuf::try_from(self.ebpf.map("SYSCALL_EVENTS").expect("map exists"))
            .expect("map is of chosen type")
    }

    /// Return a mutable view to the PID allow list array map
    pub fn pid_allow_list_mut<'ebpf>(&'ebpf mut self) -> Array<&'ebpf mut MapData, pid_t> {
        Array::try_from(self.ebpf.map_mut("PID_ALLOW_LIST").expect("map exists"))
            .expect("map is of chosen type")
    }
}
