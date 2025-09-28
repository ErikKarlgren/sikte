use std::{borrow::Borrow, fmt::Debug};

use super::{error::EbpfError, map_types::*};
use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::{PerfEvent, Program, ProgramError, RawTracePoint, TracePoint},
};
use aya_log::EbpfLogger;
use log::debug;
use sikte_common::constants::{attach_points::*, program_names::*};

/// Central point for interacting with eBPF from user space
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
    pub fn load_perf_events_program(&mut self) -> Result<&mut PerfEvent, EbpfError> {
        let program = self.get_program::<PerfEvent>(SIKTE_PERF_EVENTS);
        debug!("Loading perf events program");
        program
            .load()
            .map_err(|e| EbpfError::as_load_error(e, SIKTE_PERF_EVENTS))?;
        Ok(program)
    }

    /// Load trace points program. The user chooses what to attach it to.
    pub fn load_tracepoints_program(&mut self) -> Result<&mut TracePoint, ProgramError> {
        let program = self.get_program::<TracePoint>(SIKTE_TRACE_POINTS);
        debug!("Loading trace points program");
        program.load()?;
        Ok(program)
    }

    /// Load raw tracepoints program for sys_enter
    pub fn attach_sys_enter_program(&mut self) -> Result<SysEnterProgram, EbpfError> {
        let program = self.get_program::<RawTracePoint>(SIKTE_RAW_TRACE_POINT_AT_ENTER);

        debug!("Loading {SYS_ENTER} program");
        program
            .load()
            .map_err(|e| EbpfError::as_load_error(e, SIKTE_RAW_TRACE_POINT_AT_ENTER))?;

        debug!("Attaching to {SYS_ENTER}");
        program.attach(SYS_ENTER).map_err(|e| {
            EbpfError::as_attach_error(e, SIKTE_RAW_TRACE_POINT_AT_ENTER, SYS_ENTER)
        })?;

        Ok(SysEnterProgram { _private: () })
    }

    /// Load raw tracepoints program for sys_exit
    pub fn attach_sys_exit_program(&mut self) -> Result<SysExitProgram, EbpfError> {
        let program = self.get_program::<RawTracePoint>(SIKTE_RAW_TRACE_POINT_AT_EXIT);
        debug!("Loading {SYS_EXIT} program");
        program
            .load()
            .map_err(|e| EbpfError::as_load_error(e, SIKTE_RAW_TRACE_POINT_AT_EXIT))?;

        debug!("Attaching to {SYS_EXIT}");
        program
            .attach(SYS_EXIT)
            .map_err(|e| EbpfError::as_attach_error(e, SIKTE_RAW_TRACE_POINT_AT_EXIT, SYS_EXIT))?;

        Ok(SysExitProgram { _private: () })
    }

    /// Retrieves an eBPF program by its name
    fn get_program<'ebpf, T>(&'ebpf mut self, name: &str) -> &'ebpf mut T
    where
        &'ebpf mut T: TryFrom<&'ebpf mut Program>,
        <&'ebpf mut T as TryFrom<&'ebpf mut Program>>::Error: Debug,
    {
        debug!("Retrieving program {name}");
        let program = self.ebpf.program_mut(name).expect("program exists");
        program
            .try_into()
            .expect(format!("program can be converted to {}", stringify!(T)).as_str())
    }

    /// Take the syscalls ring buffer
    pub fn take_syscalls_ringbuf(&mut self) -> SyscallRingBuf {
        let ringbuf = RingBuf::try_from(self.ebpf.take_map("SYSCALL_EVENTS").expect("map exists"))
            .expect("map is of chosen type");
        SyscallRingBuf(ringbuf)
    }

    /// Return a mutable view to the PID allow list array map
    pub fn pid_allow_list_mut(&mut self) -> PidAllowList {
        let list = Array::try_from(self.ebpf.map("PID_ALLOW_LIST").expect("map exists"))
            .expect("map is of chosen type");
        PidAllowList(list)
    }
}

/// Represents that the 'sys_enter' program has been loaded into the kernel
pub struct SysEnterProgram {
    /// Private field. This avoids letting the user create an instance of this type
    _private: (),
}

/// Represents that the 'sys_exit' program has been loaded into the kernel
pub struct SysExitProgram {
    /// Private field. This avoids letting the user create an instance of this type
    _private: (),
}
