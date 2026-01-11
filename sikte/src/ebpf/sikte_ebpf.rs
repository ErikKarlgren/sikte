use std::mem::MaybeUninit;

use crate::common::constants::{attach_points::*, program_names::*};
use libbpf_rs::{
    Link,
    skel::{OpenSkel, SkelBuilder},
};
use log::debug;

use super::error::EbpfError;

// Include generated skeleton (following libbpf-rs examples pattern)
mod sikte_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/sikte.skel.rs"
    ));
}

pub use sikte_skel::*;

/// Central point for interacting with eBPF from user space
pub struct SikteEbpf {
    skel: SikteSkel<'static>,
}

impl SikteEbpf {
    /// Load eBPF programs with CO-RE support
    pub fn load() -> Result<SikteEbpf, EbpfError> {
        debug!("Opening eBPF skeleton");

        // Open skeleton (parses object but doesn't load into kernel)
        let skel_builder = SikteSkelBuilder::default();
        let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
        let open_skel = skel_builder
            .open(open_object)
            .map_err(|e| EbpfError::as_load_error(e, "open skeleton"))?;

        debug!("Loading eBPF programs into kernel (CO-RE relocations will be applied)");

        // Load programs into kernel (performs CO-RE relocations)
        let skel = open_skel
            .load()
            .map_err(|e| EbpfError::as_load_error(e, "load skeleton"))?;

        debug!("eBPF programs loaded successfully with CO-RE support");

        Ok(SikteEbpf { skel })
    }

    /// Attach sys_enter raw tracepoint
    pub fn attach_sys_enter_program(&mut self) -> Result<SysEnterProgram, EbpfError> {
        debug!("Attaching {SIKTE_RAW_TRACE_POINT_AT_ENTER} program to {SYS_ENTER}");

        let link = self
            .skel
            .progs
            .sikte_raw_trace_point_at_enter
            .attach()
            .map_err(|e| {
                EbpfError::as_attach_error(e, SIKTE_RAW_TRACE_POINT_AT_ENTER, SYS_ENTER)
            })?;

        debug!("Successfully attached {SYS_ENTER} program");
        Ok(SysEnterProgram { _link: link })
    }

    /// Attach sys_exit raw tracepoint
    pub fn attach_sys_exit_program(&mut self) -> Result<SysExitProgram, EbpfError> {
        debug!("Attaching {SIKTE_RAW_TRACE_POINT_AT_EXIT} program to {SYS_EXIT}");

        let link = self
            .skel
            .progs
            .sikte_raw_trace_point_at_exit
            .attach()
            .map_err(|e| EbpfError::as_attach_error(e, SIKTE_RAW_TRACE_POINT_AT_EXIT, SYS_EXIT))?;

        debug!("Successfully attached {SYS_EXIT} program");
        Ok(SysExitProgram { _link: link })
    }

    /// Get reference to SYSCALL_EVENTS ring buffer map
    pub fn syscall_events_map(&self) -> &libbpf_rs::Map {
        &self.skel.maps.SYSCALL_EVENTS
    }

    /// Get reference to PID_ALLOW_LIST hash map
    pub fn pid_allow_list_map(&self) -> &libbpf_rs::Map {
        &self.skel.maps.PID_ALLOW_LIST
    }
}

/// Represents that the 'sys_enter' program has been loaded into the kernel. When dropped, deattach
/// it
pub struct SysEnterProgram {
    /// Private field that contains the link to `sys_enter`
    _link: Link,
}

/// Represents that the 'sys_exit' program has been loaded into the kernel. When dropped, deattach
/// it
pub struct SysExitProgram {
    /// Private field that contains the link to `sys_enter`
    _link: Link,
}
