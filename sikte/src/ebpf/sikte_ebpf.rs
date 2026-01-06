use std::mem::MaybeUninit;

use crate::common::constants::{attach_points::*, program_names::*};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
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
            .map_err(|e| EbpfError::LoadError {
                program: "skeleton",
                source: e,
            })?;

        debug!("Loading eBPF programs into kernel (CO-RE relocations will be applied)");

        // Load programs into kernel (performs CO-RE relocations)
        let skel = open_skel.load().map_err(|e| EbpfError::LoadError {
            program: "skeleton",
            source: e,
        })?;

        debug!("eBPF programs loaded successfully with CO-RE support");

        Ok(SikteEbpf { skel })
    }

    /// Attach sys_enter raw tracepoint
    pub fn attach_sys_enter_program(&mut self) -> Result<SysEnterProgram, EbpfError> {
        debug!(
            "Attaching {} program to {}",
            SIKTE_RAW_TRACE_POINT_AT_ENTER, SYS_ENTER
        );

        // Attach all programs in skeleton
        // TODO: For more granular control, could use:
        // self.skel.progs().sikte_raw_trace_point_at_enter().attach()?
        self.skel.attach().map_err(|e| EbpfError::AttachError {
            program: SIKTE_RAW_TRACE_POINT_AT_ENTER,
            attach_target: SYS_ENTER,
            source: e,
        })?;

        debug!("Successfully attached sys_enter program");
        Ok(SysEnterProgram { _private: () })
    }

    /// Attach sys_exit raw tracepoint
    pub fn attach_sys_exit_program(&mut self) -> Result<SysExitProgram, EbpfError> {
        debug!(
            "Attaching {} program to {}",
            SIKTE_RAW_TRACE_POINT_AT_EXIT, SYS_EXIT
        );

        // Note: attach() is already called in attach_sys_enter_program
        // Since skeleton.attach() attaches all programs, this is a no-op
        // but we keep it for API compatibility

        debug!("sys_exit program attached (via skeleton.attach())");
        Ok(SysExitProgram { _private: () })
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
