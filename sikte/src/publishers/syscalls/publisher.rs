use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::anyhow;
use bytemuck::checked;
use log::{error, warn};
use sikte_common::raw_tracepoints::syscalls::SyscallData;
use tokio::sync::broadcast::Sender;

use crate::{
    ebpf::{SysEnterProgram, SysExitProgram, map_types::SyscallRingBuf},
    events::Event,
    publishers::EventPublisher,
};

/// Requirements for SyscallPublisher
pub struct Requirements {
    _sys_enter: SysEnterProgram,
    _sys_exit: SysExitProgram,
}

impl Requirements {
    pub fn new(sys_enter: SysEnterProgram, sys_exit: SysExitProgram) -> Requirements {
        Requirements {
            _sys_enter: sys_enter,
            _sys_exit: sys_exit,
        }
    }
}

/// Publishes syscall data to an EventBus
pub struct SyscallPublisher {
    /// Requirements for creating this struct. These are just capability tokens
    _requirements: Requirements,
    /// Ring buffer for polling
    ring_buffer: libbpf_rs::RingBuffer<'static>,
    /// Boolean that tells us if the user interrupted the program
    interrupted: Arc<AtomicBool>,
}

impl SyscallPublisher {
    /// Create new SyscallPublisher with libbpf-rs RingBuffer callback pattern
    pub fn new(
        requirements: Requirements,
        ring_buf: SyscallRingBuf,
        interrupted: Arc<AtomicBool>,
        tx: Sender<Event>,
    ) -> Result<SyscallPublisher, libbpf_rs::Error> {
        // Create ring buffer with callback
        let mut builder = libbpf_rs::RingBufferBuilder::new();

        builder.add(ring_buf.map(), move |data: &[u8]| -> i32 {
            // Parse syscall data
            match checked::try_from_bytes::<SyscallData>(data) {
                Ok(syscall_data) => {
                    // Send to event bus
                    if let Err(e) = tx.send(Event::Syscall(*syscall_data)) {
                        error!("Failed to send syscall event: {}", e);
                        return -1;
                    }
                    0
                }
                Err(e) => {
                    warn!("Failed to parse syscall data: {:?}", e);
                    -1
                }
            }
        })?;

        let ring_buffer = builder.build()?;

        Ok(SyscallPublisher {
            _requirements: requirements,
            ring_buffer,
            interrupted,
        })
    }
}

impl EventPublisher for SyscallPublisher {
    fn get_name(&self) -> &str {
        "Syscall"
    }

    async fn publish_events(&mut self, _tx: &Sender<Event>) -> anyhow::Result<u32> {
        // Check for interruption
        if self.interrupted.load(Ordering::Acquire) {
            return Err(anyhow!("Interrupted by user"));
        }

        // Poll ring buffer in a blocking task
        // The callback registered in new() will send events
        let rb = &mut self.ring_buffer;
        let result = tokio::task::block_in_place(|| rb.poll(Duration::from_millis(100)));

        match result {
            Ok(_) => Ok(0), // Event count tracked in callback
            Err(e) => Err(anyhow!("Ring buffer poll error: {}", e)),
        }
    }
}
