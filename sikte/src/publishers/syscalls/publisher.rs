// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use log::{debug, warn};
use tokio::sync::broadcast::Sender;

use crate::{
    common::generated_types::SyscallData,
    ebpf::{SysEnterProgram, SysExitProgram, map_types::SyscallRingBuf},
    events::Event,
    publishers::{EventPublisher, PublishEventError},
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

        // Non-zero return values in the callback will stop ring buffer consumption early.
        builder.add(ring_buf.map(), move |data: &[u8]| -> i32 {
            let mut syscall_data = SyscallData::default();
            // copy into struct to ensure memory alignment
            match plain::copy_from_bytes(&mut syscall_data, data) {
                Ok(()) => {
                    if let Err(e) = tx.send(Event::Syscall(syscall_data)) {
                        debug!("Cannot send syscall event to queue: {e}");
                    }
                }
                Err(e) => {
                    warn!("Failed to parse syscall data: {e:?}");
                }
            };
            0
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

    async fn publish_events(&mut self, _tx: &Sender<Event>) -> Result<u32, PublishEventError> {
        // Check for interruption
        if self.interrupted.load(Ordering::Acquire) {
            return Err(PublishEventError::Interrupted);
        }

        // Poll ring buffer in a blocking task
        // The callback registered in new() will send events
        let rb = &mut self.ring_buffer;
        let result = tokio::task::block_in_place(|| rb.poll(Duration::from_millis(100)));

        match result {
            Ok(()) => Ok(0), // Event count tracked in callback
            Err(e) => Err(PublishEventError::Libbpf(e)),
        }
    }
}
