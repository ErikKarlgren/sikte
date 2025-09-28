use anyhow::anyhow;
use aya::maps::{MapData, RingBuf};
use bytemuck::checked;
use log::error;
use sikte_common::raw_tracepoints::syscalls::SyscallData;
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::broadcast::Sender,
    task::yield_now,
};

use crate::{
    ebpf::{SysEnterProgram, SysExitProgram, map_types::SyscallRingBuf},
    events::Event,
    publishers::EventPublisher,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Requirements for SyscallPublisher
pub struct Requirements {
    sys_enter: SysEnterProgram,
    sys_exit: SysExitProgram,
}

impl Requirements {
    pub fn new(sys_enter: SysEnterProgram, sys_exit: SysExitProgram) -> Requirements {
        Requirements {
            sys_enter,
            sys_exit,
        }
    }
}

/// Publishes syscall data to an EventBus
// pub struct SyscallPublisher<T: IsRingBufData> {
pub struct SyscallPublisher {
    /// Requirements for creating this struct. These are just capability tokens, so not actually
    /// used
    _requirements: Requirements,
    /// Syscall ring buffer
    // ring_buf_fd: AsyncFd<RingBuf<T>>,
    ring_buf_fd: AsyncFd<RingBuf<MapData>>,
    /// Boolean that tells us if the user interrupted the program
    interrupted: Arc<AtomicBool>,
}

// impl<T: IsRingBufData> SyscallPublisher<T> {
impl SyscallPublisher {
    /// Create new SyscallPublisher, but only if the user already has the given requirements, which
    /// must be given by `SikteEbpf`. It might fail if a file descriptor cannot be open for the ring
    /// buffer.
    pub fn new(
        requirements: Requirements,
        ring_buf: SyscallRingBuf,
        interrupted: Arc<AtomicBool>,
    ) -> std::io::Result<SyscallPublisher> {
        let ring_buf_fd = AsyncFd::with_interest(ring_buf.0, Interest::READABLE)?;
        Ok(SyscallPublisher {
            _requirements: requirements,
            ring_buf_fd,
            interrupted,
        })
    }
}

// impl<T: IsRingBufData> EventPublisher for SyscallPublisher<T> {
impl EventPublisher for SyscallPublisher {
    fn get_name(&self) -> &str {
        "Syscall"
    }

    fn publish_events(
        &mut self,
        tx: &Sender<Event>,
    ) -> impl Future<Output = anyhow::Result<u32>> + Send {
        async {
            const YIELD_LIMIT: u32 = 1000;

            let mut num_events = 0u32;
            let mut guard = self.ring_buf_fd.readable_mut().await?;

            let ring_buf = guard.get_inner_mut();

            if self.interrupted.load(Ordering::Acquire) {
                return Err(anyhow!("Interrupted by user"));
            }

            while let Some(item) = ring_buf.next() {
                num_events += 1;

                let raw_data: &[u8] = &item;
                let syscall_data = checked::try_from_bytes::<SyscallData>(raw_data)
                    .map_err(|err| anyhow!("Could not parse SyscallData: {err:?}"))?;

                if let Err(e) = tx.send(Event::Syscall(*syscall_data)) {
                    error!("Could not send event: {e}");
                    // There might not be any subscribers ready yet
                    yield_now().await;
                }

                // Check periodically if program has been interrupted. Otherwise, yield to not hog
                // up tokio's resources.
                if num_events % YIELD_LIMIT == 0 {
                    if self.interrupted.load(Ordering::Acquire) {
                        return Err(anyhow!("Interrupted by user"));
                    } else {
                        yield_now().await;
                    }
                }
            }

            guard.clear_ready();
            Ok(num_events)
        }
    }
}
