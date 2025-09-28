use std::borrow::Borrow;

use aya::maps::{Array, MapData, RingBuf};
use libc::pid_t;

/// Helper trait for ringbuf data. Send is required to be able to access ring bufs from async tasks
// pub trait IsRingBufData: MapData + Send {}
// pub trait IsRingBufData: Borrow<MapData> + Send {}

/// Syscall ring buffer
// pub struct SyscallRingBuf<'ebpf, T: Borrow<MapData>>(pub RingBuf<&'ebpf T>);
// pub struct SyscallRingBuf<T: IsRingBufData>(pub RingBuf<T>);
pub struct SyscallRingBuf(pub RingBuf<MapData>);

/// PID allow list
// pub struct PidAllowList<'ebpf>(pub Array<&'ebpf mut MapData, pid_t>);
// TODO: refactor into a "PID allow set"
pub struct PidAllowList<'ebpf>(pub Array<&'ebpf MapData, pid_t>);

impl PidAllowList<'_> {
    // TODO: add code here
}
