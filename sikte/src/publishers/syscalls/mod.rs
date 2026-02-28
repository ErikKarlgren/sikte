// SPDX-License-Identifier: AGPL-3.0-or-later
mod publisher;
mod table;

pub use publisher::{Requirements, SyscallPublisher};
pub use table::{MAX_NUM_SYSCALLS, SyscallID};
