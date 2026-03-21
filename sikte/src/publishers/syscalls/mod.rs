// SPDX-License-Identifier: AGPL-3.0-or-later
mod publisher;
mod table;

pub use publisher::{Requirements, SyscallPublisher};
pub use table::{MAX_NUM_SYSCALLS, SyscallID, build_syscall_id_to_name_table};
