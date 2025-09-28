pub mod main;
mod producer;
mod table;

pub use producer::{Requirements, SyscallPublisher};
pub use table::to_syscall_name;
