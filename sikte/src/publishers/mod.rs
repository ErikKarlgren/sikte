mod event_publisher;
mod perf_events;
pub mod syscalls;

pub use event_publisher::EventPublisher;
// DEPRECATED: we need to migrate this to a Publisher model
pub use perf_events::main::perf_events;
