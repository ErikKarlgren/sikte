use std::future::Future;

use crate::events::Event;

/// Extracts eBPF events from the kernel and publishes them
pub trait EventPublisher {
    /// Get name
    fn get_name(&self) -> &str;
    /// Publishes an event
    fn publish_event(&mut self) -> impl Future<Output = Event> + Send;
}
