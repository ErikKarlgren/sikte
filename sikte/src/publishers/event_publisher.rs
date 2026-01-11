// SPDX-License-Identifier: AGPL-3.0-or-later
use std::future::Future;

use tokio::sync::broadcast::Sender;

use crate::events::Event;

/// Extracts eBPF events from the kernel and publishes them
pub trait EventPublisher {
    /// Get name
    fn get_name(&self) -> &str;

    /// Publishes events to a given Sender<Event>.
    /// This function may return even if there are some events left to publish so as not to hoard tokio's async queue.
    /// Returns the number of published events before yielding, or an error.
    fn publish_events(
        &mut self,
        tx: &Sender<Event>,
    ) -> impl Future<Output = anyhow::Result<u32>> + Send;
}
