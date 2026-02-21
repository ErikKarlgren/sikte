// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fmt::Display;

use thiserror::Error;
use tokio::sync::broadcast::Sender;

use crate::events::Event;

/// Error which prevented a publisher from publishing an ebpf event
#[derive(Error, Debug)]
pub enum PublishEventError {
    /// sikte was interrupted
    Interrupted,
    /// Error related to libbpf
    Libbpf(libbpf_rs::Error),
}

impl Display for PublishEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishEventError::Interrupted => write!(f, "interrupted"),
            PublishEventError::Libbpf(error) => write!(f, "libbpf error: {error}"),
        }
    }
}

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
    ) -> impl Future<Output = Result<u32, PublishEventError>> + Send;
}
