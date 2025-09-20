use log::debug;
use sikte_common::raw_tracepoints::syscalls::SyscallData;
use tokio::sync::broadcast::{Receiver, Sender, error::RecvError};

use crate::consumers::EventSubscriber;

/// Enum for representing all the possible eBPF events in this program
#[derive(Clone)]
pub enum Event {
    /// Syscall event
    Syscall(SyscallData),
}

/// Multiple-producer & multiple-consumer event bus
pub struct EventBus {
    sender: Sender<Event>,
    receiver: Receiver<Event>,
}

impl EventBus {
    pub fn get_sender(&self) -> Sender<Event> {
        self.sender.clone()
    }

    /// Spawn a subscription task that will run inside tokio
    pub async fn spawn_subscription<S>(&self, subscriber: S)
    where
        S: EventSubscriber + Send + 'static,
    {
        let mut rx = self.sender.subscribe();
        let name = subscriber.get_name();

        tokio::spawn(async move {
            match rx.recv().await {
                Ok(event) => match event {
                    Event::Syscall(syscall_data) => subscriber.read_syscall(&syscall_data),
                },
                Err(err) => match err {
                    RecvError::Closed => {
                        debug!("Event bus was closed. Finished subscription for {name}");
                        return;
                    }
                    RecvError::Lagged(n) => debug!("{name} has lagged by {n} messages"),
                },
            }
        });
    }
}
