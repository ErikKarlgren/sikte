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
        let rx = self.sender.subscribe();
        tokio::spawn(subscription(subscriber, rx));
    }
}

async fn subscription<S>(subscriber: S, mut rx: Receiver<Event>)
where
    S: EventSubscriber + Send + 'static,
{
    let name = subscriber.get_name();

    loop {
        match rx.recv().await {
            Ok(event) => match event {
                Event::Syscall(syscall_data) => subscriber.read_syscall(&syscall_data),
            },
            Err(err) => match err {
                RecvError::Closed => {
                    debug!("Event bus was closed. Finished subscription for {name}");
                    break;
                }
                RecvError::Lagged(n) => debug!("{name} has lagged by {n} messages"),
            },
        }
    }
}
