use log::{debug, error};
use sikte_common::raw_tracepoints::syscalls::SyscallData;
use tokio::{
    sync::broadcast::{Receiver, Sender, error::RecvError},
    task::JoinHandle,
};

use crate::{publishers::EventPublisher, subscribers::EventSubscriber};

/// Enum for representing all the possible eBPF events in this program
#[derive(Clone)]
pub enum Event {
    /// Syscall event
    Syscall(SyscallData),
}

/// Multiple-publisher & multiple-consumer event bus
pub struct EventBus {
    sender: Sender<Event>,
    join_handles: Vec<JoinHandle<()>>,
}

impl EventBus {
    /// Create a new `EventBus`
    pub fn new() -> EventBus {
        const CAPACITY: usize = 2 << 15;
        let (sender, _) = tokio::sync::broadcast::channel(CAPACITY);
        EventBus {
            sender,
            join_handles: vec![],
        }
    }

    /// Spawn a publishment task that will run inside tokio
    pub fn spawn_publishment<P>(&mut self, publisher: P)
    where
        P: EventPublisher + Send + 'static,
    {
        debug!("Spawn publishment: {}", publisher.get_name());
        let tx = self.sender.clone();
        let handle = tokio::spawn(publishment(publisher, tx));
        self.join_handles.push(handle);
    }

    /// Spawn a subscription task that will run inside tokio
    pub fn spawn_subscription<S>(&mut self, subscriber: S)
    where
        S: EventSubscriber + Send + 'static,
    {
        debug!("Spawn subscription: {}", subscriber.get_name());
        let rx = self.sender.subscribe();
        let handle = tokio::spawn(subscription(subscriber, rx));
        self.join_handles.push(handle);
    }
}

impl Drop for EventBus {
    fn drop(&mut self) {
        for handle in &self.join_handles {
            handle.abort();
        }
    }
}

async fn publishment<P>(mut publisher: P, tx: Sender<Event>)
where
    P: EventPublisher + Send + 'static,
{
    loop {
        let num_events = publisher.publish_events(&tx).await;
        if let Err(err) = num_events {
            error!("Error with publisher {}: {err}", publisher.get_name());
        }
    }
}

async fn subscription<S>(mut subscriber: S, mut rx: Receiver<Event>)
where
    S: EventSubscriber + Send + 'static,
{
    loop {
        match rx.recv().await {
            Ok(event) => match event {
                Event::Syscall(syscall_data) => subscriber.read_syscall(&syscall_data),
            },
            Err(err) => match err {
                RecvError::Closed => {
                    debug!(
                        "Event bus was closed. Finished subscription for {}",
                        subscriber.get_name()
                    );
                    break;
                }
                RecvError::Lagged(n) => {
                    debug!("{} has lagged by {} messages", subscriber.get_name(), n)
                }
            },
        }
    }
}
