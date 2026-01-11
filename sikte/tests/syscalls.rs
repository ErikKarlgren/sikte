use nix::{
    sys::wait::{WaitStatus, waitpid},
    unistd::{ForkResult, fork},
};
use sikte::{
    common::generated_types::{SyscallData, syscall_state_tag},
    ebpf::{
        SikteEbpf,
        map_types::{PidAllowList, SyscallRingBuf},
    },
    events::EventBus,
    memlock_rlimit::bump_memlock_rlimit,
    publishers::syscalls::{self, SyscallID, SyscallPublisher},
    subscribers::EventSubscriber,
};
use std::{
    fs::File,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct TestSubscriber {
    name: String,
    syscalls: Arc<Mutex<Vec<SyscallData>>>,
}

impl TestSubscriber {
    fn new() -> Self {
        Self {
            name: "TestSubscriber".to_string(),
            syscalls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl EventSubscriber for TestSubscriber {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn read_syscall(&mut self, syscall_data: &SyscallData) {
        self.syscalls.lock().unwrap().push(*syscall_data);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trace_child_process_read_syscall() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            // PARENT PROCESS
            let child_pid = child.as_raw();

            // 1. Set up tracing
            bump_memlock_rlimit();
            let mut ebpf = SikteEbpf::load().expect("Failed to load eBPF program");

            let interrupted = Arc::new(AtomicBool::new(false));
            let mut event_bus = EventBus::new();
            let subscriber = TestSubscriber::new();
            event_bus.spawn_subscription(subscriber.clone());

            let pid_allow_list = PidAllowList::new(ebpf.pid_allow_list_map());
            pid_allow_list
                .insert(child_pid)
                .expect("Failed to insert PID into allowlist");

            let sys_enter = ebpf
                .attach_sys_enter_program()
                .expect("Failed to attach sys_enter program");
            let sys_exit = ebpf
                .attach_sys_exit_program()
                .expect("Failed to attach sys_exit program");

            let requirements = syscalls::Requirements::new(sys_enter, sys_exit);
            let ring_buf = SyscallRingBuf::new(ebpf.syscall_events_map());
            let tx = event_bus.tx();
            let publisher = SyscallPublisher::new(requirements, ring_buf, interrupted.clone(), tx)
                .expect("Failed to create publisher");

            event_bus.spawn_publishment(publisher);

            // 2. Wait for child to exit and events to be processed
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    assert_eq!(pid, child);
                    assert_eq!(status, 0);
                }
                other => panic!("Expected child to exit gracefully, got {:?}", other),
            }
            tokio::time::sleep(Duration::from_millis(250)).await; // Allow time for events to propagate

            // 3. Stop tracing
            interrupted.store(true, Ordering::Release);
            tokio::time::sleep(Duration::from_millis(100)).await;

            // 4. Assert that at least one read syscall was made
            let syscalls = subscriber.syscalls.lock().unwrap();
            let read_syscall_found = syscalls.iter().any(|s| {
                if s.state.tag == syscall_state_tag::AT_ENTER {
                    let enter_data = unsafe { s.state.data.at_enter };
                    enter_data.syscall_id == SyscallID::read as i64
                } else {
                    false
                }
            });

            assert!(
                read_syscall_found,
                "No read (0) syscall was found for the traced process"
            );
        }
        Ok(ForkResult::Child) => {
            // CHILD PROCESS
            // Give parent time to start tracing
            std::thread::sleep(Duration::from_millis(100));

            // Execute a read syscall
            let mut file = File::open("/dev/zero").unwrap();
            let mut buffer = [0; 1];
            file.read_exact(&mut buffer).unwrap();

            // Exit cleanly
            std::process::exit(0);
        }
        Err(_) => {
            panic!("Fork failed");
        }
    }
}
