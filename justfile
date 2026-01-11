### BUILD COMMANDS ###

default: check

check:
    clang-format -i sikte/src/bpf/sikte.bpf.c sikte/src/bpf/sikte.h
    cargo +nightly fmt --all
    cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

build: check
    cargo build --all-targets --all-features

build-release: check
    cargo build --all-targets --all-features --release --locked

test: build
    RUST_BACKTRACE=1 sudo -E cargo test --all-features

run *args: (run-log "info" args)

run-log log_level *args: build
    RUST_BACKTRACE=1 RUST_LOG={{log_level}} cargo run --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

dbg-test *args:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=rust-gdb cargo test {{args}}

install-local: build-release
    sudo cp target/release/sikte /usr/local/bin/
    @echo "Installed to /usr/local/bin/sikte"

uninstall-local:
    sudo rm -f /usr/local/bin/sikte


### DOCKER COMMANDS ###

docker-build:
    ./scripts/docker-build.sh

docker-clean:
    docker image rm sikte-builder || true
    docker system prune -f


### OTHER COMMANDS ###
check-system:
    @echo "Checking eBPF system requirements..."
    # Kernel version:
    @uname -r
    # BPF syscall available:
    @grep -q CONFIG_BPF_SYSCALL=y /boot/config-$(uname -r) 2>/dev/null && echo 'YES' || echo 'UNKNOWN'
    # Debug filesystem:
    @mount | grep debugfs || echo 'NOT MOUNTED'
    # Capabilities:
    @which capsh >/dev/null && capsh --print || echo 'capsh not found'
