### BUILD COMMANDS ###

default: check

build:
    cargo build

build-release:
    cargo build --release

check:
    cargo check && cargo clippy

run *args: (run-log "info")

run-log log_level *args: build
    RUST_BACKTRACE=1 RUST_LOG={{log_level}} cargo run --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

test:
    RUST_BACKTRACE=1 cargo test

dbg-test *args:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=rust-gdb cargo test {{args}}

install-local: build-release
    sudo cp target/release/sikte /usr/local/bin/
    @echo "Installed to /usr/local/bin/sikte"

uninstall-local:
    sudo rm -f /usr/local/bin/sikte


### DOCKER COMMANDS ###

docker-build:
    # Build inside docker container
    docker build --target builder -t sikte-builder .
    # Run container, and copy binary to target directory
    mkdir -p target/from-docker/
    docker run --rm -v $(pwd):/output sikte-builder cp /app/target/release/sikte /output/target/from-docker/
    @echo "Finished! You can find the binary in /output/target/from-docker/"

docker-clean:
    docker image rm sikte-builder || true
    docker system prune -f


### OTHER COMMANDS ###

fix:
    cargo clippy --fix
    cargo +nightly fmt
    git add .
    git commit -m "chore(clippy): run fixes"

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
