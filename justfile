# https://just.systems

default: check

build:
    cargo build

check:
    cargo check && cargo clippy

run log_level *args: build
    RUST_BACKTRACE=1 RUST_LOG={{log_level}} cargo run --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

run-log-info *args: (run "info" args)
run-log-debug *args: (run "debug" args)
run-log-trace *args: (run "trace" args)

test:
    RUST_BACKTRACE=1 cargo test

dbg-test *args:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=rust-gdb cargo test {{args}}

fix:
    cargo clippy --fix
    cargo +nightly fmt
    git add .
    git commit -m "chore(clippy): run fixes"

docker-build:
    # Build inside docker container
    docker build --target builder -t sikte-builder .
    # Run container, and copy binary to target directory
    mkdir -p target/from-docker/
    docker run --rm -v $(pwd):/output sikte-builder cp /app/target/release/sikte /output/target/from-docker/
    # Finished: you can find the binary in /output/target/from-docker/

# Aliases
b: build
c: check
r *args: (run-log-info args)
t: test
