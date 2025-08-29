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

fix:
    cargo clippy --fix
    cargo +nightly fmt
    git add .
    git commit -m "chore(clippy): run fixes"

# Aliases
b: build
c: check
r *args: (run args)
t: test
