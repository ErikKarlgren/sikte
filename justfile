# https://just.systems

default: check

build:
    cargo build

check:
    cargo check && cargo clippy

run *args: build
    RUST_BACKTRACE=1 RUST_LOG=info  cargo run --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

run-log-debug *args: build
    RUST_BACKTRACE=1 RUST_LOG=debug cargo run --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

run-log-trace *args: build
    RUST_BACKTRACE=1 RUST_LOG=trace cargo run --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

fix:
    cargo clippy --fix

# Aliases
b: build
c: check
r *args: (run args)
