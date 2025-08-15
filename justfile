# https://just.systems

default: check

build:
    cargo build

check:
    cargo check && cargo clippy

run: build
    RUST_BACKTRACE=1 RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'

# Aliases
b: build
c: check
r: run
