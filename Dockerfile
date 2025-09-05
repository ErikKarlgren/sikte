# Install Rust toolchain and eBPF dependencies
FROM rust:1.88-slim AS builder

# Install system dependencies needed for eBPF compilation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    lld \
    libelf-dev \
    zlib1g-dev \
    linux-libc-dev \
    pkg-config \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install bpf-linker for Aya eBPF programs
RUN cargo install bpf-linker

# Install nightly toolchain and rust-src for eBPF compilation
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && rustup default nightly \
    && rustup override set 1.88.0

# Set working directory
WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY sikte/Cargo.toml ./sikte/
COPY sikte-common/Cargo.toml ./sikte-common/
COPY sikte-ebpf/Cargo.toml ./sikte-ebpf/

# Fetch dependencies
RUN cargo fetch

# Copy source code
COPY . .

# Build the application in release mode with a locked Cargo.lock
RUN cargo build --release --locked

# And now, the user needs to extract the binary out
