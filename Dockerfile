# Install Rust toolchain and eBPF dependencies
FROM rust:1.92-slim AS builder

# Install system dependencies needed for eBPF compilation
RUN apt-get update && \
    apt-get install -y build-essential zlib1g-dev clang llvm libelf1 libelf-dev libbpf-dev clang-format just && \
    rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install stable && \
    rustup component add --toolchain nightly-x86_64-unknown-linux-gnu rustfmt && \
    rustup component add rustfmt

# Set working directory
WORKDIR /app

RUN rustup override set 1.92.0

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY sikte/Cargo.toml ./sikte/

# Fetch dependencies
RUN cargo fetch

# Copy source code
COPY . .

# Build the application in release mode with a locked Cargo.lock
RUN just build-release

# And now, the user needs to extract the binary out
