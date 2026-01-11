#!/bin/sh
set -e
docker_tag="sikte-builder"
docker_output_dir="/output"

# Build inside docker container
docker build --target builder -t "$docker_tag" .

# Run tests inside container
# --privileged    We need some privileges to be able to trace a program
# --pid=host      Share PIDs with host. Sikte can't distinguish right now between kernel level and container's PIDs
docker run --rm \
	--privileged \
	-e RUST_BACKTRACE=1 \
	-e RUST_LOG=debug \
	--pid=host \
	--volume "$(pwd):${docker_output_dir}" \
	"$docker_tag" \
	cargo test --all-features -- --no-capture

