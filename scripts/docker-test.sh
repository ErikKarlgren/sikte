#!/bin/sh
docker_tag="sikte-builder"
docker_output_dir="/output"

# Build inside docker container
docker build --target builder -t "$docker_tag" .

# Run tests inside container
docker run --rm \
	--volume "$(pwd):${docker_output_dir}" \
	"$docker_tag" \
	cargo test --release --verbose --locked

