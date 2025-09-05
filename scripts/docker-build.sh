#!/bin/sh
docker_tag="sikte-builder"
docker_output_dir="/output"
target_dir="target/from-docker/"

# Build inside docker container
docker build --target builder -t "$docker_tag" .

# Run container, and copy binary to target directory
mkdir -p "$target_dir"
docker run --rm \
	--volume "$(pwd):${docker_output_dir}" \
	"$docker_tag" \
	cp "/app/target/release/sikte" "${docker_output_dir}/${target_dir}"

echo "Finished! You can find the binary in /output/${target_dir}"
