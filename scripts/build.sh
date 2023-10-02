#!/usr/bin/env bash

cd $(dirname "${BASH_SOURCE[0]}")
set -euo pipefail

archs=()
for arg in "$@"; do
  if [[ $arg == --arch=* ]]; then
    arch="${arg#*=}"
    archs+=( "$arch" )
  else
    echo "Unknown argument: $arg"
    exit 1
  fi
done

current=$(go env GOARCH)
if [ ${#archs[@]} -eq 0 ]; then
  echo "No architectures specified. Defaulting to $current..."
  archs=( "$current" ) 
fi

for arch in "${archs[@]}"; do
  GOARCH=$arch CGO_ENABLED=0 go build -o ./envbuilder-$arch ../cmd/envbuilder && \
    docker build --build-arg PLATFORM=$arch -t envbuilder:${arch} -f Dockerfile . &
done
wait

# Check if archs contains the current. If so, then output a message!
if [[ " ${archs[@]} " =~ " ${current} " ]]; then
  docker tag envbuilder:${arch} envbuilder:latest
  echo "Tagged $current as envbuilder:latest!"
fi
