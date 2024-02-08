#!/usr/bin/env bash

cd $(dirname "${BASH_SOURCE[0]}")
set -euo pipefail

archs=()
push=false
ssh=false
base="envbuilder"
tag="latest"

for arg in "$@"; do
  if [[ $arg == --arch=* ]]; then
    arch="${arg#*=}"
    archs+=( "$arch" )
  elif [[ $arg == --push ]]; then
    push=true
  elif [[ $arg == --base=* ]]; then
    base="${arg#*=}"
  elif [[ $arg == --tag=* ]]; then
    tag="${arg#*=}"
  elif [[ $arg == --ssh ]]; then
    ssh=true
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

# We have to use docker buildx to tag multiple images with
# platforms tragically, so we have to create a builder.
BUILDER_NAME="envbuilder"
BUILDER_EXISTS=$(docker buildx ls | grep $BUILDER_NAME || true)

# If builder doesn't exist, create it
if [ -z "$BUILDER_EXISTS" ]; then
  echo "Creating dockerx builder $BUILDER_NAME..."
  docker buildx create --use --platform=linux/arm64,linux/amd64,linux/arm/v7 --name $BUILDER_NAME
else
  echo "Builder $BUILDER_NAME already exists. Using it."
  docker buildx use $BUILDER_NAME
fi

# Ensure the builder is bootstrapped and ready to use
docker buildx inspect --bootstrap &> /dev/null

for arch in "${archs[@]}"; do
  echo "Building for $arch..."
  GOARCH=$arch CGO_ENABLED=0 go build -o ./envbuilder-$arch ../cmd/envbuilder &
done
wait

args=()
for arch in "${archs[@]}"; do
  args+=( --platform linux/$arch )
done
if [ "$push" = true ]; then
  args+=( --push )
else
  args+=( --load )
fi

if [ "$ssh" = true ]; then
  if [ -d "./.ssh" ] && [ "$(ls -A ./.ssh)" ]; then
    echo "The .ssh/ directory is not empty. Skipping key generation."
  else
    echo "Generate default private key under .ssh/ folder"
    mkdir -p "./.ssh"
    ssh-keygen -t ed25519 -f "./.ssh/id_ed25519"
  fi
  docker buildx build "${args[@]}" -t $base:$tag -t $base:latest -f Dockerfile.sshkey .
else
  docker buildx build "${args[@]}" -t $base:$tag -t $base:latest -f Dockerfile .
fi

# Check if archs contains the current. If so, then output a message!
if [[ -z "${CI:-}" ]] && [[ " ${archs[@]} " =~ " ${current} " ]]; then
  docker tag $base:$tag envbuilder:latest
  echo "Tagged $current as envbuilder:latest!"
fi
