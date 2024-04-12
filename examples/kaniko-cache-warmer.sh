#!/usr/bin/env bash

# This is an example script to pull a number of images into the Kaniko cache
# to have them ready for consumption by envbuilder.
# Ref: https://github.com/coder/envbuilder/blob/main/README.md#image-caching
KANIKO_CACHE_VOLUME=${KANIKO_CACHE_VOLUME:-"kanikocache"}
IMAGES=(
    alpine:latest
    debian:latest
    ubuntu:latest
)

set -euo pipefail

if ! docker volume inspect "${KANIKO_CACHE_VOLUME}" > /dev/null 2>&1; then
    echo "Kaniko cache volume does not exist; creating it."
    docker volume create "${KANIKO_CACHE_VOLUME}"
fi

for img in "${IMAGES[@]}"; do
    echo "Fetching image ${img} to kaniko cache ${KANIKO_CACHE_VOLUME}"
    docker run --rm \
        -v "${KANIKO_CACHE_VOLUME}:/cache" \
        gcr.io/kaniko-project/warmer:latest \
            --cache-dir=/cache \
            --image="${img}"
done
