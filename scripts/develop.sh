#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"
set -euxo pipefail

./build.sh

docker run --rm -it \
    -e GIT_URL=https://github.com/denoland/deno \
    -e INIT_SCRIPT="bash" \
    envbuilder:latest
