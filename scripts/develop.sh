#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"
set -euxo pipefail

./build.sh || exit 1

docker run --rm -it \
    -e ENVBUILDER_GIT_URL=https://github.com/denoland/deno \
    -e ENVBUILDER_INIT_SCRIPT="bash" \
    envbuilder:latest
