#!/usr/bin/env bash

cd $(dirname "${BASH_SOURCE[0]}")
set -euxo pipefail

./build.sh

docker run --rm -it \
    -e REPO_URL=https://github.com/microsoft/vscode-remote-try-go \
    -e INIT_SCRIPT="sleep infinity" \
    envbuilder:latest
