#!/usr/bin/env bash

cd $(dirname "${BASH_SOURCE[0]}")
set -euxo pipefail

CGO_ENABLED=0 go build -o ./envbuilder ../cmd/envbuilder
docker build -t envbuilder:latest .
