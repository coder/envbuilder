#!/usr/bin/env bash

set -euo pipefail

# Start the rootless docker daemon as a non-root user
nohup rootlesskit --net=slirp4netns --mtu=1500 --disable-host-loopback --port-driver=builtin --copy-up=/etc --copy-up=/run dockerd >"/tmp/dockerd-rootless.log" 2>&1 &
