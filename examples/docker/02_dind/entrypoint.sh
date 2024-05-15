#!/usr/bin/env bash

set -euo pipefail

nohup dockerd > /var/log/docker.log 2>&1 &

exec bash --login