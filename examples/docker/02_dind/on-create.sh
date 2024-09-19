#!/usr/bin/env bash

set -euo pipefail

# Start Docker in the background
sudo -u root /bin/sh -c 'nohup dockerd 2>&1 > /var/log/docker.log &'

# Wait for Docker to start
for attempt in $(seq 1 10); do
  if [[ $attempt -eq 10 ]]; then
    echo "Failed to start Docker"
    exit 1
  fi
  if [[ ! -e /var/run/docker.sock ]]; then
    sleep 1
  else
    break
  fi
done
# Change the owner of the Docker socket so that the coder user can use it.
# Using `newgrp docker` is kind of annoying.
sudo chown coder:docker /var/run/docker.sock
