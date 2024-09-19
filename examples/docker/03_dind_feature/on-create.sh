#!/usr/bin/env bash

set -euo pipefail

# Run the docker init script. This needs to be
# run as root. It will take care of starting the
# daemon and adding the ubuntu user to the docker
# group.
sudo /usr/local/share/docker-init.sh

# Change the owner of the Docker socket so that the non-root user can use it.
sudo chown ubuntu:docker /var/run/docker.sock
