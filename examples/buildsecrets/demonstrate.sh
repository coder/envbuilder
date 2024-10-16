#!/bin/bash

./../../scripts/build.sh --base=build-secrets-envbuilder
docker run -it --rm \
    -e ENVBUILDER_INIT_SCRIPT='/bin/sh' \
    -e ENVBUILDER_WORKSPACE_FOLDER=/workspace \
    -e ENVBUILDER_SECRET_FOO='this is a secret' \
    -v $PWD:/workspace \
    build-secrets-envbuilder:latest

# This script will drop you into a shell inside an envbuilder built alpine container.
# Notice that the secret that was set above is nowhere to be found. Yet, it's sha256 is
# present in /secret_hash.txt. This is a demonstration of how secrets can be passed to
# the build process without being exposed in the final running container. If you'd like to
# dig deeper, you can extract the built image, which is inside /workspace/.envbuilder.tmp.
# It's only there for demonstration purposes. We would not keep the tmp dir there
# in the final PR.