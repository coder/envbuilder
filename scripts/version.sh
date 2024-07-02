#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

last_tag="$(git describe --tags --abbrev=0)"
version="$last_tag"

# Remove the "v" prefix.
echo "${version#v}"
