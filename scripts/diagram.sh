#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"
set -euxo pipefail

d2 ./diagram.d2 --pad=32 -t 1 ./diagram-light.svg
d2 ./diagram.d2 --pad=32 -t 200 ./diagram-dark.svg