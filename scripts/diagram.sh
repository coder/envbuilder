#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"
set -euxo pipefail

formats=( svg png )
for format in "${formats[@]}"; do
  d2 ./diagram.d2 --pad=32 -t 1 "./diagram-light.${format}"
  d2 ./diagram.d2 --pad=32 -t 200 "./diagram-dark.${format}"
done
