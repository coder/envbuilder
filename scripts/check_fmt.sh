#!/bin/bash

list="$(go run mvdan.cc/gofumpt@v0.6.0 -l .)"
if [[ -n $list ]]; then
  echo -e "error: The following files have changes:\n\n${list}\n\nDiff:\n\n"
  go run mvdan.cc/gofumpt@v0.6.0 -d .
  exit 1
fi
