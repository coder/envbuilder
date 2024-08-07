#!/usr/bin/env bash

# This script is meant to be sourced by other scripts. To source this script:
#     # shellcheck source=scripts/lib.sh
#     source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

set -euo pipefail

# Avoid sourcing this script multiple times to guard against when lib.sh
# is used by another sourced script, it can lead to confusing results.
if [[ ${SCRIPTS_LIB_IS_SOURCED:-0} == 1 ]]; then
	return
fi
# Do not export to avoid this value being inherited by non-sourced
# scripts.
SCRIPTS_LIB_IS_SOURCED=1

# We have to define realpath before these otherwise it fails on Mac's bash.
SCRIPT="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
SCRIPT_DIR="$(realpath "$(dirname "$SCRIPT")")"

function project_root {
	# Nix sets $src in derivations!
	[[ -n "${src:-}" ]] && echo "$src" && return

	# Try to use `git rev-parse --show-toplevel` to find the project root.
	# If this directory is not a git repository, this command will fail.
	git rev-parse --show-toplevel 2>/dev/null && return
}

PROJECT_ROOT="$(cd "$SCRIPT_DIR" && realpath "$(project_root)")"

# cdroot changes directory to the root of the repository.
cdroot() {
	cd "$PROJECT_ROOT" || error "Could not change directory to '$PROJECT_ROOT'"
}

# log prints a message to stderr
log() {
	echo "$*" 1>&2
}

# error prints an error message and returns an error exit code.
error() {
	log "ERROR: $*"
	exit 1
}
