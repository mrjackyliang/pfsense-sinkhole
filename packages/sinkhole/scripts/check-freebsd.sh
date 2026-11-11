#!/bin/sh

set -eu

workspace_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

main() {
	cd "${workspace_directory}"
	sh ./scripts/test-restore-runtime.sh
}

main "$@"
