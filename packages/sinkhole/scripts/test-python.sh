#!/bin/sh

set -eu

workspace_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1

exec python3 -m unittest discover \
	--start-directory "${workspace_directory}/tests" \
	--pattern 'test_unbound_module.py' \
	--verbose
