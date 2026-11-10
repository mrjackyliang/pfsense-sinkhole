#!/bin/sh

set -eu

workspace_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1

if [ "${SINKHOLE_SKIP_PHP_TESTS:-0}" = '1' ]; then
	echo 'SKIP: PHP end-to-end compiler explicitly disabled by SINKHOLE_SKIP_PHP_TESTS=1; running the Python module half with equivalent fixtures.' >&2
	exec python3 "${workspace_directory}/tests/e2e.py" --python-only
fi

temporary_directory=''

cleanup() {
	if [ -n "${temporary_directory}" ] && [ -d "${temporary_directory}" ]; then
		rm -rf -- "${temporary_directory}"
	fi
}

trap cleanup EXIT HUP INT TERM

if command -v php >/dev/null 2>&1; then
	temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/sinkhole-e2e.XXXXXXXX")
	php "${workspace_directory}/tests/e2e-compile.php" \
		"${temporary_directory}/active" initial
	php "${workspace_directory}/tests/e2e-compile.php" \
		"${temporary_directory}/zero" zero
	export SINKHOLE_E2E_PHP_MODE=local
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	cache_directory="${HOME}/Library/Caches/sinkhole-e2e"
	mkdir -p "${cache_directory}"
	temporary_directory=$(mktemp -d "${cache_directory}/run.XXXXXXXX")
	php_test_image="${PHP_TEST_IMAGE:-php:8.3-cli-alpine}"
	docker run --rm \
		--network none \
		--volume "${workspace_directory}:/workspace:ro" \
		--volume "${temporary_directory}:/e2e" \
		"${php_test_image}" \
		php /workspace/tests/e2e-compile.php /e2e/active initial
	docker run --rm \
		--network none \
		--volume "${workspace_directory}:/workspace:ro" \
		--volume "${temporary_directory}:/e2e" \
		"${php_test_image}" \
		php /workspace/tests/e2e-compile.php /e2e/zero zero
	export SINKHOLE_E2E_PHP_MODE=docker
else
	echo 'ERROR: the end-to-end compiler test requires php or a usable Docker daemon.' >&2

	exit 1
fi

export SINKHOLE_E2E_TEMP="${temporary_directory}"
export PHP_TEST_IMAGE="${PHP_TEST_IMAGE:-php:8.3-cli-alpine}"

python3 "${workspace_directory}/tests/e2e.py"
