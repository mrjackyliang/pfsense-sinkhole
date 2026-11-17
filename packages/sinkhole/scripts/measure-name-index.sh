#!/bin/sh

set -eu

workspace_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repository_directory=$(CDPATH= cd -- "${workspace_directory}/../.." && pwd)
unique_names="${1:-2500000}"
query_count="${2:-100000}"
php_test_image="${PHP_TEST_IMAGE:-php:8.3-cli-alpine}"
baseline_reference="${SINKHOLE_BASELINE_REF:-HEAD}"
cache_directory="${HOME}/Library/Caches/sinkhole-perf"
run_directory=''

cleanup() {
	if [ -n "${run_directory}" ] && [ -d "${run_directory}" ]; then
		rm -rf -- "${run_directory}"
	fi
}

trap cleanup EXIT HUP INT TERM

mkdir -p "${cache_directory}"
run_directory=$(mktemp -d "${cache_directory}/run.XXXXXXXX")
run_name=$(basename -- "${run_directory}")

if command -v php >/dev/null 2>&1; then
	php -d memory_limit=-1 "${workspace_directory}/tests/perf-compile.php" \
		"${run_directory}/compile" "${unique_names}"
	cp -RL "${run_directory}/compile/runtime/sinkhole" "${run_directory}/generation"
else
	docker run --rm \
		--network none \
		--volume "${workspace_directory}:/workspace:ro" \
		--volume "${cache_directory}:/perf" \
		"${php_test_image}" \
		sh -c "php -d memory_limit=-1 /workspace/tests/perf-compile.php /tmp/compile ${unique_names} \
			&& cp -RL /tmp/compile/runtime/sinkhole /perf/${run_name}/generation"
fi

git -C "${repository_directory}" show \
	"${baseline_reference}:packages/sinkhole/port/files/usr/local/pkg/sinkhole/sinkhole_unbound.py" \
	>"${run_directory}/baseline_unbound.py"

python3 -I "${workspace_directory}/tests/perf_name_index.py" \
	--module "${workspace_directory}/port/files/usr/local/pkg/sinkhole/sinkhole_unbound.py" \
	--baseline-module "${run_directory}/baseline_unbound.py" \
	--data "${run_directory}/generation" \
	--queries "${query_count}"
