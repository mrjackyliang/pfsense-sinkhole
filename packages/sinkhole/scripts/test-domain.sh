#!/bin/sh

set -eu

workspace_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "${SINKHOLE_SKIP_PHP_TESTS:-0}" = '1' ]; then
	echo 'SKIP: PHP lint and tests explicitly disabled by SINKHOLE_SKIP_PHP_TESTS=1.' >&2

	exit 0
fi

run_php_tests() {
	php_command=$1

	find ./port/files \
		-type f \
		\( -name '*.php' -o -name '*.inc' -o -path '*/usr/local/sbin/sinkhole' \) \
		-print0 \
		| xargs -0 -n 1 "${php_command}" -l
	"${php_command}" ./tests/require-classes.php
	"${php_command}" ./tests/domain.php
	"${php_command}" ./tests/page-render.php
	"${php_command}" ./tests/catalog.php
	"${php_command}" ./tests/services.php
	"${php_command}" ./tests/runtime.php
	"${php_command}" ./tests/download-client.php
	"${php_command}" ./tests/pfsense-adapter.php
	"${php_command}" ./tests/alerts.php
	"${php_command}" ./tests/redirect.php
	"${php_command}" ./tests/ip.php
	"${php_command}" ./tests/bypass.php
	"${php_command}" ./tests/updates.php
}

if command -v php >/dev/null 2>&1; then
	(
		cd "${workspace_directory}"
		run_php_tests php
	)

	exit 0
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	php_test_image="${PHP_TEST_IMAGE:-php:8.3-cli-alpine}"

	exec docker run --rm \
		--network none \
		--volume "${workspace_directory}:/workspace:ro" \
		--workdir /workspace \
		"${php_test_image}" \
		sh -c '
			find ./port/files -type f \
				\( -name "*.php" -o -name "*.inc" -o -path "*/usr/local/sbin/sinkhole" \) \
				-print0 \
				| xargs -0 -n 1 php -l \
			&& php ./tests/require-classes.php \
			&& php ./tests/domain.php \
			&& php ./tests/page-render.php \
			&& php ./tests/catalog.php \
			&& php ./tests/services.php \
			&& php ./tests/runtime.php \
			&& php ./tests/download-client.php \
			&& php ./tests/pfsense-adapter.php \
			&& php ./tests/alerts.php \
			&& php ./tests/redirect.php \
			&& php ./tests/ip.php \
			&& php ./tests/bypass.php \
			&& php ./tests/updates.php
		'
fi

echo 'ERROR: PHP lint and tests require php or a usable Docker daemon.' >&2

exit 1
