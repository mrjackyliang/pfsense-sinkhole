#!/bin/sh

set -eu

workspace_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/sinkhole-restore.XXXXXXXX")

cleanup() {
	rm -rf -- "${temporary_directory}"
}

file_mode() {
	path=$1

	if stat -f '%Lp' "${path}" >/dev/null 2>&1; then
		stat -f '%Lp' "${path}"
	else
		stat -c '%a' "${path}"
	fi
}

assert_mode() {
	expected=$1
	path=$2
	actual=$(file_mode "${path}")

	if [ "${actual}" != "${expected}" ]; then
		echo "FAIL: expected mode ${expected} for ${path}, received ${actual}." >&2

		exit 1
	fi
}

file_owner() {
	path=$1

	if stat -f '%Su' "${path}" >/dev/null 2>&1; then
		stat -f '%Su' "${path}"
	else
		stat -c '%U' "${path}"
	fi
}

trap cleanup EXIT HUP INT TERM

mirror_root="${temporary_directory}/mirror"
mirror_storage="${mirror_root}/sinkhole.d"
mirror_generation="${mirror_storage}/.sinkhole-generation-0123456789abcdef"
mirror_clients="${mirror_root}/sinkhole-clients"
runtime_root="${temporary_directory}/runtime"
current_user=$(id -un)
current_group=$(id -gn)

mkdir -p "${mirror_generation}" "${mirror_clients}" "${runtime_root}"
chmod 0711 "${runtime_root}"
printf '%s\n' '# fixture module' >"${mirror_root}/sinkhole.py"
chmod 0600 "${mirror_root}/sinkhole.py"
printf '%s\n' '{"schema_version":3}' >"${mirror_generation}/manifest.json"
printf '%s\n' 'example.test	0	' >"${mirror_generation}/domains.tsv"
printf '%s\n' 'bypass.example.test		encrypted_dns' >"${mirror_generation}/bypass.tsv"
printf '%s\n' 'allowed.example.test' >"${mirror_generation}/allow.txt"
printf '%s\n' 'network-allowed.example.test' >"${mirror_generation}/allow-network-11111111111111111111111111111111.txt"
printf '%s\n' 'device-allowed.example.test' >"${mirror_generation}/allow-device-22222222222222222222222222222222.txt"
printf '%s\n' 'fixture-generation' >"${mirror_generation}/generation"
printf '%s\n' '{"schema_version":2,"generated_at":"2026-01-01T00:00:00+00:00","content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","networks":[],"interfaces":[],"devices":{},"conflicts":[]}' >"${mirror_clients}/clients.json"
printf '%s\n' 'must not copy' >"${mirror_root}/unrelated.test"
printf '%s\n' 'must not copy' >"${mirror_generation}/unrelated.test"
ln -s 'sinkhole.d/.sinkhole-generation-0123456789abcdef' "${mirror_root}/sinkhole"
printf '%s\n' 'preserved' >"${runtime_root}/preserved.test"

SINKHOLE_MIRROR_ROOT="${mirror_root}" \
SINKHOLE_RUNTIME_ROOT="${runtime_root}" \
SINKHOLE_UNBOUND_USER="${current_user}" \
SINKHOLE_UNBOUND_GROUP="${current_group}" \
SINKHOLE_ROOT_USER="${current_user}" \
SINKHOLE_ROOT_GROUP="${current_group}" \
	sh "${workspace_directory}/port/files/usr/local/pkg/sinkhole/restore-runtime.sh"

assert_mode 711 "${runtime_root}"
assert_mode 755 "${runtime_root}/sinkhole.d"
assert_mode 755 "${runtime_root}/sinkhole-state"
assert_mode 644 "${runtime_root}/sinkhole.py"
assert_mode 755 "${runtime_root}/sinkhole-clients"
assert_mode 644 "${runtime_root}/sinkhole-clients/clients.json"

if [ "$(file_owner "${runtime_root}/sinkhole-clients")" != "${current_user}" ] \
	|| [ "$(file_owner "${runtime_root}/sinkhole-clients/clients.json")" != "${current_user}" ]; then
	echo 'FAIL: the restored client map owner is incorrect.' >&2

	exit 1
fi

for data_file in manifest.json domains.tsv bypass.tsv allow.txt generation; do
	if [ ! -r "${runtime_root}/sinkhole/${data_file}" ]; then
		echo "FAIL: restored ${data_file} is not readable." >&2

		exit 1
	fi

	assert_mode 644 "${runtime_root}/sinkhole/${data_file}"
done

for data_file in \
	allow-network-11111111111111111111111111111111.txt \
	allow-device-22222222222222222222222222222222.txt; do
	if [ ! -r "${runtime_root}/sinkhole/${data_file}" ]; then
		echo "FAIL: restored ${data_file} is not readable." >&2

		exit 1
	fi

	assert_mode 644 "${runtime_root}/sinkhole/${data_file}"
done

if [ ! -f "${runtime_root}/preserved.test" ]; then
	echo 'FAIL: the restore changed unrelated runtime-root contents.' >&2

	exit 1
fi

if [ -e "${runtime_root}/unrelated.test" ] || [ -e "${runtime_root}/sinkhole/unrelated.test" ]; then
	echo 'FAIL: the restore copied a file outside the fixed allowlist.' >&2

	exit 1
fi

active_target=$(readlink "${runtime_root}/sinkhole")

case "${active_target}" in
	sinkhole.d/.sinkhole-generation-????????????????) ;;
	*)
		echo "FAIL: the active generation target is invalid: ${active_target}." >&2

		exit 1
		;;
esac

assert_mode 755 "${runtime_root}/${active_target}"

missing_runtime_root="${temporary_directory}/missing-runtime"

SINKHOLE_MIRROR_ROOT="${mirror_root}" \
SINKHOLE_RUNTIME_ROOT="${missing_runtime_root}" \
SINKHOLE_UNBOUND_USER="${current_user}" \
SINKHOLE_UNBOUND_GROUP="${current_group}" \
SINKHOLE_ROOT_USER="${current_user}" \
SINKHOLE_ROOT_GROUP="${current_group}" \
	sh "${workspace_directory}/port/files/usr/local/pkg/sinkhole/restore-runtime.sh"

assert_mode 755 "${missing_runtime_root}"
assert_mode 755 "${missing_runtime_root}/sinkhole-state"
assert_mode 755 "${missing_runtime_root}/sinkhole-clients"
assert_mode 644 "${missing_runtime_root}/sinkhole-clients/clients.json"

echo 'PASS restore runtime ownership and mode boundaries'
