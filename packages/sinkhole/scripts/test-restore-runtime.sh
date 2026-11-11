#!/bin/sh

set -eu

skip_message="SKIP: the boot-restore test needs FreeBSD's sh and BSD mv; scripts/check-freebsd.sh runs it in the FreeBSD build VM during publish."
host_system=$(uname -s)
capability_directory=$(mktemp -d "${TMPDIR:-/tmp}/sinkhole-restore-capability.XXXXXXXX")
pipefail_supported='true'
mv_fh_supported='true'

if ! sh -c 'set -o pipefail' >/dev/null 2>&1; then
	pipefail_supported='false'
fi

printf '%s\n' 'source' >"${capability_directory}/source"
printf '%s\n' 'destination' >"${capability_directory}/destination"

if ! mv -fh -- \
	"${capability_directory}/source" \
	"${capability_directory}/destination" >/dev/null 2>&1; then
	mv_fh_supported='false'
elif [ -e "${capability_directory}/source" ] \
	|| ! grep -qx 'source' "${capability_directory}/destination"; then
	mv_fh_supported='false'
fi

rm -rf -- "${capability_directory}"

if [ "${pipefail_supported}" != 'true' ] || [ "${mv_fh_supported}" != 'true' ]; then
	if [ "${host_system}" = 'FreeBSD' ]; then
		echo "FAIL: FreeBSD cannot run the boot-restore test faithfully: pipefail=${pipefail_supported}, mv-fh=${mv_fh_supported}." >&2

		exit 1
	fi

	echo "${skip_message}" >&2

	exit 0
fi

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

assert_log() {
	expected_priority=$1
	expected_message=$2
	log_file=$3
	expected_log="-t sinkhole -p ${expected_priority} ${expected_message}"
	log_lines=$(wc -l <"${log_file}" | tr -d ' ')

	if [ "${log_lines}" != '1' ]; then
		echo "FAIL: expected exactly one ${expected_priority} log line, received ${log_lines}." >&2

		exit 1
	fi

	actual_log=$(sed -n '1p' "${log_file}")

	if [ "${actual_log}" != "${expected_log}" ]; then
		echo "FAIL: unexpected log line: ${actual_log}." >&2

		exit 1
	fi
}

assert_boot_status() {
	expected_level=$1
	expected_message=$2
	status_file=$3

	if [ ! -f "${status_file}" ] || [ -L "${status_file}" ]; then
		echo "FAIL: ${status_file} is not a regular boot-status file." >&2

		exit 1
	fi

	status_lines=$(wc -l <"${status_file}" | tr -d ' ')

	if [ "${status_lines}" != '1' ]; then
		echo "FAIL: expected exactly one ${expected_level} boot-status line, received ${status_lines}." >&2

		exit 1
	fi

	actual_status=$(sed -n '1p' "${status_file}")
	tab=$(printf '\t')
	timestamp=${actual_status%%"${tab}"*}
	expected_status="${timestamp}${tab}${expected_level}${tab}${expected_message}"

	case "${timestamp}" in
		'' | *[!0-9]*)
			echo "FAIL: boot status has an invalid Unix timestamp: ${timestamp}." >&2

			exit 1
			;;
	esac

	if [ "${actual_status}" != "${expected_status}" ]; then
		echo "FAIL: unexpected boot-status line: ${actual_status}." >&2

		exit 1
	fi

	assert_mode 644 "${status_file}"

	if [ "$(file_owner "${status_file}")" != "${current_user}" ]; then
		echo 'FAIL: the boot-status owner is incorrect.' >&2

		exit 1
	fi
}

assert_no_temporary_files() {
	path=$1
	temporary_paths=$(find "${path}" \
		\( -name '.sinkhole-module-*' \
		-o -name '.sinkhole-generation-*' \
		-o -name '.clients-*' \
		-o -name 'active-link' \) \
		-print)

	if [ -n "${temporary_paths}" ]; then
		echo "FAIL: restore left temporary files under ${path}: ${temporary_paths}." >&2

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

run_restore() {
	restore_mirror_root=$1
	restore_runtime_root=$2
	restore_log_file=$3
	restore_boot_status=$4

	SINKHOLE_MIRROR_ROOT="${restore_mirror_root}" \
	SINKHOLE_RUNTIME_ROOT="${restore_runtime_root}" \
	SINKHOLE_UNBOUND_USER="${current_user}" \
	SINKHOLE_UNBOUND_GROUP="${current_group}" \
	SINKHOLE_ROOT_USER="${current_user}" \
	SINKHOLE_ROOT_GROUP="${current_group}" \
	SINKHOLE_LOGGER="${logger_stub}" \
	SINKHOLE_LOG_FILE="${restore_log_file}" \
	SINKHOLE_BOOT_STATUS="${restore_boot_status}" \
		sh "${workspace_directory}/port/files/usr/local/pkg/sinkhole/restore-runtime.sh"
}

trap cleanup EXIT HUP INT TERM

mirror_root="${temporary_directory}/mirror"
mirror_storage="${mirror_root}/sinkhole.d"
mirror_generation="${mirror_storage}/.sinkhole-generation-0123456789abcdef"
mirror_clients="${mirror_root}/sinkhole-clients"
runtime_root="${temporary_directory}/runtime"
current_user=$(id -un)
current_group=$(id -gn)
logger_stub="${temporary_directory}/logger-stub.sh"
runtime_log="${temporary_directory}/runtime.log"
runtime_boot_status="${temporary_directory}/runtime.status"

printf '%s\n' \
	'#!/bin/sh' \
	'printf '\''%s\n'\'' "$*" >> "${SINKHOLE_LOG_FILE}"' \
	>"${logger_stub}"
chmod 0755 "${logger_stub}"
: >"${runtime_log}"

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

run_restore "${mirror_root}" "${runtime_root}" "${runtime_log}" "${runtime_boot_status}"

assert_log \
	daemon.notice \
	"Restored the Sinkhole module, lists generation fixture-generation and client map to ${runtime_root} before Unbound start." \
	"${runtime_log}"
assert_boot_status \
	notice \
	"Restored the Sinkhole module, lists generation fixture-generation and client map to ${runtime_root} before Unbound start." \
	"${runtime_boot_status}"

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
missing_runtime_log="${temporary_directory}/missing-runtime.log"
missing_runtime_boot_status="${temporary_directory}/missing-runtime.status"

: >"${missing_runtime_log}"
run_restore \
	"${mirror_root}" \
	"${missing_runtime_root}" \
	"${missing_runtime_log}" \
	"${missing_runtime_boot_status}"

assert_log \
	daemon.notice \
	"Restored the Sinkhole module, lists generation fixture-generation and client map to ${missing_runtime_root} before Unbound start." \
	"${missing_runtime_log}"
assert_boot_status \
	notice \
	"Restored the Sinkhole module, lists generation fixture-generation and client map to ${missing_runtime_root} before Unbound start." \
	"${missing_runtime_boot_status}"

assert_mode 755 "${missing_runtime_root}"
assert_mode 755 "${missing_runtime_root}/sinkhole-state"
assert_mode 755 "${missing_runtime_root}/sinkhole-clients"
assert_mode 644 "${missing_runtime_root}/sinkhole-clients/clients.json"

no_clients_mirror="${temporary_directory}/no-clients-mirror"
no_clients_runtime="${temporary_directory}/no-clients-runtime"
no_clients_log="${temporary_directory}/no-clients.log"
no_clients_boot_status="${temporary_directory}/no-clients.status"

cp -R "${mirror_root}" "${no_clients_mirror}"
rm -rf -- "${no_clients_mirror}/sinkhole-clients"
: >"${no_clients_log}"
run_restore \
	"${no_clients_mirror}" \
	"${no_clients_runtime}" \
	"${no_clients_log}" \
	"${no_clients_boot_status}"

assert_log \
	daemon.notice \
	"Restored the Sinkhole module and lists generation fixture-generation to ${no_clients_runtime} before Unbound start." \
	"${no_clients_log}"
assert_boot_status \
	notice \
	"Restored the Sinkhole module and lists generation fixture-generation to ${no_clients_runtime} before Unbound start." \
	"${no_clients_boot_status}"

if [ -e "${no_clients_runtime}/sinkhole-clients" ]; then
	echo 'FAIL: a missing client-map mirror created runtime client files.' >&2

	exit 1
fi

missing_module_mirror="${temporary_directory}/missing-module-mirror"
missing_module_runtime="${temporary_directory}/missing-module-runtime"
missing_module_log="${temporary_directory}/missing-module.log"
missing_module_error="${temporary_directory}/missing-module.error"
missing_module_boot_status="${temporary_directory}/missing-module.status"

mkdir -p "${missing_module_mirror}"
: >"${missing_module_log}"

if run_restore \
	"${missing_module_mirror}" \
	"${missing_module_runtime}" \
	"${missing_module_log}" \
	"${missing_module_boot_status}" 2>"${missing_module_error}"; then
	echo 'FAIL: a missing module mirror did not fail the restore.' >&2

	exit 1
fi

if ! grep -Fx 'Sinkhole module mirror is unavailable.' "${missing_module_error}" >/dev/null; then
	echo 'FAIL: the missing module failure did not preserve its stderr reason.' >&2

	exit 1
fi

assert_log \
	daemon.err \
	'Sinkhole module mirror is unavailable.' \
	"${missing_module_log}"
assert_boot_status \
	err \
	'Sinkhole module mirror is unavailable.' \
	"${missing_module_boot_status}"
assert_no_temporary_files "${missing_module_runtime}"

invalid_generation_mirror="${temporary_directory}/invalid-generation-mirror"
invalid_generation_runtime="${temporary_directory}/invalid-generation-runtime"
invalid_generation_log="${temporary_directory}/invalid-generation.log"
invalid_generation_error="${temporary_directory}/invalid-generation.error"
invalid_generation_boot_status="${temporary_directory}/invalid-generation.status"

mkdir -p "${invalid_generation_mirror}"
cp "${mirror_root}/sinkhole.py" "${invalid_generation_mirror}/sinkhole.py"
ln -s 'sinkhole.d/not-a-generation' "${invalid_generation_mirror}/sinkhole"
: >"${invalid_generation_log}"

if run_restore \
	"${invalid_generation_mirror}" \
	"${invalid_generation_runtime}" \
	"${invalid_generation_log}" \
	"${invalid_generation_boot_status}" 2>"${invalid_generation_error}"; then
	echo 'FAIL: an invalid active generation did not fail the restore.' >&2

	exit 1
fi

if ! grep -Fx \
	'Sinkhole data mirror has an invalid active generation.' \
	"${invalid_generation_error}" >/dev/null; then
	echo 'FAIL: the invalid generation failure did not preserve its stderr reason.' >&2

	exit 1
fi

assert_log \
	daemon.err \
	'Sinkhole data mirror has an invalid active generation.' \
	"${invalid_generation_log}"
assert_boot_status \
	err \
	'Sinkhole data mirror has an invalid active generation.' \
	"${invalid_generation_boot_status}"
assert_no_temporary_files "${invalid_generation_runtime}"

status_write_failure_runtime="${temporary_directory}/status-write-failure-runtime"
status_write_failure_log="${temporary_directory}/status-write-failure.log"
status_write_failure_path="${temporary_directory}/missing-status-parent/sinkhole-boot-restore"

: >"${status_write_failure_log}"

if ! run_restore \
	"${mirror_root}" \
	"${status_write_failure_runtime}" \
	"${status_write_failure_log}" \
	"${status_write_failure_path}"; then
	echo 'FAIL: a boot-status write failure changed a successful restore exit status.' >&2

	exit 1
fi

assert_log \
	daemon.notice \
	"Restored the Sinkhole module, lists generation fixture-generation and client map to ${status_write_failure_runtime} before Unbound start." \
	"${status_write_failure_log}"

if [ -e "${status_write_failure_path}" ] || [ -L "${status_write_failure_path}" ]; then
	echo 'FAIL: a failed boot-status write left a destination entry.' >&2

	exit 1
fi

status_write_failure_error_runtime="${temporary_directory}/status-write-failure-error-runtime"
status_write_failure_error_log="${temporary_directory}/status-write-failure-error.log"
status_write_failure_error="${temporary_directory}/status-write-failure.error"

: >"${status_write_failure_error_log}"

if run_restore \
	"${missing_module_mirror}" \
	"${status_write_failure_error_runtime}" \
	"${status_write_failure_error_log}" \
	"${status_write_failure_path}" 2>"${status_write_failure_error}"; then
	echo 'FAIL: a boot-status write failure changed a failed restore exit status.' >&2

	exit 1
fi

if ! grep -Fx 'Sinkhole module mirror is unavailable.' \
	"${status_write_failure_error}" >/dev/null; then
	echo 'FAIL: a status-write failure changed the restore failure reason.' >&2

	exit 1
fi

assert_log \
	daemon.err \
	'Sinkhole module mirror is unavailable.' \
	"${status_write_failure_error_log}"

echo 'PASS restore runtime ownership, mode, boot-status, logging and cleanup boundaries'
