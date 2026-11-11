#!/bin/sh
set -euo pipefail

mirror_root="${SINKHOLE_MIRROR_ROOT:-/cf/conf/sinkhole/unbound}"
runtime_root="${SINKHOLE_RUNTIME_ROOT:-/var/unbound}"
unbound_user="${SINKHOLE_UNBOUND_USER:-unbound}"
unbound_group="${SINKHOLE_UNBOUND_GROUP:-unbound}"
root_user="${SINKHOLE_ROOT_USER:-root}"
root_group="${SINKHOLE_ROOT_GROUP:-wheel}"
logger_command="${SINKHOLE_LOGGER:-logger}"
boot_status="${SINKHOLE_BOOT_STATUS:-/var/run/sinkhole-boot-restore}"
runtime_storage="${runtime_root}/sinkhole.d"
runtime_state="${runtime_root}/sinkhole-state"
runtime_clients="${runtime_root}/sinkhole-clients"
runtime_link="${runtime_root}/sinkhole"
temporary_module=''
temporary_clients=''
new_generation=''
temporary_boot_status=''
failure_reason=''
restored_generation=''
restored_clients='false'

cleanup() {
  if [ -n "${temporary_module}" ] && [ -e "${temporary_module}" ]; then
    rm -f -- "${temporary_module}"
  fi

  if [ -n "${new_generation}" ] && [ -d "${new_generation}" ]; then
    rm -rf -- "${new_generation}"
  fi

  if [ -n "${temporary_clients}" ] && [ -e "${temporary_clients}" ]; then
    rm -f -- "${temporary_clients}"
  fi

  if [ -n "${temporary_boot_status}" ] \
    && { [ -e "${temporary_boot_status}" ] || [ -L "${temporary_boot_status}" ]; }; then
    rm -f -- "${temporary_boot_status}"
  fi
}

log_outcome() {
  priority=$1
  message=$2

  "${logger_command}" -t sinkhole -p "${priority}" "${message}" >/dev/null 2>&1 || :
}

write_boot_status() {
  level=$1
  message=$2
  timestamp="$(date '+%s' 2>/dev/null)" || return 0

  temporary_boot_status="$(mktemp "${boot_status}.XXXXXXXX" 2>/dev/null)" || {
    temporary_boot_status=''
    return 0
  }

  if ! printf '%s\t%s\t%s\n' "${timestamp}" "${level}" "${message}" \
    >"${temporary_boot_status}" \
    || ! chmod 0644 "${temporary_boot_status}" \
    || ! chown -h "${root_user}:${root_group}" "${temporary_boot_status}" \
    || ! mv -fh -- "${temporary_boot_status}" "${boot_status}"; then
    if rm -f -- "${temporary_boot_status}" >/dev/null 2>&1; then
      temporary_boot_status=''
    fi

    return 0
  fi

  temporary_boot_status=''
}

on_exit() {
  exit_status=$?

  trap - EXIT HUP INT TERM
  set +e

  cleanup

  if [ "${exit_status}" -eq 0 ]; then
    if [ "${restored_clients}" = 'true' ]; then
      success_message="Restored the Sinkhole module, lists generation ${restored_generation} and client map to ${runtime_root} before Unbound start."
    else
      success_message="Restored the Sinkhole module and lists generation ${restored_generation} to ${runtime_root} before Unbound start."
    fi

    write_boot_status notice "${success_message}"
    log_outcome daemon.notice "${success_message}"
  else
    if [ -z "${failure_reason}" ]; then
      failure_reason="Sinkhole boot restore failed unexpectedly with exit status ${exit_status}."
    fi

    write_boot_status err "${failure_reason}"
    log_outcome daemon.err "${failure_reason}"
  fi

  cleanup

  exit "${exit_status}"
}

report_failure() {
  failure_reason=$1

  printf '%s\n' "${failure_reason}" >&2
}

ensure_runtime_root() {
  if [ -L "${runtime_root}" ]; then
    report_failure 'Sinkhole runtime root must not be a symbolic link.'
    return 1
  fi

  if [ ! -d "${runtime_root}" ]; then
    old_umask=$(umask)
    umask 0022
    mkdir -p -- "${runtime_root}"
    umask "${old_umask}"
    chown -h "${unbound_user}:${unbound_group}" "${runtime_root}"

    if [ -L "${runtime_root}" ] || [ ! -d "${runtime_root}" ]; then
      report_failure 'Sinkhole runtime root changed during creation.'
      return 1
    fi
  fi
}

ensure_runtime_storage() {
  if [ -L "${runtime_storage}" ]; then
    report_failure 'Sinkhole runtime storage must not be a symbolic link.'
    return 1
  fi

  if [ ! -d "${runtime_storage}" ]; then
    old_umask=$(umask)
    umask 0022
    mkdir -- "${runtime_storage}"
    umask "${old_umask}"
    chown -h "${root_user}:${root_group}" "${runtime_storage}"

    if [ -L "${runtime_storage}" ] || [ ! -d "${runtime_storage}" ]; then
      report_failure 'Sinkhole runtime storage changed during creation.'
      return 1
    fi
  fi
}

ensure_runtime_state() {
  if [ -L "${runtime_state}" ] || { [ -e "${runtime_state}" ] && [ ! -d "${runtime_state}" ]; }; then
    rm -f -- "${runtime_state}"
  fi

  if [ ! -d "${runtime_state}" ]; then
    old_umask=$(umask)
    umask 0022
    mkdir -- "${runtime_state}"
    umask "${old_umask}"
    chown -h "${unbound_user}:${unbound_group}" "${runtime_state}"

    if [ -L "${runtime_state}" ] || [ ! -d "${runtime_state}" ]; then
      report_failure 'Sinkhole runtime state changed during creation.'
      return 1
    fi
  fi
}

restore_module() {
  local_source="${mirror_root}/sinkhole.py"

  if [ ! -f "${local_source}" ] || [ -L "${local_source}" ]; then
    report_failure 'Sinkhole module mirror is unavailable.'
    return 1
  fi

  attempt=0

  while [ "${attempt}" -lt 10 ]; do
    module_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    candidate_module="${runtime_storage}/.sinkhole-module-${module_suffix}"

    if [ ! -e "${candidate_module}" ] && [ ! -L "${candidate_module}" ]; then
      old_umask=$(umask)
      umask 0022

      if install -m 0644 "${local_source}" "${candidate_module}" 2>/dev/null; then
        umask "${old_umask}"
        temporary_module="${candidate_module}"
        break
      fi

      umask "${old_umask}"
    fi

    attempt=$((attempt + 1))
  done

  if [ -z "${temporary_module}" ] || [ -L "${temporary_module}" ] || [ ! -f "${temporary_module}" ]; then
    report_failure 'Unable to create the Sinkhole runtime module.'
    return 1
  fi

  chown -h "${root_user}:${root_group}" "${temporary_module}"
  mv -fh -- "${temporary_module}" "${runtime_root}/sinkhole.py"
  temporary_module=''
}

restore_generation() {
  active_target="$(readlink "${mirror_root}/sinkhole")"

  if ! printf '%s\n' "${active_target}" \
    | grep -Eq '^sinkhole\.d/\.sinkhole-generation-[0-9a-f]{16}$'; then
    report_failure 'Sinkhole data mirror has an invalid active generation.'
    return 1
  fi

  source_generation="${mirror_root}/${active_target}"

  if [ ! -d "${source_generation}" ] || [ -L "${source_generation}" ]; then
    report_failure 'Sinkhole data mirror is unavailable.'
    return 1
  fi

  for data_file in manifest.json domains.tsv bypass.tsv allow.txt generation; do
    source_file="${source_generation}/${data_file}"

    if [ ! -f "${source_file}" ] || [ -L "${source_file}" ]; then
      report_failure "Sinkhole data mirror is missing ${data_file}."
      return 1
    fi
  done

  scope_allow_files=''

  for source_file in "${source_generation}"/allow-*.txt; do
    if [ ! -e "${source_file}" ] && [ ! -L "${source_file}" ]; then
      continue
    fi

    data_file="$(basename -- "${source_file}")"

    if ! printf '%s\n' "${data_file}" \
      | grep -Eq '^allow-(network|device)-[0-9a-f]{32}\.txt$'; then
      continue
    fi

    if [ ! -f "${source_file}" ] || [ -L "${source_file}" ]; then
      report_failure "Sinkhole data mirror has an unsafe ${data_file}."
      return 1
    fi

    scope_allow_files="${scope_allow_files} ${data_file}"
  done

  attempt=0
  old_umask=$(umask)
  umask 0022

  while [ "${attempt}" -lt 10 ]; do
    generation_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    candidate_generation="${runtime_storage}/.sinkhole-generation-${generation_suffix}"

    if mkdir -- "${candidate_generation}" 2>/dev/null; then
      new_generation="${candidate_generation}"
      break
    fi

    attempt=$((attempt + 1))
  done

  umask "${old_umask}"

  if [ -z "${new_generation}" ]; then
    report_failure 'Unable to create a Sinkhole runtime generation.'
    return 1
  fi

  chown -h "${root_user}:${root_group}" "${new_generation}"

  for data_file in manifest.json domains.tsv bypass.tsv allow.txt generation; do
    install -m 0644 \
      "${source_generation}/${data_file}" \
      "${new_generation}/${data_file}"
    chown -h "${root_user}:${root_group}" "${new_generation}/${data_file}"
  done

  for data_file in ${scope_allow_files}; do
    install -m 0644 \
      "${source_generation}/${data_file}" \
      "${new_generation}/${data_file}"
    chown -h "${root_user}:${root_group}" "${new_generation}/${data_file}"
  done

  restored_generation="$(sed -n '1p' "${new_generation}/generation")"

  generation_name="$(basename -- "${new_generation}")"
  link_target="sinkhole.d/${generation_name}"
  temporary_link="${new_generation}/active-link"

  ln -s "${link_target}" "${temporary_link}"

  if [ -e "${runtime_link}" ] && [ ! -L "${runtime_link}" ]; then
    rm -rf -- "${runtime_link}"
  fi

  mv -fh -- "${temporary_link}" "${runtime_link}"

  for generation_path in "${runtime_storage}"/.sinkhole-generation-*; do
    if [ ! -d "${generation_path}" ] || [ "${generation_path}" = "${new_generation}" ]; then
      continue
    fi

    generation_name="$(basename -- "${generation_path}")"

    if printf '%s\n' "${generation_name}" \
      | grep -Eq '^\.sinkhole-generation-[0-9a-f]{16}$'; then
      rm -rf -- "${generation_path}"
    fi
  done

  new_generation=''
}

restore_clients() {
  source_directory="${mirror_root}/sinkhole-clients"
  source_file="${source_directory}/clients.json"

  if [ ! -e "${source_file}" ] && [ ! -L "${source_file}" ]; then
    return 0
  fi

  if [ ! -d "${source_directory}" ] || [ -L "${source_directory}" ] \
    || [ ! -f "${source_file}" ] || [ -L "${source_file}" ]; then
    report_failure 'Sinkhole client map mirror is unsafe.'
    return 1
  fi

  if [ -L "${runtime_clients}" ] || { [ -e "${runtime_clients}" ] && [ ! -d "${runtime_clients}" ]; }; then
    rm -f -- "${runtime_clients}"
  fi

  if [ ! -d "${runtime_clients}" ]; then
    old_umask=$(umask)
    umask 0022
    mkdir -- "${runtime_clients}"
    umask "${old_umask}"
  fi

  chmod 0755 "${runtime_clients}"
  chown -h "${root_user}:${root_group}" "${runtime_clients}"

  attempt=0

  while [ "${attempt}" -lt 10 ]; do
    client_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    candidate_clients="${runtime_clients}/.clients-${client_suffix}"

    if [ ! -e "${candidate_clients}" ] && [ ! -L "${candidate_clients}" ]; then
      if install -m 0644 "${source_file}" "${candidate_clients}" 2>/dev/null; then
        temporary_clients="${candidate_clients}"
        break
      fi
    fi

    attempt=$((attempt + 1))
  done

  if [ -z "${temporary_clients}" ] || [ ! -f "${temporary_clients}" ] \
    || [ -L "${temporary_clients}" ]; then
    report_failure 'Unable to restore the Sinkhole client map.'
    return 1
  fi

  chown -h "${root_user}:${root_group}" "${temporary_clients}"
  mv -fh -- "${temporary_clients}" "${runtime_clients}/clients.json"
  temporary_clients=''
  restored_clients='true'
}

main() {
  trap on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  ensure_runtime_root
  ensure_runtime_storage
  ensure_runtime_state
  restore_module
  restore_generation
  restore_clients
}

main "$@"
