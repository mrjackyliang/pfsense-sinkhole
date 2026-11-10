#!/bin/sh
set -euo pipefail

mirror_root="${SINKHOLE_MIRROR_ROOT:-/cf/conf/sinkhole/unbound}"
runtime_root="${SINKHOLE_RUNTIME_ROOT:-/var/unbound}"
unbound_user="${SINKHOLE_UNBOUND_USER:-unbound}"
unbound_group="${SINKHOLE_UNBOUND_GROUP:-unbound}"
root_user="${SINKHOLE_ROOT_USER:-root}"
root_group="${SINKHOLE_ROOT_GROUP:-wheel}"
runtime_storage="${runtime_root}/sinkhole.d"
runtime_state="${runtime_root}/sinkhole-state"
runtime_clients="${runtime_root}/sinkhole-clients"
runtime_link="${runtime_root}/sinkhole"
temporary_module=''
temporary_clients=''
new_generation=''

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
}

ensure_runtime_root() {
  if [ -L "${runtime_root}" ]; then
    echo 'Sinkhole runtime root must not be a symbolic link.' >&2
    return 1
  fi

  if [ ! -d "${runtime_root}" ]; then
    old_umask=$(umask)
    umask 0022
    mkdir -p -- "${runtime_root}"
    umask "${old_umask}"
    chown -h "${unbound_user}:${unbound_group}" "${runtime_root}"

    if [ -L "${runtime_root}" ] || [ ! -d "${runtime_root}" ]; then
      echo 'Sinkhole runtime root changed during creation.' >&2
      return 1
    fi
  fi
}

ensure_runtime_storage() {
  if [ -L "${runtime_storage}" ]; then
    echo 'Sinkhole runtime storage must not be a symbolic link.' >&2
    return 1
  fi

  if [ ! -d "${runtime_storage}" ]; then
    old_umask=$(umask)
    umask 0022
    mkdir -- "${runtime_storage}"
    umask "${old_umask}"
    chown -h "${root_user}:${root_group}" "${runtime_storage}"

    if [ -L "${runtime_storage}" ] || [ ! -d "${runtime_storage}" ]; then
      echo 'Sinkhole runtime storage changed during creation.' >&2
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
      echo 'Sinkhole runtime state changed during creation.' >&2
      return 1
    fi
  fi
}

restore_module() {
  local_source="${mirror_root}/sinkhole.py"

  if [ ! -f "${local_source}" ] || [ -L "${local_source}" ]; then
    echo 'Sinkhole module mirror is unavailable.' >&2
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
    echo 'Unable to create the Sinkhole runtime module.' >&2
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
    echo 'Sinkhole data mirror has an invalid active generation.' >&2
    return 1
  fi

  source_generation="${mirror_root}/${active_target}"

  if [ ! -d "${source_generation}" ] || [ -L "${source_generation}" ]; then
    echo 'Sinkhole data mirror is unavailable.' >&2
    return 1
  fi

  for data_file in manifest.json domains.tsv bypass.tsv allow.txt generation; do
    source_file="${source_generation}/${data_file}"

    if [ ! -f "${source_file}" ] || [ -L "${source_file}" ]; then
      echo "Sinkhole data mirror is missing ${data_file}." >&2
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
      echo "Sinkhole data mirror has an unsafe ${data_file}." >&2
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
    echo 'Unable to create a Sinkhole runtime generation.' >&2
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
    echo 'Sinkhole client map mirror is unsafe.' >&2
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
    echo 'Unable to restore the Sinkhole client map.' >&2
    return 1
  fi

  chown -h "${root_user}:${root_group}" "${temporary_clients}"
  mv -fh -- "${temporary_clients}" "${runtime_clients}/clients.json"
  temporary_clients=''
}

main() {
  trap cleanup EXIT HUP INT TERM

  ensure_runtime_root
  ensure_runtime_storage
  ensure_runtime_state
  restore_module
  restore_generation
  restore_clients
}

main "$@"
