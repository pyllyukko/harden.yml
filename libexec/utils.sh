#!/bin/bash
function mkpatch() {
  local    _basename=$( basename "${1}" )
  local -i i=1
  # no previous file with same basename
  if [ ! -f "${logdir}/${_basename}.patch" -a ! -f "${logdir}/${_basename}-${i}.patch" ]
  then
    echo "${logdir}/${_basename}.patch"
  # one previous file with same basename
  elif [ -f "${logdir}/${_basename}.patch" -a ! -f "${logdir}/${_basename}-${i}.patch" ]
  then
    mv "${logdir}/${_basename}.patch" "${logdir}/${_basename}-${i}.patch"
    echo  "${logdir}/${_basename}-$((++i)).patch"
  # several previous files with same basename
  elif [ ! -f "${logdir}/${_basename}.patch" -a -f "${logdir}/${_basename}-${i}.patch" ]
  then
    while [ -f "${logdir}/${_basename}-$((++i)).patch" ]
    do
      true
    done
    echo  "${logdir}/${_basename}-${i}.patch"
  fi
} # mkpatch()
################################################################################
function sed_with_diff() {
  # $1 = regex $2 = file
  local ret
  local patchfilename="$(mkpatch "${2}")"
  diff -u "${2}" <(sed "${1}" "${2}") 1>"${patchfilename}"
  ret=${?}
  if [ ${ret} -ne 1 ]
  then
    rm "${patchfilename}"
    case "${ret}" in
      # "Exit status is 0 if inputs are the same"
      0)
        echo "[-] warning: diff returned ${ret}. already configured?" 1>&2
      ;;
      # "2 if trouble"
      *)
        echo "[-] error: diff returned ${ret}" 1>&2
      ;;
    esac
    return 1
  fi
  sed -i "${1}" "${2}"
  return ${?}
} # sed_with_diff()
################################################################################
function check_for_conf_file() {
  local file
  for file in "$@"
  do
    if [ ! -f "${file}" ]
    then
      echo "[-] error: file \`${file}' not found!" 1>&2
      return 1
    fi
  done
  return 0
} # check_for_conf_file()
