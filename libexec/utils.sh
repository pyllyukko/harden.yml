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
################################################################################
function print_topic() {
  echo -e "\n${1}\n${1//?/-}"
} # print_topic()
function get_lynis_hardening_index() {
  if [ ! -d ${LYNIS_DIR} ]
  then
    echo "[-] couldn't find Lynis" 1>&2
    return 1
  fi
  if [ ! -r /var/log/lynis.log ]
  then
    echo "[-] /var/log/lynis.log not readable" 1>&2
    return 1
  fi
  pushd ${LYNIS_DIR} 1>/dev/null || return 1
  # TODO: "[ Press ENTER to continue, or CTRL+C to cancel ]"
  ./lynis -q --skip-plugins --tests-from-group ${1} 1>/dev/null
  popd 1>/dev/null
  grep -o 'Hardening index.*' /var/log/lynis.log
} # get_lynis_hardening_index()
function compare_lynis_scores() {
  if [ "${1}" = "${2}" ]
  then
    echo "[-] Lynis score did not change: ${2}" 1>&2
  else
    echo "[+] Lynis score: ${2}"
  fi
} # compare_lynis_scores()
