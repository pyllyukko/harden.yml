#!/bin/bash

if [ ! -f /var/log/lynis.log ]
then
  echo "[-] Lynis log not found" 1>&2
  exit 1
fi

hardening_index="$(sed -n 's/^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} Hardening index : \[\([0-9]\+\)\] \[[# ]\+\]$/\1/p' /var/log/lynis.log)"

if [[ ! ${hardening_index} =~ ^[0-9]+$ ]]
then
  echo "[-] Couldn't determine hardening index" 1>&2
  exit 1
fi

if [ ${#} -eq 1 ] && [[ ${1} =~ ^[0-9]+$ ]]
then
  if [ "${hardening_index}" -lt "${1}" ]
  then
    echo "[-] Hardening index too low" 1>&2
    exit 1
  fi
  echo -e "[\033[1;32m+\033[0m] Lynis score sufficient"
  if [ -f /var/log/lynis.log.old ]
  then
    old_index="$(sed -n 's/^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} Hardening index : \[\([0-9]\+\)\] \[[# ]\+\]$/\1/p' /var/log/lynis.log.old)"
    if [[ ${old_index} =~ ^[0-9]+$ ]] && [ ${hardening_index} -gt ${old_index} ]
    then
      echo -e "[\033[1;32m+\033[0m] Score increase = $((hardening_index - old_index))"
    fi
  fi
fi
